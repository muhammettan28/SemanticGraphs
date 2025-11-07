#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Android APK'ları için anlamsal graf tabanlı zararlı yazılım skorlama motoru.
- build_api_graph_compact: Bir APK'dan API çağrı grafı ve metadata oluşturur.
- analyze_malware_semantically: Oluşturulan graf ve metadatayı analiz ederek
  bir zararlı yazılım skoru üretir.
"""

from __future__ import annotations
import math
from pathlib import Path
from typing import List, Dict, Tuple
import networkx as nx
import json
import sys
from analysis import packing
from analysis import constants as c
from analysis import suspicious_combinations as sc
from statistics import mean
import re
try:
    from androguard.misc import AnalyzeAPK
except ImportError:
    print("Hata: Androguard kütüphanesi bulunamadı. Lütfen 'pip install androguard' komutu ile kurun.")
    exit(1)


# semantic_graphs.py (en altta)
def _squash(x: float, K: float = 100.0, a: float = 0.04) -> float: # a=0.04 veya 0.05 olabilir, threshold yok
    return K / (1.0 + math.exp(-a * x))

def build_api_graph_compact(apk_path: str, min_weight: int = 1) -> tuple[dict, Path]:
    """
    Bir APK dosyasını analiz eder, sınıf tabanlı bir API çağrı grafiği oluşturur
    ve ilgili metadatayı çıkarır.
    """
    out_dir = Path("./graph_files")
    out_dir.mkdir(exist_ok=True)
    base_name = Path(apk_path).stem
    graph_path = out_dir / f"{base_name}.graphml"
    meta_path = out_dir / f"{base_name}.meta.json"

    a, d, dx = AnalyzeAPK(apk_path)

    # API frekans analizini
    api_frequencies = analyze_api_frequencies(dx.get_call_graph())

    cg = dx.get_call_graph()
    G = nx.DiGraph()

    for edge in cg.edges(data=True):
        src_class = edge[0].class_name
        dst_class = edge[1].class_name
        if src_class in c.STOP_CLASSES or dst_class in c.STOP_CLASSES:
            continue
        if G.has_edge(src_class, dst_class):
            G[src_class][dst_class]['weight'] += 1
        else:
            G.add_edge(src_class, dst_class, weight=1)


    G.remove_edges_from([(u, v) for u, v, d in G.edges(data=True) if d.get("weight", 1) < min_weight])
    G.remove_nodes_from(list(nx.isolates(G)))

    nx.write_graphml(G, str(graph_path))

    all_perms = a.get_permissions()
    meta = {
        'apk_name': Path(apk_path).name,
        'apk_size_kb': round(Path(apk_path).stat().st_size / 1024.0, 2),
        'all_permissions': sorted(all_perms),
        'dangerous_permissions': sorted([p.split('.')[-1] for p in all_perms if p.split('.')[-1] in c.DANGEROUS_PERMISSIONS]),
        'api_frequencies': {k: v for k, v in sorted(api_frequencies.items(), key=lambda x: x[1], reverse=True)[:10]}
    }
    with meta_path.open("w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)

    return meta, graph_path


def compute_category_entropy(log_text: str) -> float:
    """
    'Graf Kategorileri' kısmındaki kategori-frekans dağılımından Shannon entropisi hesaplar.
    Entropi -> Davranış çeşitliliği (0.0 düşük çeşitlilik / tek amaçlı, 1.0 yüksek çeşitlilik / dengeli)
    """
    # Graf Kategorileri satırlarını yakala
    section = re.search(r"Graf Kategorileri\s*\(counts_g\):([\s\S]*?)(Manifest Kategorileri|Şüpheli API Kombinasyonları)", log_text)
    if not section:
        return 0.0

    lines = section.group(1).strip().splitlines()
    freqs = []
    for line in lines:
        match = re.search(r":\s*(\d+)", line)
        if match:
            count = int(match.group(1))
            freqs.append(count)

    if not freqs:
        return 0.0

    total = sum(freqs)
    probs = [f / total for f in freqs]

    # Shannon Entropy (normalize edilmiş)
    entropy = -sum(p * math.log2(p) for p in probs if p > 0)
    max_entropy = math.log2(len(probs))
    norm_entropy = entropy / max_entropy if max_entropy > 0 else 0.0

    return round(norm_entropy, 3)

def compute_api_combo_intensity(log_text: str) -> float:
    # 1️⃣ Şüpheli kombinasyonları bul (ör. "+5.5", "Overlay + SMS + Accessibility + C2")
    combo_lines = re.findall(r"(\+[\d\.]+).*", log_text)
    combo_scores = [float(re.search(r"\+([\d\.]+)", c).group(1)) for c in combo_lines if re.search(r"\+([\d\.]+)", c)]

    # 2️⃣ Her kombinasyondaki API kategorilerini tespit et
    pattern = r"([A-Za-z_]+(?:\s*\+\s*[A-Za-z_]+)+)"
    combos = re.findall(pattern, log_text)
    parsed_combos = []
    for combo in combos:
        apis = [a.strip().lower() for a in combo.split('+')]
        if len(apis) > 1:
            parsed_combos.append(apis)

    if not parsed_combos:
        return 0.0

    # 3️⃣ API sırasını temsil eden "davranış zinciri" uzunluğu
    avg_chain_len = mean(len(c) for c in parsed_combos)

    # 4️⃣ Farklı API türlerinin çeşitliliği
    unique_apis = set(a for combo in parsed_combos for a in combo)
    diversity_factor = len(unique_apis) / 50.0  # 50 ≈ olası toplam API kategori sayısı
    diversity_factor = min(diversity_factor, 1.0)

    # 5️⃣ Kombinasyon ağırlığı (ör. (+5.5) değerlerinin ortalaması)
    if combo_scores:
        avg_weight = mean(combo_scores)
        weight_factor = min(avg_weight / 10.0, 1.0)
    else:
        weight_factor = 0.2  # düşük varsayılan

    # 6️⃣ API sıralamasına göre temporal önem (ör. zincir uzunluğu 3+ ise daha kritik)
    temporal_factor = math.tanh(avg_chain_len / 4.0)  # 1'e asimptotik yaklaşır

    # 7️⃣ Nihai yoğunluk skoru (normalize edilmiş 0–1 arası)
    intensity = (0.4 * diversity_factor +
                 0.3 * weight_factor +
                 0.3 * temporal_factor)
    return round(min(intensity, 1.0), 3)


def compute_semantic_risk_score(benign_ratio: float, log_text: str) -> float:
    api_intensity = compute_api_combo_intensity(log_text)
    cat_entropy = compute_category_entropy(log_text)
    score = (
            0.35 * (1 - benign_ratio) +
            0.40 * api_intensity +  # davranış ağırlığını biraz artır
            0.25 * (1 - cat_entropy)
    )
    return round(min(score, 1.0), 3)



def compute_semantic_bonus(counts_g, counts_m, N, E, is_packed, benign_ratio, meta, sc):
    cfg = c.BONUS_CONFIG
    raw_scores = []

    # 0) Graph density-based suspicion (sparse graphs are suspicious)
    density = (E / max(1.0, N)) if N > 0 else 0.0
    if N <= cfg["min_graph_nodes"] and E <= cfg["min_graph_edges"]:
        # very small graph -> high suspicion
        raw_scores.append(cfg["empty_graph_severity"] * cfg["max_bonus_raw"] * 0.15)
    else:
        # sparse but not empty
        if density < cfg["density_threshold_low"]:
            raw_scores.append((1.0 - (density / cfg["density_threshold_low"])) * cfg["max_bonus_raw"] * 0.08)
        elif density > cfg["density_threshold_high"]:
            # very dense graphs likely benign complex apps -> small negative or zero
            raw_scores.append(-0.02 * cfg["max_bonus_raw"] * min(1.0, density))

    # 1) Packing / obfuscation
    # is_packed might be boolean or confidence number - normalize
    if isinstance(is_packed, bool):
        pack_sev = cfg["packing_severity"] if is_packed else 0.0
    else:
        # if confidence in [0..1]
        pack_sev = float(is_packed)
    if pack_sev > 0:
        raw_scores.append(pack_sev * cfg["max_bonus_raw"] * 0.2)

    # 2) Feature-based severity sums (levelled)
    sev_sum = 0.0
    for k, base_sev in cfg["severity_weights"].items():
        count = counts_g.get(k, 0) + counts_m.get(k, 0)
        if count <= 0:
            continue
        # severity increases sublinearly with count: sev = base_sev * (1 - exp(-count/scale))
        scale = 3.0
        sev = base_sev * (1.0 - math.exp(-float(count) / scale))
        sev_sum += sev

    raw_scores.append(sev_sum * cfg["max_bonus_raw"] * 0.05)

    # 3) Suspicious combinations (use existing sc.check_suspicious_combinations)
    suspicious_bonus, detected_combos = sc.check_suspicious_combinations(counts_g, counts_m, benign_ratio)
    # assume suspicious_bonus is already a severity-like small number; scale it
    raw_scores.append(suspicious_bonus * cfg["combo_scale"] * cfg["max_bonus_raw"] * 0.01)

    # 4) Critical flag multipliers (if ransomware/spyware present, amplify)
    critical_multiplier = 1.0
    if counts_g.get("ransomware", 0) > 0 or counts_g.get("spyware", 0) > 0:
        critical_multiplier += 0.5
    if counts_g.get("banking_targets", 0) > 0 and counts_g.get("overlay", 0) > 0:
        critical_multiplier += 0.3

    total_raw = sum(raw_scores) * critical_multiplier

    # 5) Benign shield: if benign_ratio sufficiently high, down-weight bonuses
    if benign_ratio >= cfg["benign_ratio_shield"]:
        total_raw *= cfg["benign_shield_factor"]

    # 6) Squash/normalize into 0..final_scale using logistic-like squash
    K = cfg["max_bonus_raw"]
    a = 0.03
    # logistic-like mapping: final = final_scale * (1 - exp(-a * total_raw))
    # but guard negatives
    total_raw_pos = max(0.0, total_raw)
    final_score = cfg["final_scale"] * (1.0 - math.exp(-a * total_raw_pos))

    # optional debug info
    debug = {
        "raw_components": raw_scores,
        "total_raw": total_raw,
        "density": density,
        "detected_combos": detected_combos,
        "final_bonus": final_score,
    }
    return final_score, debug


def analyze_malware_semantically(graph_path: str | Path, apk_path: str | Path,subset) -> tuple[dict, float]:
    """
    Oluşturulan graf ve metadatayı analiz ederek bir zararlı yazılım skoru üretir.
    (Tüm iyileştirmeler entegre edildi: W rafine, dinamik indirim, cap'ler, benign_ui, dinamik norm, sigmoid)
    """

    # 1) VERİLERİ YÜKLE VE DEĞİŞKENLERİ AYARLA
    # ==================================================================
    graph_path = Path(graph_path)
    apk_path = Path(apk_path)
    meta_path = graph_path.with_suffix(".meta.json")
    debug_file = Path(subset +"_scores.txt")

    try:
        G = nx.read_graphml(graph_path)
        with meta_path.open("r", encoding="utf-8") as f:
            meta = json.load(f)
    except Exception as e:
        print(f"[FATAL] Analiz verileri okunamadı: {graph_path} | Hata: {e}", file=sys.stderr)
        return {"apk_name": apk_path.name, "error": str(e)}, 50.0

    report = meta.copy()
    N = G.number_of_nodes()
    E = G.number_of_edges()
    apk_size_kb = meta.get("apk_size_kb", 1024)

    is_packed = packing.is_likely_packed_with_androguard(apk_path)
    is_small = apk_size_kb <= 2000
    is_large = apk_size_kb >= 10000
    benign_heavy = len(meta.get('all_permissions', [])) > 40 and \
                   len(c.BENIGN_HINT_PERMS.intersection(meta.get('all_permissions', []))) >= 1

    # 2) nodes_str ve KATEGORİ SAYIMLARI (counts_g, counts_m)
    # ==================================================================
    nodes_str = [str(n) for n in G.nodes()]
    counts_g = {k: 0 for k in c.CATEGORY_RULES}
    counts_m = {k: 0 for k in c.CATEGORY_RULES}

    for cat, patterns in c.CATEGORY_RULES.items():
        for node in nodes_str:
            if any(p in node for p in patterns):
                counts_g[cat] += 1

    for perm in meta.get('all_permissions', []):
        cat = c.PERM_TO_CATEGORY.get(perm.split('.')[-1])
        if cat:
            counts_m[cat] += 1
    if meta.get('dangerous_permissions'):
        counts_m['dangerous_permissions'] = len(meta['dangerous_permissions'])

    # 3) BENIGN RATIO'yu ÖNCE HESAPLA (AĞIRLIK İNDİRİMİ İÇİN GEREKLİ!)
    # ==================================================================
    benign_ratio = calculate_weighted_benign_ratio(nodes_str, N)

    # 4) AĞIRLIKLARI BENIGN RATIO'YA GÖRE DÜŞÜR
    # ==================================================================
    effective_W = c.W

    if benign_ratio >= 0.7:
        # ==========================
        # 1) TAM BENIGN (SAFE ZONE)
        # ==========================
        counts_m['dangerous_permissions'] = min(counts_m.get('dangerous_permissions', 0), 1)
        counts_g['dangerous_permissions'] = min(counts_g.get('dangerous_permissions', 0), 1)
        counts_g['network'] = min(counts_g.get('network', 0), 5)
        counts_g['crypto'] = min(counts_g.get('crypto', 0), 4)
        counts_g['native_code'] = min(counts_g.get('native_code', 0), 4)
        counts_g['banking_targets'] = min(counts_g.get('banking_targets', 0), 4)
        counts_g['shell_exec'] = min(counts_g.get('shell_exec', 0), 4)
        counts_g['file_operations'] = min(counts_g.get('file_operations', 0), 4)
        counts_g['location'] = min(counts_g.get('location', 0), 4)
        counts_g['reflection'] = min(counts_g.get('reflection', 0), 4)
        counts_g['package_info'] = min(counts_g.get('package_info', 0), 4)
        counts_g['device_info'] = min(counts_g.get('device_info', 0), 4)
        counts_g['background_ops'] = min(counts_g.get('background_ops', 0), 4)
        counts_g['content_provider'] = min(counts_g.get('content_provider', 0), 4)
        counts_g['emulator_detection'] = min(counts_g.get('emulator_detection', 0), 4)
        counts_g['sqlite'] = min(counts_g.get('sqlite', 0), 4)
        counts_g['contacts'] = min(counts_g.get('contacts', 0), 4)
        counts_g['c2_communication'] = min(counts_g.get('c2_communication', 0), 4)
        counts_g['notifications'] = min(counts_g.get('notifications', 0), 4)
        counts_g['exfiltration'] = min(counts_g.get('exfiltration', 0), 4)
        counts_g['keylogging'] = min(counts_g.get('keylogging', 0), 4)
        counts_g['accessibility'] = min(counts_g.get('accessibility', 0), 4)
        counts_g['bluetooth'] = min(counts_g.get('bluetooth', 0), 4)
        counts_g['camera_capture'] = min(counts_g.get('camera_capture', 0), 3)
        counts_g['microphone_capture'] = min(counts_g.get('microphone_capture', 0), 4)
        counts_g['adware'] = min(counts_g.get('adware', 0), 3)
        counts_g['obfuscation'] = min(counts_g.get('obfuscation', 0), 3)
        counts_g['overlay'] = min(counts_g.get('overlay', 0), 4)
        counts_g['analytics'] = min(counts_g.get('analytics', 0), 5)
        counts_g['webview'] = min(counts_g.get('webview', 0), 3)
        counts_g['intent_hijacking'] = min(counts_g.get('intent_hijacking', 0), 3)
        counts_g['dynamic'] = min(counts_g.get('dynamic', 0), 3)
        counts_g['telephony'] = min(counts_g.get('telephony', 0), 3)
        counts_g['sms'] = min(counts_g.get('sms', 0), 1)
        counts_g['privileged_ops'] = min(counts_g.get('privileged_ops', 0), 2)
        counts_g['hooking_frameworks'] = min(counts_g.get('hooking_frameworks', 0), 2)
        counts_g['anti_debug'] = min(counts_g.get('anti_debug', 0), 2)
        counts_g['data_theft'] = min(counts_g.get('data_theft', 0), 2)


    elif benign_ratio >= 0.3:
        # ==========================
        # 2) YARI BENIGN (GRAY ZONE)
        # ==========================
        counts_m['dangerous_permissions'] = min(counts_m.get('dangerous_permissions', 0), 5)
        counts_g['dangerous_permissions'] = min(counts_g.get('dangerous_permissions', 0), 5)
        counts_g['network'] = min(counts_g.get('network', 0), 8)
        counts_g['crypto'] = min(counts_g.get('crypto', 0), 8)
        counts_g['native_code'] = min(counts_g.get('native_code', 0), 8)
        counts_g['banking_targets'] = min(counts_g.get('banking_targets', 0), 7)
        counts_g['shell_exec'] = min(counts_g.get('shell_exec', 0), 8)
        counts_g['file_operations'] = min(counts_g.get('file_operations', 0), 8)
        counts_g['location'] = min(counts_g.get('location', 0), 8)
        counts_g['reflection'] = min(counts_g.get('reflection', 0), 8)
        counts_g['package_info'] = min(counts_g.get('package_info', 0), 8)
        counts_g['device_info'] = min(counts_g.get('device_info', 0), 8)
        counts_g['background_ops'] = min(counts_g.get('background_ops', 0), 8)
        counts_g['content_provider'] = min(counts_g.get('content_provider', 0), 8)
        counts_g['emulator_detection'] = min(counts_g.get('emulator_detection', 0), 8)
        counts_g['sqlite'] = min(counts_g.get('sqlite', 0), 8)
        counts_g['contacts'] = min(counts_g.get('contacts', 0), 6)
        counts_g['c2_communication'] = min(counts_g.get('c2_communication', 0), 6)
        counts_g['notifications'] = min(counts_g.get('notifications', 0), 6)
        counts_g['exfiltration'] = min(counts_g.get('exfiltration', 0), 6)
        counts_g['keylogging'] = min(counts_g.get('keylogging', 0), 6)
        counts_g['accessibility'] = min(counts_g.get('accessibility', 0), 6)
        counts_g['bluetooth'] = min(counts_g.get('bluetooth', 0), 6)
        counts_g['camera_capture'] = min(counts_g.get('camera_capture', 0), 5)
        counts_g['microphone_capture'] = min(counts_g.get('microphone_capture', 0), 5)
        counts_g['adware'] = min(counts_g.get('adware', 0), 5)
        counts_g['obfuscation'] = min(counts_g.get('obfuscation', 0), 5)
        counts_g['overlay'] = min(counts_g.get('overlay', 0), 5)
        counts_g['analytics'] = min(counts_g.get('analytics', 0), 8)
        counts_g['telephony'] = min(counts_g.get('telephony', 0), 4)
        counts_g['sms'] = min(counts_g.get('sms', 0), 3)
        counts_g['webview'] = min(counts_g.get('webview', 0), 5)
        counts_g['intent_hijacking'] = min(counts_g.get('intent_hijacking', 0), 5)
        counts_g['dynamic'] = min(counts_g.get('dynamic', 0), 5)
        counts_g['privileged_ops'] = min(counts_g.get('privileged_ops', 0), 4)
        counts_g['hooking_frameworks'] = min(counts_g.get('hooking_frameworks', 0), 4)
        counts_g['anti_debug'] = min(counts_g.get('anti_debug', 0), 4)
        counts_g['data_theft'] = min(counts_g.get('data_theft', 0), 4)


    else:
        # ==========================
        # 3) ZARARLI (MALWARE ZONE)
        # ==========================
        counts_m['dangerous_permissions'] = min(counts_m.get('dangerous_permissions', 0), 20)
        counts_g['dangerous_permissions'] = min(counts_g.get('dangerous_permissions', 0), 20)
        counts_g['network'] = min(counts_g.get('network', 0), 30)
        counts_g['crypto'] = min(counts_g.get('crypto', 0), 12)
        counts_g['native_code'] = min(counts_g.get('native_code', 0), 12)
        counts_g['banking_targets'] = min(counts_g.get('banking_targets', 0), 10)
        counts_g['shell_exec'] = min(counts_g.get('shell_exec', 0), 20)
        counts_g['location'] = min(counts_g.get('location', 0), 12)
        counts_g['file_operations'] = min(counts_g.get('file_operations', 0), 20)
        counts_g['reflection'] = min(counts_g.get('reflection', 0), 12)
        counts_g['package_info'] = min(counts_g.get('package_info', 0), 12)
        counts_g['device_info'] = min(counts_g.get('device_info', 0), 12)
        counts_g['background_ops'] = min(counts_g.get('background_ops', 0), 12)
        counts_g['content_provider'] = min(counts_g.get('content_provider', 0), 12)
        counts_g['emulator_detection'] = min(counts_g.get('emulator_detection', 0), 12)
        counts_g['sqlite'] = min(counts_g.get('sqlite', 0), 12)
        counts_g['contacts'] = min(counts_g.get('contacts', 0), 8)
        counts_g['c2_communication'] = min(counts_g.get('c2_communication', 0), 8)
        counts_g['notifications'] = min(counts_g.get('notifications', 0), 8)
        counts_g['exfiltration'] = min(counts_g.get('exfiltration', 0), 8)
        counts_g['keylogging'] = min(counts_g.get('keylogging', 0), 8)
        counts_g['accessibility'] = min(counts_g.get('accessibility', 0), 8)
        counts_g['bluetooth'] = min(counts_g.get('bluetooth', 0), 8)
        counts_g['camera_capture'] = min(counts_g.get('camera_capture', 0), 5)
        counts_g['microphone_capture'] = min(counts_g.get('microphone_capture', 0), 5)
        counts_g['adware'] = min(counts_g.get('adware', 0), 6)
        counts_g['obfuscation'] = min(counts_g.get('obfuscation', 0), 6)
        counts_g['overlay'] = min(counts_g.get('overlay', 0), 6)
        counts_g['analytics'] = min(counts_g.get('analytics', 0), 20)
        counts_g['telephony'] = min(counts_g.get('telephony', 0), 5)
        counts_g['sms'] = min(counts_g.get('sms', 0), 10)
        counts_g['webview'] = min(counts_g.get('webview', 0), 10)
        counts_g['intent_hijacking'] = min(counts_g.get('intent_hijacking', 0), 10)
        counts_g['dynamic'] = min(counts_g.get('dynamic', 0), 10)
        counts_g['privileged_ops'] = min(counts_g.get('privileged_ops', 0), 10)
        counts_g['hooking_frameworks'] = min(counts_g.get('hooking_frameworks', 0), 10)
        counts_g['anti_debug'] = min(counts_g.get('anti_debug', 0), 10)

        # 6) HAM SEMANTİK VE YAPISAL SKORLARI HESAPLA
        # ==================================================================
        sem_g_raw = sum(effective_W.get(cat, 1.0) * count for cat, count in counts_g.items())
        sem_m_raw = sum(effective_W.get(cat, 1.0) * count for cat, count in counts_m.items())

        beta = 1.0
        if is_small:
            beta = 1.5
        elif is_large:
            beta = 0.75
        sem_raw = sem_g_raw + beta * sem_m_raw

        avg_degree = (2 * E) / N if N > 0 else 0
        norm = 1.0 + math.log1p(N / 1000) + math.log1p(E / 500) + (avg_degree / 10)
        sem_normed = sem_raw / norm if norm > 1 else sem_raw

        structural = 0.0
        if N > 10:
            max_out = max((d for _, d in G.out_degree()), default=0)
            max_in = max((d for _, d in G.in_degree()), default=0)
            density = nx.density(G)
            hub_score = (max_out + max_in) / (2 * N) if N > 0 else 0
            mod_penalty = 0
            try:
                if N > 20:
                    communities = nx.community.greedy_modularity_communities(G.to_undirected())
                    modularity = nx.community.modularity(G.to_undirected(), communities)
                    mod_penalty = (1 - modularity) * 5
            except Exception:
                pass
            structural = math.log1p(max_out) * 2 + hub_score * 15 + density * 8 + mod_penalty

        # 7) SEZGİSEL BONUSLARI HESAPLA
        # ==================================================================
        bonus, bonus_debug = compute_semantic_bonus(
            counts_g, counts_m, N, E, is_packed, benign_ratio, meta, sc
        )
        report["bonus_debug"] = bonus_debug

        # 8) NİHAİ SKORU HESAPLA (DİNAMİK NORMALİZASYON + BENIGN İNDİRİMİ)
        # ==================================================================
        mult = 1.0
        if is_small:
            mult = 1.2
        elif is_large:
            mult = 0.9
        else:
            mult = 0.85

        total_raw_unnormalized = (sem_normed + structural + bonus) * mult
        normalization_factor = math.log(max(N, 10))
        total_raw_normalized = total_raw_unnormalized / normalization_factor

        # 8-A) Kombinasyon Bayrakları (benign indirimi / tehdit sınıflaması için)
        uses_admin = counts_g.get('admin_operations', 0) > 0
        uses_accessibility = counts_g.get('accessibility', 0) > 0
        uses_crypto = counts_g.get('crypto', 0) > 1
        uses_dynamic_code = counts_g.get('dynamic', 0) > 0
        uses_shell_exec = counts_g.get('shell_exec', 0) > 0
        uses_sms = counts_g.get('sms', 0) > 0 or counts_m.get('sms', 0) > 0
        uses_keylogging = counts_g.get('keylogging', 0) > 0
        uses_overlay = counts_g.get('overlay', 0) > 0
        has_banking_targets = counts_g.get('banking_targets', 0) > 0
        has_c2_comm = counts_g.get('network', 0) > 0

        # BENIGN İNDİRİMİ (SADECE BİR KEZ!)
        very_high_threat_combo_1 = uses_accessibility and uses_overlay and has_banking_targets
        very_high_threat_combo_2 = uses_admin and uses_crypto
        very_high_threat_combo_3 = uses_sms and has_c2_comm and uses_dynamic_code
        very_high_threat_combo_4 = uses_dynamic_code and uses_shell_exec
        is_very_high_threat = (
                very_high_threat_combo_1 or
                very_high_threat_combo_2 or
                very_high_threat_combo_3 or
                very_high_threat_combo_4
        )

        is_medium_threat_combo = uses_dynamic_code and (uses_accessibility or uses_keylogging)

        if is_packed or is_very_high_threat:
            reduction_multiplier = 1.0
        elif is_medium_threat_combo and benign_ratio > 0.7:
            print(f"[!] Orta Risk + Yüksek Benign Ratio ({benign_ratio:.1%}) -> İndirim İptal Edildi.")
            reduction_multiplier = 1.0
        else:
            slope = 5.0
            center = 0.55
            reduction_multiplier = 1.0 / (1.0 + math.exp(slope * (benign_ratio - center)))

        total_raw = total_raw_normalized * reduction_multiplier

    # 9) SİGMOİD SQUASH (DÜŞÜK total_raw İÇİN UYARLANDI)
    # ==================================================================
    a=0.04
    K=100.0
    total = _squash(total_raw, K, a)

    # 10) DEBUG LOG
    # ==================================================================
    try:
        with debug_file.open("a", encoding="utf-8") as f:
            f.write(f"\n{'=' * 80}\n")
            f.write(f"APK: {meta['apk_name']}\n")
            f.write(f"  N={N}, E={E}, size={apk_size_kb}KB, is_packed={is_packed}\n")
            f.write(f"  sem_normed={sem_normed:.4f}\n")
            f.write(f"  structural={structural:.4f}\n")
            f.write(f"  bonus={bonus:.4f}\n")
            f.write(f"  mult={mult:.2f}\n")
            f.write(
                f"  total_raw_unnormalized={(sem_normed + structural + bonus):.4f} * {mult:.2f} = {total_raw_unnormalized:.4f}\n")
            f.write(f"  normalization_factor={normalization_factor:.4f}\n")
            f.write(f"  total_raw_normalized={total_raw_normalized:.4f}\n")
            f.write(f"\n  Benign Library Hits: Weighted ratio = {benign_ratio:.2%}\n")
            f.write(f"  Benign Reduction Multiplier: {reduction_multiplier:.4f}\n")
            f.write(f"  FINAL total_raw={total_raw:.4f}\n")

            f.write(f"\n  Graf Kategorileri (counts_g):\n")
            for cat, count in sorted(counts_g.items(), key=lambda x: x[1], reverse=True):
                if count > 0:
                    f.write(
                        f"    {cat}: {count} (weight={c.W.get(cat, 1.0)}, contribution={count * c.W.get(cat, 1.0):.2f})\n")

            f.write(f"\n  Manifest Kategorileri (counts_m):\n")
            for cat, count in sorted(counts_m.items(), key=lambda x: x[1], reverse=True):
                if count > 0:
                    f.write(
                        f"    {cat}: {count} (weight={c.W.get(cat, 1.0)}, contribution={count * c.W.get(cat, 1.0):.2f})\n")

            f.write("\n  Şüpheli API Kombinasyonları:\n")
            if detected_combos:
                for combo in detected_combos:
                    f.write(f"    {combo}\n")
            else:
                f.write(f"    (Yok)\n")

            f.write(f"\n  Squash Function:\n")
            f.write(f"    _squash(total_raw={total_raw:.4f}, K={K}, a={a}) -> {total:.4f}\n")
            f.flush()
    except Exception as e:
        print(f"[HATA] Debug dosyası yazılamadı: {e}", file=sys.stderr)

    # 8) RAPORU GÜNCELLE VE DÖNDÜR
    # ==================================================================
    report.update({
        'node_count': N,
        'edge_count': E,
        'sem_score_normed': round(sem_normed, 4),
        'structural_score': round(structural, 4),
        'bonus_score': round(bonus, 4),
        'total_raw': round(total_raw, 4),
        'malware_score': round(total, 4)
    })

    # === Log Text oluşturma ===
    log_text_parts = []
    for k, v in report.items():
        if isinstance(v, str):
            log_text_parts.append(v)
        elif isinstance(v, (list, dict)):
            log_text_parts.append(str(v))
    log_text = "\n".join(log_text_parts)

    # === Semantic Risk ve Hybrid Score ===
    semantic_risk = compute_semantic_risk_score(benign_ratio, log_text)
    report["semantic_risk_score"] = semantic_risk

    malware_score = (
            report.get("squashed_score")
            or report.get("total_raw_normalized")
            or report.get("malware_score")
            or 0.0
    )

    # --- 2D adaptive risk_weight (benign_ratio x semantic_risk) ---
    if benign_ratio >= 0.7:
        if semantic_risk > 0.6:
            risk_weight = 0.20
        elif semantic_risk > 0.4:
            risk_weight = 0.10
        else:
            risk_weight = 0.05

    elif benign_ratio >= 0.4:
        if semantic_risk > 0.7:
            risk_weight = 0.35
        elif semantic_risk > 0.5:
            risk_weight = 0.25
        else:
            risk_weight = 0.15

    else:
        if semantic_risk > 0.8:
            risk_weight = 0.45
        elif semantic_risk > 0.6:
            risk_weight = 0.40
        else:
            risk_weight = 0.30

    # --- Base hybrid (weighted combination) ---
    hybrid_score = (1 - risk_weight) * malware_score + (risk_weight * (semantic_risk * 100))

    # --- Extra penalty for extremely low benign_ratio (< 0.15) ---
    LIB_RATIO_THRESHOLD = 0.20  # %15 altı = neredeyse hiç benign library yok
    PENALTY_ALPHA = 0.20  # semantik risk oranına göre çarpan

    if benign_ratio < LIB_RATIO_THRESHOLD:
        penalty_factor = 1.0 + (semantic_risk * PENALTY_ALPHA)
        hybrid_score *= penalty_factor

    # --- Clamp and finalize ---
    hybrid_score = max(0.0, min(hybrid_score, 100.0))
    report["hybrid_score"] = round(hybrid_score, 4)

    return report, round(hybrid_score, 4)


def analyze_api_frequencies(cg) -> Dict[str, int]:
    """API çağrı sıklıklarını analiz eder"""
    api_call_frequencies = {}
    for edge in cg.edges(data=True):
        dst_class = edge[1].class_name
        if dst_class not in api_call_frequencies:
            api_call_frequencies[dst_class] = 0
        api_call_frequencies[dst_class] += 1
    return api_call_frequencies


def calculate_weighted_benign_ratio(nodes_str: list[str], N: int) -> float:
    if N == 0:
        return 0.0

    benign_hits = 0
    # BENIGN_LIBRARIES'i constants'dan import ettiğinizi varsayalım (örn: import constants as c)
    for node in nodes_str:
        # startswith KULLANARAK doğru kontrol
        if any(node.startswith(lib) for lib in c.BENIGN_LIBRARIES):
            benign_hits += 1

    # Gerçek oranı (0.0 ile 1.0 arası) döndür
    return benign_hits / N