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
from report import debug_log as dt
from statistics import mean
import re

try:
    from androguard.misc import AnalyzeAPK
except ImportError:
    print("Hata: Androguard kütüphanesi bulunamadı. Lütfen 'pip install androguard' komutu ile kurun.")
    exit(1)


def _squash(x: float, K: float = 100.0, a: float = 0.04) -> float:  # a=0.04 veya 0.05 olabilir, threshold yok
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
        'dangerous_permissions': sorted(
            [p.split('.')[-1] for p in all_perms if p.split('.')[-1] in c.DANGEROUS_PERMISSIONS]),
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
    section = re.search(
        r"Graf Kategorileri\s*\(counts_g\):([\s\S]*?)(Manifest Kategorileri|Şüpheli API Kombinasyonları)", log_text)
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

def compute_semantic_bonus(counts_g, counts_m, N, E, is_packed, benign_ratio, sc):
    cfg = c.BONUS_CONFIG
    raw_scores = []

    density = (E / max(1.0, N)) if N > 0 else 0.0
    if N <= cfg["min_graph_nodes"] and E <= cfg["min_graph_edges"]:
        raw_scores.append(cfg["empty_graph_severity"] * cfg["max_bonus_raw"] * 0.15)
    else:
        if density < cfg["density_threshold_low"]:
            raw_scores.append((1.0 - (density / cfg["density_threshold_low"])) * cfg["max_bonus_raw"] * 0.08)
        elif density > cfg["density_threshold_high"]:
            raw_scores.append(-0.02 * cfg["max_bonus_raw"] * min(1.0, density))

    if isinstance(is_packed, bool):
        pack_sev = cfg["packing_severity"] if is_packed else 0.0
    else:
        pack_sev = float(is_packed)
    if pack_sev > 0:
        raw_scores.append(pack_sev * cfg["max_bonus_raw"] * 0.2)

    sev_sum = 0.0
    for k, base_sev in cfg["severity_weights"].items():
        count = counts_g.get(k, 0) + counts_m.get(k, 0)
        if count <= 0:
            continue

        scale = 3.0
        sev = base_sev * (1.0 - math.exp(-float(count) / scale))
        sev_sum += sev

    raw_scores.append(sev_sum * cfg["max_bonus_raw"] * 0.05)

    # GÜNCELLEME: suspicious_combinations artık 3 değer dönüyor (score, combos, flags)
    # Flags burada gerekli olmadığı için '_' ile yoksayıyoruz.
    suspicious_score, detected_combos, _ = sc.check_suspicious_combinations(counts_g, counts_m, benign_ratio)

    raw_scores.append(suspicious_score * cfg["combo_scale"] * cfg["max_bonus_raw"] * 0.01)

    critical_multiplier = 1.0
    if counts_g.get("ransomware", 0) > 0 or counts_g.get("spyware", 0) > 0:
        critical_multiplier += 0.5
    if counts_g.get("banking_targets", 0) > 0 and counts_g.get("overlay", 0) > 0:
        critical_multiplier += 0.3

    total_raw = sum(raw_scores) * critical_multiplier

    if benign_ratio >= cfg["benign_ratio_shield"]:
        total_raw *= cfg["benign_shield_factor"]

    a = cfg.get("bonus_a", 1.0)
    cap = cfg["total_raw_cap"]

    # scale raw into [0, 1+] range
    scaled = max(0.0, total_raw / cap)

    final_score = cfg["final_scale"] * (1.0 - math.exp(-a * scaled))

    debug = {
        "raw_components": raw_scores,
        "total_raw": total_raw,
        "a": a,
        "density": density,
        "detected_combos": detected_combos,
        "final_bonus": final_score,
    }
    return final_score, debug

def analyze_malware_semantically(graph_path: str | Path, apk_path: str | Path, subset) -> tuple[dict, float]:
    graph_path = Path(graph_path)
    apk_path = Path(apk_path)
    meta_path = graph_path.with_suffix(".meta.json")
    debug_file_txt = Path("results/" + subset + "_scores.txt")

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

    benign_ratio = calculate_weighted_benign_ratio(nodes_str, N, apk_path)

    effective_W = c.W
    
    # 1. GÜRÜLTÜLÜ (NOISY): Benign applerde çok sık olanlar
    noisy_cats = [
        'network', 'file_operations', 'reflection', 'crypto', 'native_code',
        'notifications', 'webview', 'background_ops', 'content_provider',
        'device_info', 'bluetooth', 'location', 'shared_prefs', 'sqlite',
        'analytics', 'adware', 'payment_sdk', 'permissions', 'sensor',
        'account', 'nfc', 'calendar', 'contacts', 'clipboard'
    ]
    
    # 2. RİSKLİ (RISKY): Benign'de olabilir ama az olmalı
    risky_cats = [
        'sms', 'telephony', 'banking_targets', 'shell_exec', 'accessibility',
        'overlay', 'dynamic', 'privileged_ops', 'system_keys', 'camera_capture',
        'microphone_capture', 'package_info', 'vpn', 'intent_hijacking',
        'classloader_manipulation', 'hooking_frameworks'
    ]
    
    # 3. ZARARLI (MALICIOUS): Benign app'te neredeyse hiç olmamalı
    malicious_cats = [
        'admin_operations', 'keylogging', 'screenshot', 'exfiltration',
        'persistence', 'ui_injection', 'data_theft', 'anti_vm', 
        'c2_communication', 'ransomware', 'spyware', 'permission_abuse',
        'root_detection', 'emulator_detection', 'anti_debug', 'obfuscation'
    ]

    # --- BÖLGE 1: GÜVENLİ (BENIGN) BÖLGE (Ratio >= 0.75) ---
    if benign_ratio >= 0.75:
        # A) Bonusları Serbest Bırak (Skoru düşürmeleri için)
        counts_g['modern_libs'] = min(counts_g.get('modern_libs', 0), 300)
        counts_g['benign_ui']   = min(counts_g.get('benign_ui', 0), 300)

        # B) Gürültülü Kategorileri Çok Sıkı Bastır (Max 2-3)
        # Bu kategoriler benign app'lerde yüzlerce kez geçebilir, skoru şişirmesin.
        for cat in noisy_cats:
            counts_g[cat] = min(counts_g.get(cat, 0), 3)

        # C) Riskli Kategorileri Tekil Yap (0 veya 1)
        # "Var mı var" mantığına döner. Adet sayıp skoru patlatmaz.
        for cat in risky_cats:
            counts_g[cat] = min(counts_g.get(cat, 0), 1)
            
        # D) Zararlı Kategorileri Sıfırla veya 1 Yap
        # Benign app içinde "ransomware" stringi geçiyorsa bu %99 ihtimalle
        # bir güvenlik kütüphanesinin içindeki değişkendir. Cezalandırma.
        for cat in malicious_cats:
            counts_g[cat] = min(counts_g.get(cat, 0), 0)  # Direkt 0 yapıyoruz, false positive önlemi

        # Manifest İzinleri de Bastır
        counts_m['dangerous_permissions'] = min(counts_m.get('dangerous_permissions', 0), 1)
        counts_g['dangerous_permissions'] = min(counts_g.get('dangerous_permissions', 0), 1)

    # --- BÖLGE 2: GRİ BÖLGE (Ratio >= 0.45) ---
    elif benign_ratio >= 0.45:
        # A) Bonuslar (Orta seviye)
        counts_g['modern_libs'] = min(counts_g.get('modern_libs', 0), 100)
        counts_g['benign_ui']   = min(counts_g.get('benign_ui', 0), 100)

        # B) Gürültü (Gevşek Limit - 20)
        for cat in noisy_cats:
            counts_g[cat] = min(counts_g.get(cat, 0), 20)

        # C) Riskli (Dikkatli Limit - 3)
        for cat in risky_cats:
            counts_g[cat] = min(counts_g.get(cat, 0), 3)

        # D) Zararlı (Var olmasına izin ver ama sınırla - 2)
        for cat in malicious_cats:
            counts_g[cat] = min(counts_g.get(cat, 0), 2)

        # Manifest
        counts_m['dangerous_permissions'] = min(counts_m.get('dangerous_permissions', 0), 5)
        counts_g['dangerous_permissions'] = min(counts_g.get('dangerous_permissions', 0), 5)

    # --- BÖLGE 3: TEHLİKELİ BÖLGE (Malware Bölgesi) ---
    else:
        # A) Bonusları Kısıtla (Malware taklidi yapamasın)
        counts_g['modern_libs'] = min(counts_g.get('modern_libs', 0), 10)
        counts_g['benign_ui']   = min(counts_g.get('benign_ui', 0), 10)

        # B) Tüm Limitleri Kaldır/Genişlet (100)
        # Malware ne yapıyorsa skora yansısın.
        all_cats = noisy_cats + risky_cats + malicious_cats
        for cat in all_cats:
            counts_g[cat] = min(counts_g.get(cat, 0), 100)

        # Manifest serbest
        counts_m['dangerous_permissions'] = min(counts_m.get('dangerous_permissions', 0), 50)
        counts_g['dangerous_permissions'] = min(counts_g.get('dangerous_permissions', 0), 50)

    sem_g_raw = sum(effective_W.get(cat, 1.0) * count for cat, count in counts_g.items())
    sem_m_raw = sum(effective_W.get(cat, 1.0) * count for cat, count in counts_m.items())

    beta = 1.0
    mult = 1.0
    if is_small:
        beta = 1.5
        mult = 1.2
    elif is_large:
        beta = 0.75
        mult = 0.9
    else:
        mult = 0.85

    sem_raw = sem_g_raw + beta * sem_m_raw

    avg_degree = (2 * E) / N if N > 0 else 0
    norm = 1.0 + math.log1p(N / 1000) + math.log1p(E / 500) + (avg_degree / 10)
    sem_normed = sem_raw / norm if norm > 1 else sem_raw

    structural = 0.0
    total_raw = 0.0
    bonus = 0.0

    suspicious_score, detected_combos, threat_flags = sc.check_suspicious_combinations(counts_g, counts_m, benign_ratio)

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

        bonus, bonus_debug = compute_semantic_bonus(
            counts_g, counts_m, N, E, is_packed, benign_ratio, sc
        )
        report["bonus_debug"] = bonus_debug["final_bonus"]

        total_raw_unnormalized = (sem_normed + structural + bonus) * mult
        normalization_factor = math.log(max(N, 10))
        total_raw_normalized = total_raw_unnormalized / normalization_factor

        is_very_high_threat = threat_flags.get("is_very_high", False)
        is_high_threat_combo = threat_flags.get("is_high", False)
        is_medium_threat_combo = threat_flags.get("is_medium", False)

        report["benign_ratio"] = benign_ratio

        reduction_multiplier = 1.0
        reduction_reason = "no reduction"


        if is_packed:
            reduction_reason = f"Packed: {is_packed} → reduction disabled"

        elif is_very_high_threat and benign_ratio < 0.75:
            # Çok yüksek tehdit var ve benign kod oranı bunu "örtbas" edecek kadar yüksek değil (0.75 altı).
            reduction_reason = f"Very High Threat + Benign Ratio < 0.75 ({benign_ratio:.2f}) → reduction disabled"

        elif is_high_threat_combo and benign_ratio < 0.65:
            reduction_reason = f"High Threat + Benign Ratio < 0.65 ({benign_ratio:.2f}) → reduction disabled"


        elif (is_very_high_threat or is_high_threat_combo or is_medium_threat_combo):
            reduction_reason = (
                f"Threat Detected (Med/High/VeryHigh) but High Benign Ratio ({benign_ratio:.2f}) → partial reduction"
            )

            # Normalden daha sert parametreler (Center'ı 0.75'e çekerek indirimi zorlaştırıyoruz)
            slope = 5.0
            center = 0.75
            sigmoid_val = 1.0 / (1.0 + math.exp(slope * (benign_ratio - center)))

            # GÜVENLİK FRENİ: Tehdit varsa skor asla %40'ın (0.4) altına inmesin.
            # Normalde benign_shield %10'lara kadar indirebilir, burada izin vermiyoruz.
            reduction_multiplier = max(sigmoid_val, 0.40)

        # ---------------------------------------------------------------------
        # 3. KADEME: STANDART İNDİRİM (NO THREAT)
        # Herhangi bir kombinasyon tehdidi yoksa, standart benign shield çalışır.
        # ---------------------------------------------------------------------
        else:
            slope = 6.0
            center = c.BONUS_CONFIG["benign_ratio_shield"]  # Genelde 0.65
            sigmoid_factor = 1.0 / (1.0 + math.exp(slope * (benign_ratio - center)))

            if benign_ratio >= center:
                # Maksimum indirim oranı (benign_shield_factor) ile sınırla
                reduction_multiplier = min(sigmoid_factor, c.BONUS_CONFIG["benign_shield_factor"])
                reduction_reason = (
                    f"Benign ratio {benign_ratio:.2f} ≥ {center} → applied shield {reduction_multiplier:.2f}"
                )
            else:
                reduction_multiplier = sigmoid_factor
                reduction_reason = f"Sigmoid reduction applied (benign_ratio={benign_ratio:.2f})"


        total_raw = total_raw_normalized * reduction_multiplier

        report["reduction_reason"] = reduction_reason
        report["reduction_multiplier"] = reduction_multiplier

    a = 0.07
    K = 100.0
    total = _squash(total_raw, K, a)

    report.update({
        'node_count': N,
        'edge_count': E,
        'sem_score_normed': round(sem_normed, 4),
        'structural_score': round(structural, 4),
        'bonus_score': round(bonus, 4),
        'total_raw': round(total_raw, 4),
        'malware_score': round(total, 4)
    })

    log_text_parts = []
    for k, v in report.items():
        if isinstance(v, str):
            log_text_parts.append(v)
        elif isinstance(v, (list, dict)):
            log_text_parts.append(str(v))
    log_text = "\n".join(log_text_parts)

    semantic_risk = compute_semantic_risk_score(benign_ratio, log_text)
    report["semantic_risk_score"] = semantic_risk

    dt.write_debug_txt(debug_file_txt, meta, N, E, apk_size_kb, is_packed, sem_normed, structural, bonus, mult,
                       total_raw_unnormalized,
                       normalization_factor, total_raw_normalized, benign_ratio, total_raw, counts_g, c, counts_m,
                       suspicious_score, detected_combos, K, a, total,semantic_risk)

    malware_score = (
            report.get("squashed_score")
            or report.get("total_raw_normalized")
            or report.get("malware_score")
            or 0.0
    )

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

    hybrid_score = (1 - risk_weight) * malware_score + (risk_weight * (semantic_risk * 100))

    LIB_RATIO_THRESHOLD = 0.20
    PENALTY_ALPHA = 0.20

    if benign_ratio < LIB_RATIO_THRESHOLD:
        penalty_factor = 1.0 + (semantic_risk * PENALTY_ALPHA)
        hybrid_score *= penalty_factor

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


def calculate_weighted_benign_ratio(
        nodes_str: list[str],
        N: int,
        apk_name: str
) -> float:
    benign_hits = 0
    matched_libs = set()

    if N == 0:
        ratio = 0.0
    else:
        for node in nodes_str:
            for lib in c.BENIGN_LIBRARIES:
                if node.startswith(lib):
                    benign_hits += 1
                    matched_libs.add(lib)  # sadece prefix’i tut
                    break
        ratio = benign_hits / N

    dt.write_benign_libs(apk_name, ratio, benign_hits, N, matched_libs)

    return ratio