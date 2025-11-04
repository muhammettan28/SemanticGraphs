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
    
    # API frekans analizini ekle
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

    # Düşük frekanslı kenarları (gürültüyü) temizle
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


def apply_benign_weight_discount(W: dict, benign_ratio: float) -> dict:
    """
    Benign kütüphane oranı yüksekse, yaygın kategorilerin ağırlığını düşür.
    """
    if benign_ratio < 0.45:
        return W.copy()

    discounted = W.copy()
    common_categories = ["network", "file_operations", "shared_prefs", "sqlite", "content_provider"]

    discount = 1.0 - (benign_ratio * 1.5)  # %50 benign_ratio → %75 indirim
    discount = max(discount, 0.1)  # En az 0.1 kalır

    for cat in common_categories:
        if cat in discounted:
            discounted[cat] *= discount

    return discounted


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
        # örnek satır: '    network: 10 (weight=2.0, contribution=20.00)'
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
    """
    Analiz loglarından API kombinasyon yoğunluğu (api_combo_intensity) hesaplar.
    Hem davranış zincir sırasını hem de kategori çeşitliliğini dikkate alır.

    Parametre:
        log_text (str): benign_scores.txt veya malware_scores.txt benzeri bir analiz çıktısı.

    Dönüş:
        intensity (float): 0.0–1.0 arası normalize edilmiş risk yoğunluğu.
    """

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

    
    
    if benign_ratio >= 0.45:
        # UYGULAMA ZARARSIZ İSE:
        # Daha bağışlayıcı ol ve tavanı DÜŞÜK tut (örn: 3)
        counts_m['dangerous_permissions'] = min(counts_m.get('dangerous_permissions', 0), 1)
        counts_g['dangerous_permissions'] = min(counts_m.get('dangerous_permissions', 0), 1)
        counts_g['network'] = min(counts_g.get('network', 0), 10)
        counts_g['crypto'] = min(counts_g.get('crypto', 0), 4)
        counts_g['native_code'] = min(counts_g.get('native_code', 0), 4)
        counts_g['banking_targets'] = min(counts_g.get('banking_targets', 0), 4)
        counts_g['shell_exec'] = min(counts_g.get('shell_exec', 0), 4)

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
        counts_g['dynamic'] = min(counts_g.get('dynamic', 0), 4)
        counts_g['accessibility'] = min(counts_g.get('accessibility', 0), 4)
        counts_g['bluetooth'] = min(counts_g.get('bluetooth', 0), 4)
        counts_g['camera_capture'] = min(counts_g.get('camera_capture', 0), 3)
        counts_g['microphone_capture'] = min(counts_g.get('microphone_capture', 0), 4)
        counts_g['adware'] = min(counts_g.get('adware', 0), 3)
        counts_g['obfuscation'] = min(counts_g.get('obfuscation', 0), 3)
        counts_g['overlay'] = min(counts_g.get('overlay', 0), 4)
        counts_g['analytics'] = min(counts_g.get('analytics', 0), 10)
        counts_g['webview'] = min(counts_g.get('telephony', 0), 3)
        counts_g['intent_hijacking'] = min(counts_g.get('intent_hijacking', 0), 3)
        counts_g['dynamic'] = min(counts_g.get('dynamic', 0), 3)
        counts_g['telephony'] = min(counts_g.get('telephony', 0), 3)
        counts_g['sms'] = min(counts_g.get('telephony', 0), 1)
        counts_g['privileged_ops'] = min(counts_g.get('privileged_ops', 0), 2)
        counts_g['hooking_frameworks'] = min(counts_g.get('hooking_frameworks', 0), 2)
        counts_g['anti_debug'] = min(counts_g.get('anti_debug', 0), 2)
        counts_g['data_theft'] = min(counts_g.get('data_theft', 0), 2)
        

    else:
        # UYGULAMA ZARARLI İSE:
        # Tam cezayı uygula ve tavanı YÜKSEK tut (örn: 10)
        counts_m['dangerous_permissions'] = min(counts_m.get('dangerous_permissions', 0), 10)
        counts_g['dangerous_permissions'] = min(counts_m.get('dangerous_permissions', 0), 10)
        counts_g['network'] = min(counts_g.get('network', 0), 30)
        counts_g['crypto'] = min(counts_g.get('crypto', 0), 12)
        counts_g['native_code'] = min(counts_g.get('native_code', 0), 12)
        counts_g['banking_targets'] = min(counts_g.get('banking_targets', 0), 10)
        counts_g['shell_exec'] = min(counts_g.get('shell_exec', 0), 10)


        counts_g['location'] = min(counts_g.get('location', 0), 12)
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
        counts_g['dynamic'] = min(counts_g.get('dynamic', 0), 8)
        counts_g['accessibility'] = min(counts_g.get('accessibility', 0), 8)
        counts_g['bluetooth'] = min(counts_g.get('bluetooth', 0), 8)
        counts_g['camera_capture'] = min(counts_g.get('camera_capture', 0), 5)
        counts_g['microphone_capture'] = min(counts_g.get('microphone_capture', 0), 5)
        counts_g['adware'] = min(counts_g.get('adware', 0), 6)
        counts_g['obfuscation'] = min(counts_g.get('obfuscation', 0), 6)
        counts_g['overlay'] = min(counts_g.get('overlay', 0), 6)
        counts_g['analytics'] = min(counts_g.get('analytics', 0), 20)
        counts_g['telephony'] = min(counts_g.get('telephony', 0), 5)
        counts_g['sms'] = min(counts_g.get('telephony', 0), 10)
        counts_g['webview'] = min(counts_g.get('telephony', 0), 10)
        counts_g['intent_hijacking'] = min(counts_g.get('intent_hijacking', 0), 10)
        counts_g['dynamic'] = min(counts_g.get('dynamic', 0), 10)
        counts_g['privileged_ops'] = min(counts_g.get('privileged_ops', 0), 10)
        counts_g['hooking_frameworks'] = min(counts_g.get('hooking_frameworks', 0), 10)
        counts_g['anti_debug'] = min(counts_g.get('anti_debug', 0), 10)
    
    counts_m['location'] = min(counts_m.get('location', 0), 3)
    counts_m['media_capture'] = min(counts_m.get('media_capture', 0), 3)
    counts_m['device_info'] = min(counts_m.get('device_info', 0), 3)
    counts_m['background_ops'] = min(counts_m.get('background_ops', 0), 3)

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
    bonus = 0.0
    is_empty_graph = N <= 5 and E <= 5

    uses_admin = counts_g.get('admin_operations', 0) > 0
    uses_accessibility = counts_g.get('accessibility', 0) > 0
    uses_reflection = counts_g.get('reflection', 0) > 0
    uses_native = counts_g.get('native_code', 0) > 0
    uses_crypto = counts_g.get('crypto', 0) > 1
    uses_dynamic_code = counts_g.get('dynamic', 0) > 0
    uses_telephony = counts_g.get('telephony', 0) > 0 or counts_m.get('telephony', 0) > 0
    uses_sms = counts_g.get('sms', 0) > 0 or counts_m.get('sms', 0) > 0
    uses_contacts = counts_g.get('contacts', 0) > 0
    uses_device_info = counts_g.get('device_info', 0) > 0
    has_c2_comm = counts_g.get('network', 0) > 0
    uses_overlay = counts_g.get('overlay', 0) > 0
    has_banking_targets = counts_g.get('banking_targets', 0) > 1
    uses_keylogging = counts_g.get('keylogging', 0) > 0
    uses_screenshot = counts_g.get('screenshot', 0) > 0
    uses_clipboard = counts_g.get('clipboard', 0) > 0
    has_root_detection = counts_g.get('root_detection', 0) > 0
    has_anti_debug = counts_g.get('anti_debug', 0) > 0
    has_emulator_detection = counts_g.get('emulator_detection', 0) > 0
    uses_shell_exec = counts_g.get('shell_exec', 0) > 0
    has_boot_receiver = any("BOOT_COMPLETED" in r for r in meta.get("receivers", []))
    uses_spyware = counts_g.get('spyware', 0) > 0
    uses_ransomware = counts_g.get('ransomware', 0) > 0

    # Seviye 1 Bonuslar
    if is_packed:
        bonus += 80.0
    elif is_empty_graph:
        print(f"[!] Düşük Karmaşıklık/Boş Graf tespiti (N={N}, E={E}). Ağır Obfuscation/Packing Cezası.")
        bonus += 80.0
        report['warning'] = "Graph is empty (N<=5), applying packing penalty."

    if uses_reflection and uses_native and uses_crypto:
        bonus += 4.0
    if has_boot_receiver and (uses_dynamic_code or uses_native):
        bonus += 10.0

    # Seviye 2 Bonuslar
    suspicious_bonus, detected_combos = check_suspicious_combinations(counts_g, counts_m,benign_ratio)
    bonus += suspicious_bonus

    if (uses_sms or uses_contacts or uses_telephony or uses_device_info) and has_c2_comm:
        bonus += 5
    if uses_accessibility and uses_overlay and has_banking_targets and (uses_telephony or uses_sms):
        bonus += 5.0
    if uses_keylogging and (uses_screenshot or uses_clipboard):
        bonus += 5.0
    if uses_admin and uses_crypto:
        bonus += 5.0
    if has_root_detection and has_anti_debug and has_emulator_detection:
        bonus += 5.0
    if uses_keylogging and has_c2_comm:
        bonus += 5.0

    # Seviye 3 Bonuslar
    critical_flags = [
        uses_sms, uses_admin, uses_dynamic_code, uses_telephony,
        has_emulator_detection, has_root_detection, uses_keylogging,
        has_banking_targets, uses_shell_exec, uses_device_info,
        uses_spyware,           # Casus yazılım davranışları
        uses_ransomware,        # Fidye yazılımı davranışları
        uses_accessibility,     # Erişilebilirlik servislerinin kötüye kullanımı
        uses_screenshot,        # Ekran görüntüsü alma
        uses_overlay            # Arayüz bindirme (Phishing için kritik)
    ]
    crit_hits = sum(critical_flags)
    if crit_hits >= 4:
        bonus += 3 * crit_hits

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

    # BENIGN İNDİRİMİ (SADECE BİR KEZ!)
    very_high_threat_combo_1 = uses_accessibility and uses_overlay and has_banking_targets
    very_high_threat_combo_2 = uses_admin and uses_crypto
    very_high_threat_combo_3 = uses_sms and has_c2_comm and uses_dynamic_code
    very_high_threat_combo_4 = uses_dynamic_code and uses_shell_exec
    is_very_high_threat = very_high_threat_combo_1 or very_high_threat_combo_2 or very_high_threat_combo_3 or very_high_threat_combo_4

    is_medium_threat_combo = uses_dynamic_code and (uses_accessibility or uses_keylogging)

    if is_packed or is_very_high_threat:
        reduction_multiplier = 1.0
    elif is_medium_threat_combo and benign_ratio > 0.45:
        print(f"[!] Orta Risk + Yüksek Benign Ratio ({benign_ratio:.1%}) -> İndirim İptal Edildi.")
        reduction_multiplier = 1.0
    else:
        eğim = 5.0
        merkez = 0.55
        reduction_multiplier = 1.0 / (1.0 + math.exp(eğim * (benign_ratio - merkez)))

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

    return report, round(total, 4)


def analyze_api_frequencies(cg) -> Dict[str, int]:
    """API çağrı sıklıklarını analiz eder"""
    api_call_frequencies = {}
    for edge in cg.edges(data=True):
        dst_class = edge[1].class_name
        if dst_class not in api_call_frequencies:
            api_call_frequencies[dst_class] = 0
        api_call_frequencies[dst_class] += 1
    return api_call_frequencies



from typing import Tuple, List, Dict, Set

def check_suspicious_combinations(counts_g: dict, counts_m: dict,benign_ratio: float) -> Tuple[float, List[str]]:
    """
    Şüpheli API/davranış kombinasyonlarını KATEGORİ SAYIMLARINA göre kontrol eder.
    Bu fonksiyon, düşük seviyeli (2'li) ve yüksek seviyeli (3,4,5'li) 
    tüm tetiklenen desenleri kümülatif olarak puanlar.
    """
    suspicious_score = 0.0
    detected_combinations = []

    # --- 1. Gerekli Davranış Bayraklarını Tanımla (EKSİKLER EKLENDİ) ---
    # Not: Bazı kategoriler (örn: file_access, microphone) 'constants.py' içinde
    # tanımlı olmayabilir. Bunların 'CATEGORY_RULES'a eklenmesi gerekir.
    # Şimdilik, var olanlara göre eşleştirme yapıyorum:
    flag_map = {
        'crypto': counts_g.get('crypto', 0) > 0,
        'network': counts_g.get('network', 0) > 0,
        'admin': counts_g.get('admin_operations', 0) > 0 or counts_m.get('admin_operations', 0) > 0,
        'sms': counts_g.get('sms', 0) > 0 or counts_m.get('sms', 0) > 0,
        'banking': counts_g.get('banking_targets', 0) > 1,
        'overlay': counts_g.get('overlay', 0) > 0,
        'reflection': counts_g.get('reflection', 0) > 0,
        'native': counts_g.get('native_code', 0) > 0,
        'dynamic': counts_g.get('dynamic', 0) > 0,
        'accessibility': counts_g.get('accessibility', 0) > 0,
        'keylogging': counts_g.get('keylogging', 0) > 0,
        'screenshot': counts_g.get('screenshot', 0) > 0,
        'contacts': counts_g.get('contacts', 0) > 0,
        'exfiltration': counts_g.get('exfiltration', 0) > 0,
        'persistence': counts_g.get('persistence', 0) > 0,
        'package_info': counts_g.get('package_info', 0) > 0,
        'shell_exec': counts_g.get('shell_exec', 0) > 0,
        'root_detection': counts_g.get('root_detection', 0) > 0,
        
        # --- YENİ EKLENEN KATEGORİLER ---
        # (Bu 'string' anahtarların 'constants.py'deki kategori 
        # adlarıyla eşleştiğinden emin olun)
        'location': counts_g.get('location', 0) > 0 or counts_m.get('location', 0) > 0,
        'camera': counts_g.get('camera_capture', 0) > 0 or counts_m.get('camera_capture', 0) > 0, # 'camera'yı 'media_capture'a eşledim
        'microphone': counts_g.get('microphone_capture', 0) > 0, # 'microphone'u 'media_capture'a eşledim
        'call_logs': counts_g.get('telephony', 0) > 0 or counts_m.get('telephony', 0) > 0, # 'call_logs'u 'telephony'ye eşledim
        'file_access': counts_g.get('file_operations', 0) > 0, # 'file_access'ı 'file_operations'a eşledim
        'obfuscation': counts_g.get('obfuscation', 0) > 0,
    }

    # --- 2. Tehdit Seviyelerine Göre Kombinasyon Kuralları ---

    # 2a. İKİLİ KOMBİNASYONLAR (Düşük Puanlı Taban Seviye)
    combinations = {
        ('accessibility', 'overlay'): {'score': 3.0, 'desc': 'Erişilebilirlik ile arayüz bindirme (Phishing/Trojan)'},
        ('keylogging', 'exfiltration'): {'score': 3.0, 'desc': 'Tuş vuruşlarını kaydedip dışarı sızdırma (Spyware)'},
        ('screenshot', 'exfiltration'): {'score': 3.0, 'desc': 'Ekran görüntüsü alıp dışarı sızdırma (Spyware)'},
        ('admin', 'crypto'): {'score': 3.0, 'desc': 'Cihaz yöneticisi yetkisiyle şifreleme (Ransomware riski)'},
        ('sms', 'network'): {'score': 5.0, 'desc': 'SMS mesajlarını okuyup ağa gönderme (OTP Hırsızlığı)'},
        ('contacts', 'exfiltration'): {'score': 4.0, 'desc': 'Kişi listesini çalıp dışarı sızdırma (Veri Hırsızlığı)'},
        ('dynamic', 'persistence'): {'score': 4.0, 'desc': 'Cihaz açılışında dinamik kod yükleme (Kalıcılık)'},
        ('banking', 'overlay'): {'score': 4.0, 'desc': 'Bankacılık anahtar kelimeleri ile arayüz bindirme (Banking Trojan)'},
        ('package_info', 'overlay'): {'score': 4.0, 'desc': 'Yüklü uygulamaları kontrol edip arayüz bindirme (Hedefli Phishing)'},
        ('admin', 'network'): {'score': 23.5, 'desc': 'Cihaz yöneticisi yetkileriyle ağ iletişimi'},
        ('root_detection', 'shell_exec'): {'score': 3.0, 'desc': 'Root tespiti sonrası shell komutu çalıştırma (Yetki Yükseltme)'},
        ('crypto', 'network'): {'score': 3.0, 'desc': 'Şifrelenmiş ağ iletişimi (C2/Komuta Kontrol olabilir)'},
        ('reflection', 'native'): {'score': 3.0, 'desc': 'Reflection ve native kod kullanımı (Gizlenme/Obfuscation)'},
    }

    # 2b. ÜÇLÜ KOMBİNASYONLAR (Yüksek Puanlı Zincirler)
    triple_combinations = {
        # ============ BANKING TROJAN VARYANTLARI ============
        ('accessibility', 'overlay', 'sms'): {'score': 6.0, 'desc': 'Tam Banking Trojan profili: Overlay + SMS + Accessibility'},
        ('accessibility', 'overlay', 'network'): {'score': 5.5, 'desc': 'Banking Trojan C2: Overlay + Accessibility + Komuta kontrol'},
        ('package_info', 'overlay', 'sms'): {'score': 5.0, 'desc': 'Hedefli saldırı: Uygulama tarama + Overlay + SMS okuma'},
        ('banking', 'overlay', 'sms'): {'score': 5.5, 'desc': 'Banking keyword detection + Overlay + SMS intercept'},
        ('accessibility', 'banking', 'network'): {'score': 5.0, 'desc': 'Kimlik bilgisi hırsızlığı: Accessibility + Banking kelime + Network'},
        ('overlay', 'sms', 'network'): {'score': 4.5, 'desc': 'Phishing + SMS okuma + C2 iletişimi'},
        ('accessibility', 'overlay', 'contacts'): {'score': 4.8, 'desc': 'Overlay attack + Kişi listesi çalma + Accessibility'},
        
        # ============ SPYWARE VARYANTLARI ============
        ('keylogging', 'screenshot', 'exfiltration'): {'score': 5.5, 'desc': 'Kapsamlı gözetleme: Tuş kaydı + Ekran + Sızdırma'},
        ('keylogging', 'accessibility', 'network'): {'score': 5.0, 'desc': 'Tuş kaydı + Accessibility ile veri toplama + Network sızdırma'},
        ('screenshot', 'accessibility', 'exfiltration'): {'score': 4.8, 'desc': 'Ekran kaydı + Accessibility monitoring + Veri sızdırma'},
        ('location', 'camera', 'exfiltration'): {'score': 5.5, 'desc': 'Lokasyon + Kamera + Veri sızdırma (Stalkerware)'},
        ('microphone', 'location', 'exfiltration'): {'score': 4.8, 'desc': 'Ses kaydı + Konum + Sızdırma (Gelişmiş gözetleme)'},
        ('contacts', 'sms', 'exfiltration'): {'score': 4.0, 'desc': 'Kişiler + SMS + Sızdırma (İletişim gözetleme)'},
        ('call_logs', 'sms', 'exfiltration'): {'score': 5.2, 'desc': 'Arama geçmişi + SMS + Sızdırma (İletişim profilleme)'},
        ('camera', 'microphone', 'exfiltration'): {'score': 4.0, 'desc': 'Kamera + Mikrofon + Sızdırma (Tam gözetleme)'},
        
        # ============ RANSOMWARE VARYANTLARI ============
        ('admin', 'crypto', 'exfiltration'): {'score': 5.5, 'desc': 'Ransomware zinciri: Admin + Şifreleme + Veri çalma'},
        ('admin', 'crypto', 'network'): {'score': 5.0, 'desc': 'Ransomware C2: Admin + Şifreleme + Komuta kontrolü'},
        ('admin', 'file_access', 'crypto'): {'score': 5.5, 'desc': 'Dosya şifreleme: Admin + Depolama erişimi + Kriptografi'},
        ('crypto', 'network', 'exfiltration'): {'score': 4.5, 'desc': 'Veri şifreleme + C2 + Sızdırma (Double extortion)'},
        ('admin', 'crypto', 'overlay'): {'score': 5.8, 'desc': 'Ransomware + Phishing: Admin + Şifreleme + Sahte ekran'},
        
        # ============ PERSISTENCE & STEALTH ============
        ('admin', 'persistence', 'network'): {'score': 4.5, 'desc': 'Kalıcı tehdit: Admin + Açılışta çalışma + C2 iletişimi'},
        ('root_detection', 'persistence', 'network'): {'score': 4.8, 'desc': 'Root tespiti + Kalıcılık + C2 (Gelişmiş tehdit)'},
        ('dynamic', 'persistence', 'network'): {'score': 4.5, 'desc': 'Dinamik yükleme + Kalıcılık + C2 (Polimorfik malware)'},
        ('reflection', 'native', 'obfuscation'): {'score': 5.0, 'desc': 'Reflection + Native kod + Obfuscation (Anti-analiz)'},
        ('dynamic', 'obfuscation', 'network'): {'score': 4.8, 'desc': 'Dinamik yükleme + Gizleme + Network (Gizli C2)'},
        ('root_detection', 'shell_exec', 'persistence'): {'score': 5.0, 'desc': 'Root + Shell komutları + Kalıcılık (Rootkit davranışı)'},
        
        # ============ DATA THEFT CHAINS ============
        ('contacts', 'sms', 'network'): {'score': 5.0, 'desc': 'Kişiler + SMS + Network (İletişim verileri çalma)'},
        ('contacts', 'call_logs', 'exfiltration'): {'score': 4.8, 'desc': 'Kişiler + Arama kayıtları + Sızdırma'},
        ('location', 'network', 'persistence'): {'score': 4.5, 'desc': 'Sürekli konum izleme + Network + Kalıcılık'},
        ('package_info', 'network', 'persistence'): {'score': 4.5, 'desc': 'Uygulama profilleme + C2 + Kalıcılık (Recon)'},
        ('file_access', 'exfiltration', 'network'): {'score': 4.2, 'desc': 'Dosya erişimi + Sızdırma + Network (Veri hırsızlığı)'},
        
        # ============ PRIVILEGE ESCALATION ============
        ('root_detection', 'shell_exec', 'admin'): {'score': 5.5, 'desc': 'Root tespit + Shell + Admin (Yetki yükseltme zinciri)'},
        ('reflection', 'shell_exec', 'admin'): {'score': 5.5, 'desc': 'Reflection + Shell + Admin (Dinamik yetki yükseltme)'},
        ('native', 'shell_exec', 'root_detection'): {'score': 4.8, 'desc': 'Native kod + Shell + Root (Düşük seviye saldırı)'},
        
        # ============ HYBRID THREATS ============
        ('accessibility', 'admin', 'network'): {'score': 5.0, 'desc': 'Accessibility + Admin + C2 (Çok amaçlı tehdit)'},
        ('overlay', 'admin', 'persistence'): {'score': 4.8, 'desc': 'Overlay + Admin + Kalıcılık (Kalıcı phishing)'},
        ('sms', 'network', 'persistence'): {'score': 4.0, 'desc': 'SMS + Network + Kalıcılık (SMS botnet)'},
        ('banking', 'network', 'obfuscation'): {'score': 5.2, 'desc': 'Banking hedefleme + C2 + Gizleme (Sofistike trojan)'},
    }

    # 2c. DÖRTLÜ KOMBİNASYONLAR
    quad_combinations = {
        ('accessibility', 'overlay', 'sms', 'network'): {'score': 6.0, 'desc': 'TAM BANKING TROJAN: Overlay + SMS + Accessibility + C2'},
        ('accessibility', 'overlay', 'sms', 'contacts'): {'score': 6.5, 'desc': 'Banking Trojan + Sosyal mühendislik: Full overlay + İletişim verileri'},
        ('package_info', 'overlay', 'sms', 'network'): {'score': 6.3, 'desc': 'Hedefli Banking Trojan: Uygulama tarama + Overlay + SMS + C2'},
        ('banking', 'overlay', 'accessibility', 'network'): {'score': 6.5, 'desc': 'Keyword-based Banking Trojan: Tam profil'},
        ('admin', 'crypto', 'persistence', 'network'): {'score': 6.0, 'desc': 'TAM RANSOMWARE: Admin + Şifreleme + Kalıcılık + C2'},
        ('admin', 'crypto', 'exfiltration', 'network'): {'score': 6.0, 'desc': 'Double Extortion Ransomware: Şifreleme + Veri çalma + C2'},
        ('admin', 'file_access', 'crypto', 'network'): {'score': 6.5, 'desc': 'Tam dosya şifreleme zinciri + C2'},
        ('keylogging', 'screenshot', 'contacts', 'exfiltration'): {'score': 6.0, 'desc': 'TAM SPYWARE: Tuş kaydı + Ekran + Kişiler + Sızdırma'},
        ('accessibility', 'keylogging', 'screenshot', 'exfiltration'): {'score': 6.8, 'desc': 'Gelişmiş Spyware: Accessibility-based monitoring + Sızdırma'},
        ('camera', 'microphone', 'location', 'exfiltration'): {'score': 6.5, 'desc': 'Tam gözetleme paketi: Kamera + Mikrofon + Konum + Sızdırma'},
        ('sms', 'call_logs', 'contacts', 'exfiltration'): {'score': 6.0, 'desc': 'İletişim gözetleme: SMS + Aramalar + Kişiler + Sızdırma'},
        ('keylogging', 'accessibility', 'network', 'persistence'): {'score': 6.2, 'desc': 'Kalıcı keylogger: Tuş kaydı + Accessibility + C2 + Persistence'},
        ('root_detection', 'shell_exec', 'persistence', 'network'): {'score': 6.5, 'desc': 'APT profili: Root + Shell + Kalıcılık + C2'},
        ('admin', 'persistence', 'obfuscation', 'network'): {'score': 6.0, 'desc': 'Gizli APT: Admin + Kalıcılık + Gizleme + C2'},
        ('dynamic', 'persistence', 'network', 'obfuscation'): {'score': 5.8, 'desc': 'Polimorfik APT: Dinamik yükleme + Persistence + C2 + Gizleme'},
        ('accessibility', 'admin', 'network', 'persistence'): {'score': 6.3, 'desc': 'Çok amaçlı kalıcı tehdit: Accessibility + Admin + C2 + Persistence'},
        ('overlay', 'admin', 'persistence', 'network'): {'score': 6.0, 'desc': 'Kalıcı phishing platformu: Overlay + Admin + Persistence + C2'},
        ('package_info', 'network', 'persistence', 'obfuscation'): {'score': 5.5, 'desc': 'Recon + Kalıcı C2: Hedef profilleme + Network + Persistence + Stealth'},
        ('contacts', 'sms', 'location', 'exfiltration'): {'score': 5.8, 'desc': 'Kapsamlı veri çalma: Kişiler + SMS + Konum + Sızdırma'},
        ('file_access', 'exfiltration', 'network', 'persistence'): {'score': 5.5, 'desc': 'Sürekli veri hırsızlığı: Dosyalar + Sızdırma + C2 + Persistence'},
    }

    # 2d. BEŞLİ KOMBİNASYONLAR (Neredeyse %100 Malware)
    penta_combinations = {
        ('accessibility', 'overlay', 'sms', 'network', 'contacts'): {'score': 6.0, 'desc': '🚨 ULTIMATE BANKING TROJAN: Full capability'},
        ('accessibility', 'overlay', 'sms', 'network', 'persistence'): {'score': 6.0, 'desc': '🚨 Kalıcı Banking Trojan: Tam profil + Persistence'},
        ('keylogging', 'screenshot', 'accessibility', 'exfiltration', 'network'): {'score': 6.0, 'desc': '🚨 ULTIMATE SPYWARE: Tam gözetleme + C2'},
        ('camera', 'microphone', 'location', 'exfiltration', 'persistence'): {'score': 6.0, 'desc': '🚨 Kalıcı Stalkerware: Tam sensör erişimi + Persistence'},
        ('admin', 'crypto', 'exfiltration', 'network', 'persistence'): {'score': 6.0, 'desc': '🚨 ULTIMATE RANSOMWARE: Double extortion + Persistence'},
        ('root_detection', 'shell_exec', 'persistence', 'network', 'obfuscation'): {'score': 6.0, 'desc': '🚨 ULTIMATE APT: Root + Shell + Stealth + C2 + Persistence'},
        ('admin', 'persistence', 'network', 'obfuscation', 'dynamic'): {'score': 6.0, 'desc': '🚨 Polimorfik APT: Admin + Multi-stage + Stealth + C2'},
    }

    # --- 3. Kombinasyonları Kümülatif Olarak Kontrol Et ---
    
    # Kategori setlerini frozenset olarak oluştur (lookup için daha hızlı)
    active_flags: Set[str] = {flag for flag, is_active in flag_map.items() if is_active}

    # Her bir kombinasyon listesini (dict) ve boyutunu (tuple) tanımla

    if benign_ratio< 0.45:
        combo_levels_to_check = [
            (penta_combinations, 5),
            (quad_combinations, 4),
            (triple_combinations, 3),
            (combinations, 2)
        ]

        # Kümülatif kontrol
        # Not: Bu yaklaşım, bir 5'li kombinasyonun aynı zamanda 4'lü, 3'lü ve 2'li
        # alt kümelerini de tetikleyip puanlarını toplamasına izin verir.
        # Bu, "yoğunluğu" ödüllendiren ve ayrışmayı artıran bilinçli bir tasarımdır.
        
        for combo_dict, level in combo_levels_to_check:
            for combo_keys, data in combo_dict.items():
                # 'combo_keys' (örn: ('a', 'b', 'c')) 'active_flags'in bir alt kümesi mi?
                
                # Hızlı kontrol: Eğer combo_keys'in uzunluğu aktif flag'lerden fazlaysa atla
                if len(combo_keys) > len(active_flags):
                    continue
                
                # Tüm anahtarlar aktif flag set'inde mevcut mu?
                all_present = True
                for key in combo_keys:
                    if key not in active_flags:
                        all_present = False
                        break
                
                if all_present:
                    suspicious_score += data['score']
                    detected_combinations.append(f"{data['desc']} (+{data['score']})")
    else:
        # Yüksek riskli (3/4/5'li) kuralları tetikleme.
        # Sadece 2'li kurallardan gelen düşük puanla kalır.
        if len(active_flags) > 0: # Sadece loglama için
             detected_combinations.append(f"[INFO] Yüksek benign_ratio ({benign_ratio:.2f}) nedeniyle 3+ kombinasyonlar atlandı.")

    return suspicious_score, detected_combinations


def calculate_weighted_benign_ratio(nodes_str: list[str], N: int) -> float:
    """
        Güvenilir kütüphanelerin (constants.BENIGN_LIBRARIES)
        toplam düğümlere ORANINI hesaplar. (Basit Versiyon)
        """
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