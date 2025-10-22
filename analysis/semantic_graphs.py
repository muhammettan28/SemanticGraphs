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

try:
    from androguard.misc import AnalyzeAPK
except ImportError:
    print("Hata: Androguard kütüphanesi bulunamadı. Lütfen 'pip install androguard' komutu ile kurun.")
    exit(1)


def _squash(x: float, K: float = 100.0, a: float = 0.008) -> float: # a=0.05'ten 0.025'e düşürüldü
    """Skoru tanh benzeri bir fonksiyonla [0, K] aralığına sıkıştırır."""
    return K * (math.tanh(x * a) + 1) / 2.0


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


def analyze_malware_semantically(graph_path: str | Path, apk_path: str | Path) -> tuple[dict, float]:
    """
    Oluşturulan graf ve metadatayı analiz ederek bir zararlı yazılım skoru üretir.
    (Yeniden düzenlenmiş ve mantıksal hataları düzeltilmiş versiyon)
    """

    # 1) VERİLERİ YÜKLE VE DEĞİŞKENLERİ AYARLA
    # ==================================================================
    graph_path = Path(graph_path)
    apk_path = Path(apk_path)
    meta_path = graph_path.with_suffix(".meta.json")
    debug_file = Path("debug_scores.txt")

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

    # 2) ÖZELLİKLERİ SAY (GRAF & MANIFEST)
    # ==================================================================
    counts_g = {k: 0 for k in c.CATEGORY_RULES}
    counts_m = {k: 0 for k in c.CATEGORY_RULES}

    nodes_str = [str(n) for n in G.nodes()]
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

    # 3) SAYIMLARI AYARLA (HEURISTICS & CAPS)
    # ==================================================================
    if is_large and benign_heavy:
        for k in ("sms", "admin_operations"):
            if counts_g.get(k, 0) == 0:
                counts_m[k] = 0

    counts_g['network'] = min(counts_g.get('network', 0), 8)
    counts_g['shell_exec'] = min(counts_g.get('shell_exec', 0), 8)
    counts_g['location'] = min(counts_g.get('location', 0), 8)
    counts_g['file_operations'] = min(counts_g.get('file_operations', 0), 6)
    counts_g['crypto'] = min(counts_g.get('crypto', 0), 10)
    counts_g['reflection'] = min(counts_g.get('reflection', 0), 10)
    counts_g['package_info'] = min(counts_g.get('package_info', 0), 8)
    counts_g['device_info'] = min(counts_g.get('device_info', 0), 8)
    counts_g['background_ops'] = min(counts_g.get('background_ops', 0), 8)
    counts_g['shared_prefs'] = min(counts_g.get('shared_prefs', 0), 8)
    counts_g['content_provider'] = min(counts_g.get('content_provider', 0), 8)
    counts_g['native_code'] = min(counts_g.get('native_code', 0), 8)
    counts_g['emulator_detection'] = min(counts_g.get('emulator_detection', 0), 10)
    counts_g['banking_targets'] = min(counts_g.get('banking_targets', 0), 8)
    counts_g['sqlite'] = min(counts_g.get('sqlite', 0), 8)
    counts_g['contacts'] = min(counts_g.get('contacts', 0), 5)
    counts_g['c2_communication'] = min(counts_g.get('c2_communication', 0), 5)
    counts_g['notifications'] = min(counts_g.get('notifications', 0), 5)
    counts_g['exfiltration'] = min(counts_g.get('exfiltration', 0), 5)
    counts_g['keylogging'] = min(counts_g.get('keylogging', 0), 5)
    counts_g['dynamic'] = min(counts_g.get('dynamic', 0), 5)
    counts_g['accessibility'] = min(counts_g.get('accessibility', 0), 5)
    counts_g['bluetooth'] = min(counts_g.get('bluetooth', 0), 5)
    counts_g['media_capture'] = min(counts_g.get('media_capture', 0), 5)
    counts_g['adware'] = min(counts_g.get('adware', 0), 5)
    counts_g['obfuscation'] = min(counts_g.get('obfuscation', 0), 5)
    counts_g['overlay'] = min(counts_g.get('overlay', 0), 5)
    counts_g['adware'] = min(counts_g.get('adware', 0), 5)

    counts_m['dangerous_permissions'] = min(counts_m.get('dangerous_permissions', 0), 10)
    counts_m['file_operations'] = min(counts_m.get('file_operations', 0), 3)
    counts_m['location'] = min(counts_m.get('location', 0), 3)
    counts_m['media_capture'] = min(counts_m.get('media_capture', 0), 3)
    counts_m['device_info'] = min(counts_m.get('device_info', 0), 3)
    counts_m['background_ops'] = min(counts_m.get('background_ops', 0), 3)

    # 4) HAM SEMANTİK VE YAPISAL SKORLARI HESAPLA
    # ==================================================================
    sem_g_raw = sum(c.W.get(cat, 1.0) * count for cat, count in counts_g.items())
    sem_m_raw = sum(c.W.get(cat, 1.0) * count for cat, count in counts_m.items())

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

    # 5) SEZGİSEL BONUSLARI HESAPLA
    # ==================================================================
    bonus = 0.0
    is_empty_graph = N <= 5 and E <= 5

    # --- BU BAYRAKLAR 6C BÖLÜMÜNDE KULLANILACAK ---
    uses_admin = counts_g.get('admin_operations', 0) > 0
    uses_accessibility = counts_g.get('accessibility', 0) > 0
    # ---

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
    suspicious_bonus, detected_combos = check_suspicious_combinations(counts_g, counts_m)
    bonus += suspicious_bonus

    if (uses_sms or uses_contacts or uses_telephony or uses_device_info) and has_c2_comm:
        bonus += 4
    if uses_accessibility and uses_overlay and has_banking_targets and (uses_telephony or uses_sms):
        bonus += 4.0
    if uses_keylogging and (uses_screenshot or uses_clipboard):
        bonus += 4.0
    if uses_admin and uses_crypto:
        bonus += 4.0
    if has_root_detection and has_anti_debug and has_emulator_detection:
        bonus += 4.0

    # Seviye 3 Bonuslar
    critical_flags = [
        uses_sms, uses_admin, uses_dynamic_code, uses_telephony,
        has_emulator_detection, has_root_detection, uses_keylogging,
        has_banking_targets, uses_shell_exec, uses_device_info
    ]
    crit_hits = sum(critical_flags)
    if crit_hits >= 4:
        bonus += 2.0 * crit_hits

    # 6) NİHAİ SKORU HESAPLA (NORMALİZASYON & İNDİRİM)
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

    # 6c. Benign Kütüphane İndirimini SADECE BİR KEZ UYGULA
    # --- MANTIK HATASI DÜZELTMESİ BAŞLANGICI (False Negative'leri düzeltir) ---

    benign_ratio = calculate_weighted_benign_ratio(nodes_str, N)

    # YÜKSEK RİSK İSTİSNASI (KOMBİNASYON BAZLI):
    # Bir API'yi tek başına kullanmak (örn: sadece accessibility) indirimi engellememeli.
    # Ancak tehlikeli KOMBİNASYONLAR engellemeli.

    high_threat_combo_1 = uses_accessibility and (uses_overlay or has_banking_targets)  # UI Spoofing/Clickjacking
    high_threat_combo_2 = uses_admin and (uses_overlay or uses_crypto)  # Ransomware/Wiper
    high_threat_combo_3 = uses_sms and has_c2_comm  # SMS Trojan
    high_threat_combo_4 = uses_dynamic_code and (uses_shell_exec or uses_sms)

    is_high_threat = (
            high_threat_combo_1 or
            high_threat_combo_2 or
            high_threat_combo_3 or
            high_threat_combo_4
    )

    # İndirimi İptal Etme Koşulları:
    # 1. Paketleyici tespit edilmişse (is_packed)
    # 2. VEYA paketleyici bulunmasa BİLE yüksek riskli API (is_high_threat) kullanıyorsa
    if is_packed or is_high_threat:
        # İndirimi iptal et!
        reduction_multiplier = 1.0
    else:
        # SADECE 'paketlenmemiş' VE 'yüksek riskli olmayan'
        # uygulamalara indirim yap. (Sigmoid fonksiyonu)
        reduction_multiplier = 1.0 / (1.0 + math.exp(6 * (benign_ratio - 0.35)))

    total_raw = total_raw_normalized * reduction_multiplier

    # --- MANTIK HATASI DÜZELTMESİ SONU ---

    # 7) SQUASH UYGULA VE LOGLA
    # ==================================================================
    K_val = 100.0
    a_val = 0.04
    total = _squash(total_raw, K=K_val, a=a_val)

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
            f.write(f"    _squash(total_raw={total_raw:.4f}, K={K_val}, a={a_val}) -> {total:.4f}\n")
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

def check_suspicious_combinations(counts_g: dict, counts_m: dict) -> Tuple[float, List[str]]:
    """
    Şüpheli API kombinasyonlarını KATEGORİ SAYIMLARINA göre kontrol eder.
    (nodes_str taraması kaldırıldı, artık daha güvenilir.)
    """
    suspicious_score = 0.0
    detected_combinations = []
    
    # Bayrakları sayımlara göre ayarla
    has_crypto = counts_g.get('crypto', 0) > 0
    has_network = counts_g.get('network', 0) > 0
    has_admin = counts_g.get('admin_operations', 0) > 0 or counts_m.get('admin_operations', 0) > 0
    has_sms = counts_g.get('sms', 0) > 0 or counts_m.get('sms', 0) > 0
    has_banking = counts_g.get('banking_targets', 0) > 1
    has_overlay = counts_g.get('overlay', 0) > 0
    has_reflection = counts_g.get('reflection', 0) > 0
    has_native = counts_g.get('native_code', 0) > 0

    combinations = {
    ('crypto', 'network'): 2.0,      # 5'ten 2'ye düşürüldü
    ('reflection', 'native'): 1.0,   # 4'ten 1'e düşürüldü
    ('admin', 'network'): 5.0,       # 8'den 5'e düşürüldü
    ('sms', 'network'): 6.0,         # (Bu kalsın)
    ('banking', 'overlay'): 3.0,     # 10'dan 3'e düşürüldü
    }
    
    # Bayrakları kullanarak kontrol et
    if has_crypto and has_network:
        suspicious_score += combinations[('crypto', 'network')]
        detected_combinations.append('crypto+network')
        
    if has_reflection and has_native:
        suspicious_score += combinations[('reflection', 'native')]
        detected_combinations.append('reflection+native')
        
    if has_admin and has_network:
        suspicious_score += combinations[('admin', 'network')]
        detected_combinations.append('admin+network')
        
    if has_sms and has_network:
        suspicious_score += combinations[('sms', 'network')]
        detected_combinations.append('sms+network')
        
    if has_banking and has_overlay:
        suspicious_score += combinations[('banking', 'overlay')]
        detected_combinations.append('banking+overlay')

    return suspicious_score, detected_combinations

def calculate_weighted_benign_ratio(nodes_str: List[str], N: int) -> float:
    """
    Güvenilir kütüphanelerin (constants.BENIGN_LIBRARIES) 
    toplam düğümlere oranını hesaplar. (Düzeltilmiş Versiyon)
    """
    if N == 0:
        return 0.0
    
    # constants.py dosyasındaki asıl listeyi kullan
    # (constants zaten 'c' olarak import edilmişti)
    
    benign_hits = 0
    for node in nodes_str:
        # frozenset'te hızlı arama için (Landroidx/ Lcom/google/ vb.)
        if any(node.startswith(lib) for lib in c.BENIGN_LIBRARIES):
            benign_hits += 1
            
    # Gerçek oranı (0.0 ile 1.0 arası) döndür
    return benign_hits / N