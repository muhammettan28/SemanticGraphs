from typing import Tuple, List, Dict, Set

# Yardımcı fonksiyonu dışarıda tanımlaman güzel, böylece başka yerlerde de kullanılabilir.
def is_significant(counts_g: dict, counts_m: dict, category: str, threshold: int = 0) -> bool:
    """
    Graf (g) ve Manifest (m) sayımlarını toplar.
    Sadece toplam sayı 'threshold' değerini GEÇERSE True döner.
    """
    g_val = counts_g.get(category, 0)
    m_val = counts_m.get(category, 0)
    return (g_val + m_val) > threshold

def check_suspicious_combinations(counts_g: dict, counts_m: dict, benign_ratio: float) -> Tuple[float, List[str], Dict[str, bool]]:
    """
    Şüpheli API/davranış kombinasyonlarını KATEGORİ SAYIMLARINA göre kontrol eder.
    Benign gürültüsünü engellemek için 'threshold' (eşik) mantığı eklenmiştir.
    """
    suspicious_score = 0.0
    detected_combinations: List[str] = []

    # -------------------------------------------------------------------------
    # FLAG MAP: Modern Uygulama Gürültüsüne Göre Ayarlanmış Eşikler
    # -------------------------------------------------------------------------
    flag_map = {
        # --- KATEGORİ 1: ÇOK GÜRÜLTÜLÜ (Benign uygulamalarda standarttır, eşik yüksek) ---
        'network':       is_significant(counts_g, counts_m, 'network', 15),
        'file_access':   is_significant(counts_g, counts_m, 'file_operations', 20),
        'file_operations': is_significant(counts_g, counts_m, 'file_operations', 20),
        'crypto':        is_significant(counts_g, counts_m, 'crypto', 8),
        'benign_ui':     is_significant(counts_g, counts_m, 'benign_ui', 15),
        'reflection':    is_significant(counts_g, counts_m, 'reflection', 12),
        
        # DÜZELTME 1: Eksik parametreler eklendi
        'native':        is_significant(counts_g, counts_m, 'native_code', 5), 

        # --- KATEGORİ 2: ORTA SEVİYE RİSK (Dikkatli olunmalı) ---
        'location':      is_significant(counts_g, counts_m, 'location', 3),
        'bluetooth':     is_significant(counts_g, counts_m, 'bluetooth', 2),
        'notifications': is_significant(counts_g, counts_m, 'notifications', 4),
        'webview':       is_significant(counts_g, counts_m, 'webview', 3),
        'calendar':      is_significant(counts_g, counts_m, 'calendar', 1),
        'sensor':        is_significant(counts_g, counts_m, 'sensor', 2),
        'contacts':      is_significant(counts_g, counts_m, 'contacts', 1),
        'camera':        is_significant(counts_g, counts_m, 'camera_capture', 1),
        'microphone':    is_significant(counts_g, counts_m, 'microphone_capture', 1),
        'call_logs':     is_significant(counts_g, counts_m, 'telephony', 1),
        'vpn':           is_significant(counts_g, counts_m, 'vpn', 0),
        
        # DÜZELTME 2: Eksik parametreler eklendi
        'clipboard':     is_significant(counts_g, counts_m, 'clipboard', 1),

        # --- KATEGORİ 3: YÜKSEK RİSK (Benign'de işi yok, eşik SIFIR) ---
        'admin':            is_significant(counts_g, counts_m, 'admin_operations', 0),
        'sms':              is_significant(counts_g, counts_m, 'sms', 0),
        'banking':          is_significant(counts_g, counts_m, 'banking_targets', 1),
        'overlay':          is_significant(counts_g, counts_m, 'overlay', 0),
        'dynamic':          is_significant(counts_g, counts_m, 'dynamic', 2),
        'accessibility':    is_significant(counts_g, counts_m, 'accessibility', 0),
        'keylogging':       is_significant(counts_g, counts_m, 'keylogging', 0),
        'screenshot':       is_significant(counts_g, counts_m, 'screenshot', 0),
        'exfiltration':     is_significant(counts_g, counts_m, 'exfiltration', 0),
        'persistence':      is_significant(counts_g, counts_m, 'persistence', 0),
        'package_info':     is_significant(counts_g, counts_m, 'package_info', 2),
        'shell_exec':       is_significant(counts_g, counts_m, 'shell_exec', 0),
        'root_detection':   is_significant(counts_g, counts_m, 'root_detection', 0),
        'obfuscation':      is_significant(counts_g, counts_m, 'obfuscation', 2),
        'anti_debug':       is_significant(counts_g, counts_m, 'anti_debug', 0),
    }

    # Aktif bayraklar seti
    active_flags: Set[str] = {flag for flag, is_active in flag_map.items() if is_active}

    # --- Kritik patternler (Değişmedi) ---
    CRITICAL_COMBO_PATTERNS = [
        ("overlay", "sms", "accessibility"),
        ("overlay", "sms", "network"),
        ("admin", "crypto", "exfiltration"),
        ("accessibility", "network", "banking"),
        ("dynamic", "shell_exec"),
        ("location", "camera", "microphone", "exfiltration"),
        ("clipboard", "notifications", "accessibility"),
        ("webview", "overlay", "keylogging"),
        ("vpn", "crypto", "exfiltration"),
        ("native", "anti_debug", "obfuscation", "dynamic"),
        ("admin", "persistence", "shell_exec"),
    ]

    # --- Kombinasyon Tanımları (Değişmedi) ---
    combinations = {
        ('accessibility', 'overlay'): {'score': 1.0, 'desc': 'Erişilebilirlik + Overlay (Phishing)'},
        ('keylogging', 'exfiltration'): {'score': 1.0, 'desc': 'Keylogging + Sızdırma'},
        ('screenshot', 'exfiltration'): {'score': 1.0, 'desc': 'Ekran Görüntüsü + Sızdırma'},
        ('admin', 'crypto'): {'score': 1.0, 'desc': 'Admin + Şifreleme (Ransomware?)'},
        ('sms', 'network'): {'score': 1.0, 'desc': 'SMS + Network (OTP Hırsızlığı)'},
        ('contacts', 'exfiltration'): {'score': 1.0, 'desc': 'Kişi Listesi + Sızdırma'},
        ('dynamic', 'persistence'): {'score': 1.0, 'desc': 'Dinamik Kod + Kalıcılık'},
        ('banking', 'overlay'): {'score': 1.0, 'desc': 'Banking + Overlay'},
        ('package_info', 'overlay'): {'score': 1.0, 'desc': 'App Tarama + Overlay'},
        ('admin', 'network'): {'score': 1.5, 'desc': 'Admin + Network'},
        ('root_detection', 'shell_exec'): {'score': 1.0, 'desc': 'Root Tespiti + Shell'},
        ('crypto', 'network'): {'score': 1.0, 'desc': 'Crypto + Network (C2 Potansiyeli)'},
        ('reflection', 'native'): {'score': 1.0, 'desc': 'Reflection + Native'},
        ('location', 'camera'): {'score': 1.0, 'desc': 'Konum + Kamera (Stalkerware)'},
        ('microphone', 'exfiltration'): {'score': 1.0, 'desc': 'Mikrofon + Sızdırma'},
        ('clipboard', 'network'): {'score': 1.0, 'desc': 'Pano + Network'},
        ('webview', 'overlay'): {'score': 1.0, 'desc': 'WebView + Overlay'},
        ('notifications', 'exfiltration'): {'score': 1.0, 'desc': 'Bildirim + Sızdırma'},
        ('vpn', 'exfiltration'): {'score': 1.0, 'desc': 'VPN + Sızdırma'},
        ('native', 'obfuscation'): {'score': 1.0, 'desc': 'Native + Gizleme'},
        ('anti_debug', 'obfuscation'): {'score': 1.0, 'desc': 'Anti-Debug + Gizleme'},
        ('bluetooth', 'exfiltration'): {'score': 1.0, 'desc': 'Bluetooth + Sızdırma'},
        ('calendar', 'exfiltration'): {'score': 1.0, 'desc': 'Takvim + Sızdırma'},
        ('sensor', 'exfiltration'): {'score': 1.0, 'desc': 'Sensör + Sızdırma'},
    }

    triple_combinations = {
        ('accessibility', 'overlay', 'sms'): {'score': 2.0, 'desc': 'Overlay + SMS + Access (Banking Trojan)'},
        ('accessibility', 'overlay', 'network'): {'score': 2.0, 'desc': 'Overlay + Access + C2'},
        ('package_info', 'overlay', 'sms'): {'score': 2.0, 'desc': 'Targeting + Overlay + SMS'},
        ('banking', 'overlay', 'sms'): {'score': 2.0, 'desc': 'Banking + Overlay + SMS'},
        ('accessibility', 'banking', 'network'): {'score': 2.0, 'desc': 'Access + Banking + Network'},
        ('overlay', 'sms', 'network'): {'score': 2.0, 'desc': 'Overlay + SMS + C2'},
        ('accessibility', 'overlay', 'contacts'): {'score': 2.0, 'desc': 'Overlay + Contacts + Access'},
        ('dynamic', 'obfuscation', 'network'): {'score': 2.0, 'desc': 'Dynamic + Obfuscation + C2'},
        ('location', 'camera', 'microphone'): {'score': 2.0, 'desc': 'Konum + Kamera + Mikrofon'},
        ('location', 'camera', 'exfiltration'): {'score': 2.0, 'desc': 'Konum + Kamera + Sızdırma'},
        ('webview', 'overlay', 'keylogging'): {'score': 2.0, 'desc': 'WebView + Overlay + Keylog'},
        ('clipboard', 'notifications', 'network'): {'score': 2.0, 'desc': 'Pano + Bildirim + Network'},
        ('vpn', 'crypto', 'network'): {'score': 2.0, 'desc': 'VPN + Crypto + Network'},
        ('native', 'anti_debug', 'obfuscation'): {'score': 2.0, 'desc': 'Native + AntiDebug + Obfuscation'},
        ('microphone', 'location', 'exfiltration'): {'score': 2.0, 'desc': 'Mikrofon + Konum + Sızdırma'},
        ('package_info', 'accessibility', 'keylogging'): {'score': 2.0, 'desc': 'App Detect + Access + Keylog'},
        ('calendar', 'contacts', 'exfiltration'): {'score': 2.0, 'desc': 'Takvim + Rehber + Sızdırma'},
        ('bluetooth', 'location', 'exfiltration'): {'score': 2.0, 'desc': 'Bluetooth + Konum + Sızdırma'},
        ('webview', 'file_operations', 'exfiltration'): {'score': 2.0, 'desc': 'Web + File + Sızdırma'},
        ('sensor', 'location', 'network'): {'score': 2.0, 'desc': 'Sensör + Konum + C2'},
        ('admin', 'persistence', 'network'): {'score': 2.0, 'desc': 'Admin + Persistence + C2'},
        ('reflection', 'obfuscation', 'dynamic'): {'score': 2.0, 'desc': 'Reflection + Obfuscation + Dynamic'},
    }

    quad_combinations = {
        ('accessibility', 'overlay', 'sms', 'network'): {'score': 3.0, 'desc': 'TAM BANKING TROJAN (4)'},
        ('accessibility', 'overlay', 'sms', 'contacts'): {'score': 3.0, 'desc': 'Banking + Social Eng'},
        ('package_info', 'overlay', 'sms', 'network'): {'score': 3.0, 'desc': 'Targeted Banking Trojan'},
        ('location', 'camera', 'microphone', 'exfiltration'): {'score': 3.0, 'desc': 'FULL SURVEILLANCE'},
        ('webview', 'overlay', 'keylogging', 'exfiltration'): {'score': 3.0, 'desc': 'Advanced Web Phishing'},
        ('clipboard', 'notifications', 'accessibility', 'network'): {'score': 3.0, 'desc': '2FA Bypass Chain'},
        ('vpn', 'crypto', 'network', 'exfiltration'): {'score': 3.0, 'desc': 'Traffic Hijacking'},
        ('native', 'anti_debug', 'obfuscation', 'dynamic'): {'score': 3.0, 'desc': 'Max Evasion'},
        ('package_info', 'accessibility', 'overlay', 'keylogging'): {'score': 3.0, 'desc': 'Targeted Cred Theft'},
        ('admin', 'persistence', 'shell_exec', 'network'): {'score': 3.0, 'desc': 'Rootkit Behavior'},
        ('location', 'contacts', 'calendar', 'exfiltration'): {'score': 3.0, 'desc': 'Personal Data Theft'},
        ('bluetooth', 'location', 'sensor', 'exfiltration'): {'score': 3.0, 'desc': 'Proximity Tracking'},
        ('webview', 'file_operations', 'crypto', 'exfiltration'): {'score': 3.0, 'desc': 'File Stealer Chain'},
    }

    penta_combinations = {
        ('accessibility', 'overlay', 'sms', 'network', 'contacts'): {'score': 4.0, 'desc': 'ULTIMATE BANKING TROJAN'},
        ('location', 'camera', 'microphone', 'contacts', 'exfiltration'): {'score': 4.0, 'desc': 'ULTIMATE STALKERWARE'},
        ('accessibility', 'overlay', 'keylogging', 'clipboard', 'network'): {'score': 4.0, 'desc': 'Input Interception'},
        ('package_info', 'accessibility', 'overlay', 'sms', 'banking'): {'score': 4.0, 'desc': 'Advanced Targeted Trojan'},
        ('native', 'anti_debug', 'obfuscation', 'dynamic', 'root_detection'): {'score': 4.0, 'desc': 'Military Grade Evasion'},
        ('admin', 'persistence', 'crypto', 'network', 'shell_exec'): {'score': 4.0, 'desc': 'APT-like Threat'},
        ('vpn', 'crypto', 'network', 'exfiltration', 'admin'): {'score': 4.0, 'desc': 'Enterprise Theft'},
    }

    # --- Değişken tanımları (Flag map üzerinden) ---
    uses_accessibility = flag_map.get('accessibility', False)
    uses_overlay = flag_map.get('overlay', False)
    has_banking_targets = flag_map.get('banking', False)
    uses_admin = flag_map.get('admin', False)
    uses_crypto = flag_map.get('crypto', False)
    uses_sms = flag_map.get('sms', False)
    has_c2_comm = flag_map.get('network', False)
    uses_dynamic_code = flag_map.get('dynamic', False)
    uses_shell_exec = flag_map.get('shell_exec', False)
    uses_keylogging = flag_map.get('keylogging', False)
    uses_location = flag_map.get('location', False)
    uses_camera = flag_map.get('camera', False)
    uses_microphone = flag_map.get('microphone', False)
    uses_clipboard = flag_map.get('clipboard', False)
    uses_notifications = flag_map.get('notifications', False)
    uses_webview = flag_map.get('webview', False)
    uses_vpn = flag_map.get('vpn', False)
    uses_exfiltration = flag_map.get('exfiltration', False)
    uses_persistence = flag_map.get('persistence', False)
    uses_contacts = flag_map.get('contacts', False)
    uses_package_info = flag_map.get('package_info', False)
    uses_root_detection = flag_map.get('root_detection', False)
    uses_anti_debug = flag_map.get('anti_debug', False)
    uses_obfuscation = flag_map.get('obfuscation', False)
    uses_native = flag_map.get('native', False)
    uses_reflection = flag_map.get('reflection', False)

    # --- Very High Threat Logic ---
    very_high_threat_combo_1 = uses_accessibility and uses_overlay and has_banking_targets
    very_high_threat_combo_2 = uses_admin and uses_crypto
    very_high_threat_combo_3 = uses_sms and has_c2_comm and uses_dynamic_code
    very_high_threat_combo_4 = uses_dynamic_code and uses_shell_exec
    very_high_threat_combo_5 = (uses_location and uses_camera and uses_microphone and uses_exfiltration)
    very_high_threat_combo_6 = (uses_clipboard and uses_notifications and uses_accessibility and has_c2_comm)
    very_high_threat_combo_7 = (uses_vpn and uses_crypto and uses_exfiltration)
    very_high_threat_combo_8 = (uses_webview and uses_overlay and uses_keylogging and uses_exfiltration)
    very_high_threat_combo_9 = (uses_crypto and uses_exfiltration and uses_admin)
    very_high_threat_combo_10 = (uses_admin and uses_persistence and uses_shell_exec and has_c2_comm)
    very_high_threat_combo_11 = (uses_package_info and uses_accessibility and uses_overlay and uses_sms)

    is_very_high_threat = (
            very_high_threat_combo_1 or very_high_threat_combo_2 or
            very_high_threat_combo_3 or very_high_threat_combo_4 or
            very_high_threat_combo_5 or very_high_threat_combo_6 or
            very_high_threat_combo_7 or very_high_threat_combo_8 or
            very_high_threat_combo_9 or very_high_threat_combo_10 or
            very_high_threat_combo_11
    )

    # --- High Threat Logic ---
    high_threat_combo_1 = (uses_native and uses_anti_debug and uses_obfuscation and uses_dynamic_code)
    high_threat_combo_2 = (uses_location and (uses_camera or uses_microphone) and uses_exfiltration)
    high_threat_combo_3 = (uses_accessibility and uses_keylogging and uses_clipboard and has_c2_comm)
    high_threat_combo_4 = (uses_persistence and uses_shell_exec and has_c2_comm)
    high_threat_combo_5 = (uses_contacts and uses_sms and uses_exfiltration)
    high_threat_combo_6 = (uses_root_detection and uses_shell_exec and uses_admin)

    is_high_threat = (
            high_threat_combo_1 or high_threat_combo_2 or
            high_threat_combo_3 or high_threat_combo_4 or
            high_threat_combo_5 or high_threat_combo_6
    )

    # --- Medium Threat Logic ---
    medium_threat_combo_1 = uses_dynamic_code and (uses_accessibility or uses_keylogging)
    medium_threat_combo_2 = (uses_obfuscation and uses_dynamic_code)
    medium_threat_combo_3 = (uses_crypto and has_c2_comm and uses_obfuscation)
    medium_threat_combo_4 = (uses_overlay and uses_package_info)
    medium_threat_combo_5 = (uses_persistence and (uses_location or uses_camera or uses_microphone))
    medium_threat_combo_6 = (uses_contacts and uses_sms) or (uses_clipboard and uses_notifications)
    medium_threat_combo_7 = (uses_reflection and (uses_obfuscation or uses_native))
    medium_threat_combo_8 = (uses_vpn or (has_c2_comm and uses_crypto))

    is_medium_threat = (
            medium_threat_combo_1 or medium_threat_combo_2 or
            medium_threat_combo_3 or medium_threat_combo_4 or
            medium_threat_combo_5 or medium_threat_combo_6 or
            medium_threat_combo_7 or medium_threat_combo_8
    )

    # --- Skorlama ve Raporlama ---
    if is_very_high_threat:
        if very_high_threat_combo_1:
            suspicious_score += 1.5
            detected_combinations.append("VERY_HIGH: Accessibility + Overlay + BankingTargets (+2.5)")
        if very_high_threat_combo_2:
            suspicious_score += 1.5
            detected_combinations.append("VERY_HIGH: Admin + Crypto (Ransomware/privilege chain) (+2.0)")
        if very_high_threat_combo_3:
            suspicious_score += 1.5
            detected_combinations.append("VERY_HIGH: SMS + Network + DynamicCode (OTP/Exfiltration chain) (+2.0)")
        if very_high_threat_combo_4:
            suspicious_score += 1.5
            detected_combinations.append("VERY_HIGH: DynamicCode + ShellExec (Dynamic loader + shell) (+1)")
        if very_high_threat_combo_5:
            suspicious_score += 1.5
            detected_combinations.append("VERY_HIGH: Location + Camera + Microphone + Exfiltration (STALKERWARE) (+2.5)")
        if very_high_threat_combo_6:
            suspicious_score += 1.5
            detected_combinations.append("VERY_HIGH: Clipboard + Notifications + Accessibility + C2 (2FA Bypass) (+2.0)")
        if very_high_threat_combo_7:
            suspicious_score += 1.5
            detected_combinations.append("VERY_HIGH: VPN + Crypto + Exfiltration (Traffic Hijacking) (+2.0)")
        if very_high_threat_combo_8:
            suspicious_score += 1.5
            detected_combinations.append("VERY_HIGH: WebView + Overlay + Keylogging + Exfiltration (Web Phishing) (+1)")
        if very_high_threat_combo_9:
            suspicious_score +=1.5
            detected_combinations.append("VERY_HIGH: Crypto + Exfiltration + Admin (Data Ransom) (+2.0)")
        if very_high_threat_combo_10:
            suspicious_score += 1.5
            detected_combinations.append("VERY_HIGH: Admin + Persistence + ShellExec + C2 (Rootkit) (+2.5)")
        if very_high_threat_combo_11:
            suspicious_score += 1.5
            detected_combinations.append("VERY_HIGH: PackageInfo + Accessibility + Overlay + SMS (Targeted Banking) (+2.0)")

    if is_high_threat:
        if high_threat_combo_1:
            suspicious_score += 1.0
            detected_combinations.append("HIGH: Native + AntiDebug + Obfuscation + Dynamic (Advanced Evasion) (+1.0)")
        if high_threat_combo_2:
            suspicious_score += 1.5
            detected_combinations.append("HIGH: Location + (Camera|Microphone) + Exfiltration (Surveillance) (+1.5)")
        if high_threat_combo_3:
            suspicious_score += 1.0
            detected_combinations.append("HIGH: Accessibility + Keylogging + Clipboard + C2 (Credential Theft) (+1.0)")
        if high_threat_combo_4:
            suspicious_score += 1.0
            detected_combinations.append("HIGH: Persistence + ShellExec + C2 (Backdoor) (+1.0)")
        if high_threat_combo_5:
            suspicious_score += 1.0
            detected_combinations.append("HIGH: Contacts + SMS + Exfiltration (Social Engineering) (+1.0)")
        if high_threat_combo_6:
            suspicious_score += 1.0
            detected_combinations.append("HIGH: RootDetection + ShellExec + Admin (Privilege Escalation) (+1.0)")

    if is_medium_threat:
        if medium_threat_combo_1:
            suspicious_score += 0.5
            detected_combinations.append("MEDIUM: DynamicCode + (Accessibility|Keylogging) (+0.5)")
        if medium_threat_combo_2:
            suspicious_score += 0.5
            detected_combinations.append("MEDIUM: Obfuscation + DynamicCode (Packing) (+0.5)")
        if medium_threat_combo_3:
            suspicious_score += 0.5
            detected_combinations.append("MEDIUM: Crypto + C2 + Obfuscation (Hidden C2) (+0.5)")
        if medium_threat_combo_4:
            suspicious_score += 0.5
            detected_combinations.append("MEDIUM: Overlay + PackageInfo (Phishing Prep) (+0.5)")
        if medium_threat_combo_5:
            suspicious_score += 0.5
            detected_combinations.append("MEDIUM: Persistence + (Location|Camera|Microphone) (Background Surveillance) (+0.5)")
        if medium_threat_combo_6:
            suspicious_score += 0.5
            detected_combinations.append("MEDIUM: (Contacts+SMS) | (Clipboard+Notifications) (Data Collection) (+0.5)")
        if medium_threat_combo_7:
            suspicious_score += 0.5
            detected_combinations.append("MEDIUM: Reflection + (Obfuscation|Native) (Evasion) (+0.5)")
        if medium_threat_combo_8:
            suspicious_score += 0.5
            detected_combinations.append("MEDIUM: VPN | (C2+Crypto) (Network Manipulation) (+0.5)")

    # --- Kümülatif Kontrol (benign_ratio düşükse daha agresif) ---
    if benign_ratio < 0.70:
        combo_levels_to_check = [
            (penta_combinations, 5),
            (quad_combinations, 4),
            (triple_combinations, 3),
            (combinations, 2)
        ]

        for combo_dict, level in combo_levels_to_check:
            for combo_keys, data in combo_dict.items():
                if len(combo_keys) > len(active_flags):
                    continue

                all_present = True
                for key in combo_keys:
                    if key not in active_flags:
                        all_present = False
                        break

                if all_present:
                    suspicious_score += data['score']
                    detected_combinations.append(f"{data['desc']} (+{data['score']})")
    else:
        # Benign oranı yüksekse sadece kritik olanlara bak
        for critical in CRITICAL_COMBO_PATTERNS:
            if all(flag in active_flags for flag in critical):
                desc = f"[CRITICAL] Kritik pattern tespit edildi: {', '.join(critical)}"
                detected_combinations.append(f"{desc} (+2.0)")
                suspicious_score += 2.0

        if len(active_flags) > 0 and suspicious_score == 0:
            detected_combinations.append(
                f"[INFO] Yüksek benign_ratio ({benign_ratio:.2f}) nedeniyle standart kombinasyonlar atlandı."
            )

    threat_flags = {
        "is_very_high": is_very_high_threat,
        "is_medium": is_medium_threat,
        "is_high": is_high_threat
    }

    return suspicious_score, detected_combinations, threat_flags