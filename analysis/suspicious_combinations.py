from typing import Tuple, List, Dict, Set
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


def check_suspicious_combinations(counts_g: dict, counts_m: dict, benign_ratio: float) -> Tuple[float, List[str]]:
    """
    Şüpheli API/davranış kombinasyonlarını KATEGORİ SAYIMLARINA göre kontrol eder.
    Bu fonksiyon, düşük seviyeli (2'li) ve yüksek seviyeli (3,4,5'li)
    tüm tetiklenen desenleri kümülatif olarak puanlar.
    (Güncellenmiş: very_high_threat kombinasyonlarını doğrudan entegre eder.)
    """
    suspicious_score = 0.0
    detected_combinations: List[str] = []

    # --- flag map (mevcut mantık) ---
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
        'location': counts_g.get('location', 0) > 0 or counts_m.get('location', 0) > 0,
        'camera': counts_g.get('camera_capture', 0) > 0 or counts_m.get('camera_capture', 0) > 0,
        'microphone': counts_g.get('microphone_capture', 0) > 0,
        'call_logs': counts_g.get('telephony', 0) > 0 or counts_m.get('telephony', 0) > 0,
        'file_access': counts_g.get('file_operations', 0) > 0,
        'obfuscation': counts_g.get('obfuscation', 0) > 0,

        'clipboard': counts_g.get('clipboard', 0) > 0,
        'notifications': counts_g.get('notifications', 0) > 0,
        'webview': counts_g.get('webview', 0) > 0,
        'vpn': counts_g.get('vpn', 0) > 0,
        'sensor': counts_g.get('sensor', 0) > 0,
        'calendar': counts_g.get('calendar', 0) > 0,
        'anti_debug': counts_g.get('anti_debug', 0) > 0,
        'bluetooth': counts_g.get('bluetooth', 0) > 0,
        'file_operations': counts_g.get('file_operations', 0) > 0,
    }

    # aktif bayraklar seti
    active_flags: Set[str] = {flag for flag, is_active in flag_map.items() if is_active}

    # --- Kritik patternler (her zaman göz önünde bulundurulacak) ---
    CRITICAL_COMBO_PATTERNS = [
        ("overlay", "sms", "accessibility"),
        ("overlay", "sms", "network"),
        ("admin", "crypto", "exfiltration"),
        ("accessibility", "network", "banking"),
        ("dynamic", "shell_exec"),

        ("location", "camera", "microphone", "exfiltration"),  # Stalkerware
        ("clipboard", "notifications", "accessibility"),  # 2FA bypass
        ("webview", "overlay", "keylogging"),  # Web phishing
        ("vpn", "crypto", "exfiltration"),  # VPN hijack
        ("native", "anti_debug", "obfuscation", "dynamic"),  # Advanced evasion
        ("admin", "persistence", "shell_exec"),  # Rootkit
    ]

    # --- İki/Üç/... kombinasyon tanımları (senin orijinali muhafaza edildi) ---
    combinations = {
        ('accessibility', 'overlay'): {'score': 1.0, 'desc': 'Erişilebilirlik ile arayüz bindirme (Phishing/Trojan)'},
        ('keylogging', 'exfiltration'): {'score': 1.0, 'desc': 'Tuş vuruşlarını kaydedip dışarı sızdırma (Spyware)'},
        ('screenshot', 'exfiltration'): {'score': 1.0, 'desc': 'Ekran görüntüsü alıp dışarı sızdırma (Spyware)'},
        ('admin', 'crypto'): {'score': 1.0, 'desc': 'Cihaz yöneticisi yetkisiyle şifreleme (Ransomware riski)'},
        ('sms', 'network'): {'score': 1.0, 'desc': 'SMS mesajlarını okuyup ağa gönderme (OTP Hırsızlığı)'},
        ('contacts', 'exfiltration'): {'score': 1.0, 'desc': 'Kişi listesini çalıp dışarı sızdırma (Veri Hırsızlığı)'},
        ('dynamic', 'persistence'): {'score': 1.0, 'desc': 'Cihaz açılışında dinamik kod yükleme (Kalıcılık)'},
        ('banking', 'overlay'): {'score': 1.0, 'desc': 'Bankacılık anahtar kelimeleri ile arayüz bindirme (Banking Trojan)'},
        ('package_info', 'overlay'): {'score': 1.0, 'desc': 'Yüklü uygulamaları kontrol edip arayüz bindirme (Hedefli Phishing)'},
        ('admin', 'network'): {'score': 1.5, 'desc': 'Cihaz yöneticisi yetkileriyle ağ iletişimi'},
        ('root_detection', 'shell_exec'): {'score': 1.0, 'desc': 'Root tespiti sonrası shell komutu çalıştırma (Yetki Yükseltme)'},
        ('crypto', 'network'): {'score': 1.0, 'desc': 'Şifrelenmiş ağ iletişimi (C2/Komuta Kontrol olabilir)'},
        ('reflection', 'native'): {'score': 1.0, 'desc': 'Reflection ve native kod kullanımı (Gizlenme/Obfuscation)'},

        ('location', 'camera'): {'score': 1.0, 'desc': 'Konum + Kamera: Stalkerware/Gözetleme uygulaması'},
        ('microphone', 'exfiltration'): {'score': 1.0, 'desc': 'Ses kaydı + Veri sızdırma: Dinleme trojanı'},
        ('clipboard', 'network'): {'score': 1.0, 'desc': 'Pano okuma + Network: Şifre/Token hırsızlığı'},
        ('webview', 'overlay'): {'score': 1.0, 'desc': 'WebView + Overlay: Web-based phishing attack'},
        ('notifications', 'exfiltration'): {'score': 1.0, 'desc': 'Bildirim okuma + Sızdırma: 2FA code theft'},
        ('vpn', 'exfiltration'): {'score': 1.0, 'desc': 'VPN service + Sızdırma: Traffic interception'},
        ('native', 'obfuscation'): {'score': 1.0, 'desc': 'Native kod + Gizleme: Anti-analiz tekniği'},
        ('anti_debug', 'obfuscation'): {'score': 1.0, 'desc': 'Anti-debug + Obfuscation: Analiz karşıtı'},
        ('bluetooth', 'exfiltration'): {'score': 1.0, 'desc': 'Bluetooth + Sızdırma: Yakın cihazlara veri aktarımı'},
        ('calendar', 'exfiltration'): {'score': 1.0, 'desc': 'Takvim + Sızdırma: Hassas randevu bilgisi çalma'},
        ('sensor', 'exfiltration'): {'score': 1.0, 'desc': 'Sensör + Sızdırma: Davranış profili çıkarma'},
    }

    triple_combinations = {
        ('accessibility', 'overlay', 'sms'): {'score': 2.0, 'desc': 'Tam Banking Trojan profili: Overlay + SMS + Accessibility'},
        ('accessibility', 'overlay', 'network'): {'score': 2.0, 'desc': 'Banking Trojan C2: Overlay + Accessibility + Komuta kontrol'},
        ('package_info', 'overlay', 'sms'): {'score': 2.0, 'desc': 'Hedefli saldırı: Uygulama tarama + Overlay + SMS okuma'},
        ('banking', 'overlay', 'sms'): {'score': 2.0, 'desc': 'Banking keyword detection + Overlay + SMS intercept'},
        ('accessibility', 'banking', 'network'): {'score': 2.0, 'desc': 'Kimlik bilgisi hırsızlığı: Accessibility + Banking kelime + Network'},
        ('overlay', 'sms', 'network'): {'score': 2.0, 'desc': 'Phishing + SMS okuma + C2 iletişimi'},
        ('accessibility', 'overlay', 'contacts'): {'score': 2.0, 'desc': 'Overlay attack + Kişi listesi çalma + Accessibility'},
        ('dynamic', 'obfuscation', 'network'): {'score': 2.0,'desc': 'Dinamik yükleme + Gizleme + Network (Gizli C2)'},

        ('location', 'camera', 'microphone'): {'score': 2.0,
                                               'desc': 'STALKERWARE: Konum + Kamera + Mikrofon gözetleme'},
        ('location', 'camera', 'exfiltration'): {'score': 2.0, 'desc': 'Lokasyon-based gözetleme + Veri sızdırma'},
        ('webview', 'overlay', 'keylogging'): {'score': 2.0, 'desc': 'WebView phishing + Overlay + Keylog'},
        ('clipboard', 'notifications', 'network'): {'score': 2.0, 'desc': '2FA/OTP bypass: Pano + Bildirim + Network'},
        ('vpn', 'crypto', 'network'): {'score': 2.0, 'desc': 'VPN-based encrypted traffic analysis'},
        ('native', 'anti_debug', 'obfuscation'): {'score': 2.0,
                                                  'desc': 'Advanced evasion: Native + AntiDebug + Obfuscation'},
        ('microphone', 'location', 'exfiltration'): {'score': 2.0, 'desc': 'Audio surveillance + Lokasyon tracking'},
        ('package_info', 'accessibility', 'keylogging'): {'score': 2.0,
                                                          'desc': 'Hedefli keylogging: App detection + Accessibility'},
        ('calendar', 'contacts', 'exfiltration'): {'score': 2.0, 'desc': 'Sosyal mühendislik verisi toplama'},
        ('bluetooth', 'location', 'exfiltration'): {'score': 2.0, 'desc': 'Proximity-based tracking + Veri çalma'},
        ('webview', 'file_operations', 'exfiltration'): {'score': 2.0,
                                                         'desc': 'WebView download + File access + Sızdırma'},
        ('sensor', 'location', 'network'): {'score': 2.0, 'desc': 'Davranış profilleme: Sensör + Konum + C2'},
        ('admin', 'persistence', 'network'): {'score': 2.0, 'desc': 'Rootkit-like: Admin + Kalıcılık + C2'},
        ('reflection', 'obfuscation', 'dynamic'): {'score': 2.0,
                                                   'desc': 'Advanced packing: Reflection + Obfuscation + Dynamic loading'},
        # spyware, ransomware vb. diğer triplet'ler burada korunur...
    }

    quad_combinations = {
        ('accessibility', 'overlay', 'sms', 'network'): {'score': 3.0, 'desc': 'TAM BANKING TROJAN: Overlay + SMS + Accessibility + C2'},
        ('accessibility', 'overlay', 'sms', 'contacts'): {'score': 3.0, 'desc': 'Banking Trojan + Sosyal mühendislik: Full overlay + İletişim verileri'},
        ('package_info', 'overlay', 'sms', 'network'): {'score': 3.0, 'desc': 'Hedefli Banking Trojan: Uygulama tarama + Overlay + SMS + C2'},
        ('location', 'camera', 'microphone', 'exfiltration'): {'score': 3.0,
                                                               'desc': 'FULL SURVEILLANCE: Konum + Kamera + Mikrofon + Sızdırma'},
        ('webview', 'overlay', 'keylogging', 'exfiltration'): {'score': 3.0, 'desc': 'Advanced web phishing chain'},
        ('clipboard', 'notifications', 'accessibility', 'network'): {'score': 3.0, 'desc': 'Complete 2FA bypass chain'},
        ('vpn', 'crypto', 'network', 'exfiltration'): {'score': 3.0, 'desc': 'Encrypted traffic hijacking + Sızdırma'},
        ('native', 'anti_debug', 'obfuscation', 'dynamic'): {'score': 3.0,
                                                             'desc': 'Maximum evasion: Full anti-analysis stack'},
        ('package_info', 'accessibility', 'overlay', 'keylogging'): {'score': 3.0,
                                                                     'desc': 'Targeted credential theft: App detection + Full input capture'},
        ('admin', 'persistence', 'shell_exec', 'network'): {'score': 3.0,
                                                            'desc': 'Rootkit behavior: Admin + Persistence + Shell + C2'},
        ('location', 'contacts', 'calendar', 'exfiltration'): {'score': 3.0, 'desc': 'Complete personal data theft'},
        ('bluetooth', 'location', 'sensor', 'exfiltration'): {'score': 3.0,
                                                              'desc': 'IoT/Proximity-based tracking system'},
        ('webview', 'file_operations', 'crypto', 'exfiltration'): {'score': 3.0,
                                                                   'desc': 'File stealing + Encryption + Exfiltration'},
    }

    penta_combinations = {
        ('accessibility', 'overlay', 'sms', 'network', 'contacts'): {'score': 4.0, 'desc': 'ULTIMATE BANKING TROJAN: Full capability'},

        ('location', 'camera', 'microphone', 'contacts', 'exfiltration'): {'score': 4.0,
                                                                           'desc': 'ULTIMATE STALKERWARE: Full surveillance + Contact data'},
        ('accessibility', 'overlay', 'keylogging', 'clipboard', 'network'): {'score': 4.0,
                                                                             'desc': 'Complete input interception system'},
        ('package_info', 'accessibility', 'overlay', 'sms', 'banking'): {'score': 4.0,
                                                                         'desc': 'Advanced Banking Trojan: Full capability + Targeting'},
        ('native', 'anti_debug', 'obfuscation', 'dynamic', 'root_detection'): {'score': 4.0,
                                                                               'desc': 'Military-grade evasion: Complete anti-analysis'},
        ('admin', 'persistence', 'crypto', 'network', 'shell_exec'): {'score': 4.0,
                                                                      'desc': 'Advanced persistent threat (APT-like)'},
        ('vpn', 'crypto', 'network', 'exfiltration', 'admin'): {'score': 4.0,
                                                                'desc': 'Enterprise data theft: VPN hijacking + Admin'},
        # ... diğerleri korunur
    }


    # Bu bloklar tespit edilirse ekstra yüksek skor ve etiket ekleyeceğiz.
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
    uses_camera = flag_map.get('camera', False) or flag_map.get('camera_capture', False)
    uses_microphone = flag_map.get('microphone', False) or flag_map.get('microphone_capture', False)
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

    # very high threat booleanları (senin tanımlardakiyle eşdeğer)
    very_high_threat_combo_1 = uses_accessibility and uses_overlay and has_banking_targets
    very_high_threat_combo_2 = uses_admin and uses_crypto
    very_high_threat_combo_3 = uses_sms and has_c2_comm and uses_dynamic_code
    very_high_threat_combo_4 = uses_dynamic_code and uses_shell_exec

    # Stalkerware/Spyware - Tam gözetleme
    very_high_threat_combo_5 = (uses_location and uses_camera and uses_microphone and uses_exfiltration)

    # Complete 2FA/OTP Bypass
    very_high_threat_combo_6 = (uses_clipboard and uses_notifications and uses_accessibility and has_c2_comm)

    # VPN Traffic Hijacking
    very_high_threat_combo_7 = (uses_vpn and uses_crypto and uses_exfiltration)

    # Advanced Web Phishing
    very_high_threat_combo_8 = (uses_webview and uses_overlay and uses_keylogging and uses_exfiltration)

    # Data Ransom (Şifreleme + Sızdırma)
    very_high_threat_combo_9 = (uses_crypto and uses_exfiltration and uses_admin)

    # Rootkit-like Behavior
    very_high_threat_combo_10 = (uses_admin and uses_persistence and uses_shell_exec and has_c2_comm)

    # Targeted Banking Attack
    very_high_threat_combo_11 = (uses_package_info and uses_accessibility and uses_overlay and uses_sms)

    is_very_high_threat = (
            very_high_threat_combo_1 or very_high_threat_combo_2 or
            very_high_threat_combo_3 or very_high_threat_combo_4 or
            very_high_threat_combo_5 or very_high_threat_combo_6 or
            very_high_threat_combo_7 or very_high_threat_combo_8 or
            very_high_threat_combo_9 or very_high_threat_combo_10 or
            very_high_threat_combo_11
    )

    # ============ HIGH THREAT (6.0-7.9 skor) ============

    # Advanced Evasion Techniques
    high_threat_combo_1 = (uses_native and uses_anti_debug and uses_obfuscation and uses_dynamic_code)

    # Location-based Surveillance
    high_threat_combo_2 = (uses_location and (uses_camera or uses_microphone) and uses_exfiltration)

    # Credential Theft Chain
    high_threat_combo_3 = (uses_accessibility and uses_keylogging and uses_clipboard and has_c2_comm)

    # Persistent Backdoor
    high_threat_combo_4 = (uses_persistence and uses_shell_exec and has_c2_comm)

    # Social Engineering Data Theft
    high_threat_combo_5 = (uses_contacts and uses_sms and uses_exfiltration)

    # Privilege Escalation Chain
    high_threat_combo_6 = (uses_root_detection and uses_shell_exec and uses_admin)

    is_high_threat = (
            high_threat_combo_1 or high_threat_combo_2 or
            high_threat_combo_3 or high_threat_combo_4 or
            high_threat_combo_5 or high_threat_combo_6
    )
    # ============ MEDIUM THREAT (4.0-5.9 skor) ============

    # Anti-Analysis (mevcut + geliştirilmiş)
    medium_threat_combo_1 = uses_dynamic_code and (uses_accessibility or uses_keylogging)
    # Obfuscation + Dynamic Loading
    medium_threat_combo_2 = (uses_obfuscation and uses_dynamic_code)

    # Hidden C2 Communication
    medium_threat_combo_3 = (uses_crypto and has_c2_comm and uses_obfuscation)

    # Phishing Preparation
    medium_threat_combo_4 = (uses_overlay and uses_package_info)

    # Background Surveillance
    medium_threat_combo_5 = (uses_persistence and (uses_location or uses_camera or uses_microphone))

    # Data Collection
    medium_threat_combo_6 = (uses_contacts and uses_sms) or (uses_clipboard and uses_notifications)

    # Reflection-based Evasion
    medium_threat_combo_7 = (uses_reflection and (uses_obfuscation or uses_native))

    # VPN/Network Manipulation
    medium_threat_combo_8 = (uses_vpn or (has_c2_comm and uses_crypto))

    is_medium_threat = (
            medium_threat_combo_1 or medium_threat_combo_2 or
            medium_threat_combo_3 or medium_threat_combo_4 or
            medium_threat_combo_5 or medium_threat_combo_6 or
            medium_threat_combo_7 or medium_threat_combo_8
    )

    # Eğer very high tespit edilirse, öncelikle buna göre ek skor ve açıklama ekle
    if is_very_high_threat:
        if very_high_threat_combo_1:
            suspicious_score += 2.5
            detected_combinations.append("VERY_HIGH: Accessibility + Overlay + BankingTargets (+2.5)")
        if very_high_threat_combo_2:
            suspicious_score += 2.0
            detected_combinations.append("VERY_HIGH: Admin + Crypto (Ransomware/privilege chain) (+2.0)")
        if very_high_threat_combo_3:
            suspicious_score += 2.0
            detected_combinations.append("VERY_HIGH: SMS + Network + DynamicCode (OTP/Exfiltration chain) (+2.0)")
        if very_high_threat_combo_4:
            suspicious_score += 2.0
            detected_combinations.append("VERY_HIGH: DynamicCode + ShellExec (Dynamic loader + shell) (+1)")
        if very_high_threat_combo_5:
            suspicious_score += 1
            detected_combinations.append(
                "VERY_HIGH: Location + Camera + Microphone + Exfiltration (STALKERWARE) (+2.5)")
        if very_high_threat_combo_6:
            suspicious_score += 2.5
            detected_combinations.append(
                "VERY_HIGH: Clipboard + Notifications + Accessibility + C2 (2FA Bypass) (+2.0)")
        if very_high_threat_combo_7:
            suspicious_score += 2.0
            detected_combinations.append("VERY_HIGH: VPN + Crypto + Exfiltration (Traffic Hijacking) (+2.0)")
        if very_high_threat_combo_8:
            suspicious_score += 2.0
            detected_combinations.append(
                "VERY_HIGH: WebView + Overlay + Keylogging + Exfiltration (Web Phishing) (+1)")
        if very_high_threat_combo_9:
            suspicious_score += 2.0
            detected_combinations.append("VERY_HIGH: Crypto + Exfiltration + Admin (Data Ransom) (+2.0)")
        if very_high_threat_combo_10:
            suspicious_score += 2.5
            detected_combinations.append("VERY_HIGH: Admin + Persistence + ShellExec + C2 (Rootkit) (+2.5)")
        if very_high_threat_combo_11:
            suspicious_score += 2.0
            detected_combinations.append(
                "VERY_HIGH: PackageInfo + Accessibility + Overlay + SMS (Targeted Banking) (+2.0)")

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
    # Eğer medium threat türevleri varsa, küçük ek skorlar ver
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
            detected_combinations.append(
                "MEDIUM: Persistence + (Location|Camera|Microphone) (Background Surveillance) (+0.5)")
        if medium_threat_combo_6:
            suspicious_score += 0.5
            detected_combinations.append("MEDIUM: (Contacts+SMS) | (Clipboard+Notifications) (Data Collection) (+0.5)")
        if medium_threat_combo_7:
            suspicious_score += 0.5
            detected_combinations.append("MEDIUM: Reflection + (Obfuscation|Native) (Evasion) (+0.5)")
        if medium_threat_combo_8:
            suspicious_score += 0.5
            detected_combinations.append("MEDIUM: VPN | (C2+Crypto) (Network Manipulation) (+0.5)")

    # --- Mevcut (kademeli) kombinasyon kontrolü ---
    # benign_ratio küçükse (yani sample muhtemelen zararlı) geniş kombinasyon taraması yap
    if benign_ratio < 0.70:
        combo_levels_to_check = [
            (penta_combinations, 5),
            (quad_combinations, 4),
            (triple_combinations, 3),
            (combinations, 2)
        ]

        for combo_dict, level in combo_levels_to_check:
            for combo_keys, data in combo_dict.items():
                # küçük optimizasyon: combo uzunluğu aktif bayraklardan büyükse atla
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
        # ⚠️ Benign_ratio yüksek ama kritik pattern'leri yine de değerlendir
        for critical in CRITICAL_COMBO_PATTERNS:
            if all(flag in active_flags for flag in critical):
                desc = f"[CRITICAL] Kritik pattern tespit edildi: {', '.join(critical)}"
                detected_combinations.append(f"{desc} (+3.0)")
                suspicious_score += 3.0

        if len(active_flags) > 0:
            detected_combinations.append(
                f"[INFO] Yüksek benign_ratio ({benign_ratio:.2f}) nedeniyle diğer 3+ kombinasyonlar atlandı."
            )

    threat_flags = {
        "is_very_high": is_very_high_threat,
        "is_medium": is_medium_threat,
        "is_high": is_high_threat  # Bunu da ekleyebiliriz ilerde lazım olur
    }

    return suspicious_score, detected_combinations,threat_flags
