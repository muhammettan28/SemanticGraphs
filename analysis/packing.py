import sys
import zipfile
from androguard.misc import AnalyzeAPK

# -----------------------------------------------------------
# Yardımcı: ZIP içeriğini özetle (hızlı tarama)
# -----------------------------------------------------------
def inspect_apk_zip_minimal(apk_path: str):
    info = {"total_files": 0, "dex_files": [], "libs": [], "assets": [], "large_files": []}
    with zipfile.ZipFile(apk_path, "r") as z:
        for name in z.namelist():
            size = z.getinfo(name).file_size
            info["total_files"] += 1
            if name.endswith(".dex"):
                info["dex_files"].append((name, size))
            elif name.startswith("lib/"):
                info["libs"].append((name, size))
            elif name.startswith("assets/"):
                info["assets"].append((name, size))
            if size > 5 * 1024 * 1024:  # 5 MB üstü
                info["large_files"].append((name, size))
    return info

# -----------------------------------------------------------
# Yardımcı: Tüm stringleri Dex analizinden çıkar
# -----------------------------------------------------------
def _all_strings_from_dx(d_list):
    all_strings = set()
    for d in d_list:
        try:
            for s in d.get_strings():
                try:
                    all_strings.add(s.get_value())
                except Exception:
                    all_strings.add(str(s))
        except Exception:
            continue
    return all_strings

# -----------------------------------------------------------
# Heuristik: DexClassLoader + native / reflection kombinasyonları
# -----------------------------------------------------------
def has_suspicious_combination(dx) -> bool:
    try:
        suspicious = False
        class_loader_refs = dx.tainted_packages.search_methods("Ldalvik/system/DexClassLoader;", ".", "->", ".")
        loadlib_refs = dx.tainted_packages.search_methods("Ljava/lang/System;", "loadLibrary", "->", ".")
        reflection_refs = dx.tainted_packages.search_methods("Ljava/lang/Class;", "forName", "->", ".")

        if class_loader_refs and (loadlib_refs or reflection_refs):
            print("[HEUR] DexClassLoader + native/reflection kombinasyonu tespit edildi -> Muhtemel packer davranışı")
            suspicious = True
        return suspicious
    except Exception as e:
        print(f"[WARN] has_suspicious_combination hata: {e}", file=sys.stderr)
        return False

# -----------------------------------------------------------
# Ana fonksiyon: APK'nin pack edilmiş olup olmadığını tahmin et
# -----------------------------------------------------------
def is_likely_packed_with_androguard(apk_path: str) -> bool:
    """
    Androguard kullanarak bir APK'nın paketlenmiş veya gizlenmiş olma olasılığını
    statik olarak analiz eder. (BaiduProtect ve Jiagu dahil)
    """
    try:
        a, d_list, dx = AnalyzeAPK(apk_path)

        # KURAL 1: TİCARİ PAKETLEYİCİ TESPİTİ (EN GÜÇLÜ SİNYAL)
        # ----------------------------------------------------------------------
        
        # 1a. Jiagu native kütüphaneleri
        jiagu_libs = ["libjiagu.so", "libjiagu_a64.so", "libjgbibc_32.so", "libjgbibc_64.so"]
        apk_libs = a.get_libraries() # Tüm .so dosyalarını al
        if any(any(lib.endswith(jiagu_lib) for jiagu_lib in jiagu_libs) for lib in apk_libs):
            print(f"[!] Yüksek Güvenilirlikli Paketleyici: Jiagu native kütüphanesi tespit edildi -> {apk_path}")
            return True

        # 1b. BaiduProtect native kütüphaneleri (YENİ EKLENDİ)
        baidu_libs = ["libbaiduprotect.so", "libbdmain.so", "libBaiduProtect.so"]
        if any(any(lib.endswith(baidu_lib) for baidu_lib in baidu_libs) for lib in apk_libs):
            print(f"[!] Yüksek Güvenilirlikli Paketleyici: BaiduProtect native kütüphanesi tespit edildi -> {apk_path}")
            return True

        # 1c. Paketleyici asset (varlık) dosyaları
        packer_assets = [
            "jiagu_data.bin", "jiagu_art", "ijm_lib", ".jiagu", "jiagu.db", # Jiagu
            "baidu_dex.jar", "baiduprotect.dat", "baiduprotect.jar" # Baidu (YENİ EKLENDİ)
        ]
        asset_list = a.get_files()
        if any(any(asset in file_path for file_path in asset_list) for asset in packer_assets):
            print(f"[!] Yüksek Güvenilirlikli Paketleyici: Paketleyici asset dosyası tespit edildi -> {apk_path}")
            return True

        # 1d. Diğer bilinen paketleyicilerin Java paket isimleri
        generic_packer_strings = [
            "com.bangcle", "com.secneo", "com.tencent.legu", "com.qihoo360.protect",
            "com.baidu.protect" # Baidu (YENİ EKLENDİ)
        ]
        for d in d_list:
            for s in d.get_strings():
                if any(packer in s for packer in generic_packer_strings):
                    print(f"[!] Yüksek Güvenilirlikli Paketleyici: Bilinen paketleyici imzası bulundu ({s}) -> {apk_path}")
                    return True

        # KURAL 2: ŞÜPHELİ DAVRANIŞSAL DESENLER (Değişiklik yok)
        if has_suspicious_combination(dx):
            return True

        # KURAL 3: GELİŞTİRİLMİŞ ÖZEL APPLICATION SINIFI TESPİTİ (Değişiklik yok)
        app_class_name = a.get_attribute_value('application', 'name')
        if app_class_name and app_class_name not in ["android.app.Application", "androidx.multidex.MultiDexApplication"]:
            formatted_name = "L" + app_class_name.replace('.', '/') + ";"
            try:
                app_class = dx.get_class_analysis(formatted_name)
                if app_class:
                    class_strings = {s.get_value() for s in app_class.get_strings()}
                    if "Ldalvik/system/DexClassLoader;" in class_strings and "Ljavax/crypto/Cipher;" in class_strings:
                        print(f"[!] Olası Paketleyici: Özel Application sınıfı ({formatted_name}) İÇİNDE şifreleme ve kod yükleme tespit edildi -> {apk_path}")
                        return True
            except Exception:
                pass

    except Exception as e:
        print(f"[Androguard Analiz Hatası] {apk_path}: {e}", file=sys.stderr)

    return False