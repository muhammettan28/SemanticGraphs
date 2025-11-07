#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
CICMalDroid Batch Scoring (resume destekli)
- dataset/{benign,malware} altındaki .apk dosyalarını işler
- Önce graph (build_api_graph_compact), sonra analiz (analyze_malware_semantically)
- CSV'ye sadece: apk_name,malware_score,label yazar
- Resume: CSV'de apk_name görülenler atlanır (append modunda devam eder)
"""

import argparse
import csv
import sys
from pathlib import Path
import importlib
import traceback

CSV_HEADER = ["apk_name", "malware_score", "semantic_risk_score", "hybrid_score", "label"]  # label: benign=0, malware=1


def ensure_header(csv_path: Path) -> None:
    """CSV yoksa başlıkla oluşturur."""
    if not csv_path.exists():
        csv_path.parent.mkdir(parents=True, exist_ok=True)
        with csv_path.open("w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(CSV_HEADER)


def load_done_set(csv_path: Path) -> set[str]:
    """
    Resume için CSV'deki apk_name'leri set'e al.
    Not: Eğer aynı isimli APK hem benign hem malware'de varsa
    ve ikisini de ayrı ayrı istiyorsan anahtarı (apk_name,label) yapabilirsin.
    """
    done: set[str] = set()
    if csv_path.exists():
        with csv_path.open("r", newline="", encoding="utf-8") as f:
            try:
                reader = csv.DictReader(f)
                # Başlık beklenen formatta ise:
                if reader.fieldnames and "apk_name" in reader.fieldnames:
                    for row in reader:
                        name = row.get("apk_name")
                        if name:
                            done.add(name)
                else:

                    f.seek(0)
                    for i, line in enumerate(f):
                        if i == 0:
                            continue  # header
                        parts = line.strip().split(",")
                        if parts and parts[0]:
                            done.add(parts[0])
            except Exception:
                # Her ihtimale karşı: okunamazsa resume devre dışı gibi davranma
                pass
    return done


def iter_dataset_apks(dataset_dir: Path, subset: str | None = None):
    """Benign/malware klasörlerini gezer, (path, label) döner. benign=0, malware=1"""
    benign_dir = dataset_dir / "benign"
    malware_dir = dataset_dir / "malware"

    if subset in (None, "benign") and benign_dir.exists():
        for p in sorted(benign_dir.glob("*.apk")):
            yield p, 0
    if subset in (None, "malware") and malware_dir.exists():
        for p in sorted(malware_dir.glob("*.apk")):
            yield p, 1


import os
import sys
import csv
import traceback
import importlib
import zipfile
from pathlib import Path

# Yardımcı fonksiyonlar
def ensure_header(out_csv: Path):
    """CSV başlık satırı yoksa oluştur."""
    if not out_csv.exists():
        out_csv.parent.mkdir(parents=True, exist_ok=True)
        with out_csv.open("w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "apk_name",
                "malware_score",
                "semantic_risk_score",
                "hybrid_score",
                "label"
            ])

def load_done_set(out_csv: Path):
    """Önceden işlenmiş APK isimlerini döndür (resume desteği için)."""
    if not out_csv.exists():
        return set()
    with out_csv.open("r", encoding="utf-8") as f:
        next(f, None)
        return {line.split(",")[0] for line in f}

def is_valid_zip(path: Path) -> bool:
    """ZIP yapısını kontrol et."""
    try:
        with zipfile.ZipFile(path, 'r') as zf:
            return zf.testzip() is None
    except zipfile.BadZipFile:
        return False


def stream_score_dataset(module_name: str, dataset_dir: Path, out_csv: Path,
                         subset: str | None = None, limit: int | None = None) -> None:
    """Ana akış: build → analyze → CSV'ye yaz (resume + hata toleranslı)."""
    ensure_header(out_csv)
    done = load_done_set(out_csv)

    # Modül yükle
    mod = importlib.import_module(f"analysis.{module_name}")
    build_fn = getattr(mod, "build_api_graph_compact", None)
    analyze_fn = getattr(mod, "analyze_malware_semantically", None)
    if build_fn is None or analyze_fn is None:
        print(f"[FATAL] {module_name} içinde build_api_graph_compact ve analyze_malware_semantically olmalı.", file=sys.stderr)
        sys.exit(1)

    processed = appended = corrupt_count = small_count = badzip_count = other_err_count = 0

    with out_csv.open("a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)

        for apk_path, label in iter_dataset_apks(dataset_dir, subset=subset):
            if limit is not None and processed >= limit:
                break
            processed += 1

            # 0️⃣ Boyut kontrolü
            try:
                size = os.path.getsize(apk_path)
                if size < 50 * 1024:  # 50 KB altı dosyaları atla
                    print(f"[SKIP-SMALL] {apk_path.name} ({size} bytes)")
                    with open("small_apks.log", "a") as logf:
                        logf.write(f"{apk_path}\n")
                    small_count += 1
                    continue
            except FileNotFoundError:
                continue

            # 0️⃣ ZIP bütünlük kontrolü
            if not is_valid_zip(apk_path):
                print(f"[BAD ZIP] {apk_path.name}")
                with open("bad_zip_apks.log", "a") as logf:
                    logf.write(f"{apk_path}\n")
                badzip_count += 1
                continue

            try:
                print(f"[INFO] İşleniyor: {apk_path.name}")

                # 1️⃣ Graph oluşturma
                try:
                    meta, graph_path = build_fn(str(apk_path))
                    if not graph_path or not Path(graph_path).exists():
                        print(f"[ERROR] Graph oluşturulamadı: {apk_path.name}")
                        continue
                except (ValueError, zipfile.BadZipFile) as e:
                    if "EOCD" in str(e) or isinstance(e, zipfile.BadZipFile):
                        print(f"[CORRUPT ZIP] {apk_path.name} -> {e}")
                        with open("corrupt_apks.log", "a") as logf:
                            logf.write(f"{apk_path}\n")
                        corrupt_count += 1
                        continue
                    raise

                # 2️⃣ Analiz
                report, score = analyze_fn(graph_path, str(apk_path), subset)

                malware_score = (
                    report.get("squashed_score")
                    or report.get("total_raw_normalized")
                    or report.get("malware_score")
                    or float(score)
                )
                semantic_risk = float(report.get("semantic_risk_score", 0.0))
                hybrid_score = float(report.get("hybrid_score", 0.0))

                writer.writerow([
                    apk_path.name,
                    f"{malware_score:.4f}",
                    f"{semantic_risk:.4f}",
                    f"{hybrid_score:.4f}",
                    label
                ])
                f.flush()
                appended += 1

                print(f"[OK] {apk_path.name} -> malware: {malware_score:.3f}, semantic: {semantic_risk:.3f}, hybrid: {hybrid_score:.3f}")

            except Exception as e:
                print(f"[SKIP] {apk_path.name}: {e}")
                traceback.print_exc()
                with open("other_errors.log", "a") as logf:
                    logf.write(f"{apk_path} -> {e}\n")
                other_err_count += 1
                continue

    # --- Son Özet ---
    print("\n========== [SUMMARY] ==========")
    print(f"📦 Processed: {processed}")
    print(f"✅ Appended:  {appended}")
    print(f"💥 Corrupt ZIPs: {corrupt_count}")
    print(f"📉 Small Files: {small_count}")
    print(f"🧩 Bad ZIPs: {badzip_count}")
    print(f"⚠️ Other Errors: {other_err_count}")
    print(f"CSV Output → {out_csv}")
    print("================================")

def main():
    ap = argparse.ArgumentParser(description="Batch score APKs (resume supported).")
    ap.add_argument("--module", required=True, help="Örn: semantic_graphs")
    ap.add_argument("--dataset", required=True, type=Path, help="Benign/Malware klasörlerini içeren dizin")
    ap.add_argument("--out", required=True, type=Path, help="Çıktı CSV yolu")
    ap.add_argument("--subset", choices=["benign", "malware"], default=None, help="Sadece bir alt küme")
    ap.add_argument("--limit", type=int, default=None, help="Maks işlenecek APK sayısı (debug)")
    args = ap.parse_args()

    stream_score_dataset(args.module, args.dataset, args.out, subset=args.subset, limit=args.limit)


if __name__ == "__main__":
    main()
