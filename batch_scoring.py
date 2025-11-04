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

CSV_HEADER = ["apk_name", "malware_score", "label"]  # label: benign=0, malware=1


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


def stream_score_dataset(module_name: str, dataset_dir: Path, out_csv: Path,
                         subset: str | None = None, limit: int | None = None) -> None:
    """Ana akış: build → analyze → CSV'ye yaz (resume destekli)."""
    ensure_header(out_csv)
    done = load_done_set(out_csv)

    # Modülü yükle ve gerekli fonksiyonları çek
    mod = importlib.import_module(f"analysis.{module_name}")
    build_fn = getattr(mod, "build_api_graph_compact", None)
    analyze_fn = getattr(mod, "analyze_malware_semantically", None)
    if build_fn is None or analyze_fn is None:
        print(f"[FATAL] {module_name} içinde build_api_graph_compact ve analyze_malware_semantically olmalı.", file=sys.stderr)
        sys.exit(1)

    processed = 0
    appended = 0

    # CSV'nin var olduğundan emin ol ve append modunda aç
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    
    with out_csv.open("a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        
        for apk_path, label in iter_dataset_apks(dataset_dir, subset=subset):
            if limit is not None and processed >= limit:
                break
            processed += 1
            
            try:
                print(f"[INFO] İşleniyor: {apk_path.name}")
                
                # 1) Graph build
                meta, graph_path = build_fn(str(apk_path))
                
                if not graph_path or not Path(graph_path).exists():
                    print(f"[ERROR] Graph oluşturulamadı: {apk_path.name}")
                    continue

                # 2) Semantic analiz
                report, score = analyze_fn(graph_path, str(apk_path),subset)
                
                # CSV'ye yaz ve flush et
                row = [apk_path.name, f"{score:.4f}", label]
                writer.writerow(row)
                f.flush()
                appended += 1
                
                print(f"[OK] {apk_path.name} -> {score:.4f} (label={label})")

            except Exception as e:
                print(f"[SKIP] {apk_path.name}: {e}")
                traceback.print_exc()
                continue

    print(f"[DONE] processed={processed}, appended={appended}, csv={out_csv}")


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
