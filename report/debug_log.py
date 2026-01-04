import sys

def write_debug_txt(
        debug_file_txt,
        meta,
        N,
        E,
        apk_size_kb,
        is_packed,
        sem_normed,
        structural,
        bonus,
        mult,
        total_raw_unnormalized,
        normalization_factor,
        total_raw_normalized,
        benign_ratio,
        total_raw,
        counts_g,
        c,
        counts_m,
        suspicious_score,
        detected_combos,
        K,
        a,
        total,
        semantic_risk
        ):
    try:
        with debug_file_txt.open("a", encoding="utf-8") as f:
            f.write(f"\n{'=' * 80}\n")
            f.write(f"APK: {meta['apk_name']}\n")
            f.write(f"  N={N}, E={E}, size={apk_size_kb}KB, is_packed={is_packed}\n")
            f.write(f"  sem_normed={sem_normed:.4f}\n")
            f.write(f"  structural={structural:.4f}\n")
            f.write(f"  bonus={bonus:.4f}\n")
            f.write(f"  Semantic Risk={semantic_risk:.4f}\n")
            f.write(f"  mult={mult:.2f}\n")
            f.write(
                f"  total_raw_unnormalized={(sem_normed + structural + bonus):.4f} * {mult:.2f} = {total_raw_unnormalized:.4f}\n")
            f.write(f"  normalization_factor={normalization_factor:.4f}\n")
            f.write(f"  total_raw_normalized={total_raw_normalized:.4f}\n")
            f.write(f"\n  Benign Library Hits: Weighted ratio = {benign_ratio:.2%}\n")
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

            f.write(f"\n  Suspicous API Combinations: {suspicious_score} \n")
            f.write(f"\n  Detected Combos: {detected_combos} \n")

            f.write(f"\n  Squash Function:\n")
            f.write(f"    _squash(total_raw={total_raw:.4f}, K={K}, a={a}) -> {total:.4f}\n")
            f.flush()
    except Exception as e:
        print(f"[HATA] Debug dosyası yazılamadı: {e}", file=sys.stderr)



def write_benign_libs(apk_name,ratio,benign_hits,N,matched_libs):
    log_path: str = "results/benign_lib_results.txt"
    try:
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(f"\nAPK: {apk_name}\n")
            f.write(f"benign_ratio: {ratio:.4f} ({benign_hits}/{N})\n")
            f.write("matched_benign_libraries:\n")

            if matched_libs:
                for lib in sorted(matched_libs):
                    f.write(f"  - {lib}\n")
            else:
                f.write("  - NONE\n")

            f.write("-" * 40 + "\n")
    except Exception:
        pass  # log yüzünden pipeline asla kırılmasın