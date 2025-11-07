# ⚡ RiskFusion – Packing- and Semantic-Aware Hybrid Risk Scoring Framework for Android Malware Detection

**RiskFusion** is a hybrid semantic and structural graph analysis framework for **Android malware detection**.  
It fuses information from packing analysis, graph topology, and semantic behavior modeling to generate a comprehensive malware **risk score**.  

The framework performs static analysis on Android APKs, extracting graph-based features and manifest metadata to compute:
- `malware_score` — model-based malware likelihood  
- `semantic_risk_score` — risk derived from API graph semantics  
- `hybrid_score` — fused final risk score combining multiple evidence sources  

---

## 📁 Project Structure

```
.
├── analysis/
│   ├── constants.py               # Global constants, benign libraries, and configuration
│   ├── packing.py                 # Detects APK packing, obfuscation, and native code usage
│   ├── semantic_graphs.py         # Core pipeline for semantic + structural risk computation
│   ├── suspicious_combinations.py # Detects suspicious API behavior chains (C2, overlay, keylogging, etc.)
│   └── results_analysis.ipynb     # Notebook for visualization and post-analysis
│
├── data/
│   ├── benign/                    # Benign APK samples
│   └── malware/                   # Malware APK samples
│
├── results/                       # Output CSVs (benign_scores.csv, malware_scores.csv, etc.)
│
├── batch_scoring.py               # CLI script for batch-level processing
├── archive/                       # Backup or legacy versions
└── README.md
```

---

## ⚙️ How to Run

### Run on **all samples**
```bash
python3.14 batch_scoring.py --module semantic_graphs --dataset data --out results/scores.csv
```

### Run on **only benign samples**
```bash
python3.14 batch_scoring.py --module semantic_graphs --dataset data --subset benign --out results/benign_scores.csv
```

### Run on **only malware samples**
```bash
python3.14 batch_scoring.py --module semantic_graphs --dataset data --subset malware --out results/malware_scores.csv
```

Optional flags:
| Flag | Description |
|------|--------------|
| `--limit N` | Process only the first N APKs for quick testing |
| `--verbose` | Enable detailed debug logs (bonus calculations, suspicious combinations) |

---

## 🧠 Scoring Pipeline Overview

1. **Graph Extraction**  
   Androguard builds a control/data-flow graph for each APK.  
2. **Category Weighting**  
   API categories are weighted via predefined rules from `constants.py`.  
3. **Packing and Obfuscation Detection**  
   `packing.py` identifies packed or encrypted APKs and reflection/native patterns.  
4. **Suspicious API Combination Analysis**  
   `suspicious_combinations.py` detects high-risk chains such as  
   `Accessibility + Overlay + BankingTargets`.  
5. **Semantic Bonus Computation**  
   `compute_semantic_bonus()` aggregates graph density, severity levels,  
   and benign shields to reward or penalize samples adaptively.  
6. **Hybrid Score Fusion**  
   ```
   hybrid_score = (1 - risk_weight) * malware_score + (risk_weight * semantic_risk * 100)
   ```
   - `risk_weight` dynamically adjusts with `benign_ratio`
   - low benign_ratio → high semantic impact → higher risk  
   - high benign_ratio → reduced semantic impact → lower risk

---

## 📊 Output Format

| apk_name | malware_score | semantic_risk_score | hybrid_score | label |
|-----------|----------------|--------------------|---------------|--------|
| 0002FB40...apk | 87.3997 | 0.7580 | 95.3062 | 1 |
| 00041CB2...apk | 74.5190 | 0.7920 | 88.4918 | 1 |
| ... | ... | ... | ... | ... |

- `label=1` → malware  
- `label=0` → benign  
- `hybrid_score` is the final decision metric (typically >70 indicates high risk)

---


## 🧩 Key Configuration

| File | Purpose |
|------|----------|
| **constants.py** | Global constants, risk weights, benign library whitelist |
| **semantic_graphs.py** | Main semantic & structural risk computation pipeline |
| **packing.py** | Detects packed / obfuscated APKs |
| **suspicious_combinations.py** | High-risk API combination patterns |

---

## 🧑‍💻 Author
**Muhammet Tan**  
Department of Computer Engineering  
Sivas University of Science and Technology  
Research Areas: Android Malware Detection, Semantic Graphs, Explainable AI  
📧 Contact: muhammet.tan@sivas.edu.tr

---

## 📜 License
Apache 2.0 License – for academic and research use.
