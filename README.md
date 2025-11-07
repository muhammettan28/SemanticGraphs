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

The framework outputs a detailed CSV file summarizing the risk analysis for each APK sample.

| apk_name | malware_score | semantic_risk_score | hybrid_score | reduction_reason | benign_ratio | label |
|-----------|----------------|--------------------|---------------|------------------|---------------|--------|
| 0000511D5C2A99B303AFD14D2ACDE3EBBAD5C3426039679B25F24510A87B381C.apk | 78.6625 | 0.6000 | 81.8314 | Default (no reduction applied) | 0.0000 | 1 |
| 000109A075DC3AFA88C45523A3EDF2039177386C58A48936FEAFEE9716F7BCBB.apk | 94.9996 | 0.7650 | 100.0000 | Default (no reduction applied) | 0.0000 | 1 |
| 00013E39079F820CC8010FA9B6DEB57290B6BEE75365DFBE36B9348052760D08.apk | 82.0658 | 0.6910 | 78.8243 | Default (no reduction applied) | 0.5257 | 1 |
| 00016FA3B94E1B117851EAC18D639873B892AB833D027A41243BAEE04AA49309.apk | 93.3083 | 0.7650 | 99.8325 | Default (no reduction applied) | 0.0000 | 1 |

### Column descriptions

| Column | Description |
|--------|-------------|
| **apk_name** | The SHA-256-based filename of the analyzed APK |
| **malware_score** | Base risk derived from graph-based and structural indicators |
| **semantic_risk_score** | Risk estimated from semantic graph analysis (normalized 0–1) |
| **hybrid_score** | Final fused score combining structural + semantic + benign ratios |
| **reduction_reason** | The applied reduction policy (e.g., *Sigmoid reduction*, *High benign ratio*, etc.) |
| **benign_ratio** | Weighted ratio of benign libraries detected in the APK |
| **label** | `1` = malware, `0` = benign |

> **Interpretation:**  
> Higher `hybrid_score` values indicate stronger evidence of malicious behavior.  
> In typical evaluations, scores **above 70** are considered high-risk.
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
