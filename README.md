How to run with all samples

python3.14 cicmaldroid_batch_scoring.py --module semantic_graphs --dataset data --out results/androzoo_scores.csv


How to run with just benign samples

python3.14 batch_scoring.py --module semantic_graphs --dataset data --subset benign --out results/benign_scores.csv


How to run with just malware samples:

python3.14 batch_scoring.py --module semantic_graphs --dataset data --subset malware --out results/malware_scores.csv


