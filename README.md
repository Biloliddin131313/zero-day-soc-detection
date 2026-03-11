# 🛡️ Zero-Day SOC Detection System

> Enhancing Zero-Day Exploit Detection via Unsupervised Machine Learning in a SOC Environment

**Author:** Biloliddin Turaev  
**Institution:** Southampton Solent University  
**Programme:** BSc Cyber Security Management  
**Year:** 2025/2026

---

## 📌 Project Overview

This project builds a real-time Security Operations Centre (SOC) detection system capable of identifying zero-day exploits using unsupervised machine learning. Unlike traditional signature-based detection, this system learns what normal network traffic looks like and flags anything that deviates — meaning it can detect attacks it has never seen before.

The system was trained and evaluated on the **CICIDS2017** dataset across 5 attack modules.

---

## 🎯 Key Results

| Module | Attack Type | RF AUC | Isolation Forest AUC | Autoencoder AUC |
|--------|------------|--------|---------------------|-----------------|
| 1 | DDoS | 1.0000 | 0.7522 | 0.8592 |
| 2 | Brute Force | 0.9998 | 0.6688 | 0.6867 |
| 3 | DoS | 1.0000 | 0.8290 | 0.8318 |
| 4 | Web Attacks | 0.9998 | 0.7018 | 0.7694 |
| 5 | Botnet | 0.9996 | 0.5875 | 0.5740 |

**Key Finding:** The Autoencoder outperforms Isolation Forest on 4 out of 5 attack types, confirming the advantage of deep learning for unsupervised anomaly detection.

---

## 🧠 Models Used

### Supervised Baseline
- **Random Forest** — trained with labels, near-perfect detection across all modules

### Unsupervised (Zero-Day Capable)
- **Isolation Forest** — trained on BENIGN traffic only, detects deviations
- **Autoencoder (Deep Learning)** — learns to reconstruct normal traffic, flags high reconstruction error as anomalies

---

## 📁 Project Structure
```
zero-day-soc-detection/
├── models/                          # Trained models for all 5 modules
│   ├── autoencoder.keras            # DDoS autoencoder
│   ├── isolation_forest.pkl         # DDoS isolation forest
│   ├── bf_*/                        # Brute Force models
│   ├── dos_*/                       # DoS models
│   ├── web_*/                       # Web Attack models
│   └── bot_*/                       # Botnet models
├── results/                         # All charts, reports and evaluations
│   ├── cross_module_comparison.png  # Bar chart — all modules vs all models
│   ├── cross_module_trend.png       # Line chart — performance trends
│   ├── shap_summary.png             # SHAP explainability plot
│   ├── roc_curves.png               # ROC curves
│   ├── master_soc_report.txt        # Master SOC threat report
│   └── soc_report_*.txt             # Individual module SOC reports
├── scripts/
│   ├── ddos_module/                 # DDoS live exporter
│   │   └── ddos_exporter.py
│   └── soc_exporter.py             # Multi-module live Prometheus exporter
├── notebooks/
└── zero_day_detection.ipynb         # Main Jupyter notebook
```

---

## 🚀 Live Deployment

This system runs live with real-time metrics pushed to **Prometheus** and visualised in **Grafana**.

### Start the system

**Terminal 1 — Start the SOC exporter:**
```bash
cd ~/zero-day-soc-detection
source venv/bin/activate
python3 scripts/soc_exporter.py
```

**Terminal 2 — Start Prometheus:**
```bash
cd ~/prometheus-2.51.0.linux-amd64
./prometheus --config.file=prometheus.yml
```

**Grafana** starts automatically as a system service.

### Access the dashboard
| Service | URL |
|---------|-----|
| Jupyter Notebook | http://localhost:8888 |
| Prometheus | http://localhost:9090 |
| Grafana Dashboard | http://localhost:3000 |
| Metrics Endpoint | http://localhost:8001/metrics |

---

## 📊 Dataset

**CICIDS2017** — Canadian Institute for Cybersecurity Intrusion Detection System 2017

- Captured over 5 days in a realistic corporate network environment
- Contains both benign traffic and labelled attacks
- Used across 5 modules: DDoS, Brute Force, DoS, Web Attacks, Botnet

---

## 🔍 SHAP Explainability

The system uses **SHAP (SHapley Additive exPlanations)** to explain which network features most influenced each detection decision.

**Top 3 features for DDoS detection:**
1. Bwd Packet Length Mean (0.2407)
2. Bwd Packet Length Max (0.2405)
3. Bwd Packet Length Std (0.2097)

---

## 🏥 SOC Alert Triage

Each detected anomaly is assigned a risk tier:

| Tier | Risk Score | Action |
|------|-----------|--------|
| 🔴 CRITICAL | ≥ 0.75 | Immediate investigation |
| 🟠 HIGH | ≥ 0.50 | Investigate within 1 hour |
| 🟡 MEDIUM | ≥ 0.25 | Review within 4 hours |
| 🟢 LOW | < 0.25 | Process during normal operations |

---

## 🛠️ Tech Stack

| Tool | Purpose |
|------|---------|
| Python 3.12 | Core language |
| Scikit-learn | Random Forest, Isolation Forest |
| TensorFlow/Keras | Autoencoder deep learning model |
| SHAP | Model explainability |
| Prometheus | Live metrics collection |
| Grafana | Real-time dashboard visualisation |
| Pandas/NumPy | Data processing |
| Matplotlib/Seaborn | Visualisation |

---

## 📄 License

This project was developed for academic purposes as part of a BSc dissertation at Southampton Solent University.

---

*Built with 🛡️ by Biloliddin Turaev — Southampton Solent University 2026*
