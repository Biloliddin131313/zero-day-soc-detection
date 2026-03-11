#!/usr/bin/env python3
import pandas as pd
import numpy as np
import joblib
import time
from prometheus_client import start_http_server, Counter

flow_counter = Counter("soc_flows_total", "Flow counts", ["module", "type"])

MODULES = [
    {"name": "DDoS", "csv": "dataset/cicids2017/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv", "rf": "scripts/ddos_module/ddos_detector_rf.pkl", "scaler": "scripts/ddos_module/scaler.pkl"},
    {"name": "Brute Force", "csv": "dataset/cicids2017/bruteforce_balanced.csv", "rf": "models/bf_random_forest.pkl", "scaler": "models/bf_scaler.pkl"},
    {"name": "DoS", "csv": "dataset/cicids2017/dos_balanced.csv", "rf": "models/dos_random_forest.pkl", "scaler": "models/dos_scaler.pkl"},
    {"name": "Web Attacks", "csv": "dataset/cicids2017/CICIDS2017_sample.csv", "rf": "models/web_random_forest.pkl", "scaler": "models/web_scaler.pkl"},
    {"name": "Botnet", "csv": "dataset/cicids2017/CICIDS2017_sample.csv", "rf": "models/bot_random_forest.pkl", "scaler": "models/bot_scaler.pkl"},
]

print("Loading models...")
loaded = []
for m in MODULES:
    try:
        rf = joblib.load(m["rf"])
        scaler = joblib.load(m["scaler"])
        df = pd.read_csv(m["csv"], low_memory=False)
        df.columns = df.columns.str.strip()
        loaded.append({**m, "rf": rf, "scaler": scaler, "df": df})
        print(f"Loaded: {m['name']}")
    except Exception as e:
        print(f"Failed: {m['name']} - {e}")

def detect(module):
    try:
        df = module["df"]
        X = df.drop(columns=["Label"], errors="ignore")
        X = X.apply(pd.to_numeric, errors="coerce")
        X.replace([np.inf, -np.inf], 0, inplace=True)
        X.fillna(0, inplace=True)
        X_scaled = module["scaler"].transform(X.values)
        preds = module["rf"].predict(X_scaled)
        attack = int(np.sum(preds == 1))
        benign = int(np.sum(preds == 0))
        flow_counter.labels(module=module["name"], type="ATTACK").inc(attack)
        flow_counter.labels(module=module["name"], type="BENIGN").inc(benign)
        print(f"[{module['name']}] ATTACK={attack:,} BENIGN={benign:,}")
    except Exception as e:
        print(f"Error {module['name']}: {e}")

if __name__ == "__main__":
    start_http_server(8001)
    print("SOC exporter running on http://localhost:8001/metrics")
    while True:
        for m in loaded:
            detect(m)
        print("--- cycle complete ---")
        time.sleep(10)
