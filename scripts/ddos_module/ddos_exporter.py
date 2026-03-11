#!/usr/bin/env python3
import pandas as pd
import numpy as np
import joblib
import json
import time
from prometheus_client import start_http_server, Counter

# -------------------------
# Paths
# -------------------------
MODEL_PATH   = "ddos_detector_rf.pkl"
SCALER_PATH  = "scaler.pkl"
FEATURES_PATH = "ddos_features.json"
CSV_PATH     = "/home/bramstoker/zero-day-soc-detection/dataset/cicids2017/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"

# -------------------------
# Load model, scaler, features
# -------------------------
try:
    rf     = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    with open(FEATURES_PATH, "r") as f:
        features = json.load(f)
    print("Model, scaler, and features loaded successfully.")
except Exception as e:
    print("Error loading:", e)
    exit(1)

# -------------------------
# Prometheus metrics
# -------------------------
ddos_counter = Counter('ddos_flows_total', 'DDoS flow counts', ['type'])

# -------------------------
# Detection function
# -------------------------
def detect_ddos(flows_df):
    try:
        # Strip whitespace from column names
        flows_df.columns = flows_df.columns.str.strip()

        # Align to trained features
        X = flows_df.reindex(columns=features)
        X = X.replace([np.inf, -np.inf], 0).fillna(0)

        # Use .values to strip feature names (fixes sklearn warning)
        X_scaled = scaler.transform(X.values)

        # Predict
        predictions = rf.predict(X_scaled)

        # Check what labels the model actually uses
        unique_preds = np.unique(predictions)

        # Count results - handle both string and numeric labels
        if 'DDoS' in unique_preds or 'BENIGN' in unique_preds:
            ddos_count   = int(np.sum(predictions == 'DDoS'))
            benign_count = int(np.sum(predictions == 'BENIGN'))
        else:
            # Numeric labels: 1=attack, 0=benign
            ddos_count   = int(np.sum(predictions == 1))
            benign_count = int(np.sum(predictions == 0))

        ddos_counter.labels(type='DDoS').inc(ddos_count)
        ddos_counter.labels(type='BENIGN').inc(benign_count)

        print(f"Processed {len(flows_df)} flows: DDoS={ddos_count}, BENIGN={benign_count}")
        print(f"Unique predictions seen: {unique_preds}")

    except Exception as e:
        print("Error during processing:", e)

# -------------------------
# Main loop
# -------------------------
if __name__ == "__main__":
    start_http_server(8000)
    print("Prometheus exporter running on http://localhost:8000/metrics")

    while True:
        try:
            df = pd.read_csv(CSV_PATH)
            detect_ddos(df)
            time.sleep(10)
        except Exception as e:
            print("Error reading CSV:", e)
            time.sleep(10)
