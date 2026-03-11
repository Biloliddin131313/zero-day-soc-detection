# scripts/ddos_module/predict_ddos.py
import pandas as pd
import joblib
import json
import os

# Paths
BASE_DIR = os.path.dirname(__file__)
MODEL_PATH = os.path.join(BASE_DIR, "ddos_detector_rf.pkl")
SCALER_PATH = os.path.join(BASE_DIR, "scaler.pkl")
FEATURES_PATH = os.path.join(BASE_DIR, "ddos_features.json")
DATA_PATH = os.path.join(BASE_DIR, "../../dataset/cicids2017/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")
RESULTS_PATH = os.path.join(BASE_DIR, "../../results/ddos_predictions.csv")

# Load model and scaler
rf = joblib.load(MODEL_PATH)
scaler = joblib.load(SCALER_PATH)

# Load new flows
df = pd.read_csv(DATA_PATH)
df.columns = df.columns.str.strip()

# If features list exists, use it; else create
if os.path.exists(FEATURES_PATH):
    with open(FEATURES_PATH, "r") as f:
        features = json.load(f)
else:
    features = df.drop(columns=['Label']).columns.tolist()
    with open(FEATURES_PATH, "w") as f:
        json.dump(features, f)

# Prepare features
X = df[features]
X_scaled = scaler.transform(X)

# Predict
df["Predicted_Label"] = rf.predict(X_scaled)
df["Predicted_Label_Text"] = df["Predicted_Label"].map({0: "BENIGN", 1: "DDOS"})

# Save results
df.to_csv(RESULTS_PATH, index=False)
print("Predictions saved to:", RESULTS_PATH)
print(df[["Label", "Predicted_Label_Text"]].head())
