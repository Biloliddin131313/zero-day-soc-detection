#!/usr/bin/env python3
import os, sys, time, logging
import numpy as np
import pandas as pd
import joblib
from datetime import datetime, timedelta
from prometheus_client import start_http_server, Counter, Gauge, Histogram

os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S")
log = logging.getLogger("0xday")
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

MODULES = {
    "DDoS": {"csv":"dataset/cicids2017/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv","iso":"models/isolation_forest.pkl","ae":"models/autoencoder.keras","rf":"scripts/ddos_module/ddos_detector_rf.pkl","scaler":"scripts/ddos_module/scaler.pkl"},
    "Brute Force": {"csv":"dataset/cicids2017/bruteforce_balanced.csv","iso":"models/bf_isolation_forest.pkl","ae":"models/bf_autoencoder.keras","rf":"models/bf_random_forest.pkl","scaler":"models/bf_scaler.pkl"},
    "DoS": {"csv":"dataset/cicids2017/dos_balanced.csv","iso":"models/dos_isolation_forest.pkl","ae":"models/dos_autoencoder.keras","rf":"models/dos_random_forest.pkl","scaler":"models/dos_scaler.pkl"},
    "Web Attacks": {"csv":"dataset/cicids2017/CICIDS2017_sample.csv","iso":"models/web_isolation_forest.pkl","ae":"models/web_autoencoder.keras","rf":"models/web_random_forest.pkl","scaler":"models/web_scaler.pkl"},
    "Live DDoS": {"csv":"dataset/cicids2017/live_flows.csv","iso":"models/isolation_forest.pkl","ae":"models/autoencoder.keras","rf":"scripts/ddos_module/ddos_detector_rf.pkl","scaler":"scripts/ddos_module/scaler.pkl"},
    "Live BruteForce": {"csv":"dataset/cicids2017/live_flows.csv","iso":"models/bf_isolation_forest.pkl","ae":"models/bf_autoencoder.keras","rf":"models/bf_random_forest.pkl","scaler":"models/bf_scaler.pkl"},
    "Live DoS": {"csv":"dataset/cicids2017/live_flows.csv","iso":"models/dos_isolation_forest.pkl","ae":"models/dos_autoencoder.keras","rf":"models/dos_random_forest.pkl","scaler":"models/dos_scaler.pkl"},
    "Live WebAttacks": {"csv":"dataset/cicids2017/live_flows.csv","iso":"models/web_isolation_forest.pkl","ae":"models/web_autoencoder.keras","rf":"models/web_random_forest.pkl","scaler":"models/web_scaler.pkl"},
    "Live Botnet": {"csv":"dataset/cicids2017/live_flows.csv","iso":"models/bot_isolation_forest.pkl","ae":"models/bot_autoencoder.keras","rf":"models/bot_random_forest.pkl","scaler":"models/bot_scaler.pkl"},
    "Botnet": {"csv":"dataset/cicids2017/CICIDS2017_sample.csv","iso":"models/bot_isolation_forest.pkl","ae":"models/bot_autoencoder.keras","rf":"models/bot_random_forest.pkl","scaler":"models/bot_scaler.pkl"},
}

soc_flows = Counter("soc_flows_total", "Flow counts", ["module", "type"])
soc_incidents = Counter("soc_incidents_total", "Correlated incidents", ["module", "severity"])
soc_risk = Gauge("soc_risk_score", "Ensemble risk score", ["module"])
soc_reduction = Gauge("soc_alert_reduction_pct", "Alert suppression pct", ["module"])

class AlertCorrelator:
    def __init__(self, window=60):
        self.window = timedelta(seconds=window)
        self.active = {}
    def process(self, module, count, severity):
        now = datetime.now()
        rank = {"LOW":0,"MEDIUM":1,"HIGH":2,"CRITICAL":3}
        if module in self.active and now - self.active[module]["t"] < self.window:
            i = self.active[module]
            i["count"] += count
            if rank.get(severity,0) > rank.get(i["sev"],0): i["sev"] = severity
            return False, i["sev"], i["count"]
        self.active[module] = {"t":now,"count":count,"sev":severity}
        return True, severity, count

def classify(score):
    if score >= 0.75: return "CRITICAL"
    if score >= 0.50: return "HIGH"
    if score >= 0.25: return "MEDIUM"
    return "LOW"

def load_models():
    import tensorflow as tf
    loaded = {}
    for name, paths in MODULES.items():
        entry = {"name": name}
        csv_path = os.path.join(BASE, paths["csv"])
        if not os.path.exists(csv_path):
            log.warning(f"  [{name}] CSV missing")
            continue
        entry["csv"] = csv_path
        sp = os.path.join(BASE, paths["scaler"])
        if not os.path.exists(sp):
            log.warning(f"  [{name}] Scaler missing")
            continue
        entry["scaler"] = joblib.load(sp)
        count = 0
        rp = os.path.join(BASE, paths["rf"])
        if os.path.exists(rp):
            entry["rf"] = joblib.load(rp)
            count += 1
            log.info(f"  [{name}] RF loaded")
        ip = os.path.join(BASE, paths["iso"])
        if os.path.exists(ip):
            entry["iso"] = joblib.load(ip)
            count += 1
            log.info(f"  [{name}] IF loaded")
        ap = os.path.join(BASE, paths["ae"])
        if os.path.exists(ap):
            entry["ae"] = tf.keras.models.load_model(ap, compile=False)
            count += 1
            log.info(f"  [{name}] AE loaded")
        if count > 0:
            loaded[name] = entry
    return loaded

def process_module(name, entry, correlator):
    t0 = time.time()
    try:
        df = pd.read_csv(entry["csv"], low_memory=False)
        df.columns = df.columns.str.strip()
        X = df.drop(columns=["Label"], errors="ignore")
        if hasattr(entry["scaler"],"n_features_in_") and entry["scaler"].n_features_in_ == 77:
            X = X.drop(columns=["Destination Port"], errors="ignore")
        X = X.apply(pd.to_numeric, errors="coerce")
        X.replace([np.inf, -np.inf], 0, inplace=True)
        X.fillna(0, inplace=True)
        X_scaled = entry["scaler"].transform(X.values)
        n = len(X_scaled)
        rf_attacks = 0
        if "rf" in entry:
            rf_attacks = int(np.sum(entry["rf"].predict(X_scaled) == 1))
        iso_scores = np.zeros(n)
        if "iso" in entry:
            raw = -entry["iso"].decision_function(X_scaled)
            lo, hi = raw.min(), raw.max()
            if hi > lo: iso_scores = (raw - lo) / (hi - lo)
        ae_scores = np.zeros(n)
        if "ae" in entry:
            recon = entry["ae"].predict(X_scaled, verbose=0)
            raw = np.mean(np.square(X_scaled - recon), axis=1)
            lo, hi = raw.min(), raw.max()
            if hi > lo: ae_scores = (raw - lo) / (hi - lo)
        risk = 0.4 * iso_scores + 0.6 * ae_scores
        threshold = 0.25
        flagged = int(np.sum(risk >= threshold))
        suppressed = n - flagged
        reduction = round((suppressed / n) * 100, 1) if n > 0 else 0
        soc_flows.labels(module=name, type="ATTACK").inc(flagged)
        soc_flows.labels(module=name, type="BENIGN").inc(suppressed)
        mean_risk = float(risk[risk >= threshold].mean()) if flagged > 0 else 0.0
        soc_risk.labels(module=name).set(round(mean_risk, 4))
        soc_reduction.labels(module=name).set(reduction)
        if flagged > 0:
            sev = classify(float(risk.max()))
            is_new, sev, _ = correlator.process(name, flagged, sev)
            if is_new: soc_incidents.labels(module=name, severity=sev).inc(1)
        elapsed = time.time() - t0
        log.info(f"[{name:>12}] Flows={n:>7,} | RF={rf_attacks:>6,} | Ensemble={flagged:>6,} | Suppressed={suppressed:>7,} ({reduction}%) | Risk={mean_risk:.3f} | {elapsed:.1f}s")
    except Exception as e:
        log.error(f"[{name}] Error: {e}")

def main():
    log.info("=" * 60)
    log.info("  0xDay SOC Detection Platform v2.0")
    log.info("  RF + Isolation Forest + Autoencoder")
    log.info("=" * 60)
    loaded = load_models()
    log.info(f"{len(loaded)}/{len(MODULES)} modules active")
    if not loaded:
        log.error("No modules loaded")
        return
    start_http_server(8001)
    log.info(f"Metrics: http://localhost:8001/metrics")
    correlator = AlertCorrelator(window=60)
    cycle = 0
    while True:
        cycle += 1
        log.info(f"-- Cycle {cycle} --")
        for name, entry in loaded.items():
            process_module(name, entry, correlator)
        time.sleep(15)

if __name__ == "__main__":
    main()
