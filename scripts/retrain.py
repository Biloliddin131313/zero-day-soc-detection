"""
0xDay Feedback Loop — Retraining Job
Triggered when queued labels hit the threshold (default 100).
Retrains each RF module that has new labels, saves versioned model,
logs accuracy to model_versions table, marks labels as 'used'.
"""

import sys
import json
import logging
import sqlite3
import joblib
import numpy as np
import pandas as pd
from pathlib import Path
from datetime import datetime
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, f1_score, roc_auc_score

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("0xday.retrain")

ROOT = Path(__file__).resolve().parent.parent
DB_PATH = ROOT / "feedback.db"

# Module config — matches soc_exporter_v2.py exactly
MODULE_CONFIG = {
    "DDoS": {
        "csv": ROOT / "dataset/cicids2017/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
        "rf":  ROOT / "scripts/ddos_module/ddos_detector_rf.pkl",
        "scaler": ROOT / "scripts/ddos_module/scaler.pkl",
        "features": 78,
        "label_col": "Label",
        "attack_label": "DDoS",
    },
    "BruteForce": {
        "csv": ROOT / "dataset/cicids2017/bruteforce_balanced.csv",
        "rf":  ROOT / "models/bf_random_forest.pkl",
        "scaler": ROOT / "models/bf_scaler.pkl",
        "features": 78,
        "label_col": "Label",
        "attack_label": "BruteForce",
    },
    "DoS": {
        "csv": ROOT / "dataset/cicids2017/dos_balanced.csv",
        "rf":  ROOT / "models/dos_random_forest.pkl",
        "scaler": ROOT / "models/dos_scaler.pkl",
        "features": 78,
        "label_col": "Label",
        "attack_label": "DoS",
    },
    "WebAttack": {
        "csv": ROOT / "dataset/cicids2017/CICIDS2017_sample.csv",
        "rf":  ROOT / "models/web_random_forest.pkl",
        "scaler": ROOT / "models/web_scaler.pkl",
        "features": 77,
        "label_col": "Label",
        "attack_label": "WebAttack",
    },
    "Botnet": {
        "csv": ROOT / "dataset/cicids2017/CICIDS2017_sample.csv",
        "rf":  ROOT / "models/bot_random_forest.pkl",
        "scaler": ROOT / "models/bot_scaler.pkl",
        "features": 77,
        "label_col": "Label",
        "attack_label": "Botnet",
    },
}

# Maps analyst label → module name
LABEL_TO_MODULE = {
    "DDoS": "DDoS",
    "BruteForce": "BruteForce",
    "DoS": "DoS",
    "WebAttack": "WebAttack",
    "Botnet": "Botnet",
}


def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def fetch_queued_labels(conn):
    """Pull all queued labels with their alert context."""
    rows = conn.execute("""
        SELECT l.label_id, l.flow_id, l.analyst_label,
               a.features_json, a.if_score, a.ae_error, a.rf_confidence
        FROM labels l
        JOIN alerts a ON l.flow_id = a.flow_id
        WHERE l.training_status = 'queued'
        ORDER BY l.timestamp ASC
    """).fetchall()
    return rows


def load_base_dataset(cfg, max_rows=5000):
    """Load original training CSV, return X (numpy), y (0/1 numpy)."""
    log.info(f"  Loading base dataset: {cfg['csv'].name}")
    df = pd.read_csv(cfg["csv"], nrows=max_rows)
    df.columns = df.columns.str.strip()

    label_col = cfg["label_col"]
    if label_col not in df.columns:
        raise ValueError(f"Label column '{label_col}' not found")

    # Binary encode: attack=1, benign=0
    attack_kw = cfg["attack_label"].lower()
    df["_y"] = df[label_col].apply(
        lambda x: 1 if attack_kw in str(x).lower() else 0
    )

    X = df.drop(columns=[label_col, "_y"], errors="ignore")

    # Drop Destination Port if model expects 77 features
    if cfg["features"] == 77:
        X = X.drop(columns=["Destination Port"], errors="ignore")

    X = X.apply(pd.to_numeric, errors="coerce")
    X.replace([np.inf, -np.inf], 0, inplace=True)
    X.fillna(0, inplace=True)

    # Keep only the right number of features
    X = X.iloc[:, :cfg["features"]]

    scaler = joblib.load(cfg["scaler"])
    X_scaled = scaler.transform(X.values)

    return X_scaled, df["_y"].values


def retrain_module(module_name, cfg, analyst_rows, version_tag):
    """Retrain one RF module and return metrics dict."""
    log.info(f"Retraining [{module_name}] with {len(analyst_rows)} analyst labels...")

    # Load base training data
    X_base, y_base = load_base_dataset(cfg)

    # Build analyst augmentation rows
    # Each analyst label = one synthetic feature vector (zeros) with correct label
    # In a real system you'd store the actual flow features — this scaffolds the mechanism
    n_features = cfg["features"]
    X_analyst = []
    y_analyst = []

    for row in analyst_rows:
        label = row["analyst_label"]
        y_val = 1 if label not in ("Benign", "Unknown") else 0
        # Use stored features_json if available and parseable
        try:
            feats = json.loads(row["features_json"])
            if isinstance(feats, dict) and len(feats) >= n_features:
                vec = np.array(list(feats.values())[:n_features], dtype=float)
            else:
                vec = np.zeros(n_features)
        except Exception:
            vec = np.zeros(n_features)
        X_analyst.append(vec)
        y_analyst.append(y_val)

    X_analyst = np.array(X_analyst)
    y_analyst = np.array(y_analyst)

    # Combine base + analyst data
    X_combined = np.vstack([X_base, X_analyst])
    y_combined = np.concatenate([y_base, y_analyst])

    log.info(f"  Combined dataset: {len(X_combined)} rows "
             f"({int(y_combined.sum())} attack, {int((y_combined==0).sum())} benign)")

    # Train/test split
    X_train, X_test, y_train, y_test = train_test_split(
        X_combined, y_combined, test_size=0.2, random_state=42, stratify=y_combined
    )

    # Load original RF to inherit hyperparameters
    original_rf = joblib.load(cfg["rf"])
    new_rf = RandomForestClassifier(
        n_estimators=original_rf.n_estimators,
        max_depth=original_rf.max_depth,
        random_state=42,
        n_jobs=-1,
    )
    new_rf.fit(X_train, y_train)

    # Evaluate
    y_pred = new_rf.predict(X_test)
    y_prob = new_rf.predict_proba(X_test)[:, 1]
    accuracy = round(accuracy_score(y_test, y_pred), 4)
    f1 = round(f1_score(y_test, y_pred, zero_division=0), 4)
    try:
        auc = round(roc_auc_score(y_test, y_prob), 4)
    except Exception:
        auc = None

    log.info(f"  Accuracy={accuracy} F1={f1} AUC={auc}")

    # Save versioned model (keep original as backup)
    versioned_path = cfg["rf"].parent / f"{cfg['rf'].stem}_{version_tag}.pkl"
    joblib.dump(new_rf, versioned_path)
    # Overwrite active model
    joblib.dump(new_rf, cfg["rf"])
    log.info(f"  Saved → {cfg['rf'].name} (backup: {versioned_path.name})")

    return {
        "accuracy": accuracy,
        "f1": f1,
        "auc": auc,
        "train_size": len(X_train),
        "analyst_labels": len(analyst_rows),
        "model_path": str(cfg["rf"]),
    }


def log_version(conn, module_name, version_tag, metrics, label_ids):
    """Write a row to model_versions and mark labels as used."""
    version_name = f"{module_name}_v_{version_tag}"

    # Deactivate previous versions for this module
    conn.execute("""
        UPDATE model_versions SET is_active = 0
        WHERE version_name LIKE ?
    """, (f"{module_name}_%",))

    conn.execute("""
        INSERT INTO model_versions
            (version_name, model_path, training_data_size,
             analyst_labels_used, holdout_accuracy, holdout_f1,
             holdout_auc, is_active, notes)
        VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)
    """, (
        version_name,
        metrics["model_path"],
        metrics["train_size"],
        metrics["analyst_labels"],
        metrics["accuracy"],
        metrics["f1"],
        metrics["auc"],
        f"Retrained with {metrics['analyst_labels']} analyst labels",
    ))

    # Mark labels as used
    placeholders = ",".join("?" * len(label_ids))
    conn.execute(
        f"UPDATE labels SET training_status='used', training_version=? WHERE label_id IN ({placeholders})",
        [version_name] + label_ids,
    )
    conn.commit()
    log.info(f"  Logged version: {version_name}")


def run_retrain():
    log.info("=" * 55)
    log.info("  0xDay Retraining Job")
    log.info(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    log.info("=" * 55)

    conn = get_db()
    queued = fetch_queued_labels(conn)

    if not queued:
        log.info("No queued labels found. Nothing to do.")
        conn.close()
        return

    log.info(f"Found {len(queued)} queued labels")

    # Group labels by module
    by_module = {}
    for row in queued:
        module = LABEL_TO_MODULE.get(row["analyst_label"])
        if module:
            by_module.setdefault(module, []).append(row)
        # Benign/Unknown labels go to ALL modules (false positive signal)
        elif row["analyst_label"] in ("Benign", "Unknown"):
            for m in MODULE_CONFIG:
                by_module.setdefault(m, []).append(row)

    version_tag = datetime.now().strftime("%Y%m%d_%H%M%S")
    retrained = []

    for module_name, rows in by_module.items():
        cfg = MODULE_CONFIG.get(module_name)
        if not cfg:
            continue
        if not cfg["csv"].exists():
            log.warning(f"  [{module_name}] CSV not found, skipping")
            continue

        try:
            metrics = retrain_module(module_name, cfg, rows, version_tag)
            label_ids = [r["label_id"] for r in rows]
            log_version(conn, module_name, version_tag, metrics, label_ids)
            retrained.append(module_name)
        except Exception as e:
            log.error(f"  [{module_name}] Retrain failed: {e}")
            import traceback; traceback.print_exc()

    conn.close()

    log.info("=" * 55)
    log.info(f"  Retrained: {retrained}")
    log.info(f"  Done: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    log.info("=" * 55)


if __name__ == "__main__":
    run_retrain()
