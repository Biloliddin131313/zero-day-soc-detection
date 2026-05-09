"""
0xDay Feedback Loop — Database Writer
Persists correlated alerts to feedback.db.

Used by SOC Exporter when a new correlated incident is detected.
Failures here MUST NOT break the detection pipeline — all errors are
caught and logged, never raised.
"""

import sqlite3
import json
import uuid
import logging
from datetime import datetime
from pathlib import Path

# Resolve DB path relative to this module
HERE = Path(__file__).parent.resolve()
PROJECT_ROOT = HERE.parent
DB_PATH = PROJECT_ROOT / "feedback.db"

log = logging.getLogger("0xday.db_writer")


def write_alert(
    module_name,
    severity,
    risk_score,
    flagged_count,
    rf_attack_count,
    iso_score_mean,
    ae_score_mean,
    sample_features=None,
    shap_top10=None,
    source_ip=None,
    dest_ip=None,
):
    """
    Insert a new correlated alert into the alerts table.

    Returns the generated flow_id on success, None on failure.
    Never raises — the detection pipeline must keep running.
    """
    flow_id = str(uuid.uuid4())

    try:
        conn = sqlite3.connect(DB_PATH, timeout=5.0)
        conn.execute("PRAGMA foreign_keys = ON")

        # Build the predictions blob
        predictions = {
            "module": module_name,
            "flagged_count": flagged_count,
            "rf_attack_count": rf_attack_count,
            "iso_score_mean": round(float(iso_score_mean), 4),
            "ae_score_mean": round(float(ae_score_mean), 4),
            "ensemble_risk": round(float(risk_score), 4),
        }

        # Map module name -> rf_prediction label
        # The module name itself is the model's belief about the attack type
        rf_label_map = {
            "DDoS": "DDoS",
            "Brute Force": "BruteForce",
            "DoS": "DoS",
            "Web Attacks": "WebAttack",
            "Botnet": "Botnet",
            "Live DDoS": "DDoS",
            "Live BruteForce": "BruteForce",
            "Live DoS": "DoS",
            "Live WebAttacks": "WebAttack",
            "Live Botnet": "Botnet",
        }
        rf_prediction = rf_label_map.get(module_name, "Unknown")

        # Confidence proxy: ratio of RF attacks to total flagged
        # rf_confidence = fraction of flagged flows also caught by RF (capped 0-1)
        rf_confidence = (
            round(min(rf_attack_count / flagged_count, 1.0), 4) if flagged_count > 0 else 0.0
        )

        conn.execute(
            """
            INSERT INTO alerts (
                flow_id, timestamp, features_json, rf_prediction, rf_confidence,
                if_score, ae_error, ensemble_severity, shap_top10_json,
                status, source_ip, dest_ip
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                flow_id,
                datetime.utcnow().isoformat(),
                json.dumps(sample_features) if sample_features else json.dumps(predictions),
                rf_prediction,
                rf_confidence,
                round(float(iso_score_mean), 4),
                round(float(ae_score_mean), 4),
                severity,
                json.dumps(shap_top10) if shap_top10 else None,
                "pending",
                source_ip,
                dest_ip,
            ),
        )
        conn.commit()
        conn.close()

        log.info(
            f"DB: alert {flow_id[:8]}... saved [{module_name} / {severity} / risk={risk_score:.3f}]"
        )
        return flow_id

    except sqlite3.Error as e:
        log.warning(f"DB write failed for {module_name}: {e}")
        return None
    except Exception as e:
        log.warning(f"Unexpected error writing alert for {module_name}: {e}")
        return None


def count_pending_alerts():
    """Quick health check — returns number of unlabelled alerts."""
    try:
        conn = sqlite3.connect(DB_PATH, timeout=5.0)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM alerts WHERE status='pending'")
        count = cursor.fetchone()[0]
        conn.close()
        return count
    except Exception:
        return -1


# ─────────────────────────────────────────────────────────────
# WAIT — schema mismatch fix
# Schema says ae_error, but here I named it ae_score for clarity.
# Let me check what the schema actually uses…
# ─────────────────────────────────────────────────────────────
