"""
0xDay Feedback Loop — Retrain Scheduler
Watches feedback.db every 60s. When queued labels >= threshold, fires retrain.
Run this once in the background alongside the SOC Exporter and Flask.
"""

import time
import sqlite3
import logging
import subprocess
import sys
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("0xday.scheduler")

ROOT = Path(__file__).resolve().parent.parent
DB_PATH = ROOT / "feedback.db"
RETRAIN_SCRIPT = Path(__file__).resolve().parent / "retrain.py"
THRESHOLD = 100
CHECK_INTERVAL = 60  # seconds


def get_queued_count():
    try:
        conn = sqlite3.connect(DB_PATH, timeout=5)
        count = conn.execute(
            "SELECT COUNT(*) FROM labels WHERE training_status='queued'"
        ).fetchone()[0]
        conn.close()
        return count
    except Exception as e:
        log.error(f"DB error: {e}")
        return 0


def fire_retrain():
    log.info("=" * 50)
    log.info("THRESHOLD REACHED — firing retrain job...")
    log.info("=" * 50)
    result = subprocess.run(
        [sys.executable, str(RETRAIN_SCRIPT)],
        capture_output=False
    )
    if result.returncode == 0:
        log.info("Retrain completed successfully.")
    else:
        log.error(f"Retrain failed with code {result.returncode}")


def main():
    log.info("0xDay Retrain Scheduler started")
    log.info(f"Threshold: {THRESHOLD} labels | Check interval: {CHECK_INTERVAL}s")
    log.info(f"Watching: {DB_PATH}")

    while True:
        count = get_queued_count()
        log.info(f"Queued labels: {count}/{THRESHOLD}")

        if count >= THRESHOLD:
            fire_retrain()
        
        time.sleep(CHECK_INTERVAL)


if __name__ == "__main__":
    main()
