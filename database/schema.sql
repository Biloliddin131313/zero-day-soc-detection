-- 0xDay Feedback Loop Database Schema
-- Version 1.0
-- Three tables: alerts, labels, model_versions

CREATE TABLE IF NOT EXISTS alerts (
    flow_id              TEXT PRIMARY KEY,
    timestamp            TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    features_json        TEXT NOT NULL,
    rf_prediction        TEXT,
    rf_confidence        REAL,
    if_score             REAL,
    ae_error             REAL,
    ensemble_severity    TEXT CHECK(ensemble_severity IN ('CRITICAL','HIGH','MEDIUM','LOW')),
    shap_top10_json      TEXT,
    status               TEXT NOT NULL DEFAULT 'pending'
                         CHECK(status IN ('pending','labelled','dismissed')),
    source_ip            TEXT,
    dest_ip              TEXT
);

CREATE INDEX IF NOT EXISTS idx_alerts_status    ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_severity  ON alerts(ensemble_severity);

CREATE TABLE IF NOT EXISTS labels (
    label_id             INTEGER PRIMARY KEY AUTOINCREMENT,
    flow_id              TEXT NOT NULL,
    analyst_label        TEXT NOT NULL
                         CHECK(analyst_label IN
                            ('DDoS','BruteForce','DoS','WebAttack','Botnet','Benign','Unknown')),
    analyst_id           TEXT NOT NULL DEFAULT 'default',
    timestamp            TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    training_status      TEXT NOT NULL DEFAULT 'queued'
                         CHECK(training_status IN ('queued','used','discarded')),
    training_version     TEXT,
    analyst_notes        TEXT,
    FOREIGN KEY (flow_id) REFERENCES alerts(flow_id)
);

CREATE INDEX IF NOT EXISTS idx_labels_flow_id          ON labels(flow_id);
CREATE INDEX IF NOT EXISTS idx_labels_training_status  ON labels(training_status);
CREATE INDEX IF NOT EXISTS idx_labels_timestamp        ON labels(timestamp);

CREATE TABLE IF NOT EXISTS model_versions (
    version_id            INTEGER PRIMARY KEY AUTOINCREMENT,
    version_name          TEXT NOT NULL UNIQUE,
    model_path            TEXT NOT NULL,
    trained_at            TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    training_data_size    INTEGER NOT NULL,
    analyst_labels_used   INTEGER NOT NULL DEFAULT 0,
    holdout_accuracy      REAL,
    holdout_f1            REAL,
    holdout_auc           REAL,
    is_active             BOOLEAN NOT NULL DEFAULT 0,
    notes                 TEXT
);

CREATE INDEX IF NOT EXISTS idx_versions_active     ON model_versions(is_active);
CREATE INDEX IF NOT EXISTS idx_versions_trained_at ON model_versions(trained_at);
