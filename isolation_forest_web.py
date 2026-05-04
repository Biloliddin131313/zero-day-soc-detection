from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report, roc_auc_score

# Isolation Forest — Web Attacks
iso_web = IsolationForest(
    n_estimators=200,
    contamination=0.05,
    random_state=42,
    n_jobs=-1
)

# Train on BENIGN-only traffic
iso_web.fit(X_web_train_normal)

# Predict
iso_web_pred = (iso_web.predict(X_web_test) == -1).astype(int)
iso_web_scores = -iso_web.decision_function(X_web_test)

print("\nIsolation Forest — Web Attacks:")
print(classification_report(y_web_test, iso_web_pred, target_names=['BENIGN','WebAttack']))
print(f"ROC-AUC: {roc_auc_score(y_web_test, iso_web_scores):.4f}")
