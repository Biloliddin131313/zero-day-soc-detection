from flask import Flask, jsonify, render_template
import requests
from datetime import datetime

app = Flask(__name__)

PROMETHEUS = "http://localhost:9090"

MODULES = [
    {"id": "DDoS",        "name": "DDoS",        "type": "Distributed Denial of Service", "iso": 0.7522, "ae": 0.8592, "rf": 1.0000, "flows": 225745, "color": "#ff3b5c"},
    {"id": "Brute Force", "name": "Brute Force",  "type": "SSH · FTP Credential Attacks",  "iso": 0.6688, "ae": 0.6867, "rf": 0.9998, "flows": 55340,  "color": "#ff9500"},
    {"id": "DoS",         "name": "DoS",           "type": "Hulk · GoldenEye · Slowloris",  "iso": 0.8290, "ae": 0.8318, "rf": 1.0000, "flows": 139170, "color": "#ffd166"},
    {"id": "Web Attacks", "name": "Web Attacks",   "type": "SQLi · XSS · HTTP Brute Force", "iso": 0.7018, "ae": 0.7694, "rf": 0.9998, "flows": 24911,  "color": "#06d6a0"},
    {"id": "Botnet",      "name": "Botnet",        "type": "C2 · Covert Channel",           "iso": 0.5875, "ae": 0.5740, "rf": 0.9996, "flows": 24697,  "color": "#00d4ff"},
]

def query_prometheus(promql):
    try:
        r = requests.get(f"{PROMETHEUS}/api/v1/query", params={"query": promql}, timeout=3)
        data = r.json()
        if data["status"] == "success" and data["data"]["result"]:
            return float(data["data"]["result"][0]["value"][1])
        return None
    except:
        return None

def query_range(promql, duration="5m", step="30s"):
    try:
        import time
        end = int(time.time())
        start = end - 300
        r = requests.get(f"{PROMETHEUS}/api/v1/query_range", params={
            "query": promql, "start": start, "end": end, "step": step
        }, timeout=3)
        data = r.json()
        if data["status"] == "success" and data["data"]["result"]:
            return data["data"]["result"]
        return []
    except:
        return []

@app.route("/")
def index():
    return render_template("dashboard.html")

@app.route("/api/metrics")
def metrics():
    modules_data = []
    total_attacks = 0
    total_benign = 0
    for m in MODULES:
        mid = m["id"]
        attack = query_prometheus(f'soc_flows_total{{module="{mid}",type="ATTACK"}}') or 0
        benign = query_prometheus(f'soc_flows_total{{module="{mid}",type="BENIGN"}}') or 0
        total_attacks += attack
        total_benign += benign
        total = attack + benign
        risk = round(attack / total, 4) if total > 0 else 0.0
        modules_data.append({**m, "attack": int(attack), "benign": int(benign), "total": int(total), "risk": risk})
    return jsonify({"modules": modules_data, "total_attacks": int(total_attacks), "total_benign": int(total_benign), "timestamp": datetime.now().strftime("%H:%M:%S"), "prometheus_live": total_attacks > 0 or total_benign > 0})

@app.route("/api/chart")
def chart():
    results = []
    for m in MODULES:
        series = query_range(f'rate(soc_flows_total{{module="{m["id"]}",type="ATTACK"}}[1m])')
        if series:
            points = [[int(v[0]*1000), round(float(v[1]), 4)] for v in series[0]["values"]]
            results.append({"name": m["name"], "color": m["color"], "data": points})
    return jsonify(results)

if __name__ == "__main__":
    app.run(debug=True, port=5000)
