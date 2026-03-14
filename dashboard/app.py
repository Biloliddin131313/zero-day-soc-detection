import os
from flask import Flask, jsonify, render_template, send_file, request
import requests, json, random, urllib.request
from datetime import datetime
import io

app = Flask(__name__)
PROMETHEUS = "http://localhost:9090"
VT_API_KEY = "2790390e64cfaebb83837acdafca5af572620f0070b2cc424fc95f4c790701f3"

MODULES = [
    {"id":"DDoS","name":"DDoS","type":"Distributed Denial of Service","iso":0.7522,"ae":0.8592,"rf":1.0,"flows":225745,"color":"#ff4060"},
    {"id":"Brute Force","name":"Brute Force","type":"SSH FTP Credential Attacks","iso":0.6688,"ae":0.6867,"rf":0.9998,"flows":55340,"color":"#f5a623"},
    {"id":"DoS","name":"DoS","type":"Hulk GoldenEye Slowloris","iso":0.8290,"ae":0.8318,"rf":1.0,"flows":139170,"color":"#c8a84b"},
    {"id":"Web Attacks","name":"Web Attacks","type":"SQLi XSS HTTP Brute Force","iso":0.7018,"ae":0.7694,"rf":0.9998,"flows":24911,"color":"#00e5a0"},
    {"id":"Botnet","name":"Botnet","type":"C2 Covert Channel","iso":0.5875,"ae":0.5740,"rf":0.9996,"flows":24697,"color":"#00c2ff"},
]

MITRE_MAP = {
    "DDoS":{"id":"T1498","name":"Network Denial of Service","tactic":"Impact","sub":"T1498.001 Direct Network Flood","url":"https://attack.mitre.org/techniques/T1498"},
    "Brute Force":{"id":"T1110","name":"Brute Force","tactic":"Credential Access","sub":"T1110.001 Password Guessing","url":"https://attack.mitre.org/techniques/T1110"},
    "DoS":{"id":"T1499","name":"Endpoint Denial of Service","tactic":"Impact","sub":"T1499.002 Service Exhaustion","url":"https://attack.mitre.org/techniques/T1499"},
    "Web Attacks":{"id":"T1190","name":"Exploit Public-Facing Application","tactic":"Initial Access","sub":"SQLi XSS injection","url":"https://attack.mitre.org/techniques/T1190"},
    "Botnet":{"id":"T1071","name":"Application Layer Protocol","tactic":"Command and Control","sub":"T1071.001 Web Protocols","url":"https://attack.mitre.org/techniques/T1071"},
}

SAMPLE_IPS = ["185.220.101.45","194.165.16.72","45.153.160.2","91.108.4.0","198.96.155.3","162.247.72.201"]

def qprom(q):
    try:
        r=requests.get(f"{PROMETHEUS}/api/v1/query",params={"query":q},timeout=3).json()
        if r["status"]=="success" and r["data"]["result"]:
            return float(r["data"]["result"][0]["value"][1])
    except: pass
    return None

def qrange(q,step="30s"):
    try:
        import time
        e=int(time.time())
        r=requests.get(f"{PROMETHEUS}/api/v1/query_range",params={"query":q,"start":e-300,"end":e,"step":step},timeout=3).json()
        if r["status"]=="success" and r["data"]["result"]: return r["data"]["result"]
    except: pass
    return []

def get_metrics():
    mods,ta,tb=[],0,0
    for m in MODULES:
        a=qprom(f'soc_flows_total{{module="{m["id"]}",type="ATTACK"}}') or 0
        b=qprom(f'soc_flows_total{{module="{m["id"]}",type="BENIGN"}}') or 0
        ta+=a;tb+=b;t=a+b
        mods.append({**m,"attack":int(a),"benign":int(b),"total":int(t),"risk":round(a/t,4) if t>0 else 0.0})
    return mods,int(ta),int(tb)

def vt_lookup(ip):
    try:
        req=urllib.request.Request(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",headers={"x-apikey":VT_API_KEY})
        with urllib.request.urlopen(req,timeout=6) as r: data=json.loads(r.read())
        a=data.get("data",{}).get("attributes",{})
        s=a.get("last_analysis_stats",{})
        return {"ip":ip,"country":a.get("country","?"),"owner":a.get("as_owner","?"),"malicious":s.get("malicious",0),"suspicious":s.get("suspicious",0),"harmless":s.get("harmless",0),"reputation":a.get("reputation",0),"error":None}
    except Exception as e:
        return {"ip":ip,"error":str(e),"malicious":0,"suspicious":0,"harmless":0,"reputation":0,"country":"?","owner":"?"}

@app.route("/")
def index(): return render_template("dashboard.html")

@app.route("/api/metrics")
def metrics():
    mods,ta,tb=get_metrics()
    return jsonify({"modules":mods,"total_attacks":ta,"total_benign":tb,"timestamp":datetime.now().strftime("%H:%M:%S"),"prometheus_live":ta>0 or tb>0})

@app.route("/api/chart")
def chart():
    res=[]
    for m in MODULES:
        s=qrange(f'rate(soc_flows_total{{module="{m["id"]}",type="ATTACK"}}[1m])')
        if s: res.append({"name":m["name"],"color":m["color"],"data":[[int(v[0]*1000),round(float(v[1]),4)] for v in s[0]["values"]]})
    return jsonify(res)

@app.route("/api/mitre")
def mitre(): return jsonify(MITRE_MAP)

@app.route("/api/enrich")
def enrich():
    ip=random.choice(SAMPLE_IPS)
    return jsonify({"ip_enrichment":vt_lookup(ip),"mitre":MITRE_MAP,"timestamp":datetime.now().strftime("%H:%M:%S")})

@app.route("/api/vt/<ip>")
def virustotal(ip): return jsonify(vt_lookup(ip))


@app.route("/api/explain", methods=["POST"])
def explain_alert():
    data = request.get_json()
    module = data.get("module", "Unknown")
    risk = data.get("risk", 0)
    ae = data.get("ae_score", 0)
    iso = data.get("iso_score", 0)
    attacks = data.get("attack_count", 0)
    features = data.get("top_features", [])
    sev = "CRITICAL" if risk >= 0.75 else "HIGH" if risk >= 0.5 else "MEDIUM"
    prompt = f"You are a SOC analyst AI assistant. Explain this network security alert in plain English in 3-4 sentences. Be specific and actionable. Alert module: {module}. Severity: {sev}. Risk score: {risk}. Autoencoder anomaly score: {ae}. Isolation Forest score: {iso}. Attacks detected: {attacks}. Top SHAP features: {', '.join(features)}. Explain what this means, why the model flagged it, and what the analyst should do next."
    try:
        resp = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "Content-Type": "application/json",
                "x-api-key": "os.environ.get("ANTHROPIC_API_KEY","")",
                "anthropic-version": "2023-06-01"
            },
            json={"model": "claude-sonnet-4-20250514", "max_tokens": 300, "messages": [{"role": "user", "content": prompt}]},
            timeout=15
        )
        result = resp.json()
        print("VT response:", result)
        if "content" in result:
            return jsonify({"explanation": result["content"][0]["text"]})
        elif "error" in result:
            return jsonify({"explanation": f"API error: {result['error'].get('message','unknown')}"})
        else:
            return jsonify({"explanation": f"Unexpected response: {str(result)[:200]}"})
    except Exception as e:
        return jsonify({"explanation": f"Request failed: {str(e)}"})

if __name__=="__main__": app.run(debug=True,port=5000)