import os
from dotenv import load_dotenv
load_dotenv()
from flask import Flask, jsonify, render_template, send_file, request
import requests, json, random, urllib.request
from datetime import datetime
import io
import sqlite3
from pathlib import Path

# Path to the feedback database (project root / feedback.db)
FEEDBACK_DB = Path(__file__).resolve().parent.parent / "feedback.db"

app = Flask(__name__)
PROMETHEUS = "http://localhost:9090"
VT_API_KEY = "2790390e64cfaebb83837acdafca5af572620f0070b2cc424fc95f4c790701f3"

MODULES = [
    {"id":"DDoS","name":"DDoS","type":"Distributed Denial of Service","iso":0.7522,"ae":0.8592,"rf":1.0,"flows":225745,"color":"#ff4060"},
    {"id":"Brute Force","name":"Brute Force","type":"SSH FTP Credential Attacks","iso":0.6688,"ae":0.6867,"rf":0.9998,"flows":55340,"color":"#f5a623"},
    {"id":"DoS","name":"DoS","type":"Hulk GoldenEye Slowloris","iso":0.8290,"ae":0.8318,"rf":1.0,"flows":139170,"color":"#c8a84b"},
    {"id":"Web Attacks","name":"Web Attacks","type":"SQLi XSS HTTP Brute Force","iso":0.7018,"ae":0.7694,"rf":0.9998,"flows":24911,"color":"#00e5a0"},
    {"id":"Botnet","name":"Botnet","type":"C2 Covert Channel","iso":0.5875,"ae":0.5740,"rf":0.9996,"flows":24697,"color":"#00c2ff"},
    {"id":"Live DDoS","name":"Live DDoS","type":"Real Traffic · DDoS Models","iso":0.0,"ae":0.0,"rf":0.0,"flows":0,"color":"#a855f7"},
    {"id":"Live BruteForce","name":"Live BruteForce","type":"Real Traffic · BruteForce Models","iso":0.0,"ae":0.0,"rf":0.0,"flows":0,"color":"#c084fc"},
    {"id":"Live DoS","name":"Live DoS","type":"Real Traffic · DoS Models","iso":0.0,"ae":0.0,"rf":0.0,"flows":0,"color":"#e879f9"},
    {"id":"Live WebAttacks","name":"Live WebAttacks","type":"Real Traffic · WebAttack Models","iso":0.0,"ae":0.0,"rf":0.0,"flows":0,"color":"#f0abfc"},
    {"id":"Live Botnet","name":"Live Botnet","type":"Real Traffic · Botnet Models","iso":0.0,"ae":0.0,"rf":0.0,"flows":0,"color":"#d946ef"},
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
        mods.append({**m,"attack":int(a),"benign":int(b),"total":int(t),"flows":int(t),"risk":round(a/t,4) if t>0 else 0.0})
    return mods,int(ta),int(tb)

def vt_lookup(ip):
    try:
        req=urllib.request.Request(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",headers={"x-apikey":VT_API_KEY})
        with urllib.request.urlopen(req,timeout=6) as r: data=json.loads(r.read())
        a=data.get("data",{}).get("attributes",{})
        s=a.get("last_analysis_stats",{})
        cats = list(a.get("categories", {}).values())[:3]
        last = a.get("last_analysis_date", 0)
        from datetime import datetime as dt
        last_str = dt.fromtimestamp(last).strftime("%Y-%m-%d %H:%M") if last else "Unknown"
        total = s.get("malicious",0)+s.get("suspicious",0)+s.get("harmless",0)+s.get("undetected",0)
        asn = a.get("asn","?")
        return {"ip":ip,"country":a.get("country","?"),"owner":a.get("as_owner","?"),"malicious":s.get("malicious",0),"suspicious":s.get("suspicious",0),"harmless":s.get("harmless",0),"undetected":s.get("undetected",0),"reputation":a.get("reputation",0),"categories":cats,"last_analysis":last_str,"total_engines":total,"asn":asn,"error":None}
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
    prompt = f"""You are a SOC analyst AI. Return ONLY a valid JSON object, no markdown, no backticks, no explanation outside the JSON. Use this exact format: {{"threat":"one sentence on what attack is happening","why":"one sentence on which SHAP features triggered detection and why","actions":["action 1","action 2","action 3"],"confidence":"one sentence on model confidence and whether this is a true positive"}} Alert details: module={module}, severity={sev}, risk={risk}, ae={ae}, iso={iso}, attacks={attacks}, features={', '.join(features)}"""
    try:
        resp = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "Content-Type": "application/json",
                "x-api-key": os.environ.get("ANTHROPIC_API_KEY",""),
                "anthropic-version": "2023-06-01"
            },
            json={"model": "claude-sonnet-4-20250514", "max_tokens": 400, "messages": [{"role": "user", "content": prompt}]},
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


@app.route("/api/report")
def generate_report():
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.lib.styles import ParagraphStyle
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
        from reportlab.lib.units import cm
        from reportlab.lib.enums import TA_CENTER, TA_RIGHT
        import io
        from datetime import datetime

        mods, ta, tb = get_metrics()
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4,
            rightMargin=1.5*cm, leftMargin=1.5*cm,
            topMargin=1.5*cm, bottomMargin=1.5*cm)

        CYAN = colors.HexColor('#00aaff')
        DARK = colors.HexColor('#0d1117')
        LIGHT = colors.HexColor('#f6f8fa')
        GREY = colors.HexColor('#e1e4e8')
        RED = colors.HexColor('#d63b3b')
        AMBER = colors.HexColor('#f5a623')
        GREEN = colors.HexColor('#00c853')
        BLACK = colors.HexColor('#24292e')
        DIM = colors.HexColor('#24292e')
        WHITE = colors.white

        def P(text, size=9, color=BLACK, bold=False, align='LEFT', leading=14):
            font = 'Helvetica-Bold' if bold else 'Helvetica-Oblique' if color==DIM else 'Helvetica'
            a = {'LEFT':0,'CENTER':1,'RIGHT':2}.get(align,0)
            return Paragraph(text, ParagraphStyle('x', fontName=font, fontSize=size,
                textColor=color, alignment=a, leading=leading, spaceAfter=1))

        story = []

        # COVER
        cover_para = Paragraph(
            '<font color="#00aaff" size="22"><b>0xDay</b></font><font color="#ffffff" size="14">&nbsp;&nbsp;SOC Detection Report</font>',
            ParagraphStyle('cover', fontName='Helvetica', fontSize=14, textColor=WHITE, leading=28))
        cover = Table([[cover_para]], colWidths=[17*cm])
        cover.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,-1),DARK),('PADDING',(0,0),(-1,-1),20)]))
        story.append(cover)
        story.append(Spacer(1,0.2*cm))

        meta = Table([[
            P(f'Generated: {datetime.now().strftime("%Y-%m-%d %H:%M")}', size=8, color=DIM),
            P('Classification: CONFIDENTIAL', size=8, color=DIM, align='RIGHT')
        ]], colWidths=[8.5*cm,8.5*cm])
        story.append(meta)
        story.append(Spacer(1,0.3*cm))
        story.append(HRFlowable(width="100%", thickness=3, color=CYAN))
        story.append(Spacer(1,0.4*cm))

        # EXECUTIVE SUMMARY
        story.append(P('<font color="#00aaff"><b>Executive Summary</b></font>', size=13, bold=True))
        story.append(HRFlowable(width="100%", thickness=0.5, color=GREY))
        story.append(Spacer(1,0.2*cm))

        best_ae = max([m.get("ae",0) for m in mods]) if mods else 0
        kpi = Table([[
            P(f'<b><font color="#d63b3b" size="20">{ta:,}</font></b><br/><font size="8" color="#586069">TOTAL ATTACKS</font>', align='CENTER'),
            P(f'<b><font color="#00c853" size="20">{tb:,}</font></b><br/><font size="8" color="#586069">BENIGN FLOWS</font>', align='CENTER'),
            P(f'<b><font color="#00aaff" size="20">{best_ae:.4f}</font></b><br/><font size="8" color="#586069">BEST AE AUC</font>', align='CENTER'),
            P(f'<b><font color="#f5a623" size="20">{len(mods)}</font></b><br/><font size="8" color="#586069">ACTIVE MODULES</font>', align='CENTER'),
        ]], colWidths=[4.25*cm]*4)
        kpi.setStyle(TableStyle([
            ('BACKGROUND',(0,0),(-1,-1),LIGHT),
            ('BOX',(0,0),(0,0),0.5,GREY),('BOX',(1,0),(1,0),0.5,GREY),
            ('BOX',(2,0),(2,0),0.5,GREY),('BOX',(3,0),(3,0),0.5,GREY),
            ('TOPPADDING',(0,0),(-1,-1),14),('BOTTOMPADDING',(0,0),(-1,-1),14),
            ('ALIGN',(0,0),(-1,-1),'CENTER'),('VALIGN',(0,0),(-1,-1),'MIDDLE'),
        ]))
        story.append(kpi)
        story.append(Spacer(1,0.5*cm))

        # MODULE RESULTS
        story.append(P('<font color="#00aaff"><b>Detection Module Results</b></font>', size=13, bold=True))
        story.append(HRFlowable(width="100%", thickness=0.5, color=GREY))
        story.append(Spacer(1,0.2*cm))

        hdr = [P(t, size=8, color=WHITE, bold=True, align=a) for t,a in
               [('MODULE','LEFT'),('TYPE','LEFT'),('AE AUC','CENTER'),
                ('ISO AUC','CENTER'),('FLOWS','CENTER'),('RISK','CENTER')]]
        rows = [hdr]
        for m in mods:
            risk = m.get("risk",0)
            rc = RED if risk>=0.75 else AMBER if risk>=0.5 else GREEN
            rows.append([
                P(f'<b>{m["name"]}</b>', size=8, bold=True),
                P(m.get("type","")[:30], size=7, color=DIM),
                P(f'{m.get("ae",0):.4f}', size=8, color=CYAN, align='CENTER'),
                P(f'{m.get("iso",0):.4f}', size=8, color=colors.HexColor("#28a745"), align='CENTER'),
                P(f'{m.get("flows",0):,}', size=8, align='CENTER'),
                P(f'{risk:.4f}', size=8, color=rc, bold=True, align='CENTER'),
            ])
        t = Table(rows, colWidths=[3.5*cm,4*cm,2*cm,2*cm,2.5*cm,2*cm])
        t.setStyle(TableStyle([
            ('BACKGROUND',(0,0),(-1,0),DARK),
            ('ROWBACKGROUNDS',(0,1),(-1,-1),[WHITE,LIGHT]),
            ('GRID',(0,0),(-1,-1),0.3,GREY),
            ('TOPPADDING',(0,0),(-1,-1),7),('BOTTOMPADDING',(0,0),(-1,-1),7),
            ('LEFTPADDING',(0,0),(-1,-1),8),('VALIGN',(0,0),(-1,-1),'MIDDLE'),
        ]))
        story.append(t)
        story.append(Spacer(1,0.5*cm))

        # MITRE
        story.append(P('<font color="#00aaff"><b>MITRE ATT&amp;CK Mapping</b></font>', size=13, bold=True))
        story.append(HRFlowable(width="100%", thickness=0.5, color=GREY))
        story.append(Spacer(1,0.2*cm))

        mhdr = [P(x, size=8, color=WHITE, bold=True) for x in ['MODULE','TECHNIQUE ID','TECHNIQUE NAME','TACTIC']]
        mrows = [mhdr]
        for name, m in MITRE_MAP.items():
            mrows.append([
                P(f'<b>{name}</b>', size=8, bold=True),
                P(m["id"], size=8, color=CYAN),
                P(m["name"], size=8),
                P(m["tactic"], size=8, color=DIM),
            ])
        mt = Table(mrows, colWidths=[3*cm,3*cm,6.5*cm,4.5*cm])
        mt.setStyle(TableStyle([
            ('BACKGROUND',(0,0),(-1,0),DARK),
            ('ROWBACKGROUNDS',(0,1),(-1,-1),[WHITE,LIGHT]),
            ('GRID',(0,0),(-1,-1),0.3,GREY),
            ('TOPPADDING',(0,0),(-1,-1),7),('BOTTOMPADDING',(0,0),(-1,-1),7),
            ('LEFTPADDING',(0,0),(-1,-1),8),('VALIGN',(0,0),(-1,-1),'MIDDLE'),
        ]))
        story.append(mt)
        story.append(Spacer(1,0.5*cm))

        # FOOTER
        story.append(HRFlowable(width="100%", thickness=0.5, color=GREY))
        story.append(Spacer(1,0.2*cm))
        story.append(P('0xDay SOC Detection Platform', size=8, color=DIM, align='CENTER'))

        doc.build(story)
        buffer.seek(0)
        from flask import send_file
        return send_file(buffer, as_attachment=True,
            download_name=f"0xday_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
            mimetype='application/pdf')
    except Exception as e:
        import traceback
        return jsonify({"error": str(e), "trace": traceback.format_exc()}), 500



# ────────────────────────────────────────────────────────────
# Feedback Loop API — Step 3: Analyst Labelling
# ────────────────────────────────────────────────────────────

VALID_LABELS = {"DDoS", "BruteForce", "DoS", "WebAttack", "Botnet", "Benign", "Unknown"}


def _db_conn():
    """Open a connection to feedback.db with row factory."""
    conn = sqlite3.connect(FEEDBACK_DB, timeout=5.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


@app.route("/api/feedback/pending")
def api_feedback_pending():
    """Return all alerts with status='pending'. Newest first."""
    try:
        conn = _db_conn()
        rows = conn.execute("""
            SELECT flow_id, timestamp, rf_prediction, rf_confidence,
                   if_score, ae_error, ensemble_severity, status,
                   source_ip, dest_ip, shap_top10_json
            FROM alerts
            WHERE status = 'pending'
            ORDER BY datetime(timestamp) DESC
            LIMIT 50
        """).fetchall()
        conn.close()
        alerts = []
        for r in rows:
            shap_top10 = json.loads(r["shap_top10_json"]) if r["shap_top10_json"] else []
            alerts.append({
                "flow_id": r["flow_id"],
                "timestamp": r["timestamp"],
                "rf_prediction": r["rf_prediction"],
                "rf_confidence": r["rf_confidence"],
                "if_score": r["if_score"],
                "ae_error": r["ae_error"],
                "severity": r["ensemble_severity"],
                "source_ip": r["source_ip"],
                "dest_ip": r["dest_ip"],
                "shap_top10": shap_top10,
            })
        return jsonify({"alerts": alerts, "total": len(alerts)})
    except sqlite3.Error as e:
        return jsonify({"error": str(e), "alerts": []}), 500


@app.route("/api/feedback/label", methods=["POST"])
def api_feedback_label():
    """Analyst submits a label for a pending alert."""
    try:
        data = request.get_json(force=True)
        flow_id = data.get("flow_id", "").strip()
        label = data.get("label", "").strip()
        notes = data.get("notes", "")[:500]

        if not flow_id:
            return jsonify({"error": "flow_id required"}), 400
        if label not in VALID_LABELS:
            return jsonify({"error": f"label must be one of {sorted(VALID_LABELS)}"}), 400

        conn = _db_conn()

        existing = conn.execute(
            "SELECT status FROM alerts WHERE flow_id = ?", (flow_id,)
        ).fetchone()
        if not existing:
            conn.close()
            return jsonify({"error": "flow_id not found"}), 404

        conn.execute(
            """INSERT INTO labels
                 (flow_id, analyst_label, analyst_id, training_status, analyst_notes)
                 VALUES (?, ?, ?, 'queued', ?)""",
            (flow_id, label, "default", notes)
        )
        conn.execute(
            "UPDATE alerts SET status = 'labelled' WHERE flow_id = ?", (flow_id,)
        )
        conn.commit()

        queued = conn.execute(
            "SELECT COUNT(*) FROM labels WHERE training_status = 'queued'"
        ).fetchone()[0]
        conn.close()

        return jsonify({
            "status": "labelled",
            "flow_id": flow_id,
            "label": label,
            "queued_for_training": queued
        })
    except sqlite3.Error as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/feedback/stats")
def api_feedback_stats():
    """Counters for the panel header."""
    try:
        conn = _db_conn()
        pending  = conn.execute("SELECT COUNT(*) FROM alerts WHERE status='pending'").fetchone()[0]
        labelled = conn.execute("SELECT COUNT(*) FROM alerts WHERE status='labelled'").fetchone()[0]
        queued   = conn.execute("SELECT COUNT(*) FROM labels WHERE training_status='queued'").fetchone()[0]

        breakdown_rows = conn.execute("""
            SELECT analyst_label, COUNT(*) as c
            FROM labels
            GROUP BY analyst_label
            ORDER BY c DESC
        """).fetchall()
        breakdown = {row["analyst_label"]: row["c"] for row in breakdown_rows}
        conn.close()

        retrain_threshold = 100
        until_retrain = max(retrain_threshold - queued, 0)

        return jsonify({
            "pending_alerts": pending,
            "labelled_alerts": labelled,
            "queued_for_training": queued,
            "retrain_threshold": retrain_threshold,
            "labels_until_retrain": until_retrain,
            "breakdown": breakdown,
        })
    except sqlite3.Error as e:
        return jsonify({"error": str(e)}), 500


if __name__=="__main__": app.run(debug=True,port=5000)
