from flask import Flask, jsonify, render_template, send_file
import requests
from datetime import datetime
import io
import os

app = Flask(__name__)

PROMETHEUS = "http://localhost:9090"

MODULES = [
    {"id": "DDoS",        "name": "DDoS",        "type": "Distributed Denial of Service", "iso": 0.7522, "ae": 0.8592, "rf": 1.0000, "flows": 225745, "color": "#ff3b5c"},
    {"id": "Brute Force", "name": "Brute Force",  "type": "SSH · FTP Credential Attacks",  "iso": 0.6688, "ae": 0.6867, "rf": 0.9998, "flows": 55340,  "color": "#ff9500"},
    {"id": "DoS",         "name": "DoS",           "type": "Hulk · GoldenEye · Slowloris",  "iso": 0.8290, "ae": 0.8318, "rf": 1.0000, "flows": 139170, "color": "#ffd166"},
    {"id": "Web Attacks", "name": "Web Attacks",   "type": "SQLi · XSS · HTTP Brute Force", "iso": 0.7018, "ae": 0.7694, "rf": 0.9998, "flows": 24911,  "color": "#06d6a0"},
    {"id": "Botnet",      "name": "Botnet",        "type": "C2 · Covert Channel",           "iso": 0.5875, "ae": 0.5740, "rf": 0.9996, "flows": 24697,  "color": "#00d4ff"},
]

SHAP_FEATURES = [
    ("Bwd Packet Length Mean", 0.2407),
    ("Bwd Packet Length Max",  0.2405),
    ("Bwd Packet Length Std",  0.2097),
    ("Avg Bwd Segment Size",   0.1967),
    ("Packet Length Std",      0.1612),
    ("Packet Length Variance", 0.1437),
    ("Packet Length Mean",     0.1380),
    ("Flow IAT Max",           0.1131),
    ("Max Packet Length",      0.1041),
    ("Average Packet Size",    0.0969),
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

def query_range(promql, step="30s"):
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

def get_all_metrics():
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
    return modules_data, int(total_attacks), int(total_benign)

@app.route("/")
def index():
    return render_template("dashboard.html")

@app.route("/api/metrics")
def metrics():
    modules_data, total_attacks, total_benign = get_all_metrics()
    return jsonify({
        "modules": modules_data,
        "total_attacks": total_attacks,
        "total_benign": total_benign,
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "prometheus_live": total_attacks > 0 or total_benign > 0,
    })

@app.route("/api/chart")
def chart():
    results = []
    for m in MODULES:
        series = query_range(f'rate(soc_flows_total{{module="{m["id"]}",type="ATTACK"}}[1m])')
        if series:
            points = [[int(v[0]*1000), round(float(v[1]), 4)] for v in series[0]["values"]]
            results.append({"name": m["name"], "color": m["color"], "data": points})
    return jsonify(results)

@app.route("/api/report")
def generate_report():
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.units import mm
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT

    # ── GET LIVE DATA ──
    modules_data, total_attacks, total_benign = get_all_metrics()
    now = datetime.now().strftime("%d %B %Y  %H:%M:%S")
    prometheus_live = total_attacks > 0 or total_benign > 0

    # ── STYLES ──
    BG    = colors.HexColor('#050608')
    WHITE = colors.HexColor('#eef1f5')
    DIM   = colors.HexColor('#a0aab4')
    FAINT = colors.HexColor('#556070')
    CYAN  = colors.HexColor('#00c2ff')
    GREEN = colors.HexColor('#00e5a0')
    RED   = colors.HexColor('#ff4060')
    AMBER = colors.HexColor('#f5a623')
    LINE  = colors.HexColor('#1a2030')
    CARD  = colors.HexColor('#0a0c14')

    def style(name, **kw):
        base = {
            'fontName': 'Courier',
            'fontSize': 10,
            'textColor': WHITE,
            'leading': 16,
            'spaceAfter': 0,
        }
        base.update(kw)
        return ParagraphStyle(name, **base)

    S_TITLE   = style('title',   fontSize=28, fontName='Courier-Bold', textColor=WHITE, leading=32, spaceAfter=4)
    S_ACCENT  = style('accent',  fontSize=28, fontName='Courier-Bold', textColor=CYAN,  leading=32, spaceAfter=16)
    S_H1      = style('h1',      fontSize=11, fontName='Courier-Bold', textColor=FAINT, leading=16, spaceAfter=8, spaceBefore=20)
    S_BODY    = style('body',    fontSize=9,  textColor=DIM,   leading=14, spaceAfter=4)
    S_MONO    = style('mono',    fontSize=9,  textColor=WHITE, leading=14)
    S_SMALL   = style('small',   fontSize=8,  textColor=FAINT, leading=12)
    S_CENTER  = style('center',  fontSize=9,  textColor=DIM,   leading=14, alignment=TA_CENTER)
    S_RIGHT   = style('right',   fontSize=9,  textColor=DIM,   leading=14, alignment=TA_RIGHT)

    def HR():
        return HRFlowable(width="100%", thickness=0.5, color=LINE, spaceAfter=12, spaceBefore=4)

    def fmt(n):
        if n >= 1e6: return f"{n/1e6:.1f}M"
        if n >= 1e3: return f"{n/1e3:.1f}K"
        return str(n)

    def sev(risk):
        if risk >= 0.75: return ("CRITICAL", RED)
        if risk >= 0.50: return ("HIGH",     AMBER)
        if risk >= 0.25: return ("MEDIUM",   colors.HexColor('#c8a84b'))
        return ("LOW", GREEN)

    # ── BUILD PDF IN MEMORY ──
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=20*mm, rightMargin=20*mm,
        topMargin=20*mm,  bottomMargin=20*mm,
    )

    W = A4[0] - 40*mm
    story = []

    # ── PAGE 1: COVER ──
    story.append(Spacer(1, 20*mm))
    story.append(Paragraph("0xDay", S_TITLE))
    story.append(Paragraph("SOC Detection Report", S_ACCENT))
    story.append(Spacer(1, 2*mm))
    story.append(Paragraph(f"Generated: {now}", S_SMALL))
    story.append(Paragraph(
        f"Prometheus: {'LIVE' if prometheus_live else 'STATIC'}  |  "
        f"Modules: 5  |  Dataset: CICIDS2017",
        S_SMALL
    ))
    story.append(Spacer(1, 6*mm))
    story.append(HR())

    # ── SUMMARY KPIs ──
    story.append(Paragraph("EXECUTIVE SUMMARY", S_H1))
    kpi_data = [
        ["METRIC", "VALUE", "NOTES"],
        ["Total Attacks Detected", fmt(total_attacks), "Across all 5 modules"],
        ["Total Benign Flows",     fmt(total_benign),  "Normal traffic baseline"],
        ["Best Unsupervised AUC",  "0.8318",           "Autoencoder · DoS module"],
        ["Alert Reduction",        "61%",              "27,642 flows suppressed · DDoS"],
        ["Models per Module",      "3",                "Random Forest, Isolation Forest, Autoencoder"],
        ["SHAP Explainability",    "YES",              "Top 10 features per module"],
    ]
    kpi_table = Table(kpi_data, colWidths=[W*0.38, W*0.2, W*0.42])
    kpi_table.setStyle(TableStyle([
        ('BACKGROUND',   (0,0), (-1,0),  CARD),
        ('TEXTCOLOR',    (0,0), (-1,0),  FAINT),
        ('FONTNAME',     (0,0), (-1,0),  'Courier-Bold'),
        ('FONTSIZE',     (0,0), (-1,0),  8),
        ('BACKGROUND',   (0,1), (-1,-1), BG),
        ('TEXTCOLOR',    (0,1), (0,-1),  DIM),
        ('TEXTCOLOR',    (1,1), (1,-1),  CYAN),
        ('TEXTCOLOR',    (2,1), (2,-1),  FAINT),
        ('FONTNAME',     (0,1), (-1,-1), 'Courier'),
        ('FONTSIZE',     (0,1), (-1,-1), 9),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [BG, CARD]),
        ('GRID',         (0,0), (-1,-1), 0.5, LINE),
        ('TOPPADDING',   (0,0), (-1,-1), 6),
        ('BOTTOMPADDING',(0,0), (-1,-1), 6),
        ('LEFTPADDING',  (0,0), (-1,-1), 8),
    ]))
    story.append(kpi_table)
    story.append(Spacer(1, 6*mm))
    story.append(HR())

    # ── MODULE RESULTS ──
    story.append(Paragraph("MODULE DETECTION RESULTS", S_H1))
    story.append(Paragraph(
        "Each module trains on BENIGN traffic only. The model learns normal behaviour and flags deviations as potential attacks — enabling detection of zero-day exploits never seen before.",
        S_BODY
    ))
    story.append(Spacer(1, 3*mm))

    mod_data = [["#", "MODULE", "ATTACKS", "BENIGN", "AE AUC", "ISO AUC", "RF AUC", "SEVERITY"]]
    for i, m in enumerate(modules_data):
        s, _ = sev(m['risk'])
        mod_data.append([
            str(i+1).zfill(2),
            m['name'],
            fmt(m['attack']),
            fmt(m['benign']),
            f"{m['ae']:.4f}",
            f"{m['iso']:.4f}",
            f"{m['rf']:.4f}",
            s,
        ])

    # avg row
    avg_ae  = sum(m['ae']  for m in modules_data) / len(modules_data)
    avg_iso = sum(m['iso'] for m in modules_data) / len(modules_data)
    avg_rf  = sum(m['rf']  for m in modules_data) / len(modules_data)
    mod_data.append(["—", "AVERAGE", "—", "—", f"{avg_ae:.4f}", f"{avg_iso:.4f}", f"{avg_rf:.4f}", "—"])

    cw = [W*0.04, W*0.16, W*0.1, W*0.1, W*0.1, W*0.1, W*0.1, W*0.13]
    mod_table = Table(mod_data, colWidths=cw)
    mod_table.setStyle(TableStyle([
        ('BACKGROUND',   (0,0), (-1,0),  CARD),
        ('TEXTCOLOR',    (0,0), (-1,0),  FAINT),
        ('FONTNAME',     (0,0), (-1,0),  'Courier-Bold'),
        ('FONTSIZE',     (0,0), (-1,0),  7),
        ('BACKGROUND',   (0,1), (-1,-2), BG),
        ('BACKGROUND',   (0,-1),(-1,-1), CARD),
        ('ROWBACKGROUNDS', (0,1), (-1,-2), [BG, CARD]),
        ('TEXTCOLOR',    (0,1), (-1,-1), DIM),
        ('TEXTCOLOR',    (1,1), (1,-1),  WHITE),
        ('TEXTCOLOR',    (4,1), (4,-1),  CYAN),
        ('FONTNAME',     (0,1), (-1,-1), 'Courier'),
        ('FONTSIZE',     (0,1), (-1,-1), 8),
        ('GRID',         (0,0), (-1,-1), 0.5, LINE),
        ('TOPPADDING',   (0,0), (-1,-1), 5),
        ('BOTTOMPADDING',(0,0), (-1,-1), 5),
        ('LEFTPADDING',  (0,0), (-1,-1), 6),
        ('FONTNAME',     (0,-1),(-1,-1), 'Courier-Bold'),
    ]))
    story.append(mod_table)
    story.append(Spacer(1, 6*mm))
    story.append(HR())

    # ── ALERT TRIAGE ──
    story.append(Paragraph("ALERT TRIAGE — DDoS MODULE", S_H1))
    story.append(Paragraph(
        "Combined risk score computed from Isolation Forest + Autoencoder outputs. "
        "Flows are ranked CRITICAL / HIGH / MEDIUM / LOW to reduce analyst workload.",
        S_BODY
    ))
    story.append(Spacer(1, 3*mm))

    triage_data = [
        ["SEVERITY", "COUNT", "THRESHOLD", "ACTION"],
        ["CRITICAL", "1",      "score >= 0.75", "Immediate investigation"],
        ["HIGH",     "7",      "score >= 0.50", "Within 1 hour"],
        ["MEDIUM",   "6,330",  "score >= 0.25", "Standard queue"],
        ["LOW",      "38,811", "score < 0.25",  "Monitor only"],
        ["SUPPRESSED","27,642","score < 0.10",  "Confirmed benign — no action"],
    ]
    t_colors = [RED, AMBER, colors.HexColor('#c8a84b'), GREEN, FAINT]
    triage_table = Table(triage_data, colWidths=[W*0.18, W*0.15, W*0.25, W*0.42])
    triage_style = [
        ('BACKGROUND',   (0,0), (-1,0),  CARD),
        ('TEXTCOLOR',    (0,0), (-1,0),  FAINT),
        ('FONTNAME',     (0,0), (-1,0),  'Courier-Bold'),
        ('FONTSIZE',     (0,0), (-1,0),  8),
        ('BACKGROUND',   (0,1), (-1,-1), BG),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [BG, CARD]),
        ('TEXTCOLOR',    (1,1), (3,-1),  DIM),
        ('FONTNAME',     (0,1), (-1,-1), 'Courier'),
        ('FONTSIZE',     (0,1), (-1,-1), 9),
        ('GRID',         (0,0), (-1,-1), 0.5, LINE),
        ('TOPPADDING',   (0,0), (-1,-1), 6),
        ('BOTTOMPADDING',(0,0), (-1,-1), 6),
        ('LEFTPADDING',  (0,0), (-1,-1), 8),
    ]
    for i, col in enumerate(t_colors):
        triage_style.append(('TEXTCOLOR', (0, i+1), (0, i+1), col))
        triage_style.append(('FONTNAME',  (0, i+1), (0, i+1), 'Courier-Bold'))
    triage_table.setStyle(TableStyle(triage_style))
    story.append(triage_table)
    story.append(Spacer(1, 6*mm))
    story.append(HR())

    # ── SHAP ──
    story.append(Paragraph("SHAP FEATURE IMPORTANCE — DDoS MODULE", S_H1))
    story.append(Paragraph(
        "SHAP (SHapley Additive exPlanations) identifies which network features contributed most "
        "to the Isolation Forest anomaly score. Backward packet length features dominate — "
        "consistent with DDoS flood patterns where response traffic is abnormally small.",
        S_BODY
    ))
    story.append(Spacer(1, 3*mm))

    shap_data = [["RANK", "FEATURE", "IMPORTANCE", "RELATIVE"]]
    max_val = SHAP_FEATURES[0][1]
    for i, (feat, val) in enumerate(SHAP_FEATURES):
        bar = "█" * int(val / max_val * 20)
        shap_data.append([str(i+1).zfill(2), feat, f"{val:.4f}", bar])

    shap_table = Table(shap_data, colWidths=[W*0.08, W*0.42, W*0.15, W*0.35])
    shap_table.setStyle(TableStyle([
        ('BACKGROUND',   (0,0), (-1,0),  CARD),
        ('TEXTCOLOR',    (0,0), (-1,0),  FAINT),
        ('FONTNAME',     (0,0), (-1,0),  'Courier-Bold'),
        ('FONTSIZE',     (0,0), (-1,0),  8),
        ('BACKGROUND',   (0,1), (-1,-1), BG),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [BG, CARD]),
        ('TEXTCOLOR',    (0,1), (0,-1),  FAINT),
        ('TEXTCOLOR',    (1,1), (1,-1),  WHITE),
        ('TEXTCOLOR',    (2,1), (2,-1),  CYAN),
        ('TEXTCOLOR',    (3,1), (3,-1),  colors.HexColor('#1a4060')),
        ('FONTNAME',     (0,1), (-1,-1), 'Courier'),
        ('FONTSIZE',     (0,1), (-1,-1), 8),
        ('GRID',         (0,0), (-1,-1), 0.5, LINE),
        ('TOPPADDING',   (0,0), (-1,-1), 5),
        ('BOTTOMPADDING',(0,0), (-1,-1), 5),
        ('LEFTPADDING',  (0,0), (-1,-1), 8),
    ]))
    story.append(shap_table)
    story.append(Spacer(1, 6*mm))
    story.append(HR())

    # ── KEY FINDINGS ──
    story.append(Paragraph("KEY FINDINGS", S_H1))
    findings = [
        ("Unsupervised models detect zero-day attacks",
         "Both Isolation Forest and Autoencoder were trained on BENIGN traffic only. "
         "They never saw a single attack packet during training, yet achieved AUC scores "
         "up to 0.8318 — demonstrating genuine zero-day detection capability."),
        ("Autoencoder outperforms Isolation Forest on 4 of 5 modules",
         "Deep learning reconstruction error proved more sensitive to subtle anomalies "
         "than the tree-based Isolation Forest approach, particularly for Web Attacks (AE: 0.7694 vs ISO: 0.7018)."),
        ("DoS is the easiest attack to detect unsupervised",
         "High-volume traffic anomalies in DoS attacks produce strong deviation from "
         "the BENIGN baseline. AUC of 0.8318 (AE) and 0.8290 (ISO) — best across all modules."),
        ("Botnet is the hardest attack to detect unsupervised",
         "Slow, covert C2 communication closely mimics normal traffic patterns. "
         "AUC of 0.5740 (AE) — barely above random baseline. Highlights fundamental "
         "limitation of unsupervised detection against stealthy threats."),
        ("Alert reduction of 61% achieved on DDoS module",
         "Combined risk scoring suppressed 27,642 low-risk flows, reducing analyst "
         "workload by 61% while surfacing only 8 CRITICAL/HIGH priority alerts."),
    ]
    for i, (title, body) in enumerate(findings):
        story.append(Paragraph(f"{i+1}.  {title}", style(f'ft{i}', fontSize=10, fontName='Courier-Bold', textColor=CYAN, leading=14, spaceBefore=8)))
        story.append(Paragraph(body, S_BODY))
    story.append(Spacer(1, 6*mm))
    story.append(HR())

    # ── FOOTER NOTE ──
    story.append(Paragraph(
        f"0xDay Security Operations Platform  ·  Report generated {now}  ·  "
        f"github.com/Biloliddin131313/zero-day-soc-detection",
        style('footer', fontSize=7, textColor=FAINT, alignment=TA_CENTER)
    ))

    # ── BUILD ──
    def on_page(canvas, doc):
        canvas.saveState()
        canvas.setFillColor(BG)
        canvas.rect(0, 0, A4[0], A4[1], fill=1, stroke=0)
        canvas.setFont('Courier', 7)
        canvas.setFillColor(FAINT)
        canvas.drawString(20*mm, 12*mm, f"0xDay SOC Report · {now}")
        canvas.drawRightString(A4[0]-20*mm, 12*mm, f"Page {doc.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)
    buf.seek(0)

    filename = f"0xDay_SOC_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    return send_file(buf, as_attachment=True, download_name=filename, mimetype='application/pdf')


if __name__ == "__main__":
    app.run(debug=True, port=5000)
