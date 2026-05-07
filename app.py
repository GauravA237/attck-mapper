import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import json
import os
from detector import load_rules, detect
from reporter import export_csv, export_navigator_layer
import streamlit.components.v1 as components

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="SOC Detection Analyzer",
    page_icon="🛡️",
    layout="wide"
)

# ── Session state for architecture diagram stage selection ────────────────────
if "selected_stage" not in st.session_state:
    st.session_state.selected_stage = None

# ── Custom CSS ────────────────────────────────────────────────────────────────
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Inter:wght@400;600;700&display=swap');
    .stApp { background-color: #0E1117; }
    .main-header {
        font-family: 'Share Tech Mono', monospace;
        font-size: 2.4rem; color: #00FFAA;
        letter-spacing: 2px; margin-bottom: 0;
    }
    .sub-header {
        font-family: 'Inter', sans-serif;
        font-size: 0.95rem; color: #8B9AAD; margin-top: 4px;
    }
    div[data-testid="metric-container"] {
        background: #161B22; border: 1px solid #21262D;
        border-radius: 10px; padding: 16px;
    }
    div[data-testid="metric-container"] label { color: #8B9AAD !important; font-size: 0.8rem; }
    div[data-testid="metric-container"] div[data-testid="stMetricValue"] {
        color: #00FFAA !important; font-family: 'Share Tech Mono', monospace;
    }
    .detection-card {
        background: #161B22; border: 1px solid #21262D;
        border-left: 3px solid #00FFAA; border-radius: 8px;
        padding: 14px 18px; margin-bottom: 10px; font-family: 'Inter', sans-serif;
    }
    .detection-card.critical { border-left-color: #FF4444; }
    .detection-card.high     { border-left-color: #FF8C00; }
    .detection-card.medium   { border-left-color: #FFD700; }
    .detection-card.low      { border-left-color: #00FFAA; }
    .technique-id  { font-family: 'Share Tech Mono', monospace; color: #00FFAA; font-size: 0.85rem; }
    .technique-name { font-size: 1rem; font-weight: 600; color: #E6EDF3; }
    .tactic-badge {
        display: inline-block; background: #21262D; color: #8B9AAD;
        font-size: 0.75rem; padding: 2px 8px; border-radius: 4px;
        font-family: 'Share Tech Mono', monospace;
    }
    .log-line {
        background: #0D1117; border: 1px solid #21262D; border-radius: 4px;
        padding: 8px 12px; font-family: 'Share Tech Mono', monospace;
        font-size: 0.78rem; color: #7EE787; margin-top: 8px; word-break: break-all;
    }
    .top-detection {
        background: #161B22; border: 1px solid #FF4444;
        border-radius: 10px; padding: 20px 24px; margin-bottom: 20px;
    }
    .top-detection-label {
        font-size: 0.75rem; color: #FF4444;
        font-family: 'Share Tech Mono', monospace;
        letter-spacing: 2px; text-transform: uppercase;
    }
    .top-detection-title { font-size: 1.3rem; font-weight: 700; color: #E6EDF3; margin: 4px 0; }
    section[data-testid="stSidebar"] { background: #0D1117; border-right: 1px solid #21262D; }
    .sidebar-rule {
        font-family: 'Share Tech Mono', monospace; font-size: 0.78rem;
        color: #8B9AAD; padding: 4px 0; border-bottom: 1px solid #21262D;
    }
    .sidebar-rule span { color: #00FFAA; }
    hr { border-color: #21262D; }
    .stButton button, .stDownloadButton button {
        background: #161B22 !important; border: 1px solid #00FFAA !important;
        color: #00FFAA !important; font-family: 'Share Tech Mono', monospace !important;
        border-radius: 6px !important;
    }
    .stButton button:hover, .stDownloadButton button:hover { background: #00FFAA22 !important; }
    div[data-testid="stProgressBar"] > div { background-color: #00FFAA !important; }
    h2, h3 { color: #E6EDF3 !important; }
</style>
""", unsafe_allow_html=True)

# ── Code content for each pipeline stage ─────────────────────────────────────
STAGE_CODE = {
    "preprocessor": {
        "label": "preprocessor.py",
        "lang": "python",
        "description": "Normalizes raw log lines before pattern matching. Lowercases everything, collapses whitespace, strips non-ASCII characters, and removes empty lines so every rule runs against clean, consistent input.",
        "code": '''import re

def preprocess(log_line: str) -> str:
    line = log_line.lower().strip()
    line = re.sub(r"\\s+", " ", line)          # collapse multiple spaces
    line = re.sub(r"[^\\x20-\\x7e]", "", line) # remove non-ASCII characters
    return line

def load_log_file(filepath: str) -> list:
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()
    return [line.strip() for line in lines if line.strip()]'''
    },
    "patterns": {
        "label": "rules/patterns.json",
        "lang": "json",
        "description": "The detection rule database. Each rule defines a regex pattern, the ATT&CK technique it maps to, the tactic, a confidence score (0-1), a plain-English description, and remediation advice. Add new rules here without touching any Python.",
        "code": '''{
  "id": "R001",
  "pattern": "powershell.*-enc",
  "technique": "T1059.001",
  "technique_name": "PowerShell",
  "tactic": "Execution",
  "confidence": 0.85,
  "description": "PowerShell encoded command - common obfuscation technique",
  "remediation": "Enable PowerShell script block logging, restrict execution policy, monitor for encoded command usage"
},
{
  "id": "R002",
  "pattern": "mimikatz|sekurlsa|lsass",
  "technique": "T1003.001",
  "technique_name": "LSASS Memory",
  "tactic": "Credential Access",
  "confidence": 0.95,
  "description": "Mimikatz or LSASS access - credential dumping tool",
  "remediation": "Enable Credential Guard, protect LSASS memory, alert on abnormal access"
}'''
    },
    "detector": {
        "label": "detector.py",
        "lang": "python",
        "description": "The core mapping engine. Loads rules from patterns.json, runs each preprocessed log line through every regex pattern, and returns all matching detections with technique ID, tactic, confidence, and remediation.",
        "code": '''import re
import json
from preprocessor import preprocess

def load_rules(path="rules/patterns.json"):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def detect(log_line: str, rules: list) -> list:
    cleaned = preprocess(log_line)
    hits = []
    for rule in rules:
        if re.search(rule["pattern"], cleaned, re.IGNORECASE):
            hits.append({
                "rule_id":        rule["id"],
                "technique":      rule["technique"],
                "technique_name": rule["technique_name"],
                "tactic":         rule["tactic"],
                "confidence":     rule["confidence"],
                "description":    rule["description"],
                "remediation":    rule.get("remediation", ""),
                "matched_line":   log_line.strip()
            })
    return hits'''
    },
    "reporter": {
        "label": "reporter.py",
        "lang": "python",
        "description": "Generates three output formats: a structured JSON report for programmatic use, a CSV for spreadsheet analysis, and a Navigator layer JSON that lights up the MITRE ATT&CK matrix as a heatmap. The layer scores are derived from confidence values (0.95 confidence = score of 95).",
        "code": '''import json, csv

def export_csv(results, path="output/report.csv"):
    detections = results["detections"]
    if not detections:
        return
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=detections[0].keys())
        writer.writeheader()
        writer.writerows(detections)

def export_navigator_layer(results, path="output/layer.json"):
    # deduplicate by technique, keep highest confidence
    seen = {}
    for d in results["detections"]:
        tid = d["technique"]
        seen[tid] = max(seen.get(tid, 0), d["confidence"])
    layer = {
        "name": "SOC Detection Results",
        "domain": "enterprise-attack",
        "techniques": [
            {"techniqueID": tid, "score": int(score * 100)}
            for tid, score in seen.items()
        ],
        "gradient": {
            "colors": ["#ffffff", "#ff6666"],
            "minValue": 0, "maxValue": 100
        }
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(layer, f, indent=2)'''
    },
    "dashboard": {
        "label": "app.py — core pipeline wiring",
        "lang": "python",
        "description": "The Streamlit dashboard loads the rule library, accepts a log file or text input, runs every line through the detection engine, and renders metrics, charts, attack chain timeline, and export buttons. All five pipeline stages run on each file upload.",
        "code": '''# Load rule library once at startup
rules = load_rules()   # reads rules/patterns.json

# On file upload — run the full pipeline
lines = uploaded.read().decode("utf-8", errors="ignore").splitlines()
lines = [l.strip() for l in lines if l.strip()]

all_detections = []
for line in lines:
    # preprocessor.py normalizes the line
    # detector.py runs all regex rules against it
    hits = detect(line, rules)
    all_detections.extend(hits)

# Build structured results
results = {
    "total_lines_analyzed": len(lines),
    "total_detections":     len(all_detections),
    "unique_techniques":    len(set(d["technique"] for d in all_detections)),
    "detections":           all_detections
}

# reporter.py writes all three export formats
export_csv(results)
export_navigator_layer(results)'''
    }
}

# ── Architecture diagram SVG ──────────────────────────────────────────────────
ARCH_SVG = """
<svg width="100%" viewBox="0 0 680 500" role="img"
     xmlns="http://www.w3.org/2000/svg"
     style="font-family:'Share Tech Mono',monospace;display:block;">
  <title>SOC Detection Analyzer — pipeline architecture</title>
  <desc>Six-stage pipeline: raw input, preprocessing engine, pattern detection, ATT&CK mapping engine, reporting outputs, Streamlit dashboard</desc>
  <defs>
    <marker id="arr" viewBox="0 0 10 10" refX="8" refY="5"
            markerWidth="6" markerHeight="6" orient="auto-start-reverse">
      <path d="M2 1L8 5L2 9" fill="none" stroke="#444D56"
            stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
    </marker>
  </defs>

  <!-- Stage 1: Raw input -->
  <rect x="40" y="20" width="600" height="48" rx="8"
        fill="#161B22" stroke="#30363D" stroke-width="0.8"/>
  <text x="340" y="39" text-anchor="middle" fill="#8B9AAD" font-size="10" letter-spacing="1">RAW INPUT</text>
  <text x="340" y="57" text-anchor="middle" fill="#E6EDF3" font-size="11">
    Windows logs · Sysmon · auth.log · firewall alerts · pasted log line
  </text>

  <line x1="340" y1="68" x2="340" y2="88" stroke="#444D56" stroke-width="1" marker-end="url(#arr)"/>
  <text x="346" y="82" fill="#555E6A" font-size="10">preprocessor.py</text>

  <!-- Stage 2: Preprocessing -->
  <rect x="40" y="88" width="600" height="48" rx="8"
        fill="#0F2D25" stroke="#1D9E75" stroke-width="0.8"/>
  <text x="340" y="107" text-anchor="middle" fill="#5DCAA5" font-size="10" letter-spacing="1">PREPROCESSING ENGINE</text>
  <text x="340" y="125" text-anchor="middle" fill="#9FE1CB" font-size="11">
    Lowercase · collapse whitespace · strip non-ASCII · remove empty lines
  </text>

  <line x1="340" y1="136" x2="340" y2="156" stroke="#444D56" stroke-width="1" marker-end="url(#arr)"/>
  <text x="346" y="150" fill="#555E6A" font-size="10">detector.py + patterns.json</text>

  <!-- Stage 3: Pattern detection -->
  <rect x="40" y="156" width="600" height="62" rx="8"
        fill="#1C1A35" stroke="#534AB7" stroke-width="0.8"/>
  <text x="340" y="175" text-anchor="middle" fill="#AFA9EC" font-size="10" letter-spacing="1">PATTERN DETECTION  ·  rules/patterns.json</text>
  <rect x="58"  y="185" width="176" height="24" rx="5" fill="#26215C" stroke="#534AB7" stroke-width="0.5"/>
  <text x="146" y="201" text-anchor="middle" fill="#CECBF6" font-size="10">powershell.*-enc → T1059</text>
  <rect x="252" y="185" width="176" height="24" rx="5" fill="#26215C" stroke="#534AB7" stroke-width="0.5"/>
  <text x="340" y="201" text-anchor="middle" fill="#CECBF6" font-size="10">mimikatz|lsass → T1003</text>
  <rect x="446" y="185" width="176" height="24" rx="5" fill="#26215C" stroke="#534AB7" stroke-width="0.5"/>
  <text x="534" y="201" text-anchor="middle" fill="#CECBF6" font-size="10">schtasks.*create → T1053</text>

  <line x1="340" y1="218" x2="340" y2="238" stroke="#444D56" stroke-width="1" marker-end="url(#arr)"/>
  <text x="346" y="232" fill="#555E6A" font-size="10">enterprise-attack.json  ·  detector.py</text>

  <!-- Stage 4: ATT&CK mapping -->
  <rect x="40" y="238" width="600" height="48" rx="8"
        fill="#2A1F0A" stroke="#BA7517" stroke-width="0.8"/>
  <text x="340" y="257" text-anchor="middle" fill="#EF9F27" font-size="10" letter-spacing="1">ATT&amp;CK MAPPING ENGINE</text>
  <text x="340" y="275" text-anchor="middle" fill="#FAC775" font-size="11">
    Technique ID · Tactic · Confidence score · Severity level · Remediation
  </text>

  <line x1="340" y1="286" x2="340" y2="306" stroke="#444D56" stroke-width="1" marker-end="url(#arr)"/>
  <text x="346" y="300" fill="#555E6A" font-size="10">reporter.py</text>

  <!-- Stage 5: Three outputs -->
  <rect x="40"  y="306" width="178" height="44" rx="8" fill="#2D1208" stroke="#993C1D" stroke-width="0.8"/>
  <text x="129" y="324" text-anchor="middle" fill="#F0997B" font-size="11">JSON report</text>
  <text x="129" y="340" text-anchor="middle" fill="#F5C4B3" font-size="10">full detection details</text>

  <rect x="251" y="306" width="178" height="44" rx="8" fill="#2D1208" stroke="#993C1D" stroke-width="0.8"/>
  <text x="340" y="324" text-anchor="middle" fill="#F0997B" font-size="11">CSV report</text>
  <text x="340" y="340" text-anchor="middle" fill="#F5C4B3" font-size="10">spreadsheet-ready rows</text>

  <rect x="462" y="306" width="178" height="44" rx="8" fill="#2D1208" stroke="#993C1D" stroke-width="0.8"/>
  <text x="551" y="324" text-anchor="middle" fill="#F0997B" font-size="11">Navigator layer</text>
  <text x="551" y="340" text-anchor="middle" fill="#F5C4B3" font-size="10">ATT&amp;CK heatmap JSON</text>

  <!-- merge lines into dashboard -->
  <line x1="129" y1="350" x2="129" y2="372" stroke="#444D56" stroke-width="0.8"/>
  <line x1="340" y1="350" x2="340" y2="372" stroke="#444D56" stroke-width="0.8"/>
  <line x1="551" y1="350" x2="551" y2="372" stroke="#444D56" stroke-width="0.8"/>
  <line x1="129" y1="372" x2="551" y2="372" stroke="#444D56" stroke-width="0.8"/>
  <line x1="340" y1="372" x2="340" y2="390" stroke="#444D56" stroke-width="1" marker-end="url(#arr)"/>

  <!-- Stage 6: Dashboard -->
  <rect x="40" y="390" width="600" height="24" rx="8"
        fill="#051A36" stroke="#185FA5" stroke-width="0.8"/>
  <text x="340" y="406" text-anchor="middle" fill="#85B7EB" font-size="11">
    STREAMLIT DASHBOARD — metrics · tactic charts · attack chain timeline · export buttons
  </text>
</svg>
"""

# ── Header ────────────────────────────────────────────────────────────────────
st.markdown('<p class="main-header">🛡️ SOC DETECTION ANALYZER</p>', unsafe_allow_html=True)
st.markdown('<p class="sub-header">MITRE ATT&CK technique mapper — real log file analysis & threat intelligence</p>', unsafe_allow_html=True)
st.markdown("---")

# ── Sidebar ───────────────────────────────────────────────────────────────────
rules = load_rules()

with st.sidebar:
    st.markdown("### 🔧 Detection Engine")
    st.metric("Rules loaded", len(rules))
    st.markdown("---")
    st.markdown("**Active Rules**")
    for r in rules:
        st.markdown(
            f'<div class="sidebar-rule"><span>{r["id"]}</span> · '
            f'<span style="color:#E6EDF3">{r["technique"]}</span><br>'
            f'{r["technique_name"]}</div>',
            unsafe_allow_html=True
        )
    st.markdown("---")
    st.markdown(
        '<p style="font-size:0.75rem;color:#8B9AAD;font-family:\'Share Tech Mono\',monospace;">'
        'SOC Detection Analyzer<br>MITRE ATT&CK Enterprise v14</p>',
        unsafe_allow_html=True
    )

# ── Architecture section ──────────────────────────────────────────────────────
st.markdown("### ⚙️ System Architecture")
st.caption("How the pipeline works — click a stage button to see the code behind it")

components.html(f"""
<!DOCTYPE html>
<html>
<head>
<style>
  body {{ margin: 0; padding: 0; background: transparent; }}
  svg {{ width: 100%; height: auto; display: block; }}
</style>
</head>
<body>
{ARCH_SVG}
</body>
</html>
""", height=700, scrolling=False)

st.markdown("**Explore the code behind each stage:**")

btn_cols = st.columns(5)
stage_map = [
    ("preprocessor", "🟢 Preprocessor"),
    ("patterns",     "🟣 Pattern library"),
    ("detector",     "🟡 Mapping engine"),
    ("reporter",     "🔴 Reporter"),
    ("dashboard",    "🔵 Dashboard"),
]

for col, (key, label) in zip(btn_cols, stage_map):
    with col:
        is_active = st.session_state.selected_stage == key
        if st.button(label, key=f"btn_{key}", use_container_width=True):
            st.session_state.selected_stage = None if is_active else key
            st.rerun()

if st.session_state.selected_stage:
    stage = STAGE_CODE[st.session_state.selected_stage]
    with st.expander(f"📄 {stage['label']}", expanded=True):
        st.markdown(
            f'<p style="color:#8B9AAD;font-size:0.88rem;margin-bottom:8px;">'
            f'{stage["description"]}</p>',
            unsafe_allow_html=True
        )
        st.code(stage["code"], language=stage["lang"])

st.markdown("---")

# ── Input tabs ────────────────────────────────────────────────────────────────
tab1, tab2 = st.tabs(["📁 Upload Log File", "🔍 Analyze Text Input"])

all_detections = []
lines = []
uploaded = None
analyze_btn = False
text_input = ""

with tab1:
    uploaded = st.file_uploader(
        "Upload a log file (.txt or .log)",
        type=["txt", "log"],
        help="Upload a raw log file to run the full detection pipeline"
    )
    if uploaded:
        lines = uploaded.read().decode("utf-8", errors="ignore").splitlines()
        lines = [l.strip() for l in lines if l.strip()]
        for line in lines:
            all_detections.extend(detect(line, rules))

with tab2:
    text_input = st.text_area(
        "Paste a log line or threat description",
        placeholder="e.g. powershell.exe -EncodedCommand SQBuAHYAbwBrAGUA...",
        height=120,
        label_visibility="collapsed"
    )
    analyze_btn = st.button("⚡ Analyze", use_container_width=True)
    if analyze_btn and text_input.strip():
        lines = [l.strip() for l in text_input.splitlines() if l.strip()]
        for line in lines:
            all_detections.extend(detect(line, rules))

# ── Results ───────────────────────────────────────────────────────────────────
if not all_detections and (uploaded or (analyze_btn and text_input.strip())):
    st.warning("⚠️ No detections found in this input.")

elif all_detections:
    st.markdown("---")

    # Top detection banner
    top = max(all_detections, key=lambda x: x["confidence"])
    severity_top = "CRITICAL" if top["confidence"] >= 0.90 else "HIGH" if top["confidence"] >= 0.75 else "MEDIUM"

    st.markdown(f"""
    <div class="top-detection">
        <div class="top-detection-label">🚨 Top Detection — {severity_top}</div>
        <div class="top-detection-title">{top['technique']} — {top['technique_name']}</div>
        <div>
            <span class="tactic-badge">{top['tactic']}</span>
            &nbsp;
            <span style="color:#8B9AAD;font-size:0.85rem;">Confidence:
                <span style="color:#FF4444;font-weight:700;">{int(top['confidence']*100)}%</span>
            </span>
        </div>
        <div class="log-line">{top['matched_line'][:120]}</div>
    </div>
    """, unsafe_allow_html=True)

    # Summary metrics
    unique_techniques = len(set(d["technique"] for d in all_detections))
    unique_tactics    = len(set(d["tactic"]    for d in all_detections))

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Lines Analyzed",    len(lines) if lines else "—")
    c2.metric("Total Detections",  len(all_detections))
    c3.metric("Unique Techniques", unique_techniques)
    c4.metric("Unique Tactics",    unique_tactics)

    st.markdown("---")

    # Detection cards
    st.markdown("### 📋 Detected Techniques")
    df = pd.DataFrame(all_detections)

    col_filter, col_sort = st.columns([3, 1])
    with col_filter:
        tactics_list = ["All"] + sorted(df["tactic"].unique().tolist())
        selected_tactic = st.selectbox("Filter by tactic", tactics_list, label_visibility="collapsed")
    with col_sort:
        sort_by = st.selectbox("Sort by", ["Confidence ↓", "Tactic"], label_visibility="collapsed")

    filtered = df if selected_tactic == "All" else df[df["tactic"] == selected_tactic]
    filtered = filtered.sort_values("confidence", ascending=False) if sort_by == "Confidence ↓" else filtered.sort_values("tactic")

    for _, row in filtered.iterrows():
        conf_pct = int(row["confidence"] * 100)
        if conf_pct >= 90:   severity, color, card_class = "CRITICAL", "#FF4444", "critical"
        elif conf_pct >= 75: severity, color, card_class = "HIGH",     "#FF8C00", "high"
        elif conf_pct >= 60: severity, color, card_class = "MEDIUM",   "#FFD700", "medium"
        else:                severity, color, card_class = "LOW",      "#00FFAA", "low"

        with st.container():
            st.markdown(f"""
            <div class="detection-card {card_class}">
                <span class="technique-id">{row['technique']}</span>
                &nbsp;·&nbsp;
                <span class="technique-name">{row['technique_name']}</span>
                &nbsp;&nbsp;
                <span class="tactic-badge">{row['tactic']}</span>
                &nbsp;&nbsp;
                <span style="color:{color};font-size:0.8rem;font-family:'Share Tech Mono',monospace;">
                    ● {severity} · {conf_pct}%
                </span>
            </div>
            """, unsafe_allow_html=True)
            st.progress(row["confidence"])
            with st.expander("Details & Remediation"):
                st.markdown(f"**Rule ID:** `{row['rule_id']}`")
                st.markdown(f"**Description:** {row['description']}")
                if row.get("remediation"):
                    st.markdown(f"**🔧 Remediation:** {row['remediation']}")
                st.markdown("**Matched log line:**")
                st.code(row["matched_line"], language="bash")

    st.markdown("---")

    # Charts
    st.markdown("### 📊 Visual Analysis")
    chart1, chart2 = st.columns(2)

    with chart1:
        tactic_counts = df.groupby("tactic").size().reset_index(name="count")
        fig, ax = plt.subplots(figsize=(6, 3.5))
        fig.patch.set_facecolor('#161B22')
        ax.set_facecolor('#161B22')
        bars = ax.bar(tactic_counts["tactic"], tactic_counts["count"], color="#00FFAA", width=0.6)
        for bar in bars:
            h = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2, h + 0.05, str(int(h)),
                    ha='center', va='bottom', color='#E6EDF3', fontsize=9)
        ax.set_title("Detections by Tactic", color='#E6EDF3', fontsize=11, pad=12)
        ax.tick_params(axis='x', colors='#8B9AAD', labelsize=8)
        ax.tick_params(axis='y', colors='#8B9AAD', labelsize=8)
        for spine in ax.spines.values(): spine.set_visible(False)
        ax.yaxis.grid(True, color='#21262D', linewidth=0.5)
        ax.set_axisbelow(True)
        plt.xticks(rotation=25, ha='right')
        plt.tight_layout()
        st.pyplot(fig)

    with chart2:
        technique_counts = df.groupby(["technique", "technique_name"]).size().reset_index(name="count")
        technique_counts["label"] = technique_counts["technique"] + " " + technique_counts["technique_name"]
        fig2, ax2 = plt.subplots(figsize=(6, 3.5))
        fig2.patch.set_facecolor('#161B22')
        ax2.set_facecolor('#161B22')
        colors_bar = ["#FF4444" if c >= 2 else "#00FFAA" for c in technique_counts["count"]]
        ax2.barh(technique_counts["label"], technique_counts["count"], color=colors_bar, height=0.6)
        ax2.set_title("Detections by Technique", color='#E6EDF3', fontsize=11, pad=12)
        ax2.tick_params(axis='x', colors='#8B9AAD', labelsize=8)
        ax2.tick_params(axis='y', colors='#8B9AAD', labelsize=8)
        for spine in ax2.spines.values(): spine.set_visible(False)
        ax2.xaxis.grid(True, color='#21262D', linewidth=0.5)
        ax2.set_axisbelow(True)
        plt.tight_layout()
        st.pyplot(fig2)

    # Severity breakdown
    st.markdown("---")
    st.markdown("### 🎯 Severity Breakdown")
    critical = len([d for d in all_detections if d["confidence"] >= 0.90])
    high     = len([d for d in all_detections if 0.75 <= d["confidence"] < 0.90])
    medium   = len([d for d in all_detections if 0.60 <= d["confidence"] < 0.75])
    low      = len([d for d in all_detections if d["confidence"] < 0.60])
    s1, s2, s3, s4 = st.columns(4)
    s1.metric("🔴 Critical  ≥90%", critical)
    s2.metric("🟠 High  ≥75%",     high)
    s3.metric("🟡 Medium  ≥60%",   medium)
    s4.metric("🟢 Low  <60%",      low)

    # Attack chain timeline
    st.markdown("---")
    st.markdown("### ⏱️ Attack Chain Timeline")
    st.caption("Detections in log order — reconstruct the attacker's sequence of actions")

    for i, d in enumerate(all_detections, 1):
        conf_pct = int(d["confidence"] * 100)
        if conf_pct >= 90:   tl_color = "#FF4444"
        elif conf_pct >= 75: tl_color = "#FF8C00"
        elif conf_pct >= 60: tl_color = "#FFD700"
        else:                tl_color = "#00FFAA"

        with st.expander(f"Step {i} · [{d['technique']}] {d['technique_name']} — {d['tactic']}"):
            col_a, col_b = st.columns([1, 3])
            with col_a:
                st.markdown(f"**Rule:** `{d['rule_id']}`")
                st.markdown("**Confidence:**")
                st.markdown(f"<span style='color:{tl_color};font-size:1.2rem;font-weight:700;'>{conf_pct}%</span>", unsafe_allow_html=True)
            with col_b:
                st.markdown(f"**Description:** {d['description']}")
                if d.get("remediation"):
                    st.markdown(f"**🔧 Remediation:** {d['remediation']}")
            st.code(d["matched_line"], language="bash")

    # Exports
    st.markdown("---")
    st.markdown("### 📥 Export Results")

    os.makedirs("output", exist_ok=True)
    results = {
        "total_lines_analyzed": len(lines),
        "total_detections":     len(all_detections),
        "unique_techniques":    unique_techniques,
        "unique_tactics":       unique_tactics,
        "tactics_hit":          list(set(d["tactic"]    for d in all_detections)),
        "techniques_hit":       list(set(d["technique"] for d in all_detections)),
        "detections":           all_detections
    }
    with open("output/report.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    export_csv(results)
    export_navigator_layer(results)

    e1, e2, e3 = st.columns(3)
    with e1:
        with open("output/report.json", "rb") as f:
            st.download_button("⬇️ JSON Report",     data=f, file_name="soc_report.json",      mime="application/json", use_container_width=True)
    with e2:
        with open("output/report.csv", "rb") as f:
            st.download_button("⬇️ CSV Report",      data=f, file_name="soc_report.csv",       mime="text/csv",         use_container_width=True)
    with e3:
        with open("output/layer.json", "rb") as f:
            st.download_button("⬇️ Navigator Layer", data=f, file_name="navigator_layer.json", mime="application/json", use_container_width=True)

    st.markdown("---")
    st.caption("Upload navigator_layer.json to https://mitre-attack.github.io/attack-navigator to view your detection heatmap.")

else:
    st.info("Upload a log file or paste a log line above to begin analysis.")

# ── Footer ────────────────────────────────────────────────────────────────────
st.markdown("---")
st.markdown(
    '<p style="text-align:center;font-family:\'Share Tech Mono\',monospace;'
    'font-size:0.75rem;color:#8B9AAD;">'
    'SOC Detection Analyzer · MITRE ATT&CK Enterprise v14 · Built with Python & Streamlit</p>',
    unsafe_allow_html=True
)