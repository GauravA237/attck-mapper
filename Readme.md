# 🛡️ SOC Detection Analyzer

A Python-based Security Operations Center (SOC) detection automation tool that analyzes raw log files and maps suspicious behavior to the [MITRE ATT&CK](https://attack.mitre.org) framework. Built as a portfolio project to demonstrate real-world SOC analyst workflows — from raw log ingestion through threat intelligence mapping to visual reporting.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)
![Streamlit](https://img.shields.io/badge/Streamlit-Dashboard-FF4B4B?style=flat-square&logo=streamlit)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK%20v14-red?style=flat-square)
![Rules](https://img.shields.io/badge/Detection%20Rules-50-00FFAA?style=flat-square)

---

## What it does

This tool simulates a core SOC detection workflow:

1. Ingests raw log files or pasted log lines
2. Normalizes and preprocesses input for consistent matching
3. Runs 50 regex-based detection rules across the full MITRE ATT&CK kill chain
4. Maps every detection to a technique ID, tactic, and confidence score
5. Classifies severity — Critical, High, Medium, Low
6. Generates a structured JSON report, CSV export, and ATT&CK Navigator heatmap layer
7. Visualizes everything in an interactive Streamlit dashboard

---

## System Architecture

```
Raw Input
(log file / pasted line)
        ↓
Preprocessing Engine        ← preprocessor.py
(lowercase, normalize, strip noise)
        ↓
Pattern Detection           ← detector.py + rules/patterns.json
(50 regex rules across 14 tactics)
        ↓
ATT&CK Mapping Engine       ← detector.py + enterprise-attack.json
(technique ID, tactic, confidence, remediation)
        ↓
Reporting Engine            ← reporter.py
(JSON report, CSV, Navigator layer)
        ↓
Streamlit Dashboard         ← app.py
(metrics, charts, attack chain timeline, exports)
```

---

## Features

### Detection Engine
- 50 hand-researched detection rules covering all 14 MITRE ATT&CK tactics
- Every rule maps to a specific technique ID and sub-technique
- Confidence scoring (0.0 – 1.0) based on indicator strength
- Severity classification: Critical ≥90% · High ≥75% · Medium ≥60% · Low <60%
- Remediation guidance for every detected technique

### ATT&CK Coverage
| Tactic | Techniques covered |
|---|---|
| Reconnaissance | T1595, T1589 |
| Resource Development | T1583, T1588 |
| Initial Access | T1566, T1078, T1190 |
| Execution | T1059, T1053, T1047 |
| Persistence | T1547, T1136, T1543, T1053 |
| Privilege Escalation | T1055, T1068, T1574 |
| Defense Evasion | T1070, T1562, T1036, T1574 |
| Credential Access | T1003, T1110, T1555 |
| Discovery | T1082, T1083, T1057 |
| Lateral Movement | T1021, T1550, T1080 |
| Collection | T1005, T1056, T1113 |
| Command and Control | T1071, T1095, T1105 |
| Exfiltration | T1041, T1048, T1567 |
| Impact | T1486, T1490, T1498 |

### Dashboard
- File upload and text input modes
- Top detection banner showing highest-confidence hit
- Interactive detection cards with tactic filter and confidence sort
- Progress bar confidence visualization per detection
- Tactic bar chart and technique horizontal chart
- Severity breakdown metrics
- Attack chain timeline — detections in log order to reconstruct attacker sequence
- One-click export: JSON report, CSV, ATT&CK Navigator layer
- Interactive system architecture diagram with clickable code blocks for each pipeline stage

### Exports
- `soc_report.json` — full structured detection output
- `soc_report.csv` — spreadsheet-ready for further analysis
- `navigator_layer.json` — upload to [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator) to view heatmap

---

## Project Structure

```
soc-detection-analyzer/
│
├── app.py                    # Streamlit dashboard — main entry point
├── detector.py               # Core mapping engine
├── preprocessor.py           # Log normalization
├── reporter.py               # JSON, CSV, Navigator layer exports
├── run_analysis.py           # CLI runner (no dashboard)
├── explore_attack.py         # ATT&CK dataset explorer
├── pattern_tester.py         # Rule testing utility
│
├── rules/
│   └── patterns.json         # 50 detection rules (JSON)
│
├── output/                   # Generated reports (git-ignored)
│   ├── report.json
│   ├── report.csv
│   └── layer.json
│
├── sample.log                # Test log file with full attack chain
├── requirements.txt
└── README.md
```

---

## Setup

### Prerequisites
- Python 3.8 or higher
- pip

### Installation

```bash
# Clone the repository
git clone https://github.com/YOURUSERNAME/soc-detection-analyzer.git
cd soc-detection-analyzer

# Create virtual environment
python -m venv .venv

# Activate virtual environment
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Download ATT&CK dataset

The MITRE ATT&CK STIX dataset is required but not included in this repo due to file size. Download it automatically by running:

```bash
python explore_attack.py
```

This will download `enterprise-attack.json` (~11MB) to your project root on first run.

### Run the dashboard

```bash
streamlit run app.py
```

Opens at `http://localhost:8501` in your browser.

### Run CLI analysis (no dashboard)

```bash
python run_analysis.py
```

Analyzes `sample.log` and saves reports to `output/`.

---

## How to use

**Upload mode:**
1. Run `streamlit run app.py`
2. Click **Upload Log File** tab
3. Upload any `.txt` or `.log` file
4. View detections, charts, and attack chain timeline
5. Download JSON, CSV, or Navigator layer

**Text input mode:**
1. Click **Analyze Text Input** tab
2. Paste any log line or command
3. Click **Analyze**

**ATT&CK Navigator heatmap:**
1. Run analysis on any log file
2. Click **Download Navigator Layer**
3. Go to [mitre-attack.github.io/attack-navigator](https://mitre-attack.github.io/attack-navigator)
4. Click **Open Existing Layer → Upload from local**
5. Upload `navigator_layer.json`

---

## Rule structure

Every rule in `rules/patterns.json` follows this schema:

```json
{
  "id": "R001",
  "pattern": "powershell.*-enc",
  "technique": "T1059.001",
  "technique_name": "PowerShell",
  "tactic": "Execution",
  "confidence": 0.85,
  "description": "PowerShell encoded command - common obfuscation technique",
  "remediation": "Enable PowerShell script block logging, restrict execution policy, monitor for encoded command usage"
}
```

| Field | Description |
|---|---|
| `id` | Unique rule identifier |
| `pattern` | Python regex matched against normalized log line |
| `technique` | MITRE ATT&CK technique ID |
| `technique_name` | Human-readable technique name |
| `tactic` | ATT&CK tactic this technique belongs to |
| `confidence` | Detection confidence 0.0–1.0 |
| `description` | Plain-English explanation of what this detects |
| `remediation` | Defensive action a SOC analyst should take |

### Confidence scoring guide

| Score | Meaning | Example |
|---|---|---|
| 0.90–0.95 | Near-certain malicious — tool name or signature | `mimikatz`, `sekurlsa` |
| 0.80–0.89 | Strong indicator, rare in legitimate traffic | `certutil -urlcache` |
| 0.70–0.79 | Moderate indicator, could be legitimate | `schtasks /create` |
| 0.55–0.69 | Weak indicator, common admin activity | `whoami`, `ipconfig` |

---

## Sample attack chain

The included `sample.log` represents a complete attack chain:

```
08:23  PowerShell encoded command      T1059.001  Execution
08:24  New local user created          T1136.001  Persistence
08:24  User added to admin group       T1136.001  Persistence
08:25  Registry Run key modified       T1547.001  Persistence
08:26  Certutil downloads payload      T1105      Command & Control
08:28  sekurlsa::logonpasswords        T1003.001  Credential Access
08:29  mimikatz privilege::debug       T1003.001  Credential Access
08:30  Scheduled task created          T1053.005  Persistence
```

This demonstrates how the tool reconstructs attacker TTPs (Tactics, Techniques, and Procedures) from raw log lines.

---

## Adding new rules

1. Open `rules/patterns.json`
2. Add a new rule object following the schema above
3. Assign the next sequential ID (R051, R052, etc.)
4. Look up the technique on [attack.mitre.org](https://attack.mitre.org) to verify the ID and tactic
5. Save the file — the dashboard picks up new rules automatically on reload

No Python changes required to add new detection rules.

---

## Tech stack

| Component | Technology |
|---|---|
| Language | Python 3.8+ |
| Dashboard | Streamlit |
| Charts | Matplotlib |
| Data processing | Pandas |
| ATT&CK dataset | mitreattack-python, STIX2 |
| Pattern matching | Python re (regex) |
| Exports | JSON, CSV, Navigator JSON |
| Threat framework | MITRE ATT&CK Enterprise v14 |

---

## Future extensions

### Level 2 — Machine learning layer
Replace or augment regex rules with a trained classifier:
- Train an XGBoost or Random Forest model on labeled log data
- Output confidence scores from model probability instead of hardcoded values
- Add SHAP values for explainability — show which tokens drove the detection
- Dependencies: `scikit-learn`, `xgboost`, `shap`

### Level 3 — Real SIEM integration
Connect to live log sources instead of static file uploads:
- **Elastic/OpenSearch** — query via API, stream detections in real time
- **Splunk** — use Splunk SDK to pull events by index and time range
- **Windows Event Log** — parse Event IDs (4688 process creation, 4624 logon, 4698 scheduled task)
- **Sysmon** — parse XML event format for richer process and network telemetry

### Level 4 — Sigma rule compatibility
Replace custom JSON rules with the industry-standard Sigma format:
- Parse `.yml` Sigma rules directly
- Convert Sigma conditions to Python regex automatically
- Access the [SigmaHQ](https://github.com/SigmaHQ/sigma) rule library (4000+ community rules)
- Export detections in Sigma format for use in other SIEM platforms

### Level 5 — Threat intelligence enrichment
Enrich detections with live threat intelligence:
- **VirusTotal API** — check IPs, domains, file hashes from log lines
- **AbuseIPDB** — reputation scoring for IP addresses
- **AlienVault OTX** — pull IOC feeds and correlate with detections
- **MISP integration** — bi-directional threat sharing platform support

### Level 6 — LLM-based reasoning
Add a language model layer for context-aware analysis:
- Use Claude or GPT-4 API to explain detections in plain English
- Generate natural language attack narratives from detection sequences
- Suggest additional hunting queries based on what was detected
- Context-aware false positive reduction — understand when `whoami` is admin activity vs post-exploitation

### Level 7 — Full SOC automation pipeline
Build toward production-grade automation:
- Automated alert triage with priority queue
- Ticket creation in Jira or ServiceNow on high-confidence detections
- Email/Slack notifications for Critical detections
- Detection-as-Code pipeline — rules stored in Git, tested in CI/CD before deployment
- Multi-tenant support for analyzing logs from multiple environments

---

## Learning resources

Resources used to build and understand this project:

| Resource | Link |
|---|---|
| MITRE ATT&CK framework | [attack.mitre.org](https://attack.mitre.org) |
| ATT&CK Navigator | [mitre-attack.github.io/attack-navigator](https://mitre-attack.github.io/attack-navigator) |
| Sigma rules | [github.com/SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) |
| MITRE CAR analytics | [car.mitre.org](https://car.mitre.org) |
| Atomic Red Team | [github.com/redcanaryco/atomic-red-team](https://github.com/redcanaryco/atomic-red-team) |
| LOLBins reference | [lolbas-project.github.io](https://lolbas-project.github.io) |
| Pyramid of Pain | [Search: David Bianco Pyramid of Pain] |
| Windows Event IDs | [ultimatewindowssecurity.com](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/) |

---

## Author

Built by Gaurav — cybersecurity portfolio project.

Feel free to fork, extend, and add your own detection rules.