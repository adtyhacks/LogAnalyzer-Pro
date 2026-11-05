# LogAnalyzer Pro 🛡️

**Intelligent Multi-Endpoint Security Log Analysis & Incident Investigation Platform**

[![Python Version](https://img.shields.io/badge/python-3.11%2B%20%7C%203.12-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-76%2F76%20passed-brightgreen.svg)](tests/)
[![Platforms](https://img.shields.io/badge/endpoints-Windows%2011%20%7C%20Kali%20Linux-teal.svg)](docs/LINUX_TELEMETRY.md)
[![Framework: Streamlit](https://img.shields.io/badge/UI-Streamlit-red.svg)](https://streamlit.io/)
[![Database: SQLite WAL](https://img.shields.io/badge/database-SQLite%20WAL-lightgrey.svg)](https://sqlite.org/)

---

## 1. Professional Introduction

**LogAnalyzer Pro** is an enterprise-grade, autonomous cybersecurity log analysis and incident investigation platform. Designed for Security Operations Center (SOC) teams, incident responders, and threat hunters, the application ingests heterogeneous security telemetry across **Windows endpoints** (native Security Event XML, Sysmon, Application) and **Linux systems** (Kali Linux `auth.log`, systemd `journalctl` text & NDJSON), normalizes disparate formats into a common schema, detects complex multi-stage attack patterns using modular behavioral rules, and synthesizes related detections into correlated, cross-platform security incidents.

Built strictly with free and open-source technologies, LogAnalyzer Pro delivers enterprise SIEM and SOAR investigation capabilities with zero reliance on paid APIs or external database services.

---

## 2. Multi-Endpoint Architecture

```mermaid
flowchart TD
    subgraph Collectors ["1. Multi-Endpoint Telemetry Collection Layer"]
        W1["Windows Host: collect_windows_events.ps1"] --> W_OUT["data/collected/Security_events.xml"]
        W2["Windows Sysmon: collect_sysmon.ps1"] --> W_SYS["data/collected/sysmon_events.xml"]
        L1["Kali Linux VM: collect_linux_events.sh"] --> L_OUT["data/collected/kali_auth.log / .json"]
    end

    subgraph Ingestion ["2. Ingestion & Normalization Layer"]
        W_OUT & W_SYS --> P_WIN["WindowsEventParser / SysmonParser"]
        L_OUT --> P_LIN["LinuxAuthParser (auth.log & journal NDJSON)"]
        GEN["Generic JSON / CSV"] --> P_GEN["GenericJsonParser / GenericCsvParser"]
        P_WIN & P_LIN & P_GEN --> NORM["Schema Normalizer (NormalizedEvent)"]
    end

    subgraph Storage ["3. Persistence Layer (SQLite + WAL)"]
        NORM --> HASH["SHA-256 Event Deduplication"]
        HASH --> DB[(loganalyzer.db)]
        DB --> T_EVENTS["events table"]
        DB --> T_CHKS["channel_checkpoints table"]
        DB --> T_DETS["detections table"]
        DB --> T_INCS["incidents table"]
        DB --> T_NOTES["investigation_notes table"]
    end

    subgraph Detection ["4. Modular Detection Engine"]
        T_EVENTS --> ENG["DetectionEngine"]
        ENG --> BF["Brute-Force (T1110.001)"]
        ENG --> PS["Password Spraying (T1110.003)"]
        ENG --> SS["Suspicious Success (T1078)"]
        ENG --> MA["Multi-Account Fail (T1110.003)"]
        ENG --> SL["Privileged Login (T1078.003)"]
        ENG --> IU["Invalid User Enumeration (T1087.001)"]
        ENG --> UP["Burst Velocity Pattern (T1499)"]
        ENG --> RS["Repeated Suspicious IP"]
    end

    subgraph Correlation ["5. Cross-Platform Correlation & Risk Engine"]
        ENG --> CORR["CorrelationEngine"]
        CORR --> INTEL["Offline IP Intelligence"]
        CORR --> MITRE["MITRE ATT&CK Mapper"]
        CORR --> RSCORE["RiskScorer (0-100 Score + Cross-Platform Multiplier)"]
        RSCORE --> INC_RECS["Incident Records (Single-Host & Cross-Platform)"]
        INC_RECS --> T_INCS
    end

    subgraph Presentation ["6. Presentation & Reporting"]
        DB --> UI["Multi-Endpoint Streamlit SOC Dashboard"]
        DB --> REP["PDF & CSV Report Generator"]
    end
```
        BF & PS & SS & MA & SL & UP & RS --> ALERTS["Detection Records"]
    end

    subgraph CORRELATION ["4. Correlation & Risk Scoring"]
        ALERTS --> CORR["CorrelationEngine"]
        CORR --> MITRE["MITRE ATT&CK Knowledge Base"]
        CORR --> INTEL["Offline IP Intelligence"]
        CORR --> SCORER["Explainable Risk Scorer (0-100)"]
        SCORER --> INCS["Incident Records"]
        INCS --> T_INCS
    end

    subgraph UI ["5. Presentation & Reporting"]
        DB --> APP["Streamlit SOC Dashboard"]
        APP --> PLOTLY["Plotly Interactive Visualizations"]
        APP --> PDF["PDF Report Generator (ReportLab)"]
        APP --> CSV["CSV Telemetry Exporter"]
    end
```

---

## 5. End-to-End Data Flow

```mermaid
sequenceDiagram
    autonumber
    actor Analyst as SOC Analyst
    participant UI as Streamlit UI
    participant Parser as Log Parser Factory
    participant DB as SQLite WAL DB
    participant Engine as Detection Engine
    participant Corr as Correlation Engine
    participant Scorer as Risk Scorer

    Analyst->>UI: Upload Security Log (CSV / JSON / Syslog)
    UI->>Parser: Parse & Normalize Log Stream
    Parser-->>UI: Normalized Events List
    UI->>DB: Bulk Insert with SHA-256 Deduplication
    DB-->>UI: Inserted Event Count & IDs
    UI->>Engine: Run Detection Rules
    Engine->>Engine: Evaluate Windows & Thresholds
    Engine-->>UI: Generated Detection Records
    UI->>Corr: Correlate Findings into Incidents
    Corr->>Scorer: Calculate Explainable Risk Score (0-100)
    Scorer-->>Corr: Score & Contributing Factors
    Corr->>DB: Insert or Update Incidents
    UI->>Analyst: Interactive Dashboard Telemetry, Alerts & PDF Report
```

---

## 6. Technology Stack

- **Language:** Python 3.11+ / 3.12
- **Dashboard Interface:** Streamlit 1.30+
- **Database:** SQLite 3 (Write-Ahead Logging mode, indexed queries, parameterized statements)
- **Data Analytics:** Pandas, NumPy
- **Interactive Visualizations:** Plotly
- **Rule Configuration:** PyYAML
- **Report Generation:** ReportLab 4.0+
- **Automated Testing:** Pytest 8.0+

---

## 7. Detection Methodology

LogAnalyzer Pro features 7 detection rules configured via `loganalyzer/detection/rules_config.yaml`:

| Detection Rule | Threshold & Timing | MITRE Technique | Description |
| :--- | :--- | :--- | :--- |
| **`RULE_BRUTE_FORCE`** | $\ge 5$ failures in 10 mins | `T1110.001` | High-frequency attempts targeting a specific account or single IP. |
| **`RULE_PASSWORD_SPRAY`** | $\ge 3$ distinct accounts in 15 mins (low per-account failure cap) | `T1110.003` | Single source IP probing multiple accounts while evading single-account lockout. |
| **`RULE_SUSPICIOUS_SUCCESS`** | $\ge 3$ failures followed by success in 15 mins | `T1078` | Successful authentication immediately preceded by repeated failures (credential compromise). |
| **`RULE_MULTI_ACCOUNT_FAIL`** | $\ge 6$ failures across $\ge 4$ accounts in 20 mins | `T1110.003` | Broad account probing from a single perimeter IP. |
| **`RULE_SUSPICIOUS_LOGIN`** | Successful privileged authentication | `T1078.003` | Direct authentication to administrative identities (`root`, `Administrator`, `admin`, `system`). |
| **`RULE_UNUSUAL_PATTERNS`** | $\ge 12$ events in 60 secs | `T1499` | Transaction velocity anomaly indicative of automated credential stuffing or DoS. |
| **`RULE_REPEATED_SUSPICIOUS_IP`** | $\ge 2$ waves separated by $>15$ mins | `T1110.001` | Multi-stage recurring failure activity from the same IP. |

---

## 8. Risk-Scoring Methodology

Risk scores are normalized strictly between **0 and 100** and accompanied by an explicit breakdown of contributing risk factors:

$$\text{Risk Score} = \min\left(100, \text{Base Severity} + \text{Account Scope} + \text{Failure Volume} + \text{Compromise Indicator} + \text{Perimeter Exposure} + \text{Chained Techniques}\right)$$

### Scoring Weights:
- **Base Severity:** `CRITICAL` (+40), `HIGH` (+30), `MEDIUM` (+15), `LOW` (+5)
- **Account Blast Radius:** $>3$ distinct accounts (+20), $>1$ account (+10)
- **Failure Volume:** $\ge 10$ failures (+15), $\ge 5$ failures (+9)
- **Credential Compromise:** Success following repeated failures (+25)
- **Perimeter Origin:** Public IP origin (+10)
- **Attack Chaining:** Multi-technique correlation (+15)

---

## 9. MITRE ATT&CK Integration

Detections and correlated incidents are mapped to the MITRE ATT&CK Enterprise matrix:
- **T1110.001:** Brute Force: Password Guessing
- **T1110.003:** Brute Force: Password Spraying
- **T1078:** Valid Accounts
- **T1078.001:** Valid Accounts: Default Accounts
- **T1078.003:** Valid Accounts: Local Accounts
- **T1068:** Exploitation for Privilege Escalation
- **T1499:** Endpoint Denial of Service

---

## 10. Platform Screenshots

Actual genuine screenshots captured from the running LogAnalyzer Pro application:

| View | Screenshot |
| :--- | :--- |
| **SOC Overview Dashboard** | ![SOC Overview](assets/screenshots/01_soc_overview.png) |
| **Log Ingestion & Telemetry** | ![Log Ingestion](assets/screenshots/02_log_ingestion.png) |
| **Incident Investigation & Case Notes** | ![Incident Investigation](assets/screenshots/03_incident_investigation.png) |
| **Offline IP Intelligence & Profiling** | ![IP Intelligence](assets/screenshots/04_ip_intelligence.png) |
| **MITRE ATT&CK Technique Matrix** | ![MITRE ATT&CK View](assets/screenshots/05_mitre_attack_view.png) |
| **Reports & Telemetry Data Exports** | ![Reports & Exports](assets/screenshots/06_reports_and_exports.png) |
| **Generated PDF Security Report** | ![PDF Investigation Report](assets/screenshots/07_pdf_investigation_report.png) |

---

## 11. Installation & Setup (Windows 11)

### Prerequisites
- Python 3.11 or 3.12 installed (`python --version`).
- Git (optional, for cloning).

### Step-by-Step Installation

1. **Clone or Navigate to the Repository:**
   ```powershell
   git clone https://github.com/adtyhacks/LogAnalyzer-Pro.git
   cd LogAnalyzer-Pro
   ```

2. **Create a Virtual Environment (Recommended):**
   ```powershell
   python -m venv venv
   .\venv\Scripts\Activate.ps1
   ```

3. **Install Dependencies:**
   ```powershell
   pip install -r requirements.txt
   ```

---

## 12. Endpoint Telemetry Collection & Ingestion

### A. Windows Security Event Collection (Host)
Run an elevated PowerShell window (`Run as administrator`):
```powershell
# Collect last 50 Security events into XML
powershell -ExecutionPolicy Bypass -File scripts\collect_windows_events.ps1 -LogName Security -MaxEvents 50

# Ingest into LogAnalyzer Pro
python scripts\ingest_collected.py --file data\collected\Security_events.xml
```

### B. Kali Linux Telemetry Collection (VM / Remote Endpoint)
On your Kali Linux VM:
```bash
# Make collector executable
chmod +x scripts/collect_linux_events.sh

# Collect authentication events from auth.log or systemd journal
sudo ./scripts/collect_linux_events.sh -s "24 hours ago" -m 200 -o /tmp/kali_auth.log

# Transfer log to Windows host
scp /tmp/kali_auth.log user@<WINDOWS_IP>:"C:/path/to/LogAnalyzer-Pro/data/collected/"
```
On Windows:
```powershell
# Ingest Linux telemetry into LogAnalyzer Pro
python scripts\ingest_collected.py --file data\collected\kali_auth.log
```

### C. Controlled Linux Telemetry Lab (One-Command Placement Demo)
If a physical Kali VM is not running, run the controlled Linux simulation lab:
```powershell
python scripts\generate_linux_demo.py --ingest
```
This generates authentic Linux Syslog (`linux_demo_auth.log`) and systemd journal NDJSON (`linux_demo_journal.json`), ingests them with `is_synthetic = True`, and demonstrates cross-platform correlation across `kali-demo` and `ADTY` (`198.51.100.99`) with zero duplicate events on re-runs.

---

## 13. Execution Instructions

Launch the Streamlit SOC interface:
```powershell
streamlit run app.py
```
The interface will automatically open in your default browser at `http://localhost:8501`.

---

## 14. Demonstration Scenarios

LogAnalyzer Pro provides ready-to-run synthetic attack datasets in `data/demo_scenarios/`:
- **Scenario A (Brute Force):** Single IP targeting `root` with 7 consecutive failures.
- **Scenario B (Password Spraying):** Single IP targeting 6 distinct identities with 1 attempt each.
- **Scenario C (Credential Compromise):** 4 failures followed immediately by a successful login.
- **Scenario D (Normal Traffic):** Legitimate corporate SSH authentications generating zero false-positive alerts.

To generate or reset all demo datasets programmatically:
```powershell
python -m loganalyzer.synthetic_generator --reset-db
```
For a comprehensive step-by-step SOC walk-through, see the [SOC Demonstration Guide](docs/SOC_DEMO_GUIDE.md).

---

## 14. Automated Testing

LogAnalyzer Pro features an enterprise-grade 76-test Pytest suite covering all Windows Event Log XML & Sysmon parsers, Linux syslog & systemd journal NDJSON parsers, incremental collection checkpoints, boundary conditions, cross-platform correlation clustering, risk scoring, SQLite deduplication, privacy sanitization, and full Streamlit UI AppTest rendering.

Run the test suite:
```powershell
python -m pytest -v
```

Execution Summary:
```
============================= test session starts =============================
platform win32 -- Python 3.12.4, pytest-9.2.0, pluggy-1.7.0
rootdir: LogAnalyzer-Pro
configfile: pytest.ini
testpaths: tests
collected 76 items

tests/test_checkpoints_db.py .................................. [PASSED]
tests/test_correlation.py ..................................... [PASSED]
tests/test_dashboard_audit.py ................................. [PASSED]
tests/test_database.py ........................................ [PASSED]
tests/test_detection_rules.py ................................. [PASSED]
tests/test_linux_telemetry.py ................................. [PASSED]
tests/test_mitre_mapping.py ................................... [PASSED]
tests/test_parsers.py ......................................... [PASSED]
tests/test_real_world_validation.py ........................... [PASSED]
tests/test_reporting.py ....................................... [PASSED]
tests/test_risk_scoring.py .................................... [PASSED]
tests/test_sysmon.py .......................................... [PASSED]
tests/test_timestamp_handling.py .............................. [PASSED]
tests/test_windows_collection.py .............................. [PASSED]

======================= 76 passed, 1 warning in 48.39s ========================
```

---

## 15. Project Structure

```
LOGANALYZER PRO/
├── app.py                          # Streamlit SOC Application Entry Point
├── requirements.txt                # Production dependencies
├── LICENSE                         # MIT License
├── CONTRIBUTING.md                 # Contribution guidelines
├── pytest.ini                      # Pytest configuration
├── README.md                       # Comprehensive platform documentation
│
├── assets/                         # Visual assets & screenshots
│   └── screenshots/                # Application UI screenshots
│
├── docs/                           # Technical documentation
│   ├── ARCHITECTURE.md             # System architecture and data flow
│   ├── DETECTION_RULES.md          # Detection engine rule specifications
│   ├── TESTING.md                  # Test execution and validation guide
│   ├── FINAL_AUDIT.md              # Quality and security audit report
│   └── SOC_DEMO_GUIDE.md           # Step-by-step analyst demo walk-through
│
├── data/                           # Labeled synthetic test security logs
│   ├── linux_auth.log              # Linux SSH brute-force & spray logs
│   ├── windows_events.csv          # Windows Event Log CSV (4624/4625/4672/4740)
│   ├── windows_events.json         # Windows Event Log JSON (Remote compromise)
│   ├── generic_security.json       # Generic JSON API credential stuffing
│   ├── generic_security.csv        # Generic CSV VPN MFA failure log
│   └── demo_scenarios/             # Dedicated Scenarios A, B, C, D
│
├── loganalyzer/                    # Core application package
│   ├── __init__.py
│   ├── config.py                   # Paths, defaults, and risk weights
│   ├── schema.py                   # Normalized event schema & data models
│   ├── database.py                 # SQLite WAL manager and CRUD methods
│   ├── synthetic_generator.py      # Synthetic test log generator
│   │
│   ├── parsers/                    # Ingestion parsers
│   │   ├── __init__.py
│   │   ├── base.py                 # Base parser & timestamp normalizer
│   │   ├── linux_auth.py           # Linux auth.log / secure parser
│   │   ├── windows_events.py       # Windows Security CSV/JSON parser
│   │   ├── generic_json.py         # Generic NDJSON / JSON parser
│   │   ├── generic_csv.py          # Generic CSV log parser
│   │   └── factory.py              # File signature parser factory
│   │
│   ├── detection/                  # Detection Engine
│   │   ├── __init__.py
│   │   ├── base.py                 # Base rule class
│   │   ├── engine.py               # Rule evaluation orchestrator
│   │   ├── rules_config.yaml       # Configurable thresholds & windows
│   │   └── rules/                  # Modular behavioral rules
│   │       ├── brute_force.py
│   │       ├── password_spraying.py
│   │       ├── suspicious_success.py
│   │       ├── multi_account_fail.py
│   │       ├── suspicious_login.py
│   │       ├── unusual_patterns.py
│   │       └── repeated_suspicious_ip.py
│   │
│   ├── correlation/                # Event Correlation
│   │   ├── __init__.py
│   │   └── correlator.py           # Incident grouping & deduplication
│   │
│   ├── intel/                      # Intelligence & Mapping
│   │   ├── __init__.py
│   │   ├── ip_intelligence.py      # Offline RFC IP profiling & indicators
│   │   ├── mitre_mapper.py         # MITRE ATT&CK technique mapper
│   │   ├── risk_scorer.py          # Explainable 0-100 risk scorer
│   │   └── mitre_data.json         # Embedded MITRE technique database
│   │
│   └── reporting/                  # Reporting & Exports
│       ├── __init__.py
│       ├── pdf_report.py           # ReportLab PDF security report builder
│       └── csv_export.py           # CSV telemetry exporters
│
├── ui/                             # Streamlit SOC User Interface
│   ├── __init__.py
│   ├── components.py               # SOC CSS dark theme & metric widgets
│   └── views/                      # Navigation pages
│       ├── overview.py             # SOC Overview & Plotly analytics
│       ├── ingestion.py            # Upload, validation & synthetic data
│       ├── incidents.py            # Incident management & case notes
│       ├── ip_intel.py             # Deep IP investigation tool
│       ├── mitre_view.py           # MITRE ATT&CK matrix explorer
│       └── reports_view.py         # PDF & CSV report generation
│
└── tests/                          # Automated Pytest suite
    ├── conftest.py                 # Fixtures & temporary databases
    ├── test_parsers.py             # Parser tests
    ├── test_detection_rules.py     # All detection & boundary rule tests
    ├── test_correlation.py         # Correlation & incident tests
    ├── test_risk_scoring.py        # Risk scoring tests
    ├── test_mitre_mapping.py       # MITRE mapping tests
    ├── test_database.py            # SQLite persistence tests
    └── test_reporting.py           # PDF and CSV report tests
```

---

## 16. Limitations

- **Offline Operating Mode:** External threat intelligence (e.g. VirusTotal, AbuseIPDB, MaxMind GeoIP) is not queried by default to guarantee 100% offline functionality and zero paid API requirements.
- **Log Source Scope:** Optimized for authentication and identity security logs; deep packet inspection (PCAP) and kernel syscall tracing (eBPF) are out of scope.
- **Single-Node Architecture:** Designed for local SOC analyst workstations; distributed streaming (e.g. Apache Kafka/Elasticsearch cluster) is not included.

---

## 17. Future Enhancements

- Integrate offline MaxMind GeoLite2 MMDB for local country and city resolution without network calls.
- Implement Sigma rule translation to convert community detection signatures directly into LogAnalyzer Pro rules.
- Add Sysmon Windows Event ID coverage (Process creation `1`, Network connection `3`, DNS `22`).
- Provide automated webhook notifications (Discord, Slack, or Microsoft Teams) on `CRITICAL` incidents.

---

## 18. Security Disclaimer

This platform and its synthetic test logs are created strictly for defensive security engineering, SOC operations, and incident response research purposes. All sample logs and indicators in the `data/` directory are synthetic and do not represent real individuals, organizations, or live security incidents.

---

## 19. Author and Contribution Information

- **Author:** LogAnalyzer Pro Team
- **License:** [MIT License](LICENSE)
- **Contributions:** Contributions are welcomed! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for pull request workflows and testing instructions.
