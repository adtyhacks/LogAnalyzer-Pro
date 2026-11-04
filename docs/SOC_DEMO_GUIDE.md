# LogAnalyzer Pro — SOC Analyst Demonstration Guide

> **Notice:** All log files, usernames, hostnames, and IP addresses used in these demonstration scenarios are **synthetic** and designed exclusively for testing, detection validation, and cybersecurity educational workflows.

This guide outlines step-by-step procedures to demonstrate and verify the complete LogAnalyzer Pro detection and investigation lifecycle.

---

## Prerequisites

1. Launch the LogAnalyzer Pro application:
   ```powershell
   streamlit run app.py
   ```
2. Open your browser at `http://localhost:8501`.
3. (Optional) To start from a clean baseline, open **"Log Ingestion"** in the sidebar and click **"Reset / Clear Database"**, or run:
   ```powershell
   python -m loganalyzer.synthetic_generator --reset-db
   ```

---

## Demonstration Scenarios

### SCENARIO A — Targeted SSH Brute Force
- **Test File:** `data/demo_scenarios/scenario_a_brute_force.log`
- **Adversary Profile:** Source IP `198.51.100.110` targeting single high-privilege account `root`.
- **What to Upload:**
  1. Navigate to **"📥 Log Ingestion"**.
  2. Under **"Choose a log file to ingest"**, upload `scenario_a_brute_force.log`.
  3. Click **"Ingest Uploaded File"**.
- **What to Observe:**
  - Ingestion summary will report 7 parsed events and 0 invalid records.
  - Navigate to **"🚨 Incident Management"**:
    - Triggered Rule: `RULE_BRUTE_FORCE`
    - MITRE ATT&CK Mapping: `T1110.001 - Brute Force: Password Guessing`
    - Target: Account `root` from source `198.51.100.110`
    - Assigned Severity: `HIGH` (Risk Score: 60–75)
- **Investigation Action:**
  - Click on the incident in the dropdown.
  - Review the attack duration and failure frequency.
  - Add an Analyst Note: *"Source IP 198.51.100.110 added to perimeter drop rule on Edge Firewall."*
  - Update status from `OPEN` to `INVESTIGATING`.

---

### SCENARIO B — Distributed Multi-Account Password Spraying
- **Test File:** `data/demo_scenarios/scenario_b_password_spray.csv`
- **Adversary Profile:** Source IP `198.51.100.150` attempting access across 6 distinct accounts (`finance_lead`, `hr_manager`, `lead_dev`, `qa_lead`, `sys_admin`, `devops_eng`) with only 1 attempt per account to evade lockout thresholds.
- **What to Upload:**
  1. In **"📥 Log Ingestion"**, upload `scenario_b_password_spray.csv`.
  2. Click **"Ingest Uploaded File"**.
- **What to Observe:**
  - Triggered Rule: `RULE_PASSWORD_SPRAY` (and `RULE_MULTI_ACCOUNT_FAIL`).
  - Distinct from Brute Force: The engine recognizes that no single account exceeded lockout thresholds, but the horizontal blast radius indicates a coordinated spray.
  - MITRE ATT&CK Mapping: `T1110.003 - Brute Force: Password Spraying`.
  - Severity: `HIGH`.

---

### SCENARIO C — Suspicious Authentication (Credential Compromise)
- **Test File:** `data/demo_scenarios/scenario_c_suspicious_success.json`
- **Adversary Profile:** Source IP `203.0.113.220` fails authentication against `finance_exec` 4 consecutive times, followed immediately by a successful login.
- **What to Upload:**
  1. In **"📥 Log Ingestion"**, upload `scenario_c_suspicious_success.json`.
  2. Click **"Ingest Uploaded File"**.
- **What to Observe:**
  - Triggered Rule: `RULE_SUSPICIOUS_SUCCESS`.
  - MITRE ATT&CK Mapping: `T1078 - Valid Accounts`.
  - Assigned Severity: `CRITICAL` (Risk Score: 85–100/100).
  - Risk Factor Breakdown:
    - Base Severity: Critical (+40 pts)
    - Likely Compromise: Successful login followed repeated failures (+25 pts)
    - Perimeter Exposure: Originates from Public IP space (+10 pts)
- **Investigation Action:**
  - Navigate to **"🌐 IP Investigation"**.
  - Select `203.0.113.220`.
  - Observe the RFC profile (Public Internet) and the warning indicator: *"Potential credential compromise"*.
  - Return to **"🚨 Incident Management"**, set status to `INVESTIGATING`, and document incident containment.

---

### SCENARIO D — Normal Baseline Corporate Activity
- **Test File:** `data/demo_scenarios/scenario_d_normal_activity.log`
- **Profile:** Corporate users (`sarah.connor`, `john.doe`, `alice.smith`) logging in successfully via SSH keys from internal subnets (`10.0.1.0/24`).
- **What to Upload:**
  1. In **"📥 Log Ingestion"**, upload `scenario_d_normal_activity.log`.
  2. Click **"Ingest Uploaded File"**.
- **What to Observe:**
  - 3 events parsed and normalized.
  - **Zero false-positive alerts** generated.
  - Demonstrates that normal operational authentication does not trigger spurious detections or incidents.

---

## Generating the Final Investigation Report

1. Navigate to **"📄 Reports & Exports"** in the sidebar.
2. Click **"Generate Official PDF Investigation Report"**.
3. The engine aggregates all active events, correlated incidents, risk score factor breakdowns, and remediation recommendations.
4. Click **"⬇️ Download PDF Security Report"** to inspect the compiled document.
5. In the same view, download CSV telemetry files (`detections_export.csv`, `incidents_export.csv`, `events_export.csv`) to verify spreadsheet software compatibility.
