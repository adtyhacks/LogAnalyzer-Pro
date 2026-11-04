# LogAnalyzer Pro — System Architecture

## Overview

**LogAnalyzer Pro** is an intelligent, high-performance security log analysis and incident investigation platform designed for SOC analysts, incident responders, and threat hunters.

It employs a decoupled, modular pipeline:
1. **Ingestion & Normalization:** Ingests heterogeneous security logs (Linux Syslog, Windows Security Events, generic JSON/CSV) and normalizes them into a unified schema (`NormalizedEvent`).
2. **Persistence Engine:** Efficient SQLite persistence with Write-Ahead Logging (WAL), deterministic SHA-256 event hashing for deduplication, and indexed queries.
3. **Detection Engine:** Modular, configurable rule evaluation against the normalized event stream, linking each alert to MITRE ATT&CK Enterprise techniques.
4. **Correlation Engine:** Clusters detections across source IPs, usernames, and temporal windows into holistic security incidents, avoiding duplicate incident tickets.
5. **Security Intelligence & Risk Scoring:** Computes transparent, explainable 0–100 risk scores based on attack scope, severity, and host behavioral indicators.
6. **SOC Dashboard & Reporting:** Streamlit frontend with Plotly analytics and automated PDF report generation via ReportLab.

---

## Architectural Flowchart

```mermaid
flowchart TD
    subgraph Ingestion ["Log Ingestion Layer"]
        A1["Linux auth.log / secure"] --> P1["LinuxAuthParser"]
        A2["Windows Events (CSV/JSON)"] --> P2["WindowsEventParser"]
        A3["Generic JSON (NDJSON/Array)"] --> P3["GenericJsonParser"]
        A4["Generic CSV Logs"] --> P4["GenericCsvParser"]
        P1 & P2 & P3 & P4 --> NORM["Schema Normalizer (NormalizedEvent)"]
    end

    subgraph Storage ["Persistence Layer (SQLite)"]
        NORM --> DEDUP["SHA-256 Event Deduplicator"]
        DEDUP --> DB[(SQLite Database)]
        DB --> EV_TBL["events table"]
        DB --> DET_TBL["detections table"]
        DB --> INC_TBL["incidents table"]
        DB --> NOTE_TBL["investigation_notes table"]
    end

    subgraph Detection ["Modular Detection Engine"]
        EV_TBL --> DE["DetectionEngine"]
        DE --> R1["Brute Force (T1110.001)"]
        DE --> R2["Password Spray (T1110.003)"]
        DE --> R3["Suspicious Success (T1078)"]
        DE --> R4["Multi-Account Fail (T1110.003)"]
        DE --> R5["Privileged Login (T1078.003)"]
        DE --> R6["Burst Pattern (T1499)"]
        DE --> R7["Repeated Suspicious IP"]
        R1 & R2 & R3 & R4 & R5 & R6 & R7 --> DET_RECS["Detection Records"]
    end

    subgraph Correlation ["Incident Correlation & Risk Engine"]
        DET_RECS --> CORR["CorrelationEngine"]
        CORR --> INTEL["Offline IP Intelligence"]
        CORR --> MITRE["MITRE ATT&CK Mapper"]
        CORR --> RS["RiskScorer (0-100 Score)"]
        RS --> INC_RECS["Incident Records"]
        INC_RECS --> INC_TBL
    end

    subgraph Presentation ["Presentation & Reporting"]
        DB --> UI["SOC Streamlit Dashboard"]
        UI --> REP["PdfReportGenerator (ReportLab)"]
        UI --> EXP["CsvExporter"]
    end
```

---

## Core Data Schema

### `NormalizedEvent`
- `event_id`: Auto-incrementing database ID.
- `timestamp`: UTC datetime.
- `source_type`: `linux_auth`, `windows_events`, `generic_json`, `generic_csv`.
- `event_type`: `authentication`, `privilege`, `account_management`, `system`.
- `action`: `LOGIN`, `FAILED_LOGIN`, `SUDO`, `USER_CREATED`, `ACCOUNT_LOCKED`, `OTHER`.
- `status`: `SUCCESS`, `FAILURE`, `UNKNOWN`.
- `username`: Target or subject account name.
- `source_ip`: Source IPv4/IPv6 address.
- `port`: Connection port.
- `service`: Daemon or service name (`sshd`, `sudo`, `Security`, etc.).
- `message`: Human-readable summary.
- `raw_log`: Verbatim log line.
- `metadata`: JSON payload containing context-specific attributes (PID, LogonType, etc.).
- `event_hash`: SHA-256 hash `(timestamp, source_type, user, IP, action, status, raw_log)`.
