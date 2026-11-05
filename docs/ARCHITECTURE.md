# LogAnalyzer Pro — System Architecture (Phase 3: Multi-Endpoint)

## Overview

**LogAnalyzer Pro** is an intelligent, high-performance endpoint security log analysis and incident investigation platform designed for SOC analysts, incident responders, and threat hunters.

It employs a decoupled, multi-endpoint pipeline:
1. **Multi-Source Telemetry Ingestion & Normalization:** Ingests heterogeneous security logs from both **Windows** (native Security Event XML, Sysmon, Application) and **Linux** (Kali Linux `auth.log`, systemd `journalctl` text and NDJSON), as well as generic JSON/CSV, normalizing them into a unified schema (`NormalizedEvent`).
2. **Incremental Collection & State Checkpointing:** High-water mark state tracking in SQLite (`channel_checkpoints`) and JSON checkpoints (`data/checkpoints/`) enables reliable incremental ingestion.
3. **Persistence Engine:** Efficient SQLite persistence with Write-Ahead Logging (WAL), deterministic SHA-256 event hashing for 100% duplicate prevention, and indexed parameterized queries.
4. **Detection Engine:** Modular, configurable rule evaluation against the normalized event stream, linking each alert to MITRE ATT&CK Enterprise techniques (T1110, T1078, T1087, T1499).
5. **Cross-Platform Correlation Engine:** Clusters detections across source IPs, usernames, endpoints, and temporal windows into holistic security incidents, flagging cross-platform lateral movement between Linux and Windows hosts.
6. **Security Intelligence & Risk Scoring:** Computes transparent, explainable 0–100 risk scores based on attack scope, severity, and host behavioral indicators.
7. **Multi-Endpoint SOC Dashboard & Reporting:** Streamlit frontend with Plotly analytics, endpoint and platform filtering, and automated PDF report generation via ReportLab.

---

## Architectural Flowchart

```mermaid
flowchart TD
    subgraph Collectors ["Multi-Endpoint Telemetry Collection Layer"]
        W1["Windows Host: collect_windows_events.ps1"] --> W_OUT["data/collected/Security_events.xml"]
        W2["Windows Sysmon: collect_sysmon.ps1"] --> W_SYS["data/collected/sysmon_events.xml"]
        L1["Kali Linux VM: collect_linux_events.sh"] --> L_OUT["data/collected/kali_auth.log / .json"]
    end

    subgraph Ingestion ["Log Ingestion & Normalization Layer"]
        W_OUT & W_SYS --> P_WIN["WindowsEventParser / SysmonParser"]
        L_OUT --> P_LIN["LinuxAuthParser (auth.log & journal NDJSON)"]
        GEN["Generic JSON / CSV"] --> P_GEN["GenericJsonParser / GenericCsvParser"]
        P_WIN & P_LIN & P_GEN --> NORM["Schema Normalizer (NormalizedEvent)"]
    end

    subgraph Storage ["Persistence Layer (SQLite with WAL)"]
        NORM --> DEDUP["SHA-256 Event Deduplicator"]
        DEDUP --> DB[(SQLite Database)]
        DB --> CHK_TBL["channel_checkpoints table"]
        DB --> EV_TBL["events table"]
        DB --> DET_TBL["detections table"]
        DB --> INC_TBL["incidents table"]
        DB --> NOTE_TBL["investigation_notes table"]
    end

    subgraph Detection ["Modular Detection Engine"]
        EV_TBL --> DE["DetectionEngine"]
        DE --> R1["SSH / Windows Brute Force (T1110.001)"]
        DE --> R2["Password Spray (T1110.003)"]
        DE --> R3["Suspicious Success (T1078)"]
        DE --> R4["Multi-Account Fail (T1110.003)"]
        DE --> R5["Privileged Login (T1078.003)"]
        DE --> R6["Invalid User Enumeration (T1087.001)"]
        DE --> R7["Burst Velocity Pattern (T1499)"]
        R1 & R2 & R3 & R4 & R5 & R6 & R7 --> DET_RECS["Detection Records"]
    end

    subgraph Correlation ["Cross-Platform Correlation & Risk Engine"]
        DET_RECS --> CORR["CorrelationEngine"]
        CORR --> INTEL["Offline IP Intelligence"]
        CORR --> MITRE["MITRE ATT&CK Mapper"]
        CORR --> RS["RiskScorer (0-100 Score + Cross-Platform Multiplier)"]
        RS --> INC_RECS["Incident Records (Single-Host & Cross-Platform)"]
        INC_RECS --> INC_TBL
    end

    subgraph Presentation ["Presentation & Reporting"]
        DB --> UI["Multi-Endpoint Streamlit SOC Dashboard"]
        DB --> REP["PDF & CSV Report Generator"]
    end
```

---

## Data Model Specifications

- **`NormalizedEvent`**: Unified data class for Linux and Windows telemetry:
  - `timestamp`: UTC datetime (ISO 8601)
  - `source_type`: `linux_auth`, `windows_events`, `sysmon`, `generic_json`, `generic_csv`
  - `event_type`: `authentication`, `privilege`, `system`, `network`, `process`
  - `action`: `LOGIN`, `FAILED_LOGIN`, `SUDO`, `OTHER`
  - `status`: `SUCCESS`, `FAILURE`, `UNKNOWN`
  - `username`, `source_ip` (IPv4 & IPv6), `destination_ip`, `port`
  - `hostname`, `process_id`, `process_name`, `command_line`
  - `channel`, `record_id`, `is_synthetic`
  - `raw_log`: original verbatim record for forensic verification
  - `event_hash`: deterministic SHA-256 hash
