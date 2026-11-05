# LogAnalyzer Pro — Multi-Endpoint Telemetry Validation Report

**Phase:** Phase 3 Telemetry Integration (Windows Host & Controlled Linux Lab)  
**Report Date:** November 05, 2026  
**Status:** FULLY VERIFIED (71 Automated Tests Passing, 6/6 UI Views Verified)

---

## 1. Telemetry Sources & Ground Truth Distinction

In accordance with strict SOC integrity standards, all telemetry in LogAnalyzer Pro is clearly classified by origin:

| Telemetry Category | Source Channel | Origin Host / Environment | Events Ingested | Verification Status |
|---|---|---|---|---|
| **Genuine Windows Telemetry** | `Security` | Host: `ADTY` (Windows 11) | 50 events | **VERIFIED LIVE** (RecordID: 1825601) |
| **Genuine Windows Telemetry** | `Application` | Host: `ADTY` (Windows 11) | 10 events | **VERIFIED LIVE** (RecordID: 62327) |
| **Controlled Linux Lab Simulation** | `linux_demo_auth.log` | Simulated Host: `kali-demo` | 43 events | **VERIFIED SYNTHETIC LAB** (`is_synthetic=True`) |
| **Controlled Linux Journal Simulation** | `linux_demo_journal.json`| Simulated Host: `kali-demo` | 43 events | **VERIFIED SYNTHETIC LAB** (`is_synthetic=True`) |
| **Cross-Platform Windows Lab** | `windows_demo_cross_platform.json`| Target Host: `ADTY` | 5 events | **VERIFIED SYNTHETIC LAB** (`is_synthetic=True`) |
| **Linux Telemetry Collector Script** | `scripts/collect_linux_events.sh` | Bash script for Kali/Debian | Verified | **SCRIPT VERIFIED** (Text + JSON) |
| **Automated Test Fixtures** | Windows/Linux combined | Unit & integration tests | 71 tests | **AUTOMATED TEST SUITE** |

---

## 2. Telemetry Breakdown in Live Database

- **Total Normalized Events:** 538
- **Genuine Endpoint Events:** 447 (Windows `Security` & `Application` on `ADTY`, plus base ingested records)
- **Synthetic Simulation Events:** 91 (`kali-demo` SSH simulation + cross-platform lab pivot)
- **Genuine vs Synthetic Separation:** Guaranteed via database column `is_synthetic INTEGER DEFAULT 0` and displayed in metric cards, incident cards, PDF reports, and CSV exports.

---

## 3. Windows Telemetry Validation Summary

- **Collection:** Executed `scripts/collect_windows_events.ps1` with Administrator privileges.
- **Payload:** Extracted 50 genuine Windows security events (IDs: 4624, 4672, etc.) from `C:\Windows\System32\Winevt\Logs\Security.evtx`.
- **Forensic Integrity:** Full XML schema preserved in database column `raw_log`.
- **Deduplication:** Initial ingestion inserted 50 events; secondary ingestion skipped 50/50 duplicates.
- **Checkpoint:** SQLite table `channel_checkpoints` updated with `last_record_id: 1825601` on host `ADTY`.

---

## 4. Linux / Kali Telemetry Validation Summary

- **Demonstration Generator (`scripts/generate_linux_demo.py`):**
  - Generates 7 attack and routine scenarios: Normal SSH, Brute Force, Password Spray, Suspicious Success, Invalid User Enumeration, Burst Velocity, and Sudo Privilege execution.
  - Supports both standard syslog format and systemd journal NDJSON format with microsecond timestamps.
  - Generates cross-platform telemetry linking attacker IP `198.51.100.99` across `kali-demo` and `ADTY`.
  - Re-running the generation and ingestion is completely idempotent (0 duplicate records created).
- **Parser Engine (`LinuxAuthParser`):**
  - Robust regex parser handling legacy RFC 3164 and RFC 5424 ISO-8601 timestamps.
  - Native IPv4 and IPv6 extraction (`198.51.100.x` and `2001:db8:85a3::...`).
  - Hostname, PID, and Sudo command line parsing.
  - Systemd journal microsecond timestamp decoding.
- **Detection Rules:**
  - `RULE_INVALID_USER_ENUM`: Detects probing against non-existent accounts (MITRE T1087.001)
  - `RULE_BRUTE_FORCE`: Detects repeated SSH failures (MITRE T1110.001)
  - `RULE_PASSWORD_SPRAY`: Detects distributed attempts across accounts (MITRE T1110.003)
  - `RULE_SUSPICIOUS_SUCCESS`: Flags successful login following multiple failures (MITRE T1078)
  - `RULE_UNUSUAL_PATTERNS`: Flags high burst velocities (MITRE T1499)
- **Cross-Platform Correlation Engine:**
  - Correlated attacker IP `198.51.100.99` targeting both `kali-demo` (Linux SSH) and `ADTY` (Windows Security).
  - Raised risk score (+15 points) and assigned title: `Cross-Platform Multi-Host Attack Campaign (198.51.100.99)`.

---

## 5. Test Execution Summary

### Python Compilation:
```powershell
python -m compileall -q .
```
- **Exit Code:** `0` (Zero syntax errors, clean imports).

### Automated Test Suite:
```powershell
python -m pytest -q
```
- **Total Tests:** 71
- **Passed:** 71
- **Failed:** 0
- **Duration:** ~5.8s

### Streamlit UI Engine Verification (AppTest):
- `🛡️ SOC Overview`: Verified clean render, multi-endpoint breakdown charts, genuine vs synthetic metrics, zero exceptions.
- `📥 Log Ingestion`: Verified clean render, zero exceptions.
- `🚨 Incident Management`: Verified clean render, zero exceptions.
- `🌐 IP Investigation`: Verified clean render, zero exceptions.
- `🎯 MITRE ATT&CK Matrix`: Verified clean render, zero exceptions.
- `📄 Reports & Exports`: Verified clean render, zero exceptions.
