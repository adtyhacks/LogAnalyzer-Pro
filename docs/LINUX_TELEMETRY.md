# LogAnalyzer Pro — Linux Telemetry Integration (Phase 3)

## 1. Overview

LogAnalyzer Pro Phase 3 extends endpoint security monitoring to Linux systems (structured for Kali Linux, Debian, and Ubuntu environments).

The platform ingests, normalizes, detects, and correlates Linux authentication events, including:
- **SSH Authentication Failures** (existing user, invalid user, wrong credential)
- **SSH Successful Logins** (passwords, publickey, keyboard-interactive)
- **Invalid User Account Enumeration** (probing non-existent accounts)
- **Privilege Actions via Sudo** (command tracking, target user impersonation)
- **PAM Authentication Failures**
- **IPv4 and IPv6 Address Tracking**

---

## 2. Telemetry Ground Truth & Simulation Transparency

> [!IMPORTANT]
> **SOC Transparency & Evidence Demarcation:**  
> In this release, **Windows host telemetry is genuine** (harvested live from Windows 11 host `ADTY` via native Security Event XML).  
> For demonstrations where a physical Kali VM is unavailable, **Linux telemetry is simulated** using a controlled, deterministic laboratory generator (`scripts/generate_linux_demo.py`).  
> All simulated events are explicitly tagged with `is_synthetic = True`, ensuring that simulated data never contaminates or inflates genuine endpoint telemetry counts.

---

## 3. One-Command Demonstration Procedure (Placement Ready)

For interviewers, recruiters, and placement presentations, LogAnalyzer Pro includes a deterministic, one-command laboratory orchestration script.

### Single Execution Command:
```powershell
python scripts/generate_linux_demo.py --ingest
```

### What this accomplishes:
1. **Generates 43 Syslog text events** (`data/collected/linux_demo_auth.log`) covering 7 realistic attack and routine scenarios on simulated endpoint `kali-demo`.
2. **Generates 43 Systemd Journal NDJSON events** (`data/collected/linux_demo_journal.json`) with microsecond timestamps and systemd metadata.
3. **Generates 5 Windows correlation records** (`data/collected/windows_demo_cross_platform.json`) linking attacker IP `198.51.100.99` across Linux (`kali-demo`) and Windows (`ADTY`).
4. **Ingests all files through the production pipeline** (`scripts/ingest_collected.py`) without bypassing normalization, deduplication, detection, or correlation.
5. **Tags all events with `is_synthetic = True`** and skips duplicates on repeated runs.
6. **Produces a Cross-Platform Multi-Host Attack Campaign** (`INC-20261105-...`) linking Windows and Linux endpoints with elevated risk scoring (+15 points).

---

## 4. Realistic Attack Scenarios Simulated

| Scenario | Attacker IP | Target Account(s) | Attack Behavior | Triggered Rule & MITRE Technique |
|---|---|---|---|---|
| **A. Normal Routine SSH** | `192.168.1.50` | `developer` | Valid login via `publickey` | Baseline Normal Activity |
| **B. SSH Brute Force** | `198.51.100.50` | `root` | 6 rapid authentication failures | `RULE_BRUTE_FORCE` (T1110.001) |
| **C. Password Spraying** | `198.51.100.77` | 5 distinct users | Distributed failures across accounts | `RULE_PASSWORD_SPRAY` (T1110.003) |
| **D. Credential Compromise** | `198.51.100.110` | `deployer` | 4 failures followed by success | `RULE_SUSPICIOUS_SUCCESS` (T1078) |
| **E. Invalid User Probing** | `198.51.100.150` | `oracle`, `guest`, etc. | Probing non-existent system users | `RULE_INVALID_USER_ENUM` (T1087.001) |
| **F. High-Velocity Burst** | `198.51.100.200` | Rapid user attempts | 14 attempts within 28 seconds | `RULE_UNUSUAL_PATTERNS` (T1499) |
| **G. Sudo Activity** | `kali-demo` | `developer` $\to$ `root` | System command: `/bin/systemctl status nginx` | Privilege Tracking |
| **H. IPv6 Probing** | `2001:db8:85a3::...`| `hacker` | IPv6 remote connection failure | IPv6 Telemetry Ingestion |
| **I. Cross-Platform Threat** | `198.51.100.99` | `admin` (Linux) + `Administrator` (Windows) | Pivot across `kali-demo` and `ADTY` | `Cross-Platform Multi-Host Attack Campaign` |

---

## 5. Live Kali Linux VM Collection (Optional Alternative)

If an operator does possess a live Kali Linux environment, the standalone collection script can be executed directly:

### On Kali Linux:
```bash
chmod +x scripts/collect_linux_events.sh
sudo ./scripts/collect_linux_events.sh -s "24 hours ago" -m 200 -o /tmp/kali_auth.log
scp /tmp/kali_auth.log <user>@<WINDOWS_IP>:"c:/Users/aadit/OneDrive/Desktop/LOGANALYZER PRO/data/collected/"
```

### On Windows:
```powershell
python scripts/ingest_collected.py --file data/collected/kali_auth.log
```

---

## 6. Dashboard Transparency Features

1. **Executive SOC Overview:**
   - Metric card: `Total Events` displays breakdown: `Genuine: 447 | Lab: 91`.
   - Priority Incident Queue: Displays `Origin` badge (`🛡️ Genuine`, `🧪 Synthetic`, or `🌐 Mixed`).
2. **Incident Management:**
   - Detailed incident header shows `Origin: 🌐 Mixed Investigation` or `🧪 Synthetic Lab`.
3. **Reports & Telemetry Data Exports:**
   - CSV export contains `is_synthetic` flag and human-readable `telemetry_type` (`GENUINE (Live Host)` vs `SYNTHETIC (Lab)`).
   - Generated PDF report explicitly notes genuine vs synthetic counts in the Executive Summary table and incident findings.
