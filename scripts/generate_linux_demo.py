#!/usr/bin/env python3
"""LogAnalyzer Pro 2.0 — Controlled Linux Telemetry Demonstration Generator.

Generates realistic Linux SSH authentication & system telemetry for demonstration and testing.
Simulates attack scenarios (brute-force, password spray, credential compromise, invalid user probing)
and normal activity without requiring a physical Kali Linux VM.
"""

import sys
import argparse
import json
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Tuple

# Add project root to Python path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from loganalyzer.database import DatabaseManager


DEFAULT_HOSTNAME = "kali-demo"
DEFAULT_BASE_TIME = datetime(2026, 11, 5, 8, 0, 0, tzinfo=timezone.utc)


class LinuxDemoGenerator:
    """Generates synthetic, deterministic Linux syslog and systemd journal security telemetry."""

    def __init__(self, hostname: str = DEFAULT_HOSTNAME, base_time: datetime = DEFAULT_BASE_TIME):
        self.hostname = hostname
        self.base_time = base_time

    def generate_all_scenarios(self) -> Tuple[List[str], List[Dict[str, Any]]]:
        """Generate all demonstration scenarios in both Syslog text and Journal NDJSON formats."""
        syslog_lines: List[str] = []
        journal_records: List[Dict[str, Any]] = []

        # Current sequence cursor
        curr_time = self.base_time
        pid = 1800

        # Helper to format syslog line
        def add_event(dt: datetime, daemon: str, p_id: int, msg: str, cmdline: str = ""):
            ts_syslog = dt.strftime("%b %d %H:%M:%S")
            line = f"{ts_syslog} {self.hostname} {daemon}[{p_id}]: {msg}"
            syslog_lines.append(line)

            # Microsecond epoch timestamp for systemd journal
            usec_ts = str(int(dt.timestamp() * 1_000_000))
            record = {
                "__REALTIME_TIMESTAMP": usec_ts,
                "_HOSTNAME": self.hostname,
                "_COMM": daemon,
                "SYSLOG_IDENTIFIER": daemon,
                "_PID": str(p_id),
                "_SYSTEMD_UNIT": f"{daemon}.service",
                "_CMDLINE": cmdline or f"{daemon}: {self.hostname} [priv]",
                "MESSAGE": msg
            }
            journal_records.append(record)

        # ----------------------------------------------------------------------
        # Scenario A: Normal Routine SSH Authentication (Valid Developer)
        # ----------------------------------------------------------------------
        add_event(
            curr_time, "sshd", pid,
            "Accepted publickey for developer from 192.168.1.50 port 51200 ssh2"
        )
        curr_time += timedelta(seconds=15)
        pid += 1

        # ----------------------------------------------------------------------
        # Scenario B: SSH Brute-Force Attack (Single Target Account 'root')
        # Attacker IP: 198.51.100.50 | Target: root | 6 Rapid Failures
        # ----------------------------------------------------------------------
        bf_ip = "198.51.100.50"
        for i in range(6):
            curr_time += timedelta(seconds=8)
            pid += 1
            add_event(
                curr_time, "sshd", pid,
                f"Failed password for root from {bf_ip} port {52000 + i} ssh2"
            )

        curr_time += timedelta(minutes=2)

        # ----------------------------------------------------------------------
        # Scenario C: Password Spraying Attack (Multiple Distinct Accounts)
        # Attacker IP: 198.51.100.77 | Targets: deployer, webadmin, developer, finance_exec, svc_app
        # ----------------------------------------------------------------------
        spray_ip = "198.51.100.77"
        spray_users = ["deployer", "webadmin", "developer", "finance_exec", "svc_app"]
        for i, user in enumerate(spray_users):
            curr_time += timedelta(seconds=12)
            pid += 1
            add_event(
                curr_time, "sshd", pid,
                f"Failed password for {user} from {spray_ip} port {53000 + i} ssh2"
            )

        curr_time += timedelta(minutes=2)

        # ----------------------------------------------------------------------
        # Scenario D: Credential Compromise (Success Following Multiple Failures)
        # Attacker IP: 198.51.100.110 | Target: deployer | 4 Failures then Success
        # ----------------------------------------------------------------------
        comp_ip = "198.51.100.110"
        for i in range(4):
            curr_time += timedelta(seconds=10)
            pid += 1
            add_event(
                curr_time, "sshd", pid,
                f"Failed password for deployer from {comp_ip} port {54000 + i} ssh2"
            )
        # Immediate success
        curr_time += timedelta(seconds=15)
        pid += 1
        add_event(
            curr_time, "sshd", pid,
            f"Accepted password for deployer from {comp_ip} port 54010 ssh2"
        )

        curr_time += timedelta(minutes=2)

        # ----------------------------------------------------------------------
        # Scenario E: Invalid User Probing & Account Enumeration
        # Attacker IP: 198.51.100.150 | Non-existent accounts
        # ----------------------------------------------------------------------
        enum_ip = "198.51.100.150"
        invalid_users = ["oracle", "testuser", "scanner", "temp_admin", "guest"]
        for i, inv_user in enumerate(invalid_users):
            curr_time += timedelta(seconds=9)
            pid += 1
            add_event(
                curr_time, "sshd", pid,
                f"Failed password for invalid user {inv_user} from {enum_ip} port {55000 + i} ssh2"
            )

        curr_time += timedelta(minutes=2)

        # ----------------------------------------------------------------------
        # Scenario F: Suspicious High-Velocity Burst (DoS / Credential Stuffing)
        # Attacker IP: 198.51.100.200 | 14 attempts in 28 seconds
        # ----------------------------------------------------------------------
        burst_ip = "198.51.100.200"
        for i in range(14):
            curr_time += timedelta(seconds=2)
            pid += 1
            add_event(
                curr_time, "sshd", pid,
                f"Failed password for user_{i} from {burst_ip} port {56000 + i} ssh2"
            )

        curr_time += timedelta(minutes=1)

        # ----------------------------------------------------------------------
        # Scenario G: Normal Sudo Privilege Activity
        # ----------------------------------------------------------------------
        sudo_line = f"{curr_time.strftime('%b %d %H:%M:%S')} {self.hostname} sudo: developer : TTY=pts/0 ; PWD=/home/developer ; USER=root ; COMMAND=/bin/systemctl status nginx"
        syslog_lines.append(sudo_line)
        journal_records.append({
            "__REALTIME_TIMESTAMP": str(int(curr_time.timestamp() * 1_000_000)),
            "_HOSTNAME": self.hostname,
            "_COMM": "sudo",
            "SYSLOG_IDENTIFIER": "sudo",
            "_PID": str(pid + 1),
            "_SYSTEMD_UNIT": "sudo.service",
            "_CMDLINE": "/usr/bin/sudo /bin/systemctl status nginx",
            "MESSAGE": "developer : TTY=pts/0 ; PWD=/home/developer ; USER=root ; COMMAND=/bin/systemctl status nginx"
        })

        curr_time += timedelta(minutes=2)

        # ----------------------------------------------------------------------
        # Scenario H: IPv6 Probing Activity
        # ----------------------------------------------------------------------
        ipv6_addr = "2001:db8:85a3::8a2e:370:7334"
        pid += 1
        add_event(
            curr_time, "sshd", pid,
            f"Failed password for invalid user hacker from {ipv6_addr} port 54321 ssh2"
        )

        curr_time += timedelta(minutes=2)

        # ----------------------------------------------------------------------
        # Scenario I: Cross-Platform Attacker Telemetry
        # Designated Lab Attacker IP: 198.51.100.99
        # Attempts 5 SSH logins on kali-demo targeting 'admin'
        # ----------------------------------------------------------------------
        cross_ip = "198.51.100.99"
        for i in range(5):
            curr_time += timedelta(seconds=10)
            pid += 1
            add_event(
                curr_time, "sshd", pid,
                f"Failed password for admin from {cross_ip} port {58000 + i} ssh2"
            )

        return syslog_lines, journal_records

    def generate_cross_platform_windows_telemetry(self) -> List[Dict[str, Any]]:
        """
        Generate corresponding synthetic Windows security events for designated lab IP 198.51.100.99.
        Targeted at host ADTY, enabling the CorrelationEngine to link Linux and Windows attacks.
        """
        cross_ip = "198.51.100.99"
        win_events = []
        curr_time = self.base_time + timedelta(minutes=15)

        for i in range(5):
            curr_time += timedelta(seconds=15)
            win_events.append({
                "timestamp": curr_time.isoformat(),
                "EventID": 4625,
                "LogName": "Security",
                "ComputerName": "ADTY",
                "TargetUserName": "Administrator",
                "IpAddress": cross_ip,
                "IpPort": 49200 + i,
                "Status": "0xC000006D",
                "SubStatus": "0xC000006A",
                "FailureReason": "Unknown user name or bad password",
                "is_synthetic": True
            })

        return win_events


def main():
    parser = argparse.ArgumentParser(description="Generate controlled Linux telemetry demonstration data")
    parser.add_argument("--outdir", "-o", type=str, default="data/collected", help="Output directory")
    parser.add_argument("--hostname", type=str, default=DEFAULT_HOSTNAME, help="Simulated endpoint hostname")
    parser.add_argument("--format", type=str, choices=["syslog", "journal", "both"], default="syslog",
                        help="Format to ingest (syslog, journal, or both; default: syslog to avoid duplicate scenario counts)")
    parser.add_argument("--ingest", action="store_true", help="Automatically ingest the generated demo data into SQLite")
    parser.add_argument("--realtime", action="store_true", help="Anchor timestamps to current time instead of fixed epoch")
    args = parser.parse_args()

    out_path = Path(args.outdir)
    out_path.mkdir(parents=True, exist_ok=True)

    base_time = utc_now() if args.realtime else DEFAULT_BASE_TIME
    gen = LinuxDemoGenerator(hostname=args.hostname, base_time=base_time)

    syslog_lines, journal_records = gen.generate_all_scenarios()
    cross_win_records = gen.generate_cross_platform_windows_telemetry()

    # 1. Write Linux Syslog file
    syslog_file = out_path / "linux_demo_auth.log"
    syslog_file.write_text("\n".join(syslog_lines) + "\n", encoding="utf-8")
    print(f"[+] Generated {len(syslog_lines)} Linux Syslog events: {syslog_file}")

    # 2. Write Linux Systemd Journal NDJSON file
    journal_file = out_path / "linux_demo_journal.json"
    journal_text = "\n".join(json.dumps(r) for r in journal_records) + "\n"
    journal_file.write_text(journal_text, encoding="utf-8")
    print(f"[+] Generated {len(journal_records)} Linux Journal NDJSON records: {journal_file}")

    # 3. Write Cross-Platform Windows Correlation file
    cross_win_file = out_path / "windows_demo_cross_platform.json"
    cross_win_file.write_text(json.dumps(cross_win_records, indent=2), encoding="utf-8")
    print(f"[+] Generated {len(cross_win_records)} Cross-Platform Windows records: {cross_win_file}")

    print("\n" + "=" * 60)
    print("      LOGANALYZER PRO — CONTROLLED LINUX LAB DEMO GENERATOR")
    print("=" * 60)
    print(f"Endpoint Hostname:        {args.hostname} (Simulated Linux)")
    print(f"Windows Endpoint:         ADTY (Simulated Cross-Platform Correlation)")
    print(f"Designated Attacker IP:   198.51.100.99 (Cross-Platform Pivot)")
    print(f"Data Classification:      SYNTHETIC (Lab Demonstration)")
    print(f"Ingestion Format:         {args.format.upper()} (syslog & journal represent the same 43 scenario actions)")
    print("=" * 60)

    if args.ingest:
        print("\n[*] Orchestrating automatic ingestion through ingest_collected.py pipeline...")
        from scripts.ingest_collected import ingest_file
        from loganalyzer.detection.engine import DetectionEngine
        from loganalyzer.correlation.correlator import CorrelationEngine
        db = DatabaseManager()

        if args.format in ("syslog", "both"):
            print("\n--- 1. Ingesting Linux Syslog Auth Demo ---")
            ingest_file(syslog_file, db, analyze=False, is_synthetic=True)

        if args.format in ("journal", "both"):
            print("\n--- 2. Ingesting Linux Journal NDJSON Demo ---")
            ingest_file(journal_file, db, analyze=False, is_synthetic=True)

        print("\n--- 3. Ingesting Cross-Platform Windows Demo ---")
        ingest_file(cross_win_file, db, analyze=False, is_synthetic=True)

        print("\n--- 4. Running Unified Detection & Cross-Platform Correlation ---")
        det_engine = DetectionEngine(db_manager=db)
        correlator = CorrelationEngine(db_manager=db)
        all_events = db.get_all_normalized_events()
        detections = det_engine.analyze_events(all_events, persist=True)
        incidents = correlator.correlate(all_events, detections, persist=True)
        print(f"[+] Unified Security Analysis: {len(detections)} detection alerts, {len(incidents)} incidents correlated.")

        print("\n[+] Demonstration data successfully ingested and correlated!")
    else:
        print("\nTo ingest these demonstration datasets manually, run:")
        print(f"  python scripts/ingest_collected.py --file {syslog_file} --synthetic")
        print(f"  python scripts/ingest_collected.py --file {journal_file} --synthetic")
        print(f"  python scripts/ingest_collected.py --file {cross_win_file} --synthetic")


if __name__ == "__main__":
    from loganalyzer.config import utc_now
    main()
