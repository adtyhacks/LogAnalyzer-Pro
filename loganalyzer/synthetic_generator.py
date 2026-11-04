"""Synthetic Security Log Generator for LogAnalyzer Pro.

Generates realistic, clearly labeled synthetic security datasets demonstrating:
- SCENARIO A: Targeted Brute-Force attack against single account.
- SCENARIO B: Distributed Password Spraying across multiple accounts.
- SCENARIO C: Suspicious successful authentication following repeated failures.
- SCENARIO D: Normal baseline corporate authentication activity.

All generated records are strictly synthetic and labeled as such.
"""

from datetime import datetime, timedelta
import json
import csv
import argparse
from pathlib import Path
from loganalyzer.config import DATA_DIR, utc_now
from loganalyzer.database import DatabaseManager
from loganalyzer.parsers.factory import get_parser_for_file
from loganalyzer.detection.engine import DetectionEngine
from loganalyzer.correlation.correlator import CorrelationEngine


def generate_all_synthetic_logs(target_dir: Path = DATA_DIR) -> dict:
    target_dir.mkdir(parents=True, exist_ok=True)
    demo_dir = target_dir / "demo_scenarios"
    demo_dir.mkdir(parents=True, exist_ok=True)

    base_time = datetime(2026, 10, 24, 10, 0, 0)

    # -------------------------------------------------------------
    # 1. Main Linux Auth Log (data/linux_auth.log)
    # -------------------------------------------------------------
    linux_lines = [
        f"# SYNTHETIC SECURITY TEST LOG — FOR LOGANALYZER PRO TESTING ONLY",
        f"# Generated: {utc_now().isoformat()}",
    ]
    # Normal logins
    t = base_time
    for user, ip in [("ubuntu", "192.168.1.15"), ("developer", "192.168.1.20"), ("analyst", "10.0.0.12")]:
        linux_lines.append(f"{t.strftime('%b %d %H:%M:%S')} sec-srv01 sshd[1021]: Accepted publickey for {user} from {ip} port 49152 ssh2")
        t += timedelta(seconds=45)

    # Brute Force against 'admin' from 198.51.100.50
    t = base_time + timedelta(minutes=10)
    for _ in range(8):
        linux_lines.append(f"{t.strftime('%b %d %H:%M:%S')} sec-srv01 sshd[1452]: Failed password for invalid user admin from 198.51.100.50 port 51234 ssh2")
        t += timedelta(seconds=15)

    # Password Spraying from 198.51.100.77
    t = base_time + timedelta(minutes=25)
    for u in ["alice", "bob", "charlie", "david", "emma", "frank"]:
        linux_lines.append(f"{t.strftime('%b %d %H:%M:%S')} sec-srv01 sshd[1890]: Failed password for {u} from 198.51.100.77 port 58921 ssh2")
        t += timedelta(seconds=20)

    # Suspicious Success after repeated failures on 'deployer' from 203.0.113.19
    t = base_time + timedelta(minutes=40)
    for _ in range(4):
        linux_lines.append(f"{t.strftime('%b %d %H:%M:%S')} sec-srv01 sshd[2204]: Failed password for deployer from 203.0.113.19 port 60123 ssh2")
        t += timedelta(seconds=10)
    t += timedelta(seconds=12)
    linux_lines.append(f"{t.strftime('%b %d %H:%M:%S')} sec-srv01 sshd[2210]: Accepted password for deployer from 203.0.113.19 port 60124 ssh2")

    # Privileged root login & sudo
    t = base_time + timedelta(minutes=55)
    linux_lines.append(f"{t.strftime('%b %d %H:%M:%S')} sec-srv01 sshd[2400]: Accepted password for root from 198.51.100.99 port 41200 ssh2")
    t += timedelta(seconds=5)
    linux_lines.append(f"{t.strftime('%b %d %H:%M:%S')} sec-srv01 sudo: deployer : TTY=pts/1 ; PWD=/home/deployer ; USER=root ; COMMAND=/bin/bash")

    linux_path = target_dir / "linux_auth.log"
    with open(linux_path, "w", encoding="utf-8") as f:
        f.write("\n".join(linux_lines) + "\n")

    # -------------------------------------------------------------
    # 2. Windows Security Events CSV (data/windows_events.csv)
    # -------------------------------------------------------------
    win_csv_path = target_dir / "windows_events.csv"
    with open(win_csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "TimeCreated", "EventID", "TargetUserName", "SubjectUserName",
            "IpAddress", "IpPort", "LogonType", "Status", "WorkstationName", "Computer"
        ])
        t = base_time
        writer.writerow([t.strftime("%Y-%m-%d %H:%M:%S"), "4624", "corp_user1", "-", "10.1.2.50", "50110", "3", "0x0", "WKSTN-101", "DC-01.corp.local"])
        t += timedelta(seconds=30)
        writer.writerow([t.strftime("%Y-%m-%d %H:%M:%S"), "4624", "corp_user2", "-", "10.1.2.55", "50112", "3", "0x0", "WKSTN-102", "DC-01.corp.local"])

        # Brute-force against Administrator from 185.220.101.5
        t = base_time + timedelta(minutes=15)
        for _ in range(7):
            writer.writerow([t.strftime("%Y-%m-%d %H:%M:%S"), "4625", "Administrator", "-", "185.220.101.5", "54321", "10", "0xC000006D", "ATTACK-BOX", "DC-01.corp.local"])
            t += timedelta(seconds=12)

        # Account lockout
        t += timedelta(seconds=5)
        writer.writerow([t.strftime("%Y-%m-%d %H:%M:%S"), "4740", "Administrator", "DC-01$", "-", "-", "-", "0x0", "DC-01", "DC-01.corp.local"])

        # Password spray from 185.220.101.22
        t = base_time + timedelta(minutes=35)
        for u in ["j.smith", "m.jones", "r.williams", "k.brown", "s.miller"]:
            writer.writerow([t.strftime("%Y-%m-%d %H:%M:%S"), "4625", u, "-", "185.220.101.22", "61000", "3", "0xC000006A", "EXTERNAL", "DC-01.corp.local"])
            t += timedelta(seconds=18)

        # Privileged logon
        t = base_time + timedelta(hours=1, minutes=10)
        writer.writerow([t.strftime("%Y-%m-%d %H:%M:%S"), "4672", "-", "Administrator", "-", "-", "2", "0x0", "DC-01", "DC-01.corp.local"])

    # -------------------------------------------------------------
    # 3. Windows Security Events JSON (data/windows_events.json)
    # -------------------------------------------------------------
    win_json_path = target_dir / "windows_events.json"
    win_records = []
    t = base_time + timedelta(hours=2)
    for _ in range(5):
        win_records.append({
            "TimeCreated": t.isoformat(),
            "EventID": 4625,
            "TargetUserName": "svc_backup",
            "IpAddress": "203.0.113.88",
            "LogonType": 3,
            "Status": "0xC000006A",
            "WorkstationName": "REMOTE-CLI"
        })
        t += timedelta(seconds=20)
    t += timedelta(seconds=15)
    win_records.append({
        "TimeCreated": t.isoformat(),
        "EventID": 4624,
        "TargetUserName": "svc_backup",
        "IpAddress": "203.0.113.88",
        "LogonType": 3,
        "Status": "0x0",
        "WorkstationName": "REMOTE-CLI"
    })
    with open(win_json_path, "w", encoding="utf-8") as f:
        json.dump(win_records, f, indent=2)

    # -------------------------------------------------------------
    # 4. Generic Security JSON (data/generic_security.json)
    # -------------------------------------------------------------
    gen_json_path = target_dir / "generic_security.json"
    gen_records = []
    t = base_time + timedelta(hours=3)
    for i in range(14):
        gen_records.append({
            "timestamp": t.isoformat(),
            "event_name": "API_AUTHENTICATION",
            "status": "FAILURE",
            "username": f"api_client_{i % 3}",
            "source_ip": "192.0.2.140",
            "service": "api-gateway",
            "message": "Invalid JWT token signature"
        })
        t += timedelta(seconds=2)
    with open(gen_json_path, "w", encoding="utf-8") as f:
        json.dump(gen_records, f, indent=2)

    # -------------------------------------------------------------
    # 5. Generic Security CSV (data/generic_security.csv)
    # -------------------------------------------------------------
    gen_csv_path = target_dir / "generic_security.csv"
    with open(gen_csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "action", "status", "username", "source_ip", "service", "message"])
        t = base_time + timedelta(hours=4)
        for i in range(6):
            writer.writerow([
                t.strftime("%Y-%m-%d %H:%M:%S"),
                "VPN_LOGIN",
                "FAILED",
                f"vpn_user_{i}",
                "198.51.100.200",
                "openvpn",
                f"MFA Challenge Failure for vpn_user_{i}"
            ])
            t += timedelta(seconds=15)

    # -------------------------------------------------------------
    # DEDICATED SOC DEMONSTRATION SCENARIOS (data/demo_scenarios/)
    # -------------------------------------------------------------
    # Scenario A: Brute Force
    scen_a_path = demo_dir / "scenario_a_brute_force.log"
    scen_a_lines = [
        f"# SYNTHETIC SECURITY LOG — SCENARIO A: SSH BRUTE FORCE ATTACK",
        f"# Description: 7 repeated failed attempts against 'root' from 198.51.100.110"
    ]
    t = base_time
    for _ in range(7):
        scen_a_lines.append(f"{t.strftime('%b %d %H:%M:%S')} edge-router sshd[3312]: Failed password for root from 198.51.100.110 port 44102 ssh2")
        t += timedelta(seconds=12)
    with open(scen_a_path, "w", encoding="utf-8") as f:
        f.write("\n".join(scen_a_lines) + "\n")

    # Scenario B: Password Spraying
    scen_b_path = demo_dir / "scenario_b_password_spray.csv"
    with open(scen_b_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "event", "status", "username", "source_ip", "message"])
        t = base_time + timedelta(hours=1)
        # 1 IP targeting 6 distinct accounts with 1-2 attempts each
        for u in ["finance_lead", "hr_manager", "lead_dev", "qa_lead", "sys_admin", "devops_eng"]:
            writer.writerow([
                t.strftime("%Y-%m-%d %H:%M:%S"),
                "SSO_AUTH",
                "FAILURE",
                u,
                "198.51.100.150",
                f"Invalid credential hash for identity {u}"
            ])
            t += timedelta(seconds=25)

    # Scenario C: Suspicious Success (Credential Compromise)
    scen_c_path = demo_dir / "scenario_c_suspicious_success.json"
    scen_c_events = []
    t = base_time + timedelta(hours=2)
    # 4 failures on finance_exec
    for _ in range(4):
        scen_c_events.append({
            "timestamp": t.isoformat(),
            "action": "PORTAL_LOGIN",
            "status": "FAILURE",
            "username": "finance_exec",
            "source_ip": "203.0.113.220",
            "message": "Password authentication failed"
        })
        t += timedelta(seconds=15)
    # Subsequent Success
    t += timedelta(seconds=10)
    scen_c_events.append({
        "timestamp": t.isoformat(),
        "action": "PORTAL_LOGIN",
        "status": "SUCCESS",
        "username": "finance_exec",
        "source_ip": "203.0.113.220",
        "message": "Password authentication succeeded"
    })
    with open(scen_c_path, "w", encoding="utf-8") as f:
        json.dump(scen_c_events, f, indent=2)

    # Scenario D: Normal Corporate Activity
    scen_d_path = demo_dir / "scenario_d_normal_activity.log"
    scen_d_lines = [
        f"# SYNTHETIC SECURITY LOG — SCENARIO D: NORMAL BASELINE AUTHENTICATION",
        f"# Description: Legitimate corporate users logging in with normal success"
    ]
    t = base_time + timedelta(hours=3)
    for u, ip in [("sarah.connor", "10.0.1.10"), ("john.doe", "10.0.1.12"), ("alice.smith", "10.0.1.15")]:
        scen_d_lines.append(f"{t.strftime('%b %d %H:%M:%S')} internal-srv01 sshd[5501]: Accepted publickey for {u} from {ip} port 51000 ssh2")
        t += timedelta(minutes=15)
    with open(scen_d_path, "w", encoding="utf-8") as f:
        f.write("\n".join(scen_d_lines) + "\n")

    return {
        "linux_auth": str(linux_path),
        "windows_csv": str(win_csv_path),
        "windows_json": str(win_json_path),
        "generic_json": str(gen_json_path),
        "generic_csv": str(gen_csv_path),
        "scenario_a": str(scen_a_path),
        "scenario_b": str(scen_b_path),
        "scenario_c": str(scen_c_path),
        "scenario_d": str(scen_d_path)
    }


def ingest_demo_scenarios(db: DatabaseManager, det_engine: DetectionEngine, correlator: CorrelationEngine):
    """Programmatically load all scenarios and correlate into the database."""
    paths = generate_all_synthetic_logs()
    print("Ingesting demonstration datasets...")
    for key, p in paths.items():
        path_obj = Path(p)
        if not path_obj.exists():
            continue
        with open(path_obj, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
        parser = get_parser_for_file(path_obj.name, content[:1000])
        events, stats = parser.parse_content(content, path_obj.name)
        db.insert_events(events)
        dets = det_engine.analyze_events(events, persist=True)
        correlator.correlate(events, dets, persist=True)
        db.record_ingestion(stats)
        print(f"  [+] Processed {path_obj.name}: {len(events)} events, {len(dets)} detections")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Synthetic Security Log Generator for LogAnalyzer Pro")
    parser.add_argument("--ingest", action="store_true", help="Ingest generated datasets into database immediately")
    parser.add_argument("--reset-db", action="store_true", help="Clear database before ingesting")
    args = parser.parse_args()

    files = generate_all_synthetic_logs()
    print("Synthetic Security Datasets Generated Successfully:")
    for k, v in files.items():
        print(f"  [{k}] -> {v}")

    if args.ingest or args.reset_db:
        db = DatabaseManager()
        if args.reset_db:
            db.clear_database()
            print("Database purged.")
        det = DetectionEngine(db_manager=db)
        corr = CorrelationEngine(db_manager=db)
        ingest_demo_scenarios(db, det, corr)
        print("Demo ingestion complete! SOC Metrics:")
        print(db.get_stats_summary())
