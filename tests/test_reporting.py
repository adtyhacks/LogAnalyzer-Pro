"""Automated tests for PDF and CSV report generation."""

from pathlib import Path
from loganalyzer.reporting.pdf_report import PdfReportGenerator
from loganalyzer.reporting.csv_export import CsvExporter


def test_pdf_report_generation(tmp_path: Path):
    generator = PdfReportGenerator(reports_dir=tmp_path)

    stats = {
        "total_events": 150,
        "total_detections": 8,
        "critical_count": 2,
        "high_count": 4,
        "medium_count": 2,
        "low_count": 0,
        "open_incidents": 3,
        "unique_suspicious_ips": 4
    }

    incidents = [
        {
            "incident_id": "INC-20261024-001",
            "title": "Brute Force Campaign",
            "severity": "CRITICAL",
            "risk_score": 90.0,
            "description": "Repeated failed logins followed by compromise.",
            "source_ip": "198.51.100.5",
            "affected_accounts": ["admin", "root"],
            "mitre_techniques": ["T1110.001", "T1078"]
        }
    ]

    detections = [
        {
            "id": 1,
            "rule_id": "RULE_BRUTE_FORCE",
            "rule_name": "Brute Force Attempt",
            "severity": "HIGH",
            "source_ip": "198.51.100.5",
            "username": "admin",
            "mitre_technique_id": "T1110.001",
            "mitre_technique_name": "Brute Force: Password Guessing"
        }
    ]

    pdf_path = generator.generate_report(incidents, detections, stats, "test_report.pdf")
    assert pdf_path.exists()
    assert pdf_path.stat().st_size > 1000  # Generated valid PDF content


def test_csv_exports():
    detections = [
        {
            "id": 1,
            "timestamp": "2026-10-24 10:00:00",
            "rule_id": "RULE_BRUTE_FORCE",
            "rule_name": "Brute Force",
            "severity": "HIGH",
            "source_ip": "10.0.0.1",
            "username": "test_user",
            "event_count": 5,
            "mitre_technique_id": "T1110.001",
            "mitre_technique_name": "Password Guessing",
            "description": "Test description"
        }
    ]
    det_csv = CsvExporter.export_detections(detections)
    assert "RULE_BRUTE_FORCE" in det_csv
    assert "T1110.001" in det_csv

    incidents = [
        {
            "incident_id": "INC-001",
            "title": "Test Title",
            "severity": "HIGH",
            "risk_score": 85.0,
            "status": "OPEN",
            "created_at": "2026-10-24 10:00:00",
            "updated_at": "2026-10-24 10:05:00",
            "source_ip": "10.0.0.1",
            "affected_accounts": ["user1", "user2"],
            "mitre_techniques": ["T1110.001"],
            "description": "Incident test desc"
        }
    ]
    inc_csv = CsvExporter.export_incidents(incidents)
    assert "INC-001" in inc_csv
    assert "user1; user2" in inc_csv


def test_csv_export_events_no_row_duplication():
    events = [
        {
            "id": 1,
            "timestamp": "2026-11-05T08:00:00Z",
            "hostname": "kali-demo",
            "source_type": "linux_auth",
            "event_type": "authentication",
            "action": "LOGIN",
            "status": "SUCCESS",
            "username": "developer",
            "source_ip": "192.168.1.50",
            "port": 51200,
            "service": "sshd",
            "is_synthetic": 1,
            "message": "Accepted publickey for developer"
        }
    ]
    evt_csv = CsvExporter.export_events(events)
    lines = [line for line in evt_csv.strip().split("\r\n") if line]
    # Header + 1 event row = 2 lines (proves no duplicate row writing)
    assert len(lines) == 2, f"Expected header + 1 data line, got {len(lines)}"
    assert "SYNTHETIC (Lab)" in evt_csv


def test_privacy_sanitization_in_exports():
    from loganalyzer.utils import sanitize_privacy

    raw_text = "Login failure for aadityanaira@gmail.com on C:\\Users\\aadit\\Desktop"
    sanitized = sanitize_privacy(raw_text)
    assert "aadityanaira@gmail.com" not in sanitized
    assert "operator@corp.internal" in sanitized
    assert "C:\\Users\\aadit" not in sanitized

    # In incidents export
    incidents = [
        {
            "incident_id": "INC-002",
            "title": "Compromise of aadityanaira@gmail.com",
            "severity": "HIGH",
            "risk_score": 85.0,
            "status": "OPEN",
            "created_at": "2026-11-05 10:00:00",
            "updated_at": "2026-11-05 10:05:00",
            "source_ip": "10.0.0.1",
            "affected_accounts": ["aadit", "aadityanaira@gmail.com"],
            "mitre_techniques": ["T1078"],
            "description": "User aadit profile accessed at C:\\Users\\aadit"
        }
    ]
    inc_csv = CsvExporter.export_incidents(incidents)
    assert "aadityanaira@gmail.com" not in inc_csv
    assert "aadit" not in inc_csv.lower()
    assert "operator_admin" in inc_csv

