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
