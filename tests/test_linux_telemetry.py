"""Comprehensive tests for Linux / Kali telemetry collection, parsing, detection, and cross-platform correlation."""

import json
from datetime import datetime, timezone, timedelta
from pathlib import Path
import pytest

from loganalyzer.schema import NormalizedEvent, EventStatus, ActionType, DetectionRecord
from loganalyzer.parsers.linux_auth import LinuxAuthParser
from loganalyzer.parsers.factory import get_parser_for_file
from loganalyzer.database import DatabaseManager
from loganalyzer.detection.engine import DetectionEngine
from loganalyzer.detection.rules.invalid_user_enum import InvalidUserEnumerationRule
from loganalyzer.detection.rules.brute_force import BruteForceRule
from loganalyzer.detection.rules.password_spraying import PasswordSprayingRule
from loganalyzer.detection.rules.suspicious_success import SuspiciousSuccessRule
from loganalyzer.correlation.correlator import CorrelationEngine


FIXTURES_DIR = Path(__file__).resolve().parent.parent / "data" / "fixtures"


@pytest.fixture
def temp_db(tmp_path):
    db_file = tmp_path / "test_linux.db"
    return DatabaseManager(db_file)


class TestLinuxAuthParser:
    """Test Linux auth.log and journal parsing capabilities."""

    def test_parse_auth_log_fixture(self):
        sample_path = FIXTURES_DIR / "kali_auth_sample.log"
        assert sample_path.exists(), "Fixture kali_auth_sample.log should exist"

        parser = LinuxAuthParser()
        content = sample_path.read_text(encoding="utf-8")
        events, stats = parser.parse_content(content, filename="kali_auth_sample.log")

        assert stats.parsed_events == 14
        assert stats.invalid_records == 0
        assert len(events) == 14

        # Verify host extraction
        for ev in events:
            assert ev.hostname == "kali"

    def test_parse_failed_and_invalid_user(self):
        line = "Nov 05 06:10:01 kali sshd[1401]: Failed password for invalid user admin from 192.168.1.150 port 49152 ssh2"
        parser = LinuxAuthParser()
        events, stats = parser.parse_content(line)

        assert len(events) == 1
        ev = events[0]
        assert ev.action == ActionType.FAILED_LOGIN.value
        assert ev.status == EventStatus.FAILURE.value
        assert ev.username == "admin"
        assert ev.source_ip == "192.168.1.150"
        assert ev.port == 49152
        assert ev.process_name == "sshd"
        assert ev.process_id == 1401
        assert ev.metadata.get("invalid_user") is True

    def test_parse_accepted_ssh_login(self):
        line = "Nov 05 06:20:20 kali sshd[1423]: Accepted publickey for kali from 192.168.1.200 port 52104 ssh2"
        parser = LinuxAuthParser()
        events, stats = parser.parse_content(line)

        assert len(events) == 1
        ev = events[0]
        assert ev.action == ActionType.LOGIN.value
        assert ev.status == EventStatus.SUCCESS.value
        assert ev.username == "kali"
        assert ev.source_ip == "192.168.1.200"
        assert ev.port == 52104
        assert ev.metadata.get("auth_method") == "publickey"

    def test_ipv6_extraction(self):
        line1 = "Nov 05 06:25:00 kali sshd[1430]: Failed password for root from 2001:db8::10 port 53100 ssh2"
        line2 = "Nov 05 06:25:05 kali sshd[1431]: Accepted password for root from ::1 port 53102 ssh2"

        parser = LinuxAuthParser()
        events1, _ = parser.parse_content(line1)
        events2, _ = parser.parse_content(line2)

        assert events1[0].source_ip == "2001:db8::10"
        assert events2[0].source_ip == "::1"

    def test_sudo_command_parsing(self):
        line = "Nov 05 06:22:00 kali sudo: kali : TTY=pts/0 ; PWD=/home/kali ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow"
        parser = LinuxAuthParser()
        events, _ = parser.parse_content(line)

        assert len(events) == 1
        ev = events[0]
        assert ev.action == ActionType.SUDO.value
        assert ev.status == EventStatus.SUCCESS.value
        assert ev.username == "kali"
        assert ev.command_line == "/usr/bin/cat /etc/shadow"
        assert ev.metadata.get("target_user") == "root"

    def test_journal_json_ndjson_parsing(self):
        sample_path = FIXTURES_DIR / "kali_journal_sample.json"
        assert sample_path.exists()

        parser = LinuxAuthParser()
        content = sample_path.read_text(encoding="utf-8")
        events, stats = parser.parse_content(content, filename="kali_journal.json")

        assert stats.parsed_events == 4
        assert stats.invalid_records == 0
        assert events[0].hostname == "kali"
        assert events[0].username == "scanner"
        assert events[0].source_ip == "192.168.1.155"
        assert events[3].status == EventStatus.SUCCESS.value
        assert events[3].username == "kali"

    def test_factory_detection_for_linux(self):
        p1 = get_parser_for_file("auth.log", sample_content="Nov 05 06:10:01 kali sshd[1401]: Failed password")
        assert isinstance(p1, LinuxAuthParser)

        p2 = get_parser_for_file("kali_auth.log")
        assert isinstance(p2, LinuxAuthParser)

        p3 = get_parser_for_file("journal_ssh.json", sample_content='{"_COMM": "sshd", "MESSAGE": "Failed password"}')
        assert isinstance(p3, LinuxAuthParser)


class TestLinuxDetectionAndCorrelation:
    """Test detection rules and cross-platform correlation on Linux telemetry."""

    def test_invalid_user_enumeration_rule(self):
        rule = InvalidUserEnumerationRule({"threshold": 3, "time_window_minutes": 15})
        now = datetime(2026, 11, 5, 10, 0, 0, tzinfo=timezone.utc)

        events = [
            NormalizedEvent(
                timestamp=now + timedelta(seconds=i * 10),
                source_type="linux_auth",
                event_type="authentication",
                action=ActionType.FAILED_LOGIN.value,
                status=EventStatus.FAILURE.value,
                username=f"user_{i}",
                source_ip="198.51.100.22",
                hostname="kali",
                metadata={"invalid_user": True},
                raw_log=f"Failed password for invalid user user_{i}"
            )
            for i in range(4)
        ]

        detections = rule.evaluate(events)
        assert len(detections) >= 1
        det = detections[0]
        assert det.rule_id == "RULE_INVALID_USER_ENUM"
        assert det.source_ip == "198.51.100.22"
        assert len(det.affected_accounts) == 4
        assert det.mitre_technique_id == "T1087.001"

    def test_duplicate_prevention_on_linux_events(self, temp_db):
        sample_path = FIXTURES_DIR / "kali_auth_sample.log"
        content = sample_path.read_text(encoding="utf-8")
        parser = LinuxAuthParser()
        events, _ = parser.parse_content(content)

        # First insertion
        inserted1, dups1 = temp_db.insert_events(events)
        assert inserted1 == 14
        assert dups1 == 0

        # Second insertion of same events
        inserted2, dups2 = temp_db.insert_events(events)
        assert inserted2 == 0
        assert dups2 == 14

    def test_cross_platform_correlation(self, temp_db):
        """Verify correlation engine identifies cross-platform lateral threat across Windows & Linux."""
        correlator = CorrelationEngine(temp_db)
        now = datetime(2026, 11, 5, 12, 0, 0, tzinfo=timezone.utc)
        attacker_ip = "198.51.100.99"

        # 1. Linux SSH brute-force event
        linux_ev = NormalizedEvent(
            timestamp=now,
            source_type="linux_auth",
            event_type="authentication",
            action=ActionType.FAILED_LOGIN.value,
            status=EventStatus.FAILURE.value,
            username="root",
            source_ip=attacker_ip,
            hostname="kali",
            raw_log="Failed password for root from 198.51.100.99"
        )

        # 2. Windows Security logon failure event
        win_ev = NormalizedEvent(
            timestamp=now + timedelta(minutes=5),
            source_type="windows_events",
            event_type="authentication",
            action=ActionType.FAILED_LOGIN.value,
            status=EventStatus.FAILURE.value,
            username="Administrator",
            source_ip=attacker_ip,
            hostname="ADTY",
            channel="Security",
            raw_log="<Event>Windows Security 4625</Event>"
        )

        events = [linux_ev, win_ev]
        temp_db.insert_events(events)

        # Create two related detections from the same attacker IP
        det1 = DetectionRecord(
            rule_id="RULE_BRUTE_FORCE",
            rule_name="Brute-Force Authentication Attempt",
            severity="HIGH",
            description=f"SSH Brute force from {attacker_ip}",
            timestamp=now,
            source_ip=attacker_ip,
            username="root",
            affected_accounts=["root"],
            related_event_ids=[linux_ev.event_id]
        )
        det2 = DetectionRecord(
            rule_id="RULE_PASSWORD_SPRAY",
            rule_name="Password Spraying Attack",
            severity="HIGH",
            description=f"Windows spray from {attacker_ip}",
            timestamp=now + timedelta(minutes=5),
            source_ip=attacker_ip,
            username="Administrator",
            affected_accounts=["Administrator"],
            related_event_ids=[win_ev.event_id]
        )

        incidents = correlator.correlate(events, [det1, det2], persist=True)

        assert len(incidents) == 1
        inc = incidents[0]
        assert inc.source_ip == attacker_ip
        assert "Cross-Platform" in inc.title or any("cross-platform" in str(rf).lower() for rf in inc.risk_factors)
        assert any("Linux and Windows" in rf or "multiple endpoints" in rf for rf in inc.risk_factors)

    def test_linux_demo_generator_scenarios(self):
        from scripts.generate_linux_demo import LinuxDemoGenerator
        gen = LinuxDemoGenerator(hostname="kali-demo")
        syslog_lines, journal_records = gen.generate_all_scenarios()

        assert len(syslog_lines) >= 30
        assert len(journal_records) == len(syslog_lines)

        # Parse generated syslog
        parser = LinuxAuthParser()
        content = "\n".join(syslog_lines)
        events, stats = parser.parse_content(content, filename="linux_demo_auth.log")

        assert stats.parsed_events == len(syslog_lines)
        assert stats.invalid_records == 0

        # Verify scenarios presence
        ips = {ev.source_ip for ev in events if ev.source_ip}
        assert "198.51.100.50" in ips   # Brute-force
        assert "198.51.100.77" in ips   # Password spray
        assert "198.51.100.110" in ips  # Suspicious success
        assert "198.51.100.150" in ips  # Invalid user enum
        assert "198.51.100.200" in ips  # Burst pattern
        assert "198.51.100.99" in ips   # Cross-platform pivot

        # Verify IPv6
        ipv6_events = [ev for ev in events if ev.source_ip and ":" in ev.source_ip]
        assert len(ipv6_events) >= 1

    def test_synthetic_transparency_and_reporting(self, temp_db):
        from scripts.generate_linux_demo import LinuxDemoGenerator
        from loganalyzer.reporting.csv_export import CsvExporter
        from loganalyzer.reporting.pdf_report import PdfReportGenerator

        gen = LinuxDemoGenerator(hostname="kali-demo")
        syslog_lines, _ = gen.generate_all_scenarios()

        parser = LinuxAuthParser()
        events, _ = parser.parse_content("\n".join(syslog_lines), filename="linux_demo_auth.log")

        # Mark all as synthetic
        for ev in events:
            ev.is_synthetic = True

        temp_db.insert_events(events)

        stats = temp_db.get_stats_summary()
        assert stats["synthetic_events"] == len(events)
        assert stats["genuine_events"] == 0

        # CSV transparency verification
        ev_dicts = temp_db.get_events(limit=10)
        csv_out = CsvExporter.export_events(ev_dicts)
        assert "SYNTHETIC" in csv_out
        assert "telemetry_type" in csv_out

        # PDF report generation verification
        pdf_gen = PdfReportGenerator(reports_dir=Path(temp_db.db_path).parent)
        pdf_path = pdf_gen.generate_report([], [], stats, output_filename="test_report.pdf")
        assert pdf_path.exists()
        assert pdf_path.stat().st_size > 0
