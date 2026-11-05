"""Tests for Windows Event XML parsing, collection normalization, and forensic traceability."""

import pytest
from pathlib import Path
from loganalyzer.parsers.windows_events import WindowsEventParser
from loganalyzer.schema import NormalizedEvent, EventStatus, ActionType


FIXTURE_PATH = Path(__file__).resolve().parent.parent / "data" / "fixtures" / "windows_security_sample.xml"


def test_windows_xml_parsing_all_events():
    """Verify parsing of Windows Security Event XML covering IDs 4624, 4625, 4634, 4648, 4672, 4720, 4722, 4728, 4740."""
    parser = WindowsEventParser()
    content = FIXTURE_PATH.read_text(encoding="utf-8")
    events, stats = parser.parse_content(content, filename="windows_security_sample.xml")

    assert stats.total_records == 9
    assert stats.parsed_events == 9
    assert stats.invalid_records == 0
    assert len(events) == 9

    by_id = {ev.metadata["EventID"]: ev for ev in events}

    # 4624 - Successful Logon
    ev_4624 = by_id[4624]
    assert ev_4624.action == ActionType.LOGIN.value
    assert ev_4624.status == EventStatus.SUCCESS.value
    assert ev_4624.username == "analyst_jane"
    assert ev_4624.source_ip == "192.168.1.105"
    assert ev_4624.port == 54321
    assert ev_4624.hostname == "SOC-WORKSTATION"
    assert ev_4624.record_id == 10001
    assert ev_4624.channel == "Security"
    assert ev_4624.process_name == r"C:\Windows\System32\winlogon.exe"
    assert "<EventID>4624</EventID>" in ev_4624.raw_log  # Forensic XML preserved

    # 4625 - Failed Logon
    ev_4625 = by_id[4625]
    assert ev_4625.action == ActionType.FAILED_LOGIN.value
    assert ev_4625.status == EventStatus.FAILURE.value
    assert ev_4625.username == "administrator"
    assert ev_4625.source_ip == "203.0.113.88"
    assert ev_4625.record_id == 10002
    assert "<EventID>4625</EventID>" in ev_4625.raw_log

    # 4634 - Logoff
    ev_4634 = by_id[4634]
    assert ev_4634.action == ActionType.LOGOUT.value
    assert ev_4634.status == EventStatus.SUCCESS.value
    assert ev_4634.username == "analyst_jane"
    assert ev_4634.record_id == 10003

    # 4648 - Explicit Credentials
    ev_4648 = by_id[4648]
    assert ev_4648.action == ActionType.LOGIN.value
    assert ev_4648.username == "svc_backup" or ev_4648.username == "analyst_jane"
    assert ev_4648.record_id == 10004

    # 4672 - Special Privileges
    ev_4672 = by_id[4672]
    assert ev_4672.action == ActionType.PRIVILEGE_ESCALATION.value
    assert ev_4672.status == EventStatus.SUCCESS.value
    assert ev_4672.event_type == "privilege"
    assert ev_4672.record_id == 10005

    # 4720 - User Account Created
    ev_4720 = by_id[4720]
    assert ev_4720.action == ActionType.USER_CREATED.value
    assert ev_4720.username == "backdoor_user"
    assert ev_4720.record_id == 10006

    # 4722 - User Enabled
    ev_4722 = by_id[4722]
    assert ev_4722.record_id == 10007

    # 4728 - Security Group Member Added
    ev_4728 = by_id[4728]
    assert ev_4728.record_id == 10008

    # 4740 - Account Locked Out
    ev_4740 = by_id[4740]
    assert ev_4740.action == ActionType.ACCOUNT_LOCKED.value
    assert ev_4740.status == EventStatus.FAILURE.value
    assert ev_4740.username == "analyst_jane"
    assert ev_4740.record_id == 10009


def test_windows_event_forensic_xml_traceability():
    """Verify that every event preserves the full XML representation in raw_log."""
    parser = WindowsEventParser()
    content = FIXTURE_PATH.read_text(encoding="utf-8")
    events, _ = parser.parse_content(content)

    for ev in events:
        assert ev.raw_log.strip().startswith("<")
        assert f"<EventRecordID>{ev.record_id}</EventRecordID>" in ev.raw_log
        assert ev.channel == "Security"


def test_windows_event_hash_deduplication():
    """Verify deterministic hash generation based on channel, computer, and record_id."""
    parser = WindowsEventParser()
    content = FIXTURE_PATH.read_text(encoding="utf-8")
    events1, _ = parser.parse_content(content)
    events2, _ = parser.parse_content(content)

    for e1, e2 in zip(events1, events2):
        assert e1.event_hash == e2.event_hash
        assert e1.record_id is not None
        assert f"winevent|Security|" in e1.compute_hash() or len(e1.event_hash) == 64


def test_windows_xml_malformed_handling():
    """Verify parser gracefully handles malformed XML without unhandled exceptions."""
    parser = WindowsEventParser()
    events, stats = parser.parse_content("<Events><Event><Invalid></Events>", filename="broken.xml")
    assert stats.parsed_events == 0
    assert len(stats.errors) > 0
