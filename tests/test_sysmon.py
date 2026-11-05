"""Tests for Sysmon XML & JSON parsing, endpoint telemetry extraction, and parser factory detection."""

import pytest
from pathlib import Path
from loganalyzer.parsers.sysmon import SysmonParser
from loganalyzer.parsers.factory import get_parser_for_file
from loganalyzer.schema import NormalizedEvent, EventStatus


FIXTURE_PATH = Path(__file__).resolve().parent.parent / "data" / "fixtures" / "sysmon_sample.xml"


def test_sysmon_xml_parsing_all_events():
    """Verify parsing of Sysmon Operational XML covering Event IDs 1, 3, 11, 12, 22."""
    parser = SysmonParser()
    content = FIXTURE_PATH.read_text(encoding="utf-8")
    events, stats = parser.parse_content(content, filename="sysmon_sample.xml")

    assert stats.total_records == 5
    assert stats.parsed_events == 5
    assert stats.invalid_records == 0
    assert len(events) == 5

    by_id = {ev.metadata["EventID"]: ev for ev in events}

    # Event ID 1: Process Creation
    ev_1 = by_id[1]
    assert ev_1.action == "PROCESS_CREATE"
    assert ev_1.event_type == "process"
    assert ev_1.process_name == r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    assert ev_1.process_id == 4128
    assert ev_1.parent_process == r"C:\Windows\System32\cmd.exe"
    assert "Invoke-WebRequest" in ev_1.command_line
    assert "SHA256=" in ev_1.hashes
    assert ev_1.hostname == "SOC-ENDPOINT.corp.local"
    assert ev_1.record_id == 50001
    assert "<EventID>1</EventID>" in ev_1.raw_log

    # Event ID 3: Network Connection
    ev_3 = by_id[3]
    assert ev_3.action == "NETWORK_CONNECT"
    assert ev_3.event_type == "network"
    assert ev_3.source_ip == "192.168.1.105"
    assert ev_3.destination_ip == "198.51.100.45"
    assert ev_3.destination_port == 443
    assert ev_3.process_id == 4128
    assert ev_3.metadata["Protocol"] == "tcp"
    assert ev_3.record_id == 50002
    assert "<EventID>3</EventID>" in ev_3.raw_log

    # Event ID 11: File Create
    ev_11 = by_id[11]
    assert ev_11.action == "FILE_CREATE"
    assert ev_11.event_type == "file"
    assert "dropper.ps1" in ev_11.metadata["TargetFilename"]
    assert ev_11.record_id == 50003

    # Event ID 12: Registry CreateKey
    ev_12 = by_id[12]
    assert ev_12.action == "REGISTRY_EVENT"
    assert ev_12.event_type == "registry"
    assert "CurrentVersion\\Run" in ev_12.metadata["TargetObject"]
    assert ev_12.record_id == 50004

    # Event ID 22: DNS Query
    ev_22 = by_id[22]
    assert ev_22.action == "DNS_QUERY"
    assert ev_22.event_type == "network"
    assert ev_22.metadata["QueryName"] == "c2.attacker-infrastructure.com"
    assert ev_22.record_id == 50005


def test_sysmon_json_parsing():
    """Verify that SysmonParser can also ingest structured JSON representations."""
    parser = SysmonParser()
    sample_json = """[
        {
            "EventID": 1,
            "EventRecordID": 60001,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "UtcTime": "2026-11-05T03:30:00Z",
            "Computer": "HOST-01",
            "User": "CORP\\\\admin",
            "Image": "C:\\\\Windows\\\\System32\\\\whoami.exe",
            "CommandLine": "whoami /all",
            "ParentImage": "C:\\\\Windows\\\\System32\\\\cmd.exe",
            "ProcessId": 1234
        }
    ]"""
    events, stats = parser.parse_content(sample_json, filename="sysmon_export.json")
    assert stats.parsed_events == 1
    assert events[0].action == "PROCESS_CREATE"
    assert events[0].command_line == "whoami /all"
    assert events[0].record_id == 60001


def test_sysmon_factory_detection():
    """Verify factory returns SysmonParser for Sysmon filenames or content."""
    p1 = get_parser_for_file("sysmon_events.xml")
    assert isinstance(p1, SysmonParser)

    p2 = get_parser_for_file("export.xml", sample_content="<Event><System><Channel>Microsoft-Windows-Sysmon/Operational</Channel></System></Event>")
    assert isinstance(p2, SysmonParser)


def test_sysmon_malformed_xml_handling():
    """Verify parser returns gracefully on broken XML."""
    parser = SysmonParser()
    events, stats = parser.parse_content("<Events><Event><Broken", filename="bad.xml")
    assert stats.parsed_events == 0
    assert len(stats.errors) > 0
