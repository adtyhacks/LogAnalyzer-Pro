"""Automated tests for all log parsers and ingestion normalizers."""

import pytest
from datetime import datetime
from loganalyzer.parsers.linux_auth import LinuxAuthParser
from loganalyzer.parsers.windows_events import WindowsEventParser
from loganalyzer.parsers.generic_json import GenericJsonParser
from loganalyzer.parsers.generic_csv import GenericCsvParser
from loganalyzer.parsers.factory import get_parser_for_file
from loganalyzer.schema import EventStatus, ActionType


def test_linux_auth_parser_valid():
    parser = LinuxAuthParser()
    sample = """
Oct 24 14:22:10 web-srv01 sshd[1234]: Failed password for invalid user hacker from 198.51.100.1 port 52345 ssh2
Oct 24 14:22:15 web-srv01 sshd[1235]: Failed password for root from 198.51.100.1 port 52346 ssh2
Oct 24 14:22:20 web-srv01 sshd[1236]: Accepted publickey for ubuntu from 10.0.0.5 port 42100 ssh2
Oct 24 14:22:25 web-srv01 sudo: ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/bin/ls
"""
    events, stats = parser.parse_content(sample, "test_auth.log")

    assert stats.total_records == 4
    assert stats.parsed_events == 4
    assert stats.invalid_records == 0

    assert events[0].username == "hacker"
    assert events[0].source_ip == "198.51.100.1"
    assert events[0].status == EventStatus.FAILURE.value
    assert events[0].action == ActionType.FAILED_LOGIN.value

    assert events[1].username == "root"
    assert events[1].status == EventStatus.FAILURE.value

    assert events[2].username == "ubuntu"
    assert events[2].status == EventStatus.SUCCESS.value
    assert events[2].action == ActionType.LOGIN.value

    assert events[3].username == "ubuntu"
    assert events[3].action == ActionType.SUDO.value


def test_linux_auth_parser_invalid_lines():
    parser = LinuxAuthParser()
    sample = "Random corrupted unparseable garbage text line\nAnother broken line"
    events, stats = parser.parse_content(sample, "corrupt.log")
    # Even if parsed as generic syslog or invalid, verify graceful degradation
    assert stats.total_records == 2
    assert len(events) + stats.invalid_records == 2


def test_windows_events_parser_csv():
    parser = WindowsEventParser()
    sample = """TimeCreated,EventID,TargetUserName,IpAddress,LogonType,Status
2026-10-24 10:00:00,4625,Administrator,192.168.1.100,10,0xC000006D
2026-10-24 10:01:00,4624,user_john,192.168.1.100,2,0x0
"""
    events, stats = parser.parse_content(sample, "windows.csv")
    assert stats.total_records == 2
    assert len(events) == 2

    assert events[0].username == "Administrator"
    assert events[0].source_ip == "192.168.1.100"
    assert events[0].status == EventStatus.FAILURE.value
    assert events[0].action == ActionType.FAILED_LOGIN.value

    assert events[1].username == "user_john"
    assert events[1].status == EventStatus.SUCCESS.value
    assert events[1].action == ActionType.LOGIN.value


def test_windows_events_parser_json():
    parser = WindowsEventParser()
    sample = """[
      {"TimeCreated": "2026-10-24T12:00:00Z", "EventID": 4625, "TargetUserName": "admin", "IpAddress": "203.0.113.5"},
      {"TimeCreated": "2026-10-24T12:05:00Z", "EventID": 4720, "TargetUserName": "new_emp", "SubjectUserName": "admin"}
    ]"""
    events, stats = parser.parse_content(sample, "windows.json")
    assert stats.total_records == 2
    assert len(events) == 2
    assert events[0].username == "admin"
    assert events[0].status == EventStatus.FAILURE.value
    assert events[1].action == ActionType.USER_CREATED.value


def test_generic_json_parser():
    parser = GenericJsonParser()
    sample = """
    {"timestamp": "2026-10-24T15:00:00Z", "user": "alice", "src_ip": "10.0.0.1", "action": "LOGIN", "status": "SUCCESS"}
    {"timestamp": "2026-10-24T15:01:00Z", "user": "bob", "src_ip": "10.0.0.2", "action": "LOGIN_FAIL", "status": "FAILURE"}
    """
    events, stats = parser.parse_content(sample, "generic.ndjson")
    assert stats.total_records == 2
    assert len(events) == 2
    assert events[0].username == "alice"
    assert events[0].status == EventStatus.SUCCESS.value
    assert events[1].username == "bob"
    assert events[1].status == EventStatus.FAILURE.value


def test_generic_csv_parser():
    parser = GenericCsvParser()
    sample = """date,username,client_ip,event,result
2026-10-24 16:00:00,finance_user,172.16.1.10,AUTH,PASS
2026-10-24 16:05:00,hr_user,172.16.1.12,AUTH,FAIL
"""
    events, stats = parser.parse_content(sample, "events.csv")
    assert stats.total_records == 2
    assert len(events) == 2
    assert events[0].username == "finance_user"
    assert events[0].status == EventStatus.SUCCESS.value
    assert events[1].username == "hr_user"
    assert events[1].status == EventStatus.FAILURE.value


def test_parser_factory_auto_detection():
    p1 = get_parser_for_file("auth.log", "Oct 24 10:00:00 srv sshd[1]: Failed password")
    assert isinstance(p1, LinuxAuthParser)

    p2 = get_parser_for_file("winevent.csv", "TimeCreated,EventID,TargetUserName")
    assert isinstance(p2, WindowsEventParser)

    p3 = get_parser_for_file("audit.json", "[{\"timestamp\": \"2026-10-24\"}]")
    assert isinstance(p3, GenericJsonParser)

    p4 = get_parser_for_file("export.csv", "timestamp,user,ip,status")
    assert isinstance(p4, GenericCsvParser)
