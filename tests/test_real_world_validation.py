"""Automated validation suite covering all Phase D incremental collection and duplicate prevention scenarios."""

import pytest
import sqlite3
from pathlib import Path
from datetime import datetime, timezone
from loganalyzer.database import DatabaseManager
from loganalyzer.parsers.windows_events import WindowsEventParser
from loganalyzer.parsers.sysmon import SysmonParser
from loganalyzer.schema import NormalizedEvent, EventStatus, ActionType


def test_scenario_1_and_2_initial_and_duplicate_collection(tmp_path: Path):
    """Test 1 & 2: Initial collection inserts events, second identical collection skips duplicates without advancing checkpoint."""
    db_file = tmp_path / "test_soc_1.db"
    db = DatabaseManager(db_path=db_file)
    parser = WindowsEventParser()

    xml_batch_1 = """<Events>
      <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
        <System>
          <EventID>4624</EventID>
          <TimeCreated SystemTime="2026-11-05T01:00:00Z" />
          <EventRecordID>1001</EventRecordID>
          <Channel>Security</Channel>
          <Computer>WIN-HOST-01</Computer>
        </System>
        <EventData><Data Name="TargetUserName">analyst_a</Data></EventData>
      </Event>
      <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
        <System>
          <EventID>4625</EventID>
          <TimeCreated SystemTime="2026-11-05T01:05:00Z" />
          <EventRecordID>1002</EventRecordID>
          <Channel>Security</Channel>
          <Computer>WIN-HOST-01</Computer>
        </System>
        <EventData><Data Name="TargetUserName">analyst_b</Data></EventData>
      </Event>
    </Events>"""

    events, stats = parser.parse_content(xml_batch_1, filename="batch1.xml")
    assert stats.parsed_events == 2

    # Initial insertion
    inserted1, dups1 = db.insert_events(events)
    assert inserted1 == 2
    assert dups1 == 0

    db.update_channel_checkpoint("Security", last_record_id=1002, new_events_count=inserted1, computer_name="WIN-HOST-01")
    cp1 = db.get_channel_checkpoint("Security")
    assert cp1["last_record_id"] == 1002
    assert cp1["total_events_collected"] == 2

    # Second ingestion of the same batch (duplicate prevention)
    inserted2, dups2 = db.insert_events(events)
    assert inserted2 == 0
    assert dups2 == 2

    # Checkpoint must remain 1002
    cp2 = db.get_channel_checkpoint("Security")
    assert cp2["last_record_id"] == 1002
    assert cp2["total_events_collected"] == 2


def test_scenario_3_incremental_arrival_of_new_events(tmp_path: Path):
    """Test 3: New events with higher record IDs are inserted and checkpoint advances."""
    db_file = tmp_path / "test_soc_2.db"
    db = DatabaseManager(db_path=db_file)
    parser = WindowsEventParser()

    xml_batch_initial = """<Events>
      <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
        <System>
          <EventID>4624</EventID>
          <TimeCreated SystemTime="2026-11-05T01:00:00Z" />
          <EventRecordID>2001</EventRecordID>
          <Channel>Security</Channel>
          <Computer>WIN-HOST-01</Computer>
        </System>
        <EventData><Data Name="TargetUserName">analyst_a</Data></EventData>
      </Event>
    </Events>"""
    ev1, _ = parser.parse_content(xml_batch_initial)
    db.insert_events(ev1)
    db.update_channel_checkpoint("Security", last_record_id=2001, new_events_count=1)

    xml_batch_new = """<Events>
      <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
        <System>
          <EventID>4672</EventID>
          <TimeCreated SystemTime="2026-11-05T01:10:00Z" />
          <EventRecordID>2002</EventRecordID>
          <Channel>Security</Channel>
          <Computer>WIN-HOST-01</Computer>
        </System>
        <EventData><Data Name="SubjectUserName">admin</Data></EventData>
      </Event>
    </Events>"""
    ev2, _ = parser.parse_content(xml_batch_new)
    inserted, dups = db.insert_events(ev2)
    assert inserted == 1
    assert dups == 0

    db.update_channel_checkpoint("Security", last_record_id=2002, new_events_count=1)
    cp = db.get_channel_checkpoint("Security")
    assert cp["last_record_id"] == 2002
    assert cp["total_events_collected"] == 2


def test_scenario_4_and_6_application_restart_and_checkpoint_recovery(tmp_path: Path):
    """Test 4 & 6: Reconnecting to SQLite accurately restores checkpoint state."""
    db_file = tmp_path / "test_soc_restart.db"
    db1 = DatabaseManager(db_path=db_file)
    db1.update_channel_checkpoint("Security", last_record_id=5500, new_events_count=45, computer_name="HOST-X")

    # Simulate process restart
    del db1
    db2 = DatabaseManager(db_path=db_file)
    cp = db2.get_channel_checkpoint("Security")
    assert cp is not None
    assert cp["last_record_id"] == 5500
    assert cp["total_events_collected"] == 45
    assert cp["computer_name"] == "HOST-X"


def test_scenario_5_triple_duplicate_file_ingestion(tmp_path: Path):
    """Test 5: Ingesting an identical file 3 times never creates duplicate rows."""
    db_file = tmp_path / "test_soc_dup.db"
    db = DatabaseManager(db_path=db_file)
    parser = WindowsEventParser()

    xml = """<Events>
      <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
        <System>
          <EventID>4624</EventID>
          <TimeCreated SystemTime="2026-11-05T01:00:00Z" />
          <EventRecordID>3001</EventRecordID>
          <Channel>Security</Channel>
          <Computer>WIN-HOST-01</Computer>
        </System>
      </Event>
    </Events>"""
    ev, _ = parser.parse_content(xml)

    ins1, dup1 = db.insert_events(ev)
    ins2, dup2 = db.insert_events(ev)
    ins3, dup3 = db.insert_events(ev)

    assert ins1 == 1 and dup1 == 0
    assert ins2 == 0 and dup2 == 1
    assert ins3 == 0 and dup3 == 1

    all_evs = db.get_events()
    assert len(all_evs) == 1


def test_scenario_7_and_8_empty_and_malformed_xml_safety(tmp_path: Path):
    """Test 7 & 8: Empty content or malformed XML handled safely without advancing checkpoints."""
    db_file = tmp_path / "test_soc_malformed.db"
    db = DatabaseManager(db_path=db_file)
    parser = WindowsEventParser()

    # Empty
    ev_empty, stats_empty = parser.parse_content("")
    assert len(ev_empty) == 0

    # Malformed
    ev_bad, stats_bad = parser.parse_content("<Events><Event><Truncated", filename="bad.xml")
    assert len(ev_bad) == 0
    assert len(stats_bad.errors) > 0

    # Ensure checkpoints are untouched
    assert db.get_channel_checkpoint("Security") is None


def test_scenario_9_independent_channel_checkpoints(tmp_path: Path):
    """Test 9: Different channels (Security, Application, Sysmon) maintain isolated checkpoints."""
    db_file = tmp_path / "test_soc_channels.db"
    db = DatabaseManager(db_path=db_file)

    db.update_channel_checkpoint("Security", last_record_id=1000, new_events_count=10)
    db.update_channel_checkpoint("Application", last_record_id=60000, new_events_count=50)
    db.update_channel_checkpoint("Microsoft-Windows-Sysmon/Operational", last_record_id=250, new_events_count=5)

    sec = db.get_channel_checkpoint("Security")
    app = db.get_channel_checkpoint("Application")
    sysm = db.get_channel_checkpoint("Microsoft-Windows-Sysmon/Operational")

    assert sec["last_record_id"] == 1000
    assert app["last_record_id"] == 60000
    assert sysm["last_record_id"] == 250

    # Updating Application must not affect Security
    db.update_channel_checkpoint("Application", last_record_id=60020, new_events_count=20)
    sec_after = db.get_channel_checkpoint("Security")
    assert sec_after["last_record_id"] == 1000


def test_scenario_10_multiple_computer_names_differentiation(tmp_path: Path):
    """Test 10: Events with the same EventRecordID on different hostnames are NOT falsely deduplicated."""
    db_file = tmp_path / "test_soc_hosts.db"
    db = DatabaseManager(db_path=db_file)

    ev_host_a = NormalizedEvent(
        timestamp=datetime(2026, 11, 5, 2, 0, 0, tzinfo=timezone.utc),
        source_type="windows_events",
        event_type="authentication",
        action="LOGIN",
        status="SUCCESS",
        username="admin",
        channel="Security",
        record_id=5000,
        hostname="DC-PRIMARY"
    )

    ev_host_b = NormalizedEvent(
        timestamp=datetime(2026, 11, 5, 2, 0, 0, tzinfo=timezone.utc),
        source_type="windows_events",
        event_type="authentication",
        action="LOGIN",
        status="SUCCESS",
        username="admin",
        channel="Security",
        record_id=5000,
        hostname="WORKSTATION-02"
    )

    # Hashes must differ because hostnames differ
    assert ev_host_a.event_hash != ev_host_b.event_hash

    inserted, dups = db.insert_events([ev_host_a, ev_host_b])
    assert inserted == 2
    assert dups == 0
