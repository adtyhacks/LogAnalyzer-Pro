"""Tests for channel checkpoints, database migrations, and schema idempotency."""

import pytest
import sqlite3
from pathlib import Path
from datetime import datetime, timezone
from loganalyzer.database import DatabaseManager
from loganalyzer.schema import NormalizedEvent


def test_channel_checkpoint_lifecycle(tmp_path: Path):
    """Verify storing, retrieving, and updating channel collection checkpoints."""
    db_file = tmp_path / "test_checkpoints.db"
    db = DatabaseManager(db_path=db_file)

    # 1. Initially no checkpoint
    sec_cp = db.get_channel_checkpoint("Security")
    assert sec_cp is None

    # 2. Update Security checkpoint
    db.update_channel_checkpoint(
        channel="Security",
        last_record_id=10500,
        last_timestamp="2026-11-05T02:00:00Z",
        computer_name="WIN-SOC-01",
        new_events_count=50
    )

    sec_cp = db.get_channel_checkpoint("Security")
    assert sec_cp is not None
    assert sec_cp["channel"] == "Security"
    assert sec_cp["last_record_id"] == 10500
    assert sec_cp["total_events_collected"] == 50
    assert sec_cp["computer_name"] == "WIN-SOC-01"

    # 3. Update Sysmon channel independently
    db.update_channel_checkpoint(
        channel="Microsoft-Windows-Sysmon/Operational",
        last_record_id=3400,
        last_timestamp="2026-11-05T02:05:00Z",
        computer_name="WIN-SOC-01",
        new_events_count=120
    )

    sys_cp = db.get_channel_checkpoint("Microsoft-Windows-Sysmon/Operational")
    assert sys_cp is not None
    assert sys_cp["last_record_id"] == 3400
    assert sys_cp["total_events_collected"] == 120

    # Security checkpoint must remain unchanged
    sec_cp = db.get_channel_checkpoint("Security")
    assert sec_cp["last_record_id"] == 10500
    assert sec_cp["total_events_collected"] == 50

    # 4. Incremental update on Security
    db.update_channel_checkpoint(
        channel="Security",
        last_record_id=10550,
        last_timestamp="2026-11-05T02:30:00Z",
        computer_name="WIN-SOC-01",
        new_events_count=25
    )
    sec_cp = db.get_channel_checkpoint("Security")
    assert sec_cp["last_record_id"] == 10550
    assert sec_cp["total_events_collected"] == 75

    all_cps = db.get_all_channel_checkpoints()
    assert len(all_cps) == 2


def test_database_idempotent_migration(tmp_path: Path):
    """Verify that re-initializing the database or migrating an existing schema causes no data loss."""
    db_file = tmp_path / "test_migration.db"

    # Create minimal legacy database schema without the new columns
    conn = sqlite3.connect(str(db_file))
    conn.execute("""
        CREATE TABLE events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source_type TEXT NOT NULL,
            event_type TEXT NOT NULL,
            action TEXT NOT NULL,
            status TEXT NOT NULL,
            username TEXT,
            source_ip TEXT,
            destination_ip TEXT,
            port INTEGER,
            service TEXT,
            message TEXT,
            raw_log TEXT,
            metadata TEXT,
            event_hash TEXT UNIQUE NOT NULL
        );
    """)
    # Insert a pre-existing legacy event
    conn.execute("""
        INSERT INTO events (timestamp, source_type, event_type, action, status, username, message, raw_log, metadata, event_hash)
        VALUES ('2026-11-05T00:00:00', 'legacy', 'auth', 'LOGIN', 'SUCCESS', 'alice', 'legacy log', 'raw', '{}', 'hash_legacy_1');
    """)
    conn.commit()
    conn.close()

    # Instantiate DatabaseManager (triggers idempotent migration)
    db = DatabaseManager(db_path=db_file)

    # Verify legacy row is preserved
    legacy_events = db.get_events()
    assert len(legacy_events) == 1
    assert legacy_events[0]["username"] == "alice"
    assert legacy_events[0]["hostname"] is None  # newly added column defaults to None

    # Verify we can insert an event with all extended telemetry fields
    new_event = NormalizedEvent(
        timestamp=datetime(2026, 11, 5, 1, 0, 0, tzinfo=timezone.utc),
        source_type="windows_events",
        event_type="authentication",
        action="LOGIN",
        status="SUCCESS",
        username="bob",
        source_ip="192.168.1.50",
        hostname="WS-01",
        channel="Security",
        record_id=9999,
        process_name="lsass.exe",
        process_id=500
    )
    inserted, dup = db.insert_events([new_event])
    assert inserted == 1
    assert dup == 0

    # Retrieve and verify extended columns
    filtered = db.get_events(username="bob", channel="Security")
    assert len(filtered) == 1
    assert filtered[0]["hostname"] == "WS-01"
    assert filtered[0]["record_id"] == 9999
    assert filtered[0]["process_name"] == "lsass.exe"

    # Re-running init_database() must be completely idempotent
    db.init_database()
    assert len(db.get_events()) == 2
