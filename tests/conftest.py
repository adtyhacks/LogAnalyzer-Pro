"""Shared fixtures for LogAnalyzer Pro pytest suite."""

import pytest
from datetime import datetime, timedelta
from pathlib import Path
from loganalyzer.database import DatabaseManager
from loganalyzer.schema import NormalizedEvent, EventStatus, ActionType


@pytest.fixture
def temp_db(tmp_path: Path):
    """Provides a fresh, isolated temporary SQLite database for each test."""
    db_file = tmp_path / "test_loganalyzer.db"
    db_manager = DatabaseManager(db_path=db_file)
    yield db_manager
    if db_file.exists():
        try:
            db_file.unlink()
        except Exception:
            pass


@pytest.fixture
def sample_normalized_events():
    """Generates a small list of sample normalized events."""
    base_time = datetime(2026, 10, 24, 12, 0, 0)
    events = []

    # 5 failed logins from 198.51.100.55 for user 'admin'
    for i in range(5):
        events.append(NormalizedEvent(
            timestamp=base_time + timedelta(seconds=i * 20),
            source_type="linux_auth",
            event_type="authentication",
            action=ActionType.FAILED_LOGIN.value,
            status=EventStatus.FAILURE.value,
            username="admin",
            source_ip="198.51.100.55",
            port=22,
            service="sshd",
            message=f"Failed SSH login for admin attempt {i+1}",
            raw_log=f"Oct 24 12:0{i}:00 srv sshd[123]: Failed password for admin from 198.51.100.55 port 22 ssh2",
            event_id=i + 1
        ))

    # 1 successful login from 198.51.100.55 for user 'admin'
    events.append(NormalizedEvent(
        timestamp=base_time + timedelta(seconds=120),
        source_type="linux_auth",
        event_type="authentication",
        action=ActionType.LOGIN.value,
        status=EventStatus.SUCCESS.value,
        username="admin",
        source_ip="198.51.100.55",
        port=22,
        service="sshd",
        message="Accepted password for admin",
        raw_log="Oct 24 12:02:00 srv sshd[124]: Accepted password for admin from 198.51.100.55 port 22 ssh2",
        event_id=6
    ))

    return events
