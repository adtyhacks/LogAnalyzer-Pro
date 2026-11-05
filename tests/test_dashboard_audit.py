"""Automated Release-Readiness Audit Suite: Streamlit Views & Clean Install Resilience."""

import pytest
import shutil
from pathlib import Path
from streamlit.testing.v1 import AppTest
from loganalyzer.database import DatabaseManager


PAGES = [
    "🛡️ SOC Overview",
    "📥 Log Ingestion",
    "🚨 Incident Management",
    "🌐 IP Investigation",
    "🎯 MITRE ATT&CK",
    "📄 Reports & Exports"
]


def test_all_views_render_without_exception_on_current_db():
    """Verify that all 6 Streamlit dashboard views render without exceptions on populated telemetry."""
    for page_name in PAGES:
        at = AppTest.from_file("app.py", default_timeout=25)
        at.run()
        radio = at.sidebar.radio(key=None)
        radio.set_value(page_name).run()
        assert not at.exception, f"Exception on view '{page_name}': {at.exception}"


def test_clean_install_empty_database_resilience(tmp_path: Path, monkeypatch):
    """Verify that all 6 views render cleanly with zero exceptions on a brand-new, empty database."""
    empty_db_file = tmp_path / "empty_clean_install.db"
    # Ensure fresh DB schema is initialized
    db = DatabaseManager(empty_db_file)
    db.init_database()

    # Monkeypatch DATABASE_PATH in config and database modules
    monkeypatch.setattr("loganalyzer.config.DATABASE_PATH", empty_db_file)
    monkeypatch.setattr("loganalyzer.database.DATABASE_PATH", empty_db_file)

    for page_name in PAGES:
        at = AppTest.from_file("app.py", default_timeout=25)
        at.run()
        radio = at.sidebar.radio(key=None)
        radio.set_value(page_name).run()
        assert not at.exception, f"Clean-install exception on view '{page_name}': {at.exception}"


def test_incident_management_origin_filtering():
    """Verify incident filtering by telemetry origin (GENUINE, SYNTHETIC, MIXED)."""
    for origin_opt in ["ALL", "GENUINE", "SYNTHETIC", "MIXED"]:
        at = AppTest.from_file("app.py", default_timeout=25)
        at.run()
        at.sidebar.radio(key=None).set_value("🚨 Incident Management").run()
        assert not at.exception

        origin_boxes = [sb for sb in at.selectbox if sb.label == "Origin Filter"]
        assert len(origin_boxes) == 1
        origin_sb = origin_boxes[0]
        origin_sb.select(origin_opt).run()
        assert not at.exception, f"Exception when filtering by origin '{origin_opt}': {at.exception}"
