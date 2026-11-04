"""Automated tests for SQLite persistence, deduplication, and queries."""

from datetime import datetime
from loganalyzer.config import utc_now
from loganalyzer.schema import NormalizedEvent, DetectionRecord, IncidentRecord, IngestionStats


def test_event_insertion_and_deduplication(temp_db, sample_normalized_events):
    # First insert
    inserted, dups = temp_db.insert_events(sample_normalized_events)
    assert inserted == len(sample_normalized_events)
    assert dups == 0

    # Second insert with identical events should deduplicate based on SHA256 hash
    inserted2, dups2 = temp_db.insert_events(sample_normalized_events)
    assert inserted2 == 0
    assert dups2 == len(sample_normalized_events)

    # Verify query
    events = temp_db.get_events(limit=50)
    assert len(events) == len(sample_normalized_events)


def test_detection_persistence(temp_db):
    det = DetectionRecord(
        rule_id="RULE_TEST",
        rule_name="Test Rule",
        severity="HIGH",
        description="Test detection description",
        timestamp=utc_now(),
        source_ip="198.51.100.10",
        username="admin",
        affected_accounts=["admin"],
        event_count=5,
        related_event_ids=[1, 2],
        mitre_technique_id="T1110.001",
        mitre_technique_name="Brute Force: Password Guessing"
    )
    det_id = temp_db.insert_detection(det)
    assert det_id is not None and det_id > 0

    detections = temp_db.get_detections(severity="HIGH")
    assert len(detections) == 1
    assert detections[0]["rule_id"] == "RULE_TEST"
    assert detections[0]["source_ip"] == "198.51.100.10"


def test_incident_lifecycle(temp_db):
    inc = IncidentRecord(
        incident_id="INC-20261024-TEST",
        title="Test Incident Title",
        severity="CRITICAL",
        risk_score=92.5,
        description="Investigation test description",
        status="OPEN",
        created_at=utc_now(),
        updated_at=utc_now(),
        source_ip="203.0.113.5",
        affected_accounts=["admin"],
        related_detection_ids=[1],
        related_event_ids=[1, 2],
        mitre_techniques=["T1110.001"],
        risk_factors=["Critical severity (+40 pts)"]
    )
    inc_id = temp_db.insert_or_update_incident(inc)
    assert inc_id > 0

    # Retrieve and verify
    incidents = temp_db.get_incidents(status="OPEN")
    assert len(incidents) == 1
    assert incidents[0]["incident_id"] == "INC-20261024-TEST"

    # Add investigation note and update status
    temp_db.add_investigation_note("INC-20261024-TEST", "SOC Lead", "Host quarantined.")
    temp_db.update_incident_status("INC-20261024-TEST", "INVESTIGATING", "Analyst assigned.")

    notes = temp_db.get_investigation_notes("INC-20261024-TEST")
    assert len(notes) == 1
    assert notes[0]["author"] == "SOC Lead"

    updated_inc = temp_db.get_incidents(status="INVESTIGATING")
    assert len(updated_inc) == 1
    assert updated_inc[0]["status"] == "INVESTIGATING"


def test_ingestion_history_and_stats_summary(temp_db):
    stats = IngestionStats(
        source_file="auth.log",
        source_type="linux_auth",
        total_records=100,
        parsed_events=98,
        duplicate_events=0,
        invalid_records=2,
        duration_seconds=0.05
    )
    temp_db.record_ingestion(stats)
    history = temp_db.get_ingestion_history()
    assert len(history) == 1
    assert history[0]["source_file"] == "auth.log"

    summary = temp_db.get_stats_summary()
    assert "total_events" in summary
    assert "total_detections" in summary
    assert "open_incidents" in summary
