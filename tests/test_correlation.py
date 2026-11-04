"""Automated tests for event correlation and incident grouping."""

from datetime import datetime, timedelta
from loganalyzer.correlation.correlator import CorrelationEngine
from loganalyzer.schema import NormalizedEvent, DetectionRecord, EventStatus, ActionType


def test_correlation_groups_by_ip_and_avoids_duplicates(temp_db):
    correlator = CorrelationEngine(db_manager=temp_db)
    base_time = datetime(2026, 10, 24, 10, 0, 0)

    # Detections from same IP 198.51.100.5 within window
    det1 = DetectionRecord(
        rule_id="RULE_BRUTE_FORCE",
        rule_name="Brute-Force Authentication Attempt",
        severity="HIGH",
        description="Brute force detected",
        timestamp=base_time,
        source_ip="198.51.100.5",
        username="admin",
        affected_accounts=["admin"],
        related_event_ids=[1, 2, 3],
        mitre_technique_id="T1110.001",
        detection_id=1
    )

    det2 = DetectionRecord(
        rule_id="RULE_SUSPICIOUS_SUCCESS",
        rule_name="Suspicious Successful Login After Repeated Failures",
        severity="CRITICAL",
        description="Login after failure detected",
        timestamp=base_time + timedelta(minutes=5),
        source_ip="198.51.100.5",
        username="admin",
        affected_accounts=["admin"],
        related_event_ids=[4],
        mitre_technique_id="T1078",
        detection_id=2
    )

    events = [
        NormalizedEvent(
            timestamp=base_time,
            source_type="test",
            event_type="authentication",
            action=ActionType.FAILED_LOGIN.value,
            status=EventStatus.FAILURE.value,
            username="admin",
            source_ip="198.51.100.5",
            event_id=1
        )
    ]

    incidents = correlator.correlate(events, [det1, det2], persist=True)

    # Correlated into 1 single comprehensive incident
    assert len(incidents) == 1
    inc = incidents[0]
    assert inc.source_ip == "198.51.100.5"
    assert "admin" in inc.affected_accounts
    assert "T1110.001" in inc.mitre_techniques
    assert "T1078" in inc.mitre_techniques
    assert inc.severity in ("HIGH", "CRITICAL")
    assert inc.risk_score >= 60.0

    # Test persistence and re-correlation avoidance
    db_incidents = temp_db.get_incidents()
    assert len(db_incidents) == 1
    assert db_incidents[0]["incident_id"] == inc.incident_id
