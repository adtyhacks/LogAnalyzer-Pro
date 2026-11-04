"""Automated unit tests for all 7 detection engine rules."""

from datetime import datetime, timedelta
import pytest
from loganalyzer.config import utc_now
from loganalyzer.schema import NormalizedEvent, EventStatus, ActionType
from loganalyzer.detection.rules.brute_force import BruteForceRule
from loganalyzer.detection.rules.password_spraying import PasswordSprayingRule
from loganalyzer.detection.rules.suspicious_success import SuspiciousSuccessRule
from loganalyzer.detection.rules.multi_account_fail import MultiAccountFailRule
from loganalyzer.detection.rules.suspicious_login import SuspiciousLoginRule
from loganalyzer.detection.rules.unusual_patterns import UnusualPatternsRule
from loganalyzer.detection.rules.repeated_suspicious_ip import RepeatedSuspiciousIpRule


def test_brute_force_rule_triggers():
    rule = BruteForceRule({"threshold": 5, "time_window_minutes": 10})
    base_time = datetime(2026, 10, 24, 10, 0, 0)

    events = [
        NormalizedEvent(
            timestamp=base_time + timedelta(seconds=i * 10),
            source_type="test",
            event_type="authentication",
            action=ActionType.FAILED_LOGIN.value,
            status=EventStatus.FAILURE.value,
            username="target_user",
            source_ip="198.51.100.99",
            event_id=i
        )
        for i in range(6)
    ]

    detections = rule.evaluate(events)
    assert len(detections) >= 1
    det = detections[0]
    assert det.rule_id == "RULE_BRUTE_FORCE"
    assert det.source_ip == "198.51.100.99"
    assert det.username == "target_user"
    assert det.mitre_technique_id == "T1110.001"


def test_password_spraying_rule_triggers():
    rule = PasswordSprayingRule({"min_accounts": 3, "time_window_minutes": 15})
    base_time = datetime(2026, 10, 24, 10, 0, 0)

    users = ["user1", "user2", "user3", "user4"]
    events = [
        NormalizedEvent(
            timestamp=base_time + timedelta(seconds=i * 20),
            source_type="test",
            event_type="authentication",
            action=ActionType.FAILED_LOGIN.value,
            status=EventStatus.FAILURE.value,
            username=u,
            source_ip="198.51.100.22",
            event_id=i
        )
        for i, u in enumerate(users)
    ]

    detections = rule.evaluate(events)
    assert len(detections) >= 1
    det = detections[0]
    assert det.rule_id == "RULE_PASSWORD_SPRAY"
    assert det.source_ip == "198.51.100.22"
    assert len(det.affected_accounts) >= 3
    assert det.mitre_technique_id == "T1110.003"


def test_suspicious_success_rule_triggers():
    rule = SuspiciousSuccessRule({"min_failures_before_success": 3, "time_window_minutes": 15})
    base_time = datetime(2026, 10, 24, 10, 0, 0)

    events = [
        NormalizedEvent(
            timestamp=base_time + timedelta(seconds=i * 10),
            source_type="test",
            event_type="authentication",
            action=ActionType.FAILED_LOGIN.value,
            status=EventStatus.FAILURE.value,
            username="victim",
            source_ip="203.0.113.10",
            event_id=i
        )
        for i in range(4)
    ]

    # Followed by success
    events.append(NormalizedEvent(
        timestamp=base_time + timedelta(seconds=50),
        source_type="test",
        event_type="authentication",
        action=ActionType.LOGIN.value,
        status=EventStatus.SUCCESS.value,
        username="victim",
        source_ip="203.0.113.10",
        event_id=99
    ))

    detections = rule.evaluate(events)
    assert len(detections) == 1
    det = detections[0]
    assert det.rule_id == "RULE_SUSPICIOUS_SUCCESS"
    assert det.username == "victim"
    assert det.source_ip == "203.0.113.10"
    assert det.mitre_technique_id == "T1078"


def test_multi_account_fail_rule_triggers():
    rule = MultiAccountFailRule({"min_accounts": 4, "min_failures": 5, "time_window_minutes": 20})
    base_time = datetime(2026, 10, 24, 10, 0, 0)

    users = ["usrA", "usrB", "usrC", "usrD", "usrE"]
    events = [
        NormalizedEvent(
            timestamp=base_time + timedelta(seconds=i * 15),
            source_type="test",
            event_type="authentication",
            action=ActionType.FAILED_LOGIN.value,
            status=EventStatus.FAILURE.value,
            username=u,
            source_ip="192.0.2.77",
            event_id=i
        )
        for i, u in enumerate(users)
    ]

    detections = rule.evaluate(events)
    assert len(detections) >= 1
    assert detections[0].rule_id == "RULE_MULTI_ACCOUNT_FAIL"


def test_suspicious_login_rule_triggers():
    rule = SuspiciousLoginRule({"privileged_accounts": ["root", "administrator"]})
    event = NormalizedEvent(
        timestamp=utc_now(),
        source_type="test",
        event_type="authentication",
        action=ActionType.LOGIN.value,
        status=EventStatus.SUCCESS.value,
        username="root",
        source_ip="198.51.100.5",
        event_id=1
    )

    detections = rule.evaluate([event])
    assert len(detections) == 1
    assert detections[0].rule_id == "RULE_SUSPICIOUS_LOGIN"
    assert detections[0].username == "root"


def test_unusual_patterns_burst_rule():
    rule = UnusualPatternsRule({"burst_threshold": 10, "burst_window_seconds": 60})
    base_time = datetime(2026, 10, 24, 10, 0, 0)

    events = [
        NormalizedEvent(
            timestamp=base_time + timedelta(seconds=i * 2),
            source_type="test",
            event_type="authentication",
            action=ActionType.FAILED_LOGIN.value,
            status=EventStatus.FAILURE.value,
            username=f"user_{i}",
            source_ip="198.51.100.40",
            event_id=i
        )
        for i in range(12)
    ]

    detections = rule.evaluate(events)
    assert len(detections) >= 1
    assert detections[0].rule_id == "RULE_UNUSUAL_PATTERNS"
    assert detections[0].mitre_technique_id == "T1499"


def test_repeated_suspicious_ip_rule():
    rule = RepeatedSuspiciousIpRule({"min_detections": 2})
    base_time = datetime(2026, 10, 24, 10, 0, 0)

    events = []
    # Wave 1: 3 failures
    for i in range(3):
        events.append(NormalizedEvent(
            timestamp=base_time + timedelta(seconds=i * 10),
            source_type="test",
            event_type="authentication",
            action=ActionType.FAILED_LOGIN.value,
            status=EventStatus.FAILURE.value,
            username="admin",
            source_ip="198.51.100.80",
            event_id=i
        ))

    # Wave 2: 3 failures after 30 minutes
    wave2_time = base_time + timedelta(minutes=30)
    for i in range(3):
        events.append(NormalizedEvent(
            timestamp=wave2_time + timedelta(seconds=i * 10),
            source_type="test",
            event_type="authentication",
            action=ActionType.FAILED_LOGIN.value,
            status=EventStatus.FAILURE.value,
            username="admin",
            source_ip="198.51.100.80",
            event_id=i + 10
        ))

    detections = rule.evaluate(events)
    assert len(detections) >= 1
    assert detections[0].rule_id == "RULE_REPEATED_SUSPICIOUS_IP"


def test_brute_force_boundary_below_threshold():
    """Boundary test: 4 failures when threshold is 5 should NOT trigger."""
    rule = BruteForceRule({"threshold": 5, "time_window_minutes": 10})
    base_time = datetime(2026, 10, 24, 10, 0, 0)

    events = [
        NormalizedEvent(
            timestamp=base_time + timedelta(seconds=i * 10),
            source_type="test",
            event_type="authentication",
            action=ActionType.FAILED_LOGIN.value,
            status=EventStatus.FAILURE.value,
            username="target_user",
            source_ip="198.51.100.99",
            event_id=i
        )
        for i in range(4)
    ]
    detections = rule.evaluate(events)
    assert len(detections) == 0


def test_brute_force_events_outside_time_window():
    """Events spaced beyond the configured time window should NOT trigger."""
    rule = BruteForceRule({"threshold": 5, "time_window_minutes": 10})
    base_time = datetime(2026, 10, 24, 10, 0, 0)

    # 5 events spaced 3 minutes apart = 12 minutes total duration (> 10 mins)
    events = [
        NormalizedEvent(
            timestamp=base_time + timedelta(minutes=i * 3),
            source_type="test",
            event_type="authentication",
            action=ActionType.FAILED_LOGIN.value,
            status=EventStatus.FAILURE.value,
            username="target_user",
            source_ip="198.51.100.99",
            event_id=i
        )
        for i in range(5)
    ]
    detections = rule.evaluate(events)
    assert len(detections) == 0


def test_password_spraying_vs_brute_force_separation():
    """
    Ensure the system strictly distinguishes targeted single-account brute-force
    from multi-account password spraying.
    """
    spray_rule = PasswordSprayingRule({"min_accounts": 3, "max_failures_per_account": 3, "time_window_minutes": 15})
    bf_rule = BruteForceRule({"threshold": 5, "time_window_minutes": 10})
    base_time = datetime(2026, 10, 24, 10, 0, 0)

    # Scenario 1: Attacker hits 1 account with 8 failures (Pure Brute Force)
    bf_events = [
        NormalizedEvent(
            timestamp=base_time + timedelta(seconds=i * 10),
            source_type="test",
            event_type="authentication",
            action=ActionType.FAILED_LOGIN.value,
            status=EventStatus.FAILURE.value,
            username="admin",
            source_ip="198.51.100.22",
            event_id=i
        )
        for i in range(8)
    ]
    assert len(bf_rule.evaluate(bf_events)) >= 1
    assert len(spray_rule.evaluate(bf_events)) == 0  # Must NOT confuse with spray

    # Scenario 2: Attacker hits 4 accounts with 2 attempts each (Pure Spray)
    spray_events = []
    idx = 0
    for u in ["userA", "userB", "userC", "userD"]:
        for _ in range(2):
            spray_events.append(NormalizedEvent(
                timestamp=base_time + timedelta(seconds=idx * 15),
                source_type="test",
                event_type="authentication",
                action=ActionType.FAILED_LOGIN.value,
                status=EventStatus.FAILURE.value,
                username=u,
                source_ip="198.51.100.22",
                event_id=idx
            ))
            idx += 1

    assert len(spray_rule.evaluate(spray_events)) >= 1
    # BF rule on per-(ip,user) should NOT trigger because max per account is 2 (< threshold 5)
    assert len(bf_rule.evaluate(spray_events)) == 0


def test_suspicious_success_with_intervening_success():
    """An intervening success resets prior failures so subsequent logins don't re-trigger."""
    rule = SuspiciousSuccessRule({"min_failures_before_success": 3, "time_window_minutes": 15})
    base_time = datetime(2026, 10, 24, 10, 0, 0)

    # 3 failures
    events = [
        NormalizedEvent(
            timestamp=base_time + timedelta(seconds=i * 10),
            source_type="test",
            event_type="authentication",
            action=ActionType.FAILED_LOGIN.value,
            status=EventStatus.FAILURE.value,
            username="victim",
            source_ip="203.0.113.10",
            event_id=i
        )
        for i in range(3)
    ]
    # Success 1 -> Triggers alert
    events.append(NormalizedEvent(
        timestamp=base_time + timedelta(seconds=40),
        source_type="test",
        event_type="authentication",
        action=ActionType.LOGIN.value,
        status=EventStatus.SUCCESS.value,
        username="victim",
        source_ip="203.0.113.10",
        event_id=10
    ))
    # Immediate Success 2 (no new failures) -> Should NOT produce a duplicate alert
    events.append(NormalizedEvent(
        timestamp=base_time + timedelta(seconds=45),
        source_type="test",
        event_type="authentication",
        action=ActionType.LOGIN.value,
        status=EventStatus.SUCCESS.value,
        username="victim",
        source_ip="203.0.113.10",
        event_id=11
    ))

    detections = rule.evaluate(events)
    assert len(detections) == 1  # Exactly 1 detection, not 2


def test_detection_rules_empty_dataset():
    """All rules should gracefully handle empty event lists."""
    rules = [
        BruteForceRule(),
        PasswordSprayingRule(),
        SuspiciousSuccessRule(),
        MultiAccountFailRule(),
        SuspiciousLoginRule(),
        UnusualPatternsRule(),
        RepeatedSuspiciousIpRule()
    ]
    for r in rules:
        assert r.evaluate([]) == []


def test_detection_rules_malformed_events():
    """Rules should handle events with missing or None attributes safely."""
    base_time = datetime(2026, 10, 24, 10, 0, 0)
    malformed = [
        NormalizedEvent(
            timestamp=base_time,
            source_type="corrupt",
            event_type="unknown",
            action="UNKNOWN",
            status="UNKNOWN",
            username=None,
            source_ip=None,
            event_id=None
        )
    ]
    rules = [
        BruteForceRule(),
        PasswordSprayingRule(),
        SuspiciousSuccessRule(),
        MultiAccountFailRule(),
        SuspiciousLoginRule(),
        UnusualPatternsRule(),
        RepeatedSuspiciousIpRule()
    ]
    for r in rules:
        res = r.evaluate(malformed)
        assert isinstance(res, list)


def test_different_source_ips_isolation():
    """Failures across disparate source IPs should not be incorrectly combined into a single brute-force."""
    rule = BruteForceRule({"threshold": 5, "time_window_minutes": 10})
    base_time = datetime(2026, 10, 24, 10, 0, 0)

    events = []
    # 3 failures from IP 1.1.1.1
    for i in range(3):
        events.append(NormalizedEvent(
            timestamp=base_time + timedelta(seconds=i * 10),
            source_type="test",
            event_type="authentication",
            action=ActionType.FAILED_LOGIN.value,
            status=EventStatus.FAILURE.value,
            username="admin",
            source_ip="1.1.1.1",
            event_id=i
        ))
    # 3 failures from IP 2.2.2.2
    for i in range(3):
        events.append(NormalizedEvent(
            timestamp=base_time + timedelta(seconds=i * 10),
            source_type="test",
            event_type="authentication",
            action=ActionType.FAILED_LOGIN.value,
            status=EventStatus.FAILURE.value,
            username="admin",
            source_ip="2.2.2.2",
            event_id=i + 10
        ))

    detections = rule.evaluate(events)
    # Neither IP reached threshold 5, so no detection should be triggered
    assert len(detections) == 0

