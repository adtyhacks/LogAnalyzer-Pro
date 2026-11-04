"""Suspicious successful login after repeated failures detection rule."""

from collections import defaultdict
from datetime import timedelta
from typing import List, Dict, Any, Optional
from loganalyzer.detection.base import BaseDetectionRule
from loganalyzer.schema import NormalizedEvent, DetectionRecord, ActionType, EventStatus


class SuspiciousSuccessRule(BaseDetectionRule):
    """
    Detects a successful authentication preceded by repeated failed login
    attempts from the same source IP or targeting the same username.
    """

    DEFAULT_RULE_ID = "RULE_SUSPICIOUS_SUCCESS"
    DEFAULT_RULE_NAME = "Suspicious Successful Login After Repeated Failures"

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        cfg = config or {}
        if "rule_id" not in cfg:
            cfg["rule_id"] = self.DEFAULT_RULE_ID
        if "rule_name" not in cfg:
            cfg["rule_name"] = self.DEFAULT_RULE_NAME
        super().__init__(cfg)
        self.min_failures = self.config.get("min_failures_before_success", 3)
        self.time_window = timedelta(minutes=self.config.get("time_window_minutes", 15))

    def evaluate(self, events: List[NormalizedEvent]) -> List[DetectionRecord]:
        if not self.enabled:
            return []

        detections: List[DetectionRecord] = []
        # Sort all authentication events chronologically
        auth_events = [
            e for e in sorted(events, key=lambda x: x.timestamp)
            if e.event_type in ("authentication", "security") or e.action in (ActionType.LOGIN.value, ActionType.FAILED_LOGIN.value)
        ]

        if not auth_events:
            return detections

        # Group by (source_ip) or (username)
        # We check both: same IP followed by success, or same username followed by success
        for idx, ev in enumerate(auth_events):
            if ev.status != EventStatus.SUCCESS.value and ev.action != ActionType.LOGIN.value:
                continue

            # This is a SUCCESS login event. Look backwards within time_window
            success_time = ev.timestamp
            prior_failures: List[NormalizedEvent] = []

            for past_ev in reversed(auth_events[:idx]):
                if (success_time - past_ev.timestamp) > self.time_window:
                    break

                # Check if it was a failure and shares either source_ip or username
                is_fail = (past_ev.status == EventStatus.FAILURE.value or past_ev.action == ActionType.FAILED_LOGIN.value)
                matches_identity = (
                    (ev.source_ip and past_ev.source_ip and ev.source_ip == past_ev.source_ip) or
                    (ev.username and past_ev.username and ev.username == past_ev.username)
                )

                if matches_identity:
                    if is_fail:
                        prior_failures.append(past_ev)
                    elif past_ev.status == EventStatus.SUCCESS.value or past_ev.action == ActionType.LOGIN.value:
                        # Intervening successful authentication resets the failure chain
                        break

            if len(prior_failures) >= self.min_failures:
                related_ids = [e.event_id for e in prior_failures if e.event_id is not None]
                if ev.event_id:
                    related_ids.append(ev.event_id)

                det = DetectionRecord(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=self.severity,
                    description=(
                        f"Potential credential compromise: User '{ev.username or 'unknown'}' successfully logged in "
                        f"from IP '{ev.source_ip or 'unknown'}' after {len(prior_failures)} preceding failed login attempts."
                    ),
                    timestamp=ev.timestamp,
                    source_ip=ev.source_ip,
                    username=ev.username,
                    affected_accounts=[ev.username] if ev.username else [],
                    event_count=len(prior_failures) + 1,
                    related_event_ids=related_ids,
                    mitre_technique_id="T1078",
                    mitre_technique_name="Valid Accounts",
                    evidence={
                        "successful_timestamp": ev.timestamp.isoformat(),
                        "prior_failure_count": len(prior_failures),
                        "compromised_account": ev.username,
                        "origin_ip": ev.source_ip
                    }
                )
                detections.append(det)

        return detections
