"""Brute-Force Authentication Attempt detection rule."""

from collections import defaultdict
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from loganalyzer.detection.base import BaseDetectionRule
from loganalyzer.schema import NormalizedEvent, DetectionRecord, ActionType, EventStatus


class BruteForceRule(BaseDetectionRule):
    """Detects high volumes of failed login attempts targeting a specific account or source IP."""

    DEFAULT_RULE_ID = "RULE_BRUTE_FORCE"
    DEFAULT_RULE_NAME = "Brute-Force Authentication Attempt"

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        cfg = config or {}
        if "rule_id" not in cfg:
            cfg["rule_id"] = self.DEFAULT_RULE_ID
        if "rule_name" not in cfg:
            cfg["rule_name"] = self.DEFAULT_RULE_NAME
        super().__init__(cfg)
        self.threshold = self.config.get("threshold", 5)
        self.time_window = timedelta(minutes=self.config.get("time_window_minutes", 10))

    def evaluate(self, events: List[NormalizedEvent]) -> List[DetectionRecord]:
        if not self.enabled:
            return []

        detections: List[DetectionRecord] = []
        # Filter only failed login events
        failures = [
            e for e in events
            if e.status == EventStatus.FAILURE.value or e.action == ActionType.FAILED_LOGIN.value
        ]
        if not failures:
            return detections

        # Group by (source_ip, username) and (source_ip)
        failures_sorted = sorted(failures, key=lambda x: x.timestamp)
        by_pair = defaultdict(list)

        for ev in failures_sorted:
            key = (ev.source_ip or "unknown_ip", ev.username or "unknown_user")
            by_pair[key].append(ev)

        for (src_ip, user), ev_list in by_pair.items():
            # Sliding window over events
            n = len(ev_list)
            i = 0
            while i < n:
                window_events = [ev_list[i]]
                j = i + 1
                while j < n and (ev_list[j].timestamp - ev_list[i].timestamp) <= self.time_window:
                    window_events.append(ev_list[j])
                    j += 1

                if len(window_events) >= self.threshold:
                    event_ids = [e.event_id for e in window_events if e.event_id is not None]
                    first_ts = window_events[0].timestamp
                    last_ts = window_events[-1].timestamp
                    duration_s = int((last_ts - first_ts).total_seconds())

                    det = DetectionRecord(
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        severity=self.severity,
                        description=(
                            f"Brute-force authentication detected: {len(window_events)} failed logins "
                            f"for user '{user}' from IP '{src_ip}' within {max(1, duration_s)}s."
                        ),
                        timestamp=last_ts,
                        source_ip=src_ip if src_ip != "unknown_ip" else None,
                        username=user if user != "unknown_user" else None,
                        affected_accounts=[user] if user != "unknown_user" else [],
                        event_count=len(window_events),
                        related_event_ids=event_ids,
                        mitre_technique_id="T1110.001",
                        mitre_technique_name="Brute Force: Password Guessing",
                        evidence={
                            "failure_count": len(window_events),
                            "time_window_seconds": duration_s,
                            "target_user": user,
                            "source_ip": src_ip
                        }
                    )
                    detections.append(det)
                    i = j  # Move past this window to avoid duplicate alerts
                else:
                    i += 1

        return detections
