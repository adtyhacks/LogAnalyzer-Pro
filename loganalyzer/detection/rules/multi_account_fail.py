"""Multiple account failures from one source IP detection rule."""

from collections import defaultdict
from datetime import timedelta
from typing import List, Dict, Any, Optional, Set
from loganalyzer.detection.base import BaseDetectionRule
from loganalyzer.schema import NormalizedEvent, DetectionRecord, ActionType, EventStatus


class MultiAccountFailRule(BaseDetectionRule):
    """Detects a single source IP causing authentication failures across multiple distinct accounts."""

    DEFAULT_RULE_ID = "RULE_MULTI_ACCOUNT_FAIL"
    DEFAULT_RULE_NAME = "Multiple Account Failures from Single Source IP"

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        cfg = config or {}
        if "rule_id" not in cfg:
            cfg["rule_id"] = self.DEFAULT_RULE_ID
        if "rule_name" not in cfg:
            cfg["rule_name"] = self.DEFAULT_RULE_NAME
        super().__init__(cfg)
        self.min_accounts = self.config.get("min_accounts", 4)
        self.min_failures = self.config.get("min_failures", 6)
        self.time_window = timedelta(minutes=self.config.get("time_window_minutes", 20))

    def evaluate(self, events: List[NormalizedEvent]) -> List[DetectionRecord]:
        if not self.enabled:
            return []

        detections: List[DetectionRecord] = []
        failures = [
            e for e in sorted(events, key=lambda x: x.timestamp)
            if (e.status == EventStatus.FAILURE.value or e.action == ActionType.FAILED_LOGIN.value)
            and e.source_ip and e.username
        ]

        if not failures:
            return detections

        by_ip = defaultdict(list)
        for ev in failures:
            by_ip[ev.source_ip].append(ev)

        for src_ip, ev_list in by_ip.items():
            n = len(ev_list)
            i = 0
            while i < n:
                window_events = [ev_list[i]]
                accounts: Set[str] = {ev_list[i].username}

                j = i + 1
                while j < n and (ev_list[j].timestamp - ev_list[i].timestamp) <= self.time_window:
                    accounts.add(ev_list[j].username)
                    window_events.append(ev_list[j])
                    j += 1

                if len(accounts) >= self.min_accounts and len(window_events) >= self.min_failures:
                    accts_list = sorted(list(accounts))
                    event_ids = [e.event_id for e in window_events if e.event_id is not None]
                    first_ts = window_events[0].timestamp
                    last_ts = window_events[-1].timestamp
                    duration_s = int((last_ts - first_ts).total_seconds())

                    det = DetectionRecord(
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        severity=self.severity,
                        description=(
                            f"Multiple account failures from single source IP '{src_ip}': {len(window_events)} "
                            f"failures across {len(accts_list)} accounts within {max(1, duration_s)}s."
                        ),
                        timestamp=last_ts,
                        source_ip=src_ip,
                        username=accts_list[0],
                        affected_accounts=accts_list,
                        event_count=len(window_events),
                        related_event_ids=event_ids,
                        mitre_technique_id="T1110.003",
                        mitre_technique_name="Brute Force: Password Spraying",
                        evidence={
                            "distinct_accounts": len(accts_list),
                            "accounts": accts_list,
                            "failure_count": len(window_events),
                            "time_window_seconds": duration_s
                        }
                    )
                    detections.append(det)
                    i = j
                else:
                    i += 1

        return detections
