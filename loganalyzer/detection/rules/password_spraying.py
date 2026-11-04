"""Password Spraying Attack detection rule."""

from collections import defaultdict
from datetime import timedelta
from typing import List, Dict, Any, Optional, Set
from loganalyzer.detection.base import BaseDetectionRule
from loganalyzer.schema import NormalizedEvent, DetectionRecord, ActionType, EventStatus


class PasswordSprayingRule(BaseDetectionRule):
    """
    Detects password spraying: attempts against multiple distinct accounts
    from the same source IP within a time window, evading per-account lockout.
    """

    DEFAULT_RULE_ID = "RULE_PASSWORD_SPRAY"
    DEFAULT_RULE_NAME = "Password Spraying Attack"

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        cfg = config or {}
        if "rule_id" not in cfg:
            cfg["rule_id"] = self.DEFAULT_RULE_ID
        if "rule_name" not in cfg:
            cfg["rule_name"] = self.DEFAULT_RULE_NAME
        super().__init__(cfg)
        self.min_accounts = self.config.get("min_accounts", 3)
        self.max_failures_per_account = self.config.get("max_failures_per_account", 4)
        self.time_window = timedelta(minutes=self.config.get("time_window_minutes", 15))

    def evaluate(self, events: List[NormalizedEvent]) -> List[DetectionRecord]:
        if not self.enabled:
            return []

        detections: List[DetectionRecord] = []
        # Filter failed logins with both source IP and username
        failures = [
            e for e in events
            if (e.status == EventStatus.FAILURE.value or e.action == ActionType.FAILED_LOGIN.value)
            and e.source_ip and e.username
        ]
        if not failures:
            return detections

        # Group by source_ip
        by_ip = defaultdict(list)
        for ev in sorted(failures, key=lambda x: x.timestamp):
            by_ip[ev.source_ip].append(ev)

        for src_ip, ev_list in by_ip.items():
            n = len(ev_list)
            i = 0
            while i < n:
                window_events = [ev_list[i]]
                target_accounts: Set[str] = {ev_list[i].username}
                user_counts: Dict[str, int] = defaultdict(int)
                user_counts[ev_list[i].username] += 1

                j = i + 1
                while j < n and (ev_list[j].timestamp - ev_list[i].timestamp) <= self.time_window:
                    u = ev_list[j].username
                    target_accounts.add(u)
                    user_counts[u] += 1
                    window_events.append(ev_list[j])
                    j += 1

                # Check spraying criteria:
                # 1. Distinct target accounts >= min_accounts
                # 2. Maximum attempts per single account remains low (spray behavior, avoiding brute force misclassification)
                distinct_count = len(target_accounts)
                avg_per_acct = len(window_events) / distinct_count if distinct_count > 0 else 0
                max_per_acct = max(user_counts.values()) if user_counts else 0

                if distinct_count >= self.min_accounts and max_per_acct <= (self.max_failures_per_account + 1):
                    event_ids = [e.event_id for e in window_events if e.event_id is not None]
                    first_ts = window_events[0].timestamp
                    last_ts = window_events[-1].timestamp
                    duration_s = int((last_ts - first_ts).total_seconds())

                    accts_sorted = sorted(list(target_accounts))
                    det = DetectionRecord(
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        severity=self.severity,
                        description=(
                            f"Password spraying detected from IP '{src_ip}': {len(window_events)} failed login "
                            f"attempts distributed across {distinct_count} distinct user accounts within {max(1, duration_s)}s."
                        ),
                        timestamp=last_ts,
                        source_ip=src_ip,
                        username=accts_sorted[0] if accts_sorted else None,
                        affected_accounts=accts_sorted,
                        event_count=len(window_events),
                        related_event_ids=event_ids,
                        mitre_technique_id="T1110.003",
                        mitre_technique_name="Brute Force: Password Spraying",
                        evidence={
                            "distinct_accounts_count": distinct_count,
                            "targeted_accounts": accts_sorted,
                            "total_attempts": len(window_events),
                            "avg_attempts_per_account": round(avg_per_acct, 2),
                            "time_window_seconds": duration_s
                        }
                    )
                    detections.append(det)
                    i = j
                else:
                    i += 1

        return detections
