"""Invalid User Enumeration detection rule."""

from collections import defaultdict
from datetime import timedelta
from typing import List, Dict, Any, Optional, Set

from loganalyzer.detection.base import BaseDetectionRule
from loganalyzer.schema import NormalizedEvent, DetectionRecord, ActionType, EventStatus


class InvalidUserEnumerationRule(BaseDetectionRule):
    """
    Detects attempts to enumerate non-existent or invalid accounts (e.g. via SSH).
    Adversaries often attempt common default accounts to identify active usernames.
    """

    DEFAULT_RULE_ID = "RULE_INVALID_USER_ENUM"
    DEFAULT_RULE_NAME = "Invalid User Enumeration via SSH"

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        cfg = config or {}
        if "rule_id" not in cfg:
            cfg["rule_id"] = self.DEFAULT_RULE_ID
        if "rule_name" not in cfg:
            cfg["rule_name"] = self.DEFAULT_RULE_NAME
        super().__init__(cfg)
        self.threshold = self.config.get("threshold", 3)
        self.time_window = timedelta(minutes=self.config.get("time_window_minutes", 15))

    def evaluate(self, events: List[NormalizedEvent]) -> List[DetectionRecord]:
        if not self.enabled:
            return []

        detections: List[DetectionRecord] = []

        # Filter events indicating invalid user attempts
        invalid_events: List[NormalizedEvent] = []
        for e in sorted(events, key=lambda x: x.timestamp):
            is_invalid = False
            if e.metadata and e.metadata.get("invalid_user") is True:
                is_invalid = True
            elif e.raw_log and "invalid user" in e.raw_log.lower():
                is_invalid = True
            elif e.message and "invalid" in e.message.lower() and "user" in e.message.lower():
                is_invalid = True

            if is_invalid and e.source_ip:
                invalid_events.append(e)

        if not invalid_events:
            return detections

        # Group by source IP
        by_ip = defaultdict(list)
        for ev in invalid_events:
            by_ip[ev.source_ip].append(ev)

        for src_ip, ev_list in by_ip.items():
            n = len(ev_list)
            i = 0
            while i < n:
                window_events = [ev_list[i]]
                target_accounts: Set[str] = set()
                if ev_list[i].username:
                    target_accounts.add(ev_list[i].username)

                j = i + 1
                while j < n and (ev_list[j].timestamp - ev_list[i].timestamp) <= self.time_window:
                    window_events.append(ev_list[j])
                    if ev_list[j].username:
                        target_accounts.add(ev_list[j].username)
                    j += 1

                if len(window_events) >= self.threshold:
                    event_ids = [e.event_id for e in window_events if e.event_id is not None]
                    first_ts = window_events[0].timestamp
                    last_ts = window_events[-1].timestamp
                    duration_s = int((last_ts - first_ts).total_seconds())

                    accts_sorted = sorted(list(target_accounts)) if target_accounts else ["unknown"]
                    sev = "HIGH" if len(window_events) >= 6 or len(target_accounts) >= 4 else self.severity

                    det = DetectionRecord(
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        severity=sev,
                        description=(
                            f"Invalid user enumeration detected: {len(window_events)} attempts targeting "
                            f"{len(target_accounts)} non-existent account(s) ({', '.join(accts_sorted[:5])}) "
                            f"from IP '{src_ip}' within {max(1, duration_s)}s."
                        ),
                        timestamp=last_ts,
                        source_ip=src_ip,
                        username=accts_sorted[0] if len(accts_sorted) == 1 else None,
                        affected_accounts=accts_sorted,
                        event_count=len(window_events),
                        related_event_ids=event_ids,
                        mitre_technique_id="T1087.001",
                        mitre_technique_name="Account Discovery: Local Account",
                        evidence={
                            "source_ip": src_ip,
                            "attempt_count": len(window_events),
                            "targeted_invalid_accounts": accts_sorted,
                            "duration_seconds": duration_s,
                            "window_start": first_ts.isoformat(),
                            "window_end": last_ts.isoformat()
                        }
                    )
                    detections.append(det)
                    i = j
                else:
                    i += 1

        return detections
