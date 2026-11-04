"""Unusual authentication patterns detection rule (high burst rate)."""

from collections import defaultdict
from datetime import timedelta
from typing import List, Dict, Any, Optional
from loganalyzer.detection.base import BaseDetectionRule
from loganalyzer.schema import NormalizedEvent, DetectionRecord, ActionType


class UnusualPatternsRule(BaseDetectionRule):
    """Detects abnormal burst velocity of authentication transactions within a short window."""

    DEFAULT_RULE_ID = "RULE_UNUSUAL_PATTERNS"
    DEFAULT_RULE_NAME = "Unusual Authentication Pattern (High Burst Rate)"

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        cfg = config or {}
        if "rule_id" not in cfg:
            cfg["rule_id"] = self.DEFAULT_RULE_ID
        if "rule_name" not in cfg:
            cfg["rule_name"] = self.DEFAULT_RULE_NAME
        super().__init__(cfg)
        self.burst_threshold = self.config.get("burst_threshold", 12)
        self.burst_window = timedelta(seconds=self.config.get("burst_window_seconds", 60))

    def evaluate(self, events: List[NormalizedEvent]) -> List[DetectionRecord]:
        if not self.enabled:
            return []

        detections: List[DetectionRecord] = []
        auth_events = [
            e for e in sorted(events, key=lambda x: x.timestamp)
            if e.source_ip and (e.event_type in ("authentication", "security") or e.action in (ActionType.LOGIN.value, ActionType.FAILED_LOGIN.value))
        ]

        if not auth_events:
            return detections

        by_ip = defaultdict(list)
        for ev in auth_events:
            by_ip[ev.source_ip].append(ev)

        for src_ip, ev_list in by_ip.items():
            n = len(ev_list)
            i = 0
            while i < n:
                window_events = [ev_list[i]]
                j = i + 1
                while j < n and (ev_list[j].timestamp - ev_list[i].timestamp) <= self.burst_window:
                    window_events.append(ev_list[j])
                    j += 1

                if len(window_events) >= self.burst_threshold:
                    event_ids = [e.event_id for e in window_events if e.event_id is not None]
                    first_ts = window_events[0].timestamp
                    last_ts = window_events[-1].timestamp
                    duration_s = int((last_ts - first_ts).total_seconds())

                    accounts = list({e.username for e in window_events if e.username})

                    det = DetectionRecord(
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        severity=self.severity,
                        description=(
                            f"Unusual high-frequency burst authentication detected: {len(window_events)} attempts "
                            f"from IP '{src_ip}' in {max(1, duration_s)}s (Threshold: {self.burst_threshold} per {int(self.burst_window.total_seconds())}s)."
                        ),
                        timestamp=last_ts,
                        source_ip=src_ip,
                        username=accounts[0] if accounts else None,
                        affected_accounts=accounts,
                        event_count=len(window_events),
                        related_event_ids=event_ids,
                        mitre_technique_id="T1499",
                        mitre_technique_name="Endpoint Denial of Service",
                        evidence={
                            "burst_count": len(window_events),
                            "duration_seconds": duration_s,
                            "velocity_per_second": round(len(window_events) / max(1, duration_s), 2),
                            "source_ip": src_ip
                        }
                    )
                    detections.append(det)
                    i = j
                else:
                    i += 1

        return detections
