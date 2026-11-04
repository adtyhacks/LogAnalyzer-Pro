"""Repeated suspicious source IP activity detection rule."""

from collections import defaultdict
from datetime import timedelta
from typing import List, Dict, Any, Optional
from loganalyzer.detection.base import BaseDetectionRule
from loganalyzer.schema import NormalizedEvent, DetectionRecord, EventStatus, ActionType


class RepeatedSuspiciousIpRule(BaseDetectionRule):
    """Detects recurring suspicious activity originating from the same IP across multiple distinct waves/sessions."""

    DEFAULT_RULE_ID = "RULE_REPEATED_SUSPICIOUS_IP"
    DEFAULT_RULE_NAME = "Repeated Suspicious Source IP Activity"

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        cfg = config or {}
        if "rule_id" not in cfg:
            cfg["rule_id"] = self.DEFAULT_RULE_ID
        if "rule_name" not in cfg:
            cfg["rule_name"] = self.DEFAULT_RULE_NAME
        super().__init__(cfg)
        self.min_waves = self.config.get("min_detections", 2)
        # Separate waves by at least 15 minutes of inactivity or distinct time intervals
        self.wave_gap = timedelta(minutes=15)

    def evaluate(self, events: List[NormalizedEvent]) -> List[DetectionRecord]:
        if not self.enabled:
            return []

        detections: List[DetectionRecord] = []
        failures = [
            e for e in sorted(events, key=lambda x: x.timestamp)
            if e.source_ip and (e.status == EventStatus.FAILURE.value or e.action == ActionType.FAILED_LOGIN.value)
        ]

        if not failures:
            return detections

        by_ip = defaultdict(list)
        for ev in failures:
            by_ip[ev.source_ip].append(ev)

        for src_ip, ev_list in by_ip.items():
            # Identify distinct time clusters (waves)
            waves = []
            current_wave = [ev_list[0]]

            for i in range(1, len(ev_list)):
                prev_ev = ev_list[i - 1]
                curr_ev = ev_list[i]
                if (curr_ev.timestamp - prev_ev.timestamp) > self.wave_gap:
                    waves.append(current_wave)
                    current_wave = [curr_ev]
                else:
                    current_wave.append(curr_ev)
            waves.append(current_wave)

            # Filter waves that had significant failure counts (>= 2)
            significant_waves = [w for w in waves if len(w) >= 2]

            if len(significant_waves) >= self.min_waves:
                all_wave_events = [ev for w in significant_waves for ev in w]
                event_ids = [e.event_id for e in all_wave_events if e.event_id is not None]
                accounts = list({e.username for e in all_wave_events if e.username})

                det = DetectionRecord(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=self.severity,
                    description=(
                        f"Repeated suspicious activity from IP '{src_ip}': Detected {len(significant_waves)} distinct "
                        f"attack waves comprising {len(all_wave_events)} failures across {len(accounts)} targeted accounts."
                    ),
                    timestamp=significant_waves[-1][-1].timestamp,
                    source_ip=src_ip,
                    username=accounts[0] if accounts else None,
                    affected_accounts=accounts,
                    event_count=len(all_wave_events),
                    related_event_ids=event_ids,
                    mitre_technique_id="T1110.001",
                    mitre_technique_name="Brute Force: Password Guessing",
                    evidence={
                        "wave_count": len(significant_waves),
                        "total_failures": len(all_wave_events),
                        "targeted_accounts": accounts,
                        "first_wave": significant_waves[0][0].timestamp.isoformat(),
                        "latest_wave": significant_waves[-1][-1].timestamp.isoformat()
                    }
                )
                detections.append(det)

        return detections
