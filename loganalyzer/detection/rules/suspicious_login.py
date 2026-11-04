"""Suspicious login activity detection rule."""

from typing import List, Dict, Any, Optional
from loganalyzer.detection.base import BaseDetectionRule
from loganalyzer.schema import NormalizedEvent, DetectionRecord, ActionType, EventStatus


class SuspiciousLoginRule(BaseDetectionRule):
    """Detects suspicious successful logins, particularly to high-privilege or system accounts."""

    DEFAULT_RULE_ID = "RULE_SUSPICIOUS_LOGIN"
    DEFAULT_RULE_NAME = "Suspicious Privileged Account Login"
    DEFAULT_PRIV_ACCOUNTS = ["root", "administrator", "admin", "system", "sa", "oracle"]

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        cfg = config or {}
        if "rule_id" not in cfg:
            cfg["rule_id"] = self.DEFAULT_RULE_ID
        if "rule_name" not in cfg:
            cfg["rule_name"] = self.DEFAULT_RULE_NAME
        super().__init__(cfg)
        self.privileged_accounts = set(
            a.lower() for a in self.config.get("privileged_accounts", self.DEFAULT_PRIV_ACCOUNTS)
        )

    def evaluate(self, events: List[NormalizedEvent]) -> List[DetectionRecord]:
        if not self.enabled:
            return []

        detections: List[DetectionRecord] = []
        for ev in events:
            # Check successful logins or privilege escalations
            is_success_login = (
                (ev.status == EventStatus.SUCCESS.value or ev.action in (ActionType.LOGIN.value, ActionType.PRIVILEGE_ESCALATION.value))
                and ev.username
            )
            if not is_success_login:
                continue

            username_clean = ev.username.strip().lower()
            if username_clean in self.privileged_accounts:
                event_ids = [ev.event_id] if ev.event_id else []
                det = DetectionRecord(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=self.severity,
                    description=(
                        f"Suspicious privileged account login: Account '{ev.username}' successfully authenticated "
                        f"from IP '{ev.source_ip or 'unknown'}' via {ev.service or 'service'}."
                    ),
                    timestamp=ev.timestamp,
                    source_ip=ev.source_ip,
                    username=ev.username,
                    affected_accounts=[ev.username],
                    event_count=1,
                    related_event_ids=event_ids,
                    mitre_technique_id="T1078.003",
                    mitre_technique_name="Valid Accounts: Local Accounts",
                    evidence={
                        "account": ev.username,
                        "source_ip": ev.source_ip,
                        "service": ev.service,
                        "action": ev.action,
                        "metadata": ev.metadata
                    }
                )
                detections.append(det)

        return detections
