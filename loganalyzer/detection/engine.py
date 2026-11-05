"""Detection Engine orchestrating modular rules, MITRE mapping, and persistence."""

from pathlib import Path
from typing import List, Dict, Any, Optional
import yaml

from loganalyzer.config import RULES_CONFIG_PATH
from loganalyzer.schema import NormalizedEvent, DetectionRecord
from loganalyzer.database import DatabaseManager
from loganalyzer.intel.mitre_mapper import MitreMapper

from loganalyzer.detection.rules.brute_force import BruteForceRule
from loganalyzer.detection.rules.password_spraying import PasswordSprayingRule
from loganalyzer.detection.rules.suspicious_success import SuspiciousSuccessRule
from loganalyzer.detection.rules.multi_account_fail import MultiAccountFailRule
from loganalyzer.detection.rules.suspicious_login import SuspiciousLoginRule
from loganalyzer.detection.rules.unusual_patterns import UnusualPatternsRule
from loganalyzer.detection.rules.repeated_suspicious_ip import RepeatedSuspiciousIpRule
from loganalyzer.detection.rules.invalid_user_enum import InvalidUserEnumerationRule


class DetectionEngine:
    """Orchestrates security rule evaluations against normalized event streams."""

    def __init__(self, config_path: Optional[Path] = None, db_manager: Optional[DatabaseManager] = None):
        self.config_path = config_path or RULES_CONFIG_PATH
        self.db = db_manager or DatabaseManager()
        self.mitre_mapper = MitreMapper()
        self.config = self._load_config()
        self.rules = self._init_rules()

    def _load_config(self) -> Dict[str, Any]:
        if self.config_path.exists():
            with open(self.config_path, "r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        return {}

    def _init_rules(self) -> List[Any]:
        rules_cfg = self.config.get("rules", {})
        return [
            BruteForceRule(rules_cfg.get("brute_force", {})),
            PasswordSprayingRule(rules_cfg.get("password_spraying", {})),
            SuspiciousSuccessRule(rules_cfg.get("suspicious_success", {})),
            MultiAccountFailRule(rules_cfg.get("multi_account_fail", {})),
            SuspiciousLoginRule(rules_cfg.get("suspicious_login", {})),
            UnusualPatternsRule(rules_cfg.get("unusual_patterns", {})),
            RepeatedSuspiciousIpRule(rules_cfg.get("repeated_suspicious_ip", {})),
            InvalidUserEnumerationRule(rules_cfg.get("invalid_user_enum", {}))
        ]

    def analyze_events(self, events: List[NormalizedEvent], persist: bool = True) -> List[DetectionRecord]:
        """Run all active detection rules across events and attach MITRE details."""
        detections: List[DetectionRecord] = []

        for rule in self.rules:
            if not rule.enabled:
                continue
            rule_alerts = rule.evaluate(events)
            for alert in rule_alerts:
                # Validate or enrich MITRE mapping
                mitre_tech = self.mitre_mapper.map_rule_to_technique(alert.rule_id)
                if mitre_tech:
                    alert.mitre_technique_id = mitre_tech["technique_id"]
                    alert.mitre_technique_name = mitre_tech["name"]

                if persist:
                    det_id = self.db.insert_detection(alert)
                    alert.detection_id = det_id

                detections.append(alert)

        return detections
