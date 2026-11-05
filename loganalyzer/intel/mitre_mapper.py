"""MITRE ATT&CK Enterprise technique mapper and local knowledge base."""

import json
from pathlib import Path
from typing import Dict, Any, Optional, List
from loganalyzer.config import MITRE_DATA_PATH


class MitreMapper:
    """Manages MITRE ATT&CK Enterprise technique lookups and validation."""

    def __init__(self, data_path: Optional[Path] = None):
        self.data_path = data_path or MITRE_DATA_PATH
        self._techniques: Dict[str, Dict[str, Any]] = {}
        self._load_dataset()

    def _load_dataset(self):
        if not self.data_path.exists():
            return

        with open(self.data_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        for item in data.get("techniques", []):
            self._techniques[item["technique_id"]] = item

    def get_technique(self, technique_id: str) -> Optional[Dict[str, Any]]:
        """Lookup technique details by ID."""
        return self._techniques.get(technique_id)

    def is_valid_technique(self, technique_id: str) -> bool:
        """Validate if technique ID exists in dataset."""
        return technique_id in self._techniques

    def get_all_techniques(self) -> List[Dict[str, Any]]:
        """Return all supported techniques."""
        return list(self._techniques.values())

    def map_rule_to_technique(self, rule_id: str) -> Optional[Dict[str, Any]]:
        """Deterministic mapping of detection rule identifiers to MITRE ATT&CK techniques."""
        mapping = {
            "RULE_BRUTE_FORCE": "T1110.001",
            "RULE_PASSWORD_SPRAY": "T1110.003",
            "RULE_SUSPICIOUS_SUCCESS": "T1078",
            "RULE_MULTI_ACCOUNT_FAIL": "T1110.003",
            "RULE_SUSPICIOUS_LOGIN": "T1078.003",
            "RULE_UNUSUAL_PATTERNS": "T1499",
            "RULE_REPEATED_SUSPICIOUS_IP": "T1110.001",
            "RULE_INVALID_USER_ENUM": "T1087.001"
        }
        tech_id = mapping.get(rule_id)
        if tech_id and tech_id in self._techniques:
            return self._techniques[tech_id]
        return None
