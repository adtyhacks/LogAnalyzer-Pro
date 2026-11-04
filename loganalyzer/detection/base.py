"""Abstract Base Class for modular detection rules."""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from loganalyzer.schema import NormalizedEvent, DetectionRecord


class BaseDetectionRule(ABC):
    """Abstract Base Class for LogAnalyzer Pro detection rules."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.enabled = self.config.get("enabled", True)
        self.rule_id = self.config.get("rule_id", "RULE_UNKNOWN")
        self.rule_name = self.config.get("rule_name", "Unknown Rule")
        self.severity = self.config.get("severity", "MEDIUM")
        self.description = self.config.get("description", "")

    @abstractmethod
    def evaluate(self, events: List[NormalizedEvent]) -> List[DetectionRecord]:
        """Analyze normalized event stream and return generated detection alerts."""
        pass
