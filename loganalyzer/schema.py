"""Normalized event schema and data models for LogAnalyzer Pro."""

from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
import hashlib
import json
from typing import Optional, Dict, Any, List


class EventSeverity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class EventStatus(str, Enum):
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    UNKNOWN = "UNKNOWN"


class ActionType(str, Enum):
    LOGIN = "LOGIN"
    LOGOUT = "LOGOUT"
    FAILED_LOGIN = "FAILED_LOGIN"
    SUDO = "SUDO"
    ACCOUNT_LOCKED = "ACCOUNT_LOCKED"
    USER_CREATED = "USER_CREATED"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    OTHER = "OTHER"


class IncidentStatus(str, Enum):
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"


@dataclass
class NormalizedEvent:
    """Standardized representation of a security log event across all formats."""
    timestamp: datetime
    source_type: str  # linux_auth, windows_events, generic_json, generic_csv
    event_type: str   # authentication, system, privilege, network
    action: str       # LOGIN, FAILED_LOGIN, SUDO, etc.
    status: str       # SUCCESS, FAILURE, UNKNOWN
    username: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    port: Optional[int] = None
    service: Optional[str] = None
    message: str = ""
    raw_log: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    event_hash: str = ""
    event_id: Optional[int] = None

    def __post_init__(self):
        if not self.event_hash:
            self.event_hash = self.compute_hash()

    def compute_hash(self) -> str:
        """Compute SHA256 deterministic hash to prevent duplicate event ingestion."""
        ts_str = self.timestamp.isoformat() if isinstance(self.timestamp, datetime) else str(self.timestamp)
        payload = f"{ts_str}|{self.source_type}|{self.username or ''}|{self.source_ip or ''}|{self.action}|{self.status}|{self.raw_log.strip()}"
        return hashlib.sha256(payload.encode('utf-8', errors='ignore')).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        if isinstance(d["timestamp"], datetime):
            d["timestamp"] = d["timestamp"].isoformat()
        return d


@dataclass
class IngestionStats:
    """Summary statistics for an ingestion run."""
    source_file: str
    source_type: str
    total_records: int = 0
    parsed_events: int = 0
    duplicate_events: int = 0
    invalid_records: int = 0
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    duration_seconds: float = 0.0
    errors: List[str] = field(default_factory=list)


@dataclass
class DetectionRecord:
    """Representation of an alert produced by the detection engine."""
    rule_id: str
    rule_name: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    description: str
    timestamp: datetime
    source_ip: Optional[str] = None
    username: Optional[str] = None
    affected_accounts: List[str] = field(default_factory=list)
    event_count: int = 1
    related_event_ids: List[int] = field(default_factory=list)
    mitre_technique_id: Optional[str] = None
    mitre_technique_name: Optional[str] = None
    evidence: Dict[str, Any] = field(default_factory=dict)
    detection_id: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        if isinstance(d["timestamp"], datetime):
            d["timestamp"] = d["timestamp"].isoformat()
        return d


@dataclass
class IncidentRecord:
    """Correlated security incident grouped from multiple detections and events."""
    incident_id: str
    title: str
    severity: str
    risk_score: float
    description: str
    status: str  # OPEN, INVESTIGATING, RESOLVED
    created_at: datetime
    updated_at: datetime
    source_ip: Optional[str] = None
    affected_accounts: List[str] = field(default_factory=list)
    related_detection_ids: List[int] = field(default_factory=list)
    related_event_ids: List[int] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    risk_factors: List[str] = field(default_factory=list)
    investigation_notes: str = ""
    id: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        if isinstance(d["created_at"], datetime):
            d["created_at"] = d["created_at"].isoformat()
        if isinstance(d["updated_at"], datetime):
            d["updated_at"] = d["updated_at"].isoformat()
        return d
