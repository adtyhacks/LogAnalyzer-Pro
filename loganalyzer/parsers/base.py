"""Base parser class with common normalization, timestamp parsing, and ingestion statistics."""

from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import List, Tuple, Optional, Any, Union
import re
from loganalyzer.schema import NormalizedEvent, IngestionStats, EventStatus, ActionType
from loganalyzer.config import utc_now


class BaseLogParser(ABC):
    """Abstract Base Class for all security log parsers."""

    SOURCE_TYPE = "base"

    def __init__(self):
        self.stats = IngestionStats(source_file="", source_type=self.SOURCE_TYPE)

    @abstractmethod
    def parse_content(self, content: str, filename: str = "") -> Tuple[List[NormalizedEvent], IngestionStats]:
        """Parse raw log text content and return normalized events and stats."""
        pass

    def parse_file(self, file_path: Union[str, Path]) -> Tuple[List[NormalizedEvent], IngestionStats]:
        """Read and parse a log file from disk."""
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Log file not found: {path}")

        with open(path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()

        return self.parse_content(content, filename=path.name)

    @staticmethod
    def normalize_timestamp(raw_ts: Any) -> datetime:
        """
        Convert various timestamp formats into a standard datetime object.
        Supports Syslog, ISO-8601, RFC3339, Windows Event, and standard epoch/SQL formats.
        """
        if isinstance(raw_ts, datetime):
            return raw_ts

        if not raw_ts or not isinstance(raw_ts, (str, int, float)):
            return utc_now()

        if isinstance(raw_ts, (int, float)):
            try:
                # Check if millisecond timestamp
                if raw_ts > 1e11:
                    return datetime.fromtimestamp(raw_ts / 1000.0)
                return datetime.fromtimestamp(raw_ts)
            except Exception:
                return utc_now()

        raw_str = str(raw_ts).strip()

        # 1. ISO 8601 / RFC 3339: 2026-10-24T14:22:10 or 2026-10-24T14:22:10.123Z
        try:
            cleaned = raw_str.replace("Z", "+00:00")
            return datetime.fromisoformat(cleaned)
        except Exception:
            pass

        # 2. Common explicit formats
        formats = [
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y/%m/%d %H:%M:%S",
            "%m/%d/%Y %H:%M:%S",
            "%m/%d/%Y %I:%M:%S %p",
            "%d/%b/%Y:%H:%M:%S",
            "%b %d %H:%M:%S",
            "%b  %d %H:%M:%S",  # Single digit day with double space
        ]

        for fmt in formats:
            try:
                dt = datetime.strptime(raw_str, fmt)
                # If format didn't include a year (Syslog format like 'Oct 24 14:22:10'), add current year
                if dt.year == 1900:
                    dt = dt.replace(year=utc_now().year)
                return dt
            except ValueError:
                continue

        # Regex fallback for Syslog format: "Oct 24 14:22:10" or "Oct  4 14:22:10"
        syslog_match = re.match(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})", raw_str)
        if syslog_match:
            month_str, day_str, time_str = syslog_match.groups()
            current_year = utc_now().year
            try:
                combined = f"{current_year} {month_str} {int(day_str):02d} {time_str}"
                return datetime.strptime(combined, "%Y %b %d %H:%M:%S")
            except Exception:
                pass

        return utc_now()

    @staticmethod
    def normalize_status(raw_status: Any) -> str:
        """Map heterogeneous status indicators to SUCCESS, FAILURE, or UNKNOWN."""
        if not raw_status:
            return EventStatus.UNKNOWN.value

        s = str(raw_status).strip().upper()
        if s in ("SUCCESS", "SUCCESSFUL", "ACCEPTED", "OK", "PASS", "PASSED", "ALLOW", "ALLOWED", "0", "0X0"):
            return EventStatus.SUCCESS.value
        elif s in ("FAILURE", "FAILED", "FAIL", "DENIED", "REJECTED", "INVALID", "ERROR", "1", "0XC000006D", "0XC000006A"):
            return EventStatus.FAILURE.value
        return EventStatus.UNKNOWN.value

    @staticmethod
    def normalize_action(raw_action: Any, status: str = "") -> str:
        """Normalize action string into ActionType."""
        if not raw_action:
            return ActionType.FAILED_LOGIN.value if status == EventStatus.FAILURE.value else ActionType.LOGIN.value

        a = str(raw_action).strip().upper()
        if any(k in a for k in ["FAIL", "INVALID", "BAD", "DENY", "REJECT", "AUTH_FAIL", "LOGON_FAIL"]):
            return ActionType.FAILED_LOGIN.value
        if any(k in a for k in ["LOGON", "LOGIN", "AUTH", "ACCEPTED", "SESSION_OPEN"]):
            return ActionType.LOGIN.value
        if any(k in a for k in ["LOGOFF", "LOGOUT", "SESSION_CLOSE"]):
            return ActionType.LOGOUT.value
        if "SUDO" in a:
            return ActionType.SUDO.value
        if "LOCK" in a:
            return ActionType.ACCOUNT_LOCKED.value
        if any(k in a for k in ["USER_CREATE", "CREATE_USER", "ADD_USER"]):
            return ActionType.USER_CREATED.value
        if "PRIV" in a:
            return ActionType.PRIVILEGE_ESCALATION.value

        return ActionType.OTHER.value
