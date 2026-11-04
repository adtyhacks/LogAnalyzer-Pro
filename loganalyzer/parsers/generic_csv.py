"""Generic CSV security log parser with adaptive column mapping."""

import csv
import io
import time
from datetime import datetime
from typing import List, Tuple, Dict, Any, Optional
from loganalyzer.parsers.base import BaseLogParser
from loganalyzer.schema import NormalizedEvent, IngestionStats, EventStatus, ActionType
from loganalyzer.config import utc_now


class GenericCsvParser(BaseLogParser):
    """Parses arbitrary CSV logs mapping standard security fields."""

    SOURCE_TYPE = "generic_csv"

    def parse_content(self, content: str, filename: str = "security_events.csv") -> Tuple[List[NormalizedEvent], IngestionStats]:
        start_time = time.time()
        stats = IngestionStats(
            source_file=filename,
            source_type=self.SOURCE_TYPE,
            start_time=utc_now()
        )

        events: List[NormalizedEvent] = []
        trimmed = content.strip()
        if not trimmed:
            return events, stats

        try:
            f = io.StringIO(trimmed)
            reader = csv.DictReader(f)
            for row in reader:
                stats.total_records += 1
                ev = self._normalize_row(row)
                if ev:
                    events.append(ev)
                    stats.parsed_events += 1
                else:
                    stats.invalid_records += 1
        except Exception as e:
            stats.errors.append(f"CSV read error: {str(e)}")

        stats.end_time = utc_now()
        stats.duration_seconds = round(time.time() - start_time, 4)
        return events, stats

    def _normalize_row(self, row: Dict[str, Any]) -> Optional[NormalizedEvent]:
        def get_col(*names) -> Optional[Any]:
            for n in names:
                for k, v in row.items():
                    if k and k.strip().lower() == n.lower() and v is not None and str(v).strip() != "":
                        return v
            return None

        # Timestamp
        ts_val = get_col("timestamp", "time", "date", "datetime", "created_at", "event_time")
        timestamp = self.normalize_timestamp(ts_val)

        # Status
        status_val = get_col("status", "result", "outcome", "success")
        status = self.normalize_status(status_val)

        # Action
        action_val = get_col("action", "event", "event_name", "activity", "type")
        action = self.normalize_action(action_val, status)

        # User
        user = get_col("username", "user", "user_name", "account", "target_user", "email")

        # IPs
        src_ip = get_col("source_ip", "src_ip", "ip", "client_ip", "remote_ip", "source")
        dst_ip = get_col("destination_ip", "dst_ip", "dest_ip", "target_ip", "destination")

        # Port
        port_val = get_col("port", "src_port", "source_port", "dst_port")
        port = None
        if port_val:
            try:
                port = int(port_val)
            except (ValueError, TypeError):
                pass

        # Service
        service = get_col("service", "app", "application", "daemon", "protocol")

        # Message
        message = get_col("message", "msg", "description", "details", "summary")
        if not message:
            message = f"{action} - Status: {status} | User: {user or 'N/A'} | IP: {src_ip or 'N/A'}"

        raw_str = ",".join(f"{k}:{v}" for k, v in row.items() if k)

        return NormalizedEvent(
            timestamp=timestamp,
            source_type=self.SOURCE_TYPE,
            event_type="security",
            action=action,
            status=status,
            username=str(user).strip() if user else None,
            source_ip=str(src_ip).strip() if src_ip else None,
            destination_ip=str(dst_ip).strip() if dst_ip else None,
            port=port,
            service=str(service) if service else None,
            message=str(message),
            raw_log=raw_str,
            metadata=dict(row)
        )
