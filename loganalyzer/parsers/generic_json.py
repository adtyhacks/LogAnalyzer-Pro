"""Generic JSON security log parser supporting array of objects or NDJSON."""

import json
import time
from datetime import datetime
from typing import List, Tuple, Dict, Any, Optional
from loganalyzer.parsers.base import BaseLogParser
from loganalyzer.schema import NormalizedEvent, IngestionStats, EventStatus, ActionType
from loganalyzer.config import utc_now


class GenericJsonParser(BaseLogParser):
    """Parses arbitrary JSON security logs (NDJSON or JSON array)."""

    SOURCE_TYPE = "generic_json"

    def parse_content(self, content: str, filename: str = "security_events.json") -> Tuple[List[NormalizedEvent], IngestionStats]:
        start_time = time.time()
        trimmed = content.strip()

        stats = IngestionStats(
            source_file=filename,
            source_type=self.SOURCE_TYPE,
            start_time=utc_now()
        )

        events: List[NormalizedEvent] = []
        records: List[Dict[str, Any]] = []

        if trimmed.startswith("["):
            try:
                records = json.loads(trimmed)
            except Exception as e:
                stats.errors.append(f"JSON Array decode error: {str(e)}")
                stats.invalid_records = 1
                return [], stats
        else:
            for line in trimmed.splitlines():
                if not line.strip():
                    continue
                try:
                    records.append(json.loads(line))
                except Exception:
                    stats.invalid_records += 1

        stats.total_records = len(records) + stats.invalid_records

        for rec in records:
            if not isinstance(rec, dict):
                stats.invalid_records += 1
                continue
            ev = self._normalize_record(rec)
            if ev:
                events.append(ev)
                stats.parsed_events += 1
            else:
                stats.invalid_records += 1

        stats.end_time = utc_now()
        stats.duration_seconds = round(time.time() - start_time, 4)
        return events, stats

    def _normalize_record(self, data: Dict[str, Any]) -> Optional[NormalizedEvent]:
        # Case-insensitive accessor
        def find_field(*candidates) -> Optional[Any]:
            for cand in candidates:
                for k, v in data.items():
                    if k.strip().lower() == cand.lower() and v is not None and str(v).strip() != "":
                        return v
            return None

        # Timestamp
        ts_val = find_field("timestamp", "time", "datetime", "@timestamp", "event_time", "date", "created_at")
        timestamp = self.normalize_timestamp(ts_val)

        # Status
        status_raw = find_field("status", "result", "outcome", "severity", "success")
        status = self.normalize_status(status_raw)

        # Action
        action_raw = find_field("action", "event", "event_name", "event_type", "activity", "type")
        action = self.normalize_action(action_raw, status)

        # User
        user = find_field("username", "user", "user_name", "account", "target_user", "src_user", "email")

        # Source IP
        src_ip = find_field("source_ip", "src_ip", "ip", "client_ip", "remote_ip", "host_ip", "src")
        dst_ip = find_field("destination_ip", "dst_ip", "dest_ip", "target_ip", "dst")

        # Port
        port_val = find_field("port", "src_port", "source_port", "destination_port", "dst_port")
        port = None
        if port_val:
            try:
                port = int(port_val)
            except (ValueError, TypeError):
                pass

        # Service
        service = find_field("service", "app", "application", "daemon", "process")

        # Message
        message = find_field("message", "msg", "description", "details", "summary")
        if not message:
            message = f"{action} ({status}) from {src_ip or 'unknown'} for user {user or 'unknown'}"

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
            raw_log=json.dumps(data),
            metadata=data
        )
