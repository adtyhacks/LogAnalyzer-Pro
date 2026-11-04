"""Windows Security Event log parser supporting both CSV and JSON formats."""

import csv
import io
import json
import time
from datetime import datetime
from typing import List, Tuple, Dict, Any, Optional
from loganalyzer.parsers.base import BaseLogParser
from loganalyzer.schema import NormalizedEvent, IngestionStats, EventStatus, ActionType
from loganalyzer.config import utc_now


class WindowsEventParser(BaseLogParser):
    """Parses Windows Security Event logs (Event IDs: 4624, 4625, 4672, 4720, 4740, etc.)."""

    SOURCE_TYPE = "windows_events"

    # Known Windows Event ID mappings
    EVENT_DESCRIPTIONS = {
        4624: "An account was successfully logged on",
        4625: "An account failed to log on",
        4672: "Special privileges assigned to new logon",
        4720: "A user account was created",
        4726: "A user account was deleted",
        4740: "A user account was locked out",
        4728: "A member was added to a security group",
        4732: "A member was added to a security-enabled local group"
    }

    def parse_content(self, content: str, filename: str = "windows_events.csv") -> Tuple[List[NormalizedEvent], IngestionStats]:
        start_time = time.time()
        trimmed = content.strip()

        stats = IngestionStats(
            source_file=filename,
            source_type=self.SOURCE_TYPE,
            start_time=utc_now()
        )

        events: List[NormalizedEvent] = []

        # Determine whether input is JSON or CSV
        if trimmed.startswith("{") or trimmed.startswith("["):
            events, count, invalid = self._parse_json(trimmed, stats)
            stats.total_records = count
            stats.parsed_events = len(events)
            stats.invalid_records = invalid
        else:
            events, count, invalid = self._parse_csv(trimmed, stats)
            stats.total_records = count
            stats.parsed_events = len(events)
            stats.invalid_records = invalid

        stats.end_time = utc_now()
        stats.duration_seconds = round(time.time() - start_time, 4)
        return events, stats

    def _parse_json(self, content: str, stats: IngestionStats) -> Tuple[List[NormalizedEvent], int, int]:
        events = []
        invalid = 0
        records = []

        try:
            # Check if JSON array
            if content.startswith("["):
                records = json.loads(content)
            else:
                # Could be NDJSON (Newline Delimited JSON)
                for line in content.splitlines():
                    if line.strip():
                        try:
                            records.append(json.loads(line))
                        except json.JSONDecodeError:
                            invalid += 1
        except Exception as e:
            stats.errors.append(f"JSON parsing error: {str(e)}")
            return [], 0, 1

        for idx, rec in enumerate(records, 1):
            if not isinstance(rec, dict):
                invalid += 1
                continue
            ev = self._normalize_record(rec, raw=json.dumps(rec))
            if ev:
                events.append(ev)
            else:
                invalid += 1

        return events, len(records), invalid

    def _parse_csv(self, content: str, stats: IngestionStats) -> Tuple[List[NormalizedEvent], int, int]:
        events = []
        invalid = 0
        total = 0

        try:
            f = io.StringIO(content)
            reader = csv.DictReader(f)
            for row in reader:
                total += 1
                ev = self._normalize_record(row, raw=",".join(f"{k}:{v}" for k, v in row.items()))
                if ev:
                    events.append(ev)
                else:
                    invalid += 1
        except Exception as e:
            stats.errors.append(f"CSV parsing error: {str(e)}")

        return events, total, invalid

    def _normalize_record(self, row: Dict[str, Any], raw: str) -> Optional[NormalizedEvent]:
        # Helper to find case-insensitive keys
        def get_val(*keys) -> Optional[Any]:
            for k in keys:
                for row_k, v in row.items():
                    if row_k.strip().lower() == k.lower() and v is not None and str(v).strip() != "":
                        return v
            return None

        # Extract Event ID
        event_id_raw = get_val("EventID", "EventIdentifier", "Id", "event_id")
        event_id = None
        if event_id_raw is not None:
            try:
                event_id = int(str(event_id_raw).strip())
            except ValueError:
                event_id = None

        # Extract timestamp
        ts_raw = get_val("TimeCreated", "Timestamp", "UtcTime", "TimeGenerated", "Date", "time")
        timestamp = self.normalize_timestamp(ts_raw)

        # Extract User
        user = get_val("TargetUserName", "TargetAccount", "AccountName", "User", "username", "SubjectUserName")
        # Ignore machine accounts ending in $ unless no other user
        if user and str(user).endswith("$"):
            # Check if there is a TargetUserName distinct from computer account
            subj = get_val("SubjectUserName")
            if subj and not str(subj).endswith("$"):
                user = subj

        # Extract Source IP
        ip = get_val("IpAddress", "SourceNetworkAddress", "ClientIP", "source_ip", "ip", "src_ip")
        if ip in ("-", "::1", "127.0.0.1", ""):
            if ip in ("-", ""):
                ip = None
        port_raw = get_val("IpPort", "SourcePort", "port")
        port = None
        if port_raw:
            try:
                p = int(str(port_raw))
                if p > 0:
                    port = p
            except ValueError:
                port = None

        logon_type = get_val("LogonType", "logon_type")

        # Map Event ID to Action and Status
        action = ActionType.OTHER.value
        status = EventStatus.UNKNOWN.value
        event_type = "authentication"

        if event_id == 4624:
            action = ActionType.LOGIN.value
            status = EventStatus.SUCCESS.value
        elif event_id == 4625:
            action = ActionType.FAILED_LOGIN.value
            status = EventStatus.FAILURE.value
        elif event_id == 4672:
            action = ActionType.PRIVILEGE_ESCALATION.value
            status = EventStatus.SUCCESS.value
            event_type = "privilege"
        elif event_id == 4720:
            action = ActionType.USER_CREATED.value
            status = EventStatus.SUCCESS.value
            event_type = "account_management"
        elif event_id == 4740:
            action = ActionType.ACCOUNT_LOCKED.value
            status = EventStatus.FAILURE.value
            event_type = "account_management"
        else:
            # Infer from row values
            raw_act = get_val("Action", "activity", "event")
            raw_stat = get_val("Status", "Keywords", "Result")
            status = self.normalize_status(raw_stat)
            action = self.normalize_action(raw_act, status)

        desc = self.EVENT_DESCRIPTIONS.get(event_id, f"Windows Security Event {event_id or 'Unknown'}")
        workstation = get_val("WorkstationName", "Workstation", "Computer", "ComputerName")
        msg = f"{desc} | User: {user or 'N/A'} | IP: {ip or 'N/A'}"
        if logon_type:
            msg += f" | LogonType: {logon_type}"

        metadata = {
            "EventID": event_id,
            "LogonType": logon_type,
            "Workstation": workstation,
            "Domain": get_val("TargetDomainName", "Domain")
        }

        return NormalizedEvent(
            timestamp=timestamp,
            source_type=self.SOURCE_TYPE,
            event_type=event_type,
            action=action,
            status=status,
            username=str(user).strip() if user else None,
            source_ip=str(ip).strip() if ip else None,
            port=port,
            service="Security",
            message=msg,
            raw_log=raw,
            metadata=metadata
        )
