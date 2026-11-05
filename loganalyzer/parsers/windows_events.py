"""Windows Security Event log parser supporting XML, CSV, and JSON formats."""

import csv
import io
import json
import time
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import List, Tuple, Dict, Any, Optional
from loganalyzer.parsers.base import BaseLogParser
from loganalyzer.schema import NormalizedEvent, IngestionStats, EventStatus, ActionType
from loganalyzer.config import utc_now


# Register standard Windows event namespace to preserve clean XML tags
try:
    ET.register_namespace("", "http://schemas.microsoft.com/win/2004/08/events/event")
except Exception:
    pass


class WindowsEventParser(BaseLogParser):
    """Parses Windows Security Event logs (Event IDs: 4624, 4625, 4634, 4648, 4672, 4720, 4722, 4728, 4740, etc.)."""

    SOURCE_TYPE = "windows_events"

    # Known Windows Event ID mappings
    EVENT_DESCRIPTIONS = {
        4624: "An account was successfully logged on",
        4625: "An account failed to log on",
        4634: "An account was logged off",
        4648: "A logon was attempted using explicit credentials",
        4672: "Special privileges assigned to new logon",
        4720: "A user account was created",
        4722: "A user account was enabled",
        4726: "A user account was deleted",
        4728: "A member was added to a security-enabled global group",
        4732: "A member was added to a security-enabled local group",
        4740: "A user account was locked out"
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

        # Determine whether input is XML, JSON, or CSV
        if trimmed.startswith("<") or "<Event" in trimmed:
            events, count, invalid = self._parse_xml(trimmed, stats)
            stats.total_records = count
            stats.parsed_events = len(events)
            stats.invalid_records = invalid
        elif trimmed.startswith("{") or trimmed.startswith("["):
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

    def _parse_xml(self, content: str, stats: IngestionStats) -> Tuple[List[NormalizedEvent], int, int]:
        events = []
        invalid = 0
        total = 0

        # Wrap in a root element if document has multiple top-level <Event> elements
        xml_content = content.strip()
        try:
            root = ET.fromstring(xml_content)
        except ET.ParseError:
            try:
                wrapped = f"<Events>{xml_content}</Events>"
                root = ET.fromstring(wrapped)
            except Exception as e:
                stats.errors.append(f"XML parse error: {str(e)}")
                return [], 0, 1

        def strip_ns(tag: str) -> str:
            return tag.split("}", 1)[-1] if "}" in tag else tag

        event_nodes = []
        if strip_ns(root.tag).lower() == "event":
            event_nodes.append(root)
        else:
            for child in root.iter():
                if strip_ns(child.tag).lower() == "event":
                    event_nodes.append(child)

        total = len(event_nodes)
        for ev_node in event_nodes:
            raw_xml = ET.tostring(ev_node, encoding="utf-8").decode("utf-8", errors="replace")
            ev = self._parse_xml_node(ev_node, raw_xml, strip_ns)
            if ev:
                events.append(ev)
            else:
                invalid += 1

        return events, total, invalid

    def _parse_xml_node(self, node: ET.Element, raw_xml: str, strip_ns) -> Optional[NormalizedEvent]:
        system_data: Dict[str, Any] = {}
        event_data: Dict[str, Any] = {}

        for child in node:
            child_tag = strip_ns(child.tag).lower()
            if child_tag == "system":
                for sys_child in child:
                    tag_name = strip_ns(sys_child.tag)
                    if tag_name == "TimeCreated":
                        system_data["TimeCreated"] = sys_child.attrib.get("SystemTime")
                    elif tag_name == "Execution":
                        system_data["ProcessID"] = sys_child.attrib.get("ProcessID")
                        system_data["ThreadID"] = sys_child.attrib.get("ThreadID")
                    elif tag_name == "Security":
                        system_data["UserID"] = sys_child.attrib.get("UserID")
                    else:
                        system_data[tag_name] = sys_child.text or ""
            elif child_tag in ("eventdata", "userdata"):
                for data_child in child:
                    name = data_child.attrib.get("Name")
                    val = data_child.text or ""
                    if name:
                        event_data[name] = val
                    else:
                        idx = len([k for k in event_data if k.startswith("Data_")])
                        event_data[f"Data_{idx}"] = val

        # Merge system and event data into unified dictionary
        merged = {**system_data, **event_data}
        return self._normalize_record(merged, raw=raw_xml)

    def _parse_json(self, content: str, stats: IngestionStats) -> Tuple[List[NormalizedEvent], int, int]:
        events = []
        invalid = 0
        records = []

        try:
            if content.startswith("["):
                records = json.loads(content)
            else:
                for line in content.splitlines():
                    if line.strip():
                        try:
                            records.append(json.loads(line))
                        except json.JSONDecodeError:
                            invalid += 1
        except Exception as e:
            stats.errors.append(f"JSON parsing error: {str(e)}")
            return [], 0, 1

        for rec in records:
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

        # Extract EventRecordID
        record_id_raw = get_val("EventRecordID", "RecordId", "RecordNumber", "record_id")
        record_id = None
        if record_id_raw is not None:
            try:
                record_id = int(str(record_id_raw).strip())
            except ValueError:
                record_id = None

        # Extract Channel
        channel = get_val("Channel", "channel") or "Security"

        # Extract Computer / Hostname
        workstation = get_val("WorkstationName", "Workstation", "Computer", "ComputerName")

        # Extract timestamp
        ts_raw = get_val("TimeCreated", "Timestamp", "UtcTime", "TimeGenerated", "Date", "time")
        timestamp = self.normalize_timestamp(ts_raw)

        # Extract User
        user = get_val("TargetUserName", "TargetAccount", "AccountName", "User", "username", "SubjectUserName")
        if user and str(user).endswith("$"):
            subj = get_val("SubjectUserName")
            if subj and not str(subj).endswith("$"):
                user = subj

        # Extract Source IP
        ip = get_val("IpAddress", "SourceNetworkAddress", "ClientIP", "source_ip", "ip", "src_ip")
        if ip in ("-", "::1", "127.0.0.1", ""):
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

        # Process Information
        process_name = get_val("ProcessName", "CallerProcessName", "NewProcessName", "process_name")
        process_id_raw = get_val("ProcessId", "ProcessID", "CallerProcessId", "NewProcessId")
        process_id = None
        if process_id_raw is not None:
            try:
                # Can be hex (0x1a4) or int
                p_str = str(process_id_raw).strip()
                process_id = int(p_str, 16) if p_str.startswith("0x") else int(p_str)
            except ValueError:
                process_id = None

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
        elif event_id == 4634:
            action = ActionType.LOGOUT.value
            status = EventStatus.SUCCESS.value
        elif event_id == 4648:
            action = ActionType.LOGIN.value
            status = EventStatus.SUCCESS.value
        elif event_id == 4672:
            action = ActionType.PRIVILEGE_ESCALATION.value
            status = EventStatus.SUCCESS.value
            event_type = "privilege"
        elif event_id == 4720:
            action = ActionType.USER_CREATED.value
            status = EventStatus.SUCCESS.value
            event_type = "account_management"
        elif event_id == 4722:
            action = ActionType.OTHER.value
            status = EventStatus.SUCCESS.value
            event_type = "account_management"
        elif event_id == 4728:
            action = ActionType.OTHER.value
            status = EventStatus.SUCCESS.value
            event_type = "account_management"
        elif event_id == 4740:
            action = ActionType.ACCOUNT_LOCKED.value
            status = EventStatus.FAILURE.value
            event_type = "account_management"
        else:
            raw_act = get_val("Action", "activity", "event")
            raw_stat = get_val("Status", "Keywords", "Result")
            status = self.normalize_status(raw_stat)
            action = self.normalize_action(raw_act, status)

        desc = self.EVENT_DESCRIPTIONS.get(event_id, f"Windows Security Event {event_id or 'Unknown'}")
        msg = f"{desc} | User: {user or 'N/A'} | IP: {ip or 'N/A'}"
        if logon_type:
            msg += f" | LogonType: {logon_type}"

        metadata = {
            "EventID": event_id,
            "EventRecordID": record_id,
            "Channel": channel,
            "LogonType": logon_type,
            "Workstation": workstation,
            "Domain": get_val("TargetDomainName", "Domain", "SubjectDomainName"),
            "ProcessName": process_name,
            "ProcessId": process_id,
            "Status": get_val("Status", "SubStatus"),
            "FailureReason": get_val("FailureReason")
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
            metadata=metadata,
            hostname=str(workstation).strip() if workstation else None,
            process_id=process_id,
            process_name=str(process_name).strip() if process_name else None,
            channel=str(channel).strip() if channel else "Security",
            record_id=record_id,
            destination_port=port
        )
