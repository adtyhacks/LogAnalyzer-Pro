"""Microsoft Sysmon event log parser supporting XML and JSON formats."""

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


class SysmonParser(BaseLogParser):
    """
    Parses Microsoft Sysmon Operational logs (Event IDs: 1, 3, 11, 12-14, 22).
    Source Channel: Microsoft-Windows-Sysmon/Operational
    """

    SOURCE_TYPE = "sysmon"

    EVENT_DESCRIPTIONS = {
        1: "Process creation",
        3: "Network connection detected",
        5: "Process terminated",
        7: "Image loaded",
        8: "CreateRemoteThread detected",
        11: "File created",
        12: "Registry object created or deleted",
        13: "Registry value set",
        14: "Registry key or value renamed",
        22: "DNS query",
        25: "Process tampering"
    }

    def parse_content(self, content: str, filename: str = "sysmon_events.xml") -> Tuple[List[NormalizedEvent], IngestionStats]:
        start_time = time.time()
        trimmed = content.strip()

        stats = IngestionStats(
            source_file=filename,
            source_type=self.SOURCE_TYPE,
            start_time=utc_now()
        )

        events: List[NormalizedEvent] = []

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
            # Fallback invalid format
            stats.errors.append("Unrecognized Sysmon log format (expected XML or JSON).")
            stats.invalid_records = 1

        stats.end_time = utc_now()
        stats.duration_seconds = round(time.time() - start_time, 4)
        return events, stats

    def _parse_xml(self, content: str, stats: IngestionStats) -> Tuple[List[NormalizedEvent], int, int]:
        events = []
        invalid = 0

        xml_content = content.strip()
        try:
            root = ET.fromstring(xml_content)
        except ET.ParseError:
            try:
                wrapped = f"<Events>{xml_content}</Events>"
                root = ET.fromstring(wrapped)
            except Exception as e:
                stats.errors.append(f"XML parse error in Sysmon: {str(e)}")
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

        for ev_node in event_nodes:
            raw_xml = ET.tostring(ev_node, encoding="utf-8").decode("utf-8", errors="replace")
            ev = self._parse_xml_node(ev_node, raw_xml, strip_ns)
            if ev:
                events.append(ev)
            else:
                invalid += 1

        return events, len(event_nodes), invalid

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
                        system_data["ExecutionProcessID"] = sys_child.attrib.get("ProcessID")
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

        merged = {**system_data, **event_data}
        return self._normalize_sysmon_record(merged, raw=raw_xml)

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
            ev = self._normalize_sysmon_record(rec, raw=json.dumps(rec))
            if ev:
                events.append(ev)
            else:
                invalid += 1

        return events, len(records), invalid

    def _normalize_sysmon_record(self, row: Dict[str, Any], raw: str) -> Optional[NormalizedEvent]:
        def get_val(*keys) -> Optional[Any]:
            for k in keys:
                for row_k, v in row.items():
                    if row_k.strip().lower() == k.lower() and v is not None and str(v).strip() != "":
                        return v
            return None

        # Extract Event ID
        event_id_raw = get_val("EventID", "Id", "event_id")
        event_id = None
        if event_id_raw is not None:
            try:
                event_id = int(str(event_id_raw).strip())
            except ValueError:
                event_id = None

        # Extract RecordID
        record_id_raw = get_val("EventRecordID", "RecordId", "RecordNumber")
        record_id = None
        if record_id_raw is not None:
            try:
                record_id = int(str(record_id_raw).strip())
            except ValueError:
                record_id = None

        channel = get_val("Channel") or "Microsoft-Windows-Sysmon/Operational"
        computer = get_val("Computer", "ComputerName", "Host")
        ts_raw = get_val("UtcTime", "TimeCreated", "Timestamp", "Date")
        timestamp = self.normalize_timestamp(ts_raw)

        user = get_val("User", "username")
        image = get_val("Image", "process_name")
        cmdline = get_val("CommandLine", "cmdline")
        parent_image = get_val("ParentImage", "parent_process")
        hashes = get_val("Hashes", "hashes")

        pid_raw = get_val("ProcessId", "ProcessID")
        process_id = None
        if pid_raw is not None:
            try:
                p_str = str(pid_raw).strip()
                process_id = int(p_str, 16) if p_str.startswith("0x") else int(p_str)
            except ValueError:
                process_id = None

        src_ip = get_val("SourceIp", "SourceNetworkAddress", "src_ip")
        if src_ip in ("-", "::1", "127.0.0.1", ""):
            src_ip = None

        dst_ip = get_val("DestinationIp", "dst_ip", "DestinationAddress")
        if dst_ip in ("-", "::1", "127.0.0.1", ""):
            dst_ip = None

        src_port_raw = get_val("SourcePort", "SourcePortName")
        src_port = None
        if src_port_raw:
            try:
                src_port = int(str(src_port_raw).strip())
            except ValueError:
                src_port = None

        dst_port_raw = get_val("DestinationPort", "DestinationPortName")
        dst_port = None
        if dst_port_raw:
            try:
                dst_port = int(str(dst_port_raw).strip())
            except ValueError:
                dst_port = None

        # Event type & Action Mapping
        action = ActionType.OTHER.value
        status = EventStatus.SUCCESS.value
        event_type = "endpoint"
        desc = self.EVENT_DESCRIPTIONS.get(event_id, f"Sysmon Event {event_id or 'Unknown'}")
        msg = f"{desc}"

        if event_id == 1:
            action = "PROCESS_CREATE"
            event_type = "process"
            cmd_preview = (cmdline[:100] + "...") if cmdline and len(cmdline) > 100 else (cmdline or "N/A")
            msg = f"Sysmon Process Create: {image or 'N/A'} (PID: {process_id or 'N/A'}) by {parent_image or 'N/A'} | Cmd: {cmd_preview}"
        elif event_id == 3:
            action = "NETWORK_CONNECT"
            event_type = "network"
            proto = get_val("Protocol") or "TCP"
            msg = f"Sysmon Network Connection: {image or 'N/A'} -> {dst_ip or 'N/A'}:{dst_port or 'N/A'} ({proto})"
        elif event_id == 11:
            action = "FILE_CREATE"
            event_type = "file"
            target_file = get_val("TargetFilename", "target_filename")
            msg = f"Sysmon File Create: {target_file or 'N/A'} by {image or 'N/A'}"
        elif event_id in (12, 13, 14):
            action = "REGISTRY_EVENT"
            event_type = "registry"
            target_obj = get_val("TargetObject", "target_object")
            reg_type = get_val("EventType") or "Change"
            msg = f"Sysmon Registry {reg_type}: {target_obj or 'N/A'} by {image or 'N/A'}"
        elif event_id == 22:
            action = "DNS_QUERY"
            event_type = "network"
            query_name = get_val("QueryName")
            query_results = get_val("QueryResults")
            msg = f"Sysmon DNS Query: {query_name or 'N/A'} -> {query_results or 'N/A'} by {image or 'N/A'}"

        metadata = {
            "EventID": event_id,
            "EventRecordID": record_id,
            "Channel": channel,
            "Image": image,
            "CommandLine": cmdline,
            "ParentImage": parent_image,
            "Hashes": hashes,
            "Protocol": get_val("Protocol"),
            "DestinationHostname": get_val("DestinationHostname"),
            "TargetFilename": get_val("TargetFilename"),
            "TargetObject": get_val("TargetObject"),
            "QueryName": get_val("QueryName"),
            "QueryResults": get_val("QueryResults")
        }

        return NormalizedEvent(
            timestamp=timestamp,
            source_type=self.SOURCE_TYPE,
            event_type=event_type,
            action=action,
            status=status,
            username=str(user).strip() if user else None,
            source_ip=str(src_ip).strip() if src_ip else None,
            destination_ip=str(dst_ip).strip() if dst_ip else None,
            port=src_port,
            service="Sysmon",
            message=msg,
            raw_log=raw,
            metadata=metadata,
            hostname=str(computer).strip() if computer else None,
            process_id=process_id,
            process_name=str(image).strip() if image else None,
            parent_process=str(parent_image).strip() if parent_image else None,
            command_line=str(cmdline).strip() if cmdline else None,
            destination_port=dst_port,
            hashes=str(hashes).strip() if hashes else None,
            channel=str(channel).strip() if channel else "Microsoft-Windows-Sysmon/Operational",
            record_id=record_id
        )
