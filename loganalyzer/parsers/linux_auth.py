"""Linux authentication log parser (auth.log / secure / journalctl)."""

import json
import re
import time
from datetime import datetime, timezone
from typing import List, Tuple, Optional, Dict, Any

from loganalyzer.parsers.base import BaseLogParser
from loganalyzer.schema import NormalizedEvent, IngestionStats, EventStatus, ActionType
from loganalyzer.config import utc_now


class LinuxAuthParser(BaseLogParser):
    """Parses standard Linux syslog authentication messages (auth.log, secure, journalctl text & JSON)."""

    SOURCE_TYPE = "linux_auth"

    # Regex capturing IPv4 or IPv6 addresses
    # IPv4: 192.168.1.1
    # IPv6: 2001:db8::1, ::1, fe80::..., ::ffff:192.168.1.1
    IP_PATTERN = r"(?P<ip>(?:\d{1,3}(?:\.\d{1,3}){3})|(?:[0-9a-fA-F:]{3,45}))"
    TIMESTAMP_PATTERN = r"(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"

    def __init__(self):
        super().__init__()
        self._init_patterns()

    def _init_patterns(self):
        # 1. Failed password for invalid user
        self.PAT_FAILED_INVALID = re.compile(
            rf"^{self.TIMESTAMP_PATTERN}\s+"
            r"(?P<host>\S+)\s+"
            rf"sshd\[(?P<pid>\d+)\]:\s+Failed password for invalid user (?P<user>\S+) from {self.IP_PATTERN}(?:\s+port\s+(?P<port>\d+))?"
        )

        # 2. Failed password for existing user
        self.PAT_FAILED_USER = re.compile(
            rf"^{self.TIMESTAMP_PATTERN}\s+"
            r"(?P<host>\S+)\s+"
            rf"sshd\[(?P<pid>\d+)\]:\s+Failed password for (?P<user>\S+) from {self.IP_PATTERN}(?:\s+port\s+(?P<port>\d+))?"
        )

        # 3. Accepted password / publickey / keyboard-interactive
        self.PAT_ACCEPTED = re.compile(
            rf"^{self.TIMESTAMP_PATTERN}\s+"
            r"(?P<host>\S+)\s+"
            rf"sshd\[(?P<pid>\d+)\]:\s+Accepted (?P<auth_method>\S+) for (?P<user>\S+) from {self.IP_PATTERN}(?:\s+port\s+(?P<port>\d+))?"
        )

        # 4. Invalid user attempt (e.g. 'Invalid user admin from 1.2.3.4 port 5555')
        self.PAT_INVALID_USER = re.compile(
            rf"^{self.TIMESTAMP_PATTERN}\s+"
            r"(?P<host>\S+)\s+"
            rf"sshd\[(?P<pid>\d+)\]:\s+Invalid user (?P<user>\S+) from {self.IP_PATTERN}(?:\s+port\s+(?P<port>\d+))?"
        )

        # 5. Connection closed by invalid / authenticating user
        self.PAT_CONN_CLOSED = re.compile(
            rf"^{self.TIMESTAMP_PATTERN}\s+"
            r"(?P<host>\S+)\s+"
            rf"sshd\[(?P<pid>\d+)\]:\s+Connection closed by (?:invalid user |authenticating user )?(?P<user>\S+) {self.IP_PATTERN}(?:\s+port\s+(?P<port>\d+))?"
        )

        # 6. PAM unix authentication failure
        self.PAT_PAM_FAIL = re.compile(
            rf"^{self.TIMESTAMP_PATTERN}\s+"
            r"(?P<host>\S+)\s+"
            r"(?P<service>\S+)\[(?P<pid>\d+)\]:\s+pam_unix\([^)]+\):\s+authentication failure;.*?(?:rhost=(?P<ip>\S+))?.*?\s+user=(?P<user>\S+)"
        )

        # 7. Sudo command execution
        self.PAT_SUDO = re.compile(
            rf"^{self.TIMESTAMP_PATTERN}\s+"
            r"(?P<host>\S+)\s+"
            r"sudo:\s+(?P<user>\S+)\s+:\s+TTY=\S+\s+;\s+PWD=\S+\s+;\s+USER=(?P<target_user>\S+)\s+;\s+COMMAND=(?P<cmd>.*)"
        )

        # 8. Generic syslog line fallback
        self.PAT_GENERIC_SYSLOG = re.compile(
            rf"^{self.TIMESTAMP_PATTERN}\s+"
            r"(?P<host>\S+)\s+"
            r"(?P<daemon>[^:\[]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.*)$"
        )

    def parse_content(self, content: str, filename: str = "auth.log") -> Tuple[List[NormalizedEvent], IngestionStats]:
        start_time = time.time()
        trimmed = content.strip()

        stats = IngestionStats(
            source_file=filename,
            source_type=self.SOURCE_TYPE,
            start_time=utc_now()
        )

        # Check if content is JSON or NDJSON (e.g. journalctl -o json)
        if trimmed.startswith("{") or trimmed.startswith("["):
            events, json_stats = self._parse_json_content(trimmed, filename)
            json_stats.duration_seconds = round(time.time() - start_time, 4)
            return events, json_stats

        # Standard text syslog parsing
        lines = [line.strip() for line in content.splitlines() if line.strip()]
        stats.total_records = len(lines)
        events: List[NormalizedEvent] = []

        for line_num, line_str in enumerate(lines, 1):
            event = self._parse_line(line_str)
            if event:
                events.append(event)
                stats.parsed_events += 1
            else:
                stats.invalid_records += 1
                if len(stats.errors) < 10:
                    stats.errors.append(f"Line {line_num}: Unrecognized format")

        stats.end_time = utc_now()
        stats.duration_seconds = round(time.time() - start_time, 4)
        return events, stats

    def _parse_line(self, line: str, host_override: Optional[str] = None) -> Optional[NormalizedEvent]:
        # 1. Failed password for invalid user
        match = self.PAT_FAILED_INVALID.search(line)
        if match:
            gd = match.groupdict()
            return self._build_event(
                timestamp=gd["timestamp"],
                host=host_override or gd.get("host"),
                action=ActionType.FAILED_LOGIN.value,
                status=EventStatus.FAILURE.value,
                user=gd.get("user"),
                ip=self._clean_ip(gd.get("ip")),
                port=gd.get("port"),
                service="sshd",
                process_name="sshd",
                process_id=int(gd["pid"]) if gd.get("pid") else None,
                message=f"Failed SSH login for invalid user '{gd.get('user')}' from {gd.get('ip')}",
                raw_log=line,
                metadata={"pid": gd.get("pid"), "invalid_user": True}
            )

        # 2. Failed password for existing user
        match = self.PAT_FAILED_USER.search(line)
        if match:
            gd = match.groupdict()
            is_inv = "invalid" in line.lower()
            return self._build_event(
                timestamp=gd["timestamp"],
                host=host_override or gd.get("host"),
                action=ActionType.FAILED_LOGIN.value,
                status=EventStatus.FAILURE.value,
                user=gd.get("user"),
                ip=self._clean_ip(gd.get("ip")),
                port=gd.get("port"),
                service="sshd",
                process_name="sshd",
                process_id=int(gd["pid"]) if gd.get("pid") else None,
                message=f"Failed SSH login for user '{gd.get('user')}' from {gd.get('ip')}",
                raw_log=line,
                metadata={"pid": gd.get("pid"), "invalid_user": is_inv}
            )

        # 3. Accepted password / publickey
        match = self.PAT_ACCEPTED.search(line)
        if match:
            gd = match.groupdict()
            return self._build_event(
                timestamp=gd["timestamp"],
                host=host_override or gd.get("host"),
                action=ActionType.LOGIN.value,
                status=EventStatus.SUCCESS.value,
                user=gd.get("user"),
                ip=self._clean_ip(gd.get("ip")),
                port=gd.get("port"),
                service="sshd",
                process_name="sshd",
                process_id=int(gd["pid"]) if gd.get("pid") else None,
                message=f"Successful SSH login for '{gd.get('user')}' using {gd.get('auth_method')}",
                raw_log=line,
                metadata={"pid": gd.get("pid"), "auth_method": gd.get("auth_method"), "invalid_user": False}
            )

        # 4. Invalid user attempt
        match = self.PAT_INVALID_USER.search(line)
        if match:
            gd = match.groupdict()
            return self._build_event(
                timestamp=gd["timestamp"],
                host=host_override or gd.get("host"),
                action=ActionType.FAILED_LOGIN.value,
                status=EventStatus.FAILURE.value,
                user=gd.get("user"),
                ip=self._clean_ip(gd.get("ip")),
                port=gd.get("port"),
                service="sshd",
                process_name="sshd",
                process_id=int(gd["pid"]) if gd.get("pid") else None,
                message=f"Invalid SSH user '{gd.get('user')}' attempt from {gd.get('ip')}",
                raw_log=line,
                metadata={"pid": gd.get("pid"), "invalid_user": True}
            )

        # 5. Connection closed by invalid / authenticating user
        match = self.PAT_CONN_CLOSED.search(line)
        if match:
            gd = match.groupdict()
            is_inv = "invalid" in line.lower()
            return self._build_event(
                timestamp=gd["timestamp"],
                host=host_override or gd.get("host"),
                action=ActionType.FAILED_LOGIN.value,
                status=EventStatus.FAILURE.value,
                user=gd.get("user"),
                ip=self._clean_ip(gd.get("ip")),
                port=gd.get("port"),
                service="sshd",
                process_name="sshd",
                process_id=int(gd["pid"]) if gd.get("pid") else None,
                message=f"SSH connection closed by user '{gd.get('user')}' from {gd.get('ip')}",
                raw_log=line,
                metadata={"pid": gd.get("pid"), "invalid_user": is_inv}
            )

        # 6. PAM authentication failure
        match = self.PAT_PAM_FAIL.search(line)
        if match:
            gd = match.groupdict()
            ip = self._clean_ip(gd.get("ip"))
            return self._build_event(
                timestamp=gd["timestamp"],
                host=host_override or gd.get("host"),
                action=ActionType.FAILED_LOGIN.value,
                status=EventStatus.FAILURE.value,
                user=gd.get("user"),
                ip=ip,
                service=gd.get("service") or "pam",
                process_name=gd.get("service") or "pam",
                process_id=int(gd["pid"]) if gd.get("pid") else None,
                message=f"PAM auth failure for user '{gd.get('user')}'",
                raw_log=line,
                metadata={"pid": gd.get("pid")}
            )

        # 7. Sudo command execution
        match = self.PAT_SUDO.search(line)
        if match:
            gd = match.groupdict()
            return self._build_event(
                timestamp=gd["timestamp"],
                host=host_override or gd.get("host"),
                event_type="privilege",
                action=ActionType.SUDO.value,
                status=EventStatus.SUCCESS.value,
                user=gd.get("user"),
                service="sudo",
                process_name="sudo",
                command_line=gd.get("cmd"),
                message=f"User '{gd.get('user')}' executed command as {gd.get('target_user')}: {gd.get('cmd')}",
                raw_log=line,
                metadata={"target_user": gd.get("target_user"), "command": gd.get("cmd")}
            )

        # 8. Fallback: Generic syslog line
        gen_match = self.PAT_GENERIC_SYSLOG.search(line)
        if gen_match:
            gd = gen_match.groupdict()
            msg = gd.get("message", "")

            # Heuristics for action & status
            status = EventStatus.UNKNOWN.value
            action = ActionType.OTHER.value
            if any(k in msg.lower() for k in ["failed", "failure", "invalid", "denied", "error"]):
                status = EventStatus.FAILURE.value
                action = ActionType.FAILED_LOGIN.value
            elif any(k in msg.lower() for k in ["accepted", "success", "session opened"]):
                status = EventStatus.SUCCESS.value
                action = ActionType.LOGIN.value

            extracted_ip = self._extract_ip(msg)
            user_m = re.search(r"\b(?:user|for|account)\s+([a-zA-Z0-9_\-\.]+)", msg, re.IGNORECASE)
            extracted_user = user_m.group(1) if user_m else None
            is_inv = "invalid user" in msg.lower()

            return self._build_event(
                timestamp=gd["timestamp"],
                host=host_override or gd.get("host"),
                event_type="system",
                action=action,
                status=status,
                user=extracted_user,
                ip=extracted_ip,
                service=gd.get("daemon"),
                process_name=gd.get("daemon"),
                process_id=int(gd["pid"]) if gd.get("pid") else None,
                message=msg,
                raw_log=line,
                metadata={"host": gd.get("host"), "pid": gd.get("pid"), "invalid_user": is_inv}
            )

        return None

    def _parse_json_content(self, content: str, filename: str) -> Tuple[List[NormalizedEvent], IngestionStats]:
        """Parse structured NDJSON or JSON array produced by journalctl -o json or export."""
        stats = IngestionStats(source_file=filename, source_type=self.SOURCE_TYPE, start_time=utc_now())
        records: List[Dict[str, Any]] = []

        if content.startswith("["):
            try:
                records = json.loads(content)
            except Exception as e:
                stats.errors.append(f"JSON Array decode error: {e}")
                stats.invalid_records = 1
                return [], stats
        else:
            for line in content.splitlines():
                if not line.strip():
                    continue
                try:
                    records.append(json.loads(line))
                except Exception:
                    stats.invalid_records += 1

        stats.total_records = len(records) + stats.invalid_records
        events: List[NormalizedEvent] = []

        for rec in records:
            if not isinstance(rec, dict):
                stats.invalid_records += 1
                continue

            ev = self._normalize_journal_record(rec)
            if ev:
                events.append(ev)
                stats.parsed_events += 1
            else:
                stats.invalid_records += 1

        stats.end_time = utc_now()
        return events, stats

    def _normalize_journal_record(self, rec: Dict[str, Any]) -> Optional[NormalizedEvent]:
        # Handle journalctl timestamp
        ts = None
        if "__REALTIME_TIMESTAMP" in rec:
            try:
                usec = int(rec["__REALTIME_TIMESTAMP"])
                ts = datetime.fromtimestamp(usec / 1_000_000.0, tz=timezone.utc)
            except Exception:
                pass
        elif "_SOURCE_REALTIME_TIMESTAMP" in rec:
            try:
                usec = int(rec["_SOURCE_REALTIME_TIMESTAMP"])
                ts = datetime.fromtimestamp(usec / 1_000_000.0, tz=timezone.utc)
            except Exception:
                pass

        if not ts:
            ts_cand = rec.get("timestamp") or rec.get("time") or rec.get("@timestamp")
            ts = self.normalize_timestamp(ts_cand)

        hostname = rec.get("_HOSTNAME") or rec.get("host") or rec.get("hostname")
        process_name = rec.get("_COMM") or rec.get("SYSLOG_IDENTIFIER") or rec.get("service")
        pid_raw = rec.get("_PID")
        process_id = int(pid_raw) if pid_raw and str(pid_raw).isdigit() else None
        cmd_line = rec.get("_CMDLINE")
        msg = str(rec.get("MESSAGE") or rec.get("message") or "")

        # Synthesize syslog line for parser reuse if MESSAGE exists
        if msg:
            ts_str = ts.strftime("%b %d %H:%M:%S")
            host_str = hostname or "localhost"
            proc_str = process_name or "sshd"
            pid_str = f"[{process_id}]" if process_id else ""
            synth_line = f"{ts_str} {host_str} {proc_str}{pid_str}: {msg}"

            ev = self._parse_line(synth_line, host_override=hostname)
            if ev:
                ev.timestamp = ts
                ev.process_name = process_name or ev.process_name
                ev.process_id = process_id or ev.process_id
                ev.command_line = cmd_line or ev.command_line
                ev.raw_log = json.dumps(rec)
                ev.channel = "linux_journal"
                return ev

        # Fallback if MESSAGE didn't match patterns
        status = EventStatus.SUCCESS.value if "accept" in msg.lower() or "success" in msg.lower() else EventStatus.UNKNOWN.value
        action = ActionType.LOGIN.value if status == EventStatus.SUCCESS.value else ActionType.OTHER.value
        if any(w in msg.lower() for w in ["fail", "error", "invalid", "denied"]):
            status = EventStatus.FAILURE.value
            action = ActionType.FAILED_LOGIN.value

        return NormalizedEvent(
            timestamp=ts,
            source_type=self.SOURCE_TYPE,
            event_type="authentication" if "ssh" in str(process_name).lower() else "system",
            action=action,
            status=status,
            username=rec.get("username") or rec.get("user"),
            source_ip=self._extract_ip(msg) or rec.get("source_ip"),
            hostname=hostname,
            process_name=process_name,
            process_id=process_id,
            command_line=cmd_line,
            channel="linux_journal",
            message=msg,
            raw_log=json.dumps(rec),
            metadata=rec
        )

    def _build_event(
        self,
        timestamp: Any,
        host: Optional[str],
        action: str,
        status: str,
        user: Optional[str],
        ip: Optional[str] = None,
        message: str = "",
        raw_log: str = "",
        service: Optional[str] = None,
        process_name: Optional[str] = None,
        process_id: Optional[int] = None,
        port: Optional[Any] = None,
        command_line: Optional[str] = None,
        event_type: str = "authentication",
        metadata: Optional[Dict[str, Any]] = None
    ) -> NormalizedEvent:
        parsed_port = None
        if port:
            try:
                parsed_port = int(port)
            except (ValueError, TypeError):
                parsed_port = None

        return NormalizedEvent(
            timestamp=self.normalize_timestamp(timestamp),
            source_type=self.SOURCE_TYPE,
            event_type=event_type,
            action=action,
            status=status,
            username=user.strip() if user else None,
            source_ip=ip,
            port=parsed_port,
            service=service,
            hostname=host.strip() if host else None,
            process_name=process_name,
            process_id=process_id,
            command_line=command_line,
            channel="linux_auth",
            message=message,
            raw_log=raw_log,
            metadata=metadata or {}
        )

    @staticmethod
    def _clean_ip(ip: Optional[str]) -> Optional[str]:
        if not ip:
            return None
        cleaned = ip.strip()
        if cleaned in ("", "None", "unknown", "localhost", "127.0.0.1", "::1"):
            return cleaned if cleaned in ("127.0.0.1", "::1") else None
        # Basic validation: must contain dot or colon
        if "." in cleaned or ":" in cleaned:
            return cleaned
        return None

    @staticmethod
    def _extract_ip(text: str) -> Optional[str]:
        # Try IPv4 first
        m4 = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", text)
        if m4:
            return m4.group(1)
        # Try IPv6
        m6 = re.search(r"\b([0-9a-fA-F:]{3,45})\b", text)
        if m6 and ":" in m6.group(1):
            return m6.group(1)
        return None
