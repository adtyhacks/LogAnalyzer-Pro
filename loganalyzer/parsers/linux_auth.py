"""Linux authentication log parser (auth.log / secure / audit.log)."""

import re
import time
from datetime import datetime
from typing import List, Tuple
from loganalyzer.parsers.base import BaseLogParser
from loganalyzer.schema import NormalizedEvent, IngestionStats, EventStatus, ActionType
from loganalyzer.config import utc_now


class LinuxAuthParser(BaseLogParser):
    """Parses standard Linux syslog authentication messages."""

    SOURCE_TYPE = "linux_auth"

    # Regex patterns for common Linux auth events
    # Example: Oct 24 14:22:10 server sshd[1234]: Failed password for invalid user admin from 192.168.1.105 port 54321 ssh2
    PATTERNS = [
        # 1. Failed password for invalid user
        re.compile(
            r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)\s+"
            r"(?P<host>\S+)\s+"
            r"sshd\[(?P<pid>\d+)\]:\s+Failed password for invalid user (?P<user>\S+) from (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) port (?P<port>\d+)"
        ),
        # 2. Failed password for existing user
        re.compile(
            r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)\s+"
            r"(?P<host>\S+)\s+"
            r"sshd\[(?P<pid>\d+)\]:\s+Failed password for (?P<user>\S+) from (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) port (?P<port>\d+)"
        ),
        # 3. Accepted password / publickey
        re.compile(
            r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)\s+"
            r"(?P<host>\S+)\s+"
            r"sshd\[(?P<pid>\d+)\]:\s+Accepted (?P<auth_method>\S+) for (?P<user>\S+) from (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) port (?P<port>\d+)"
        ),
        # 4. Invalid user attempt
        re.compile(
            r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)\s+"
            r"(?P<host>\S+)\s+"
            r"sshd\[(?P<pid>\d+)\]:\s+Invalid user (?P<user>\S+) from (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) port (?P<port>\d+)"
        ),
        # 5. PAM unix authentication failure
        re.compile(
            r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)\s+"
            r"(?P<host>\S+)\s+"
            r"(?P<service>\S+)\[(?P<pid>\d+)\]:\s+pam_unix\([^)]+\):\s+authentication failure;.*?(?:rhost=(?P<ip>\S+))?.*?\s+user=(?P<user>\S+)"
        ),
        # 6. Sudo command execution
        re.compile(
            r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)\s+"
            r"(?P<host>\S+)\s+"
            r"sudo:\s+(?P<user>\S+)\s+:\s+TTY=\S+\s+;\s+PWD=\S+\s+;\s+USER=(?P<target_user>\S+)\s+;\s+COMMAND=(?P<cmd>.*)"
        )
    ]

    # Generic syslog line fallback
    GENERIC_SYSLOG = re.compile(
        r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)\s+"
        r"(?P<host>\S+)\s+"
        r"(?P<daemon>[^:\[]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.*)$"
    )

    def parse_content(self, content: str, filename: str = "auth.log") -> Tuple[List[NormalizedEvent], IngestionStats]:
        start_time = time.time()
        lines = [line.strip() for line in content.splitlines() if line.strip()]

        stats = IngestionStats(
            source_file=filename,
            source_type=self.SOURCE_TYPE,
            total_records=len(lines),
            start_time=utc_now()
        )

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

    def _parse_line(self, line: str) -> NormalizedEvent:
        # Check specific patterns
        # 1 & 2: Failed password
        match = self.PATTERNS[0].search(line) or self.PATTERNS[1].search(line)
        if match:
            gd = match.groupdict()
            return NormalizedEvent(
                timestamp=self.normalize_timestamp(gd["timestamp"]),
                source_type=self.SOURCE_TYPE,
                event_type="authentication",
                action=ActionType.FAILED_LOGIN.value,
                status=EventStatus.FAILURE.value,
                username=gd.get("user"),
                source_ip=gd.get("ip"),
                port=int(gd["port"]) if gd.get("port") else None,
                service="sshd",
                message=f"Failed SSH login for user '{gd.get('user')}' from {gd.get('ip')}",
                raw_log=line,
                metadata={"pid": gd.get("pid"), "invalid_user": "invalid" in line}
            )

        # 3: Accepted password or key
        match = self.PATTERNS[2].search(line)
        if match:
            gd = match.groupdict()
            return NormalizedEvent(
                timestamp=self.normalize_timestamp(gd["timestamp"]),
                source_type=self.SOURCE_TYPE,
                event_type="authentication",
                action=ActionType.LOGIN.value,
                status=EventStatus.SUCCESS.value,
                username=gd.get("user"),
                source_ip=gd.get("ip"),
                port=int(gd["port"]) if gd.get("port") else None,
                service="sshd",
                message=f"Successful SSH login for '{gd.get('user')}' using {gd.get('auth_method')}",
                raw_log=line,
                metadata={"pid": gd.get("pid"), "auth_method": gd.get("auth_method")}
            )

        # 4: Invalid user attempt
        match = self.PATTERNS[3].search(line)
        if match:
            gd = match.groupdict()
            return NormalizedEvent(
                timestamp=self.normalize_timestamp(gd["timestamp"]),
                source_type=self.SOURCE_TYPE,
                event_type="authentication",
                action=ActionType.FAILED_LOGIN.value,
                status=EventStatus.FAILURE.value,
                username=gd.get("user"),
                source_ip=gd.get("ip"),
                port=int(gd["port"]) if gd.get("port") else None,
                service="sshd",
                message=f"Invalid SSH user '{gd.get('user')}' attempt from {gd.get('ip')}",
                raw_log=line,
                metadata={"pid": gd.get("pid"), "invalid_user": True}
            )

        # 5: PAM auth failure
        match = self.PATTERNS[4].search(line)
        if match:
            gd = match.groupdict()
            ip = gd.get("ip")
            if ip and (ip == "" or ip == "None" or not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip)):
                ip = None
            return NormalizedEvent(
                timestamp=self.normalize_timestamp(gd["timestamp"]),
                source_type=self.SOURCE_TYPE,
                event_type="authentication",
                action=ActionType.FAILED_LOGIN.value,
                status=EventStatus.FAILURE.value,
                username=gd.get("user"),
                source_ip=ip,
                service=gd.get("service") or "pam",
                message=f"PAM auth failure for user '{gd.get('user')}'",
                raw_log=line,
                metadata={"pid": gd.get("pid")}
            )

        # 6: Sudo execution
        match = self.PATTERNS[5].search(line)
        if match:
            gd = match.groupdict()
            return NormalizedEvent(
                timestamp=self.normalize_timestamp(gd["timestamp"]),
                source_type=self.SOURCE_TYPE,
                event_type="privilege",
                action=ActionType.SUDO.value,
                status=EventStatus.SUCCESS.value,
                username=gd.get("user"),
                service="sudo",
                message=f"User '{gd.get('user')}' executed command as {gd.get('target_user')}: {gd.get('cmd')}",
                raw_log=line,
                metadata={"target_user": gd.get("target_user"), "command": gd.get("cmd")}
            )

        # Fallback: Generic syslog line
        gen_match = self.GENERIC_SYSLOG.search(line)
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

            # Extract possible IP
            ip_m = re.search(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", msg)
            extracted_ip = ip_m.group(1) if ip_m else None

            # Extract possible username
            user_m = re.search(r"\b(?:user|for|account)\s+([a-zA-Z0-9_\-\.]+)", msg, re.IGNORECASE)
            extracted_user = user_m.group(1) if user_m else None

            return NormalizedEvent(
                timestamp=self.normalize_timestamp(gd["timestamp"]),
                source_type=self.SOURCE_TYPE,
                event_type="system",
                action=action,
                status=status,
                username=extracted_user,
                source_ip=extracted_ip,
                service=gd.get("daemon"),
                message=msg,
                raw_log=line,
                metadata={"host": gd.get("host"), "pid": gd.get("pid")}
            )

        return None
