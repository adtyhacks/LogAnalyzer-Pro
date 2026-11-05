"""Parser factory and log format detector."""

from pathlib import Path
from typing import Union
from loganalyzer.parsers.base import BaseLogParser
from loganalyzer.parsers.linux_auth import LinuxAuthParser
from loganalyzer.parsers.windows_events import WindowsEventParser
from loganalyzer.parsers.sysmon import SysmonParser
from loganalyzer.parsers.generic_json import GenericJsonParser
from loganalyzer.parsers.generic_csv import GenericCsvParser


def get_parser_for_file(file_path_or_name: Union[str, Path], sample_content: str = "") -> BaseLogParser:
    """
    Intelligently detect and return the suitable parser based on filename and content hints.
    """
    name = Path(file_path_or_name).name.lower()
    sample = sample_content.strip()

    # 1. Filename heuristic
    if "sysmon" in name:
        return SysmonParser()

    if "linux" in name or "auth" in name or "secure" in name or name.endswith(".log"):
        if "windows" not in name and "event" not in name and "sysmon" not in name:
            return LinuxAuthParser()

    if "windows" in name or "winevent" in name or "security_event" in name:
        return WindowsEventParser()

    # 2. Content heuristic
    if sample:
        sample_lower = sample.lower()

        # Check for Sysmon specifics
        if "microsoft-windows-sysmon" in sample_lower or "sysmon" in sample_lower:
            return SysmonParser()

        # Check if XML format
        if sample.startswith("<") or "<event" in sample_lower:
            if "sysmon" in sample_lower:
                return SysmonParser()
            return WindowsEventParser()

        # Check if sample looks like Windows CSV/JSON with EventID
        if "eventid" in sample_lower or "targetusername" in sample_lower:
            return WindowsEventParser()

        # Check if sample looks like Linux auth log or systemd journal
        if "sshd[" in sample or "pam_unix" in sample or "sudo:" in sample or "_comm" in sample_lower or "syslog_identifier" in sample_lower:
            return LinuxAuthParser()

        # JSON detection
        if sample.startswith("{") or sample.startswith("["):
            if "sysmon" in sample_lower:
                return SysmonParser()
            if "eventid" in sample_lower or "targetusername" in sample_lower:
                return WindowsEventParser()
            if "_comm" in sample_lower or "_systemd_unit" in sample_lower or "syslog_identifier" in sample_lower:
                return LinuxAuthParser()
            return GenericJsonParser()

        # CSV detection
        first_line = sample.splitlines()[0] if sample.splitlines() else ""
        if "," in first_line:
            return GenericCsvParser()

    # 3. Extension fallback
    if name.endswith(".xml"):
        return WindowsEventParser()
    elif name.endswith(".json") or name.endswith(".ndjson") or name.endswith(".jsonl"):
        return GenericJsonParser()
    elif name.endswith(".csv"):
        return GenericCsvParser()
    elif name.endswith(".log") or name.endswith(".txt"):
        return LinuxAuthParser()

    return GenericCsvParser()
