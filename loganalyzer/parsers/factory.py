"""Parser factory and log format detector."""

from pathlib import Path
from typing import Union
from loganalyzer.parsers.base import BaseLogParser
from loganalyzer.parsers.linux_auth import LinuxAuthParser
from loganalyzer.parsers.windows_events import WindowsEventParser
from loganalyzer.parsers.generic_json import GenericJsonParser
from loganalyzer.parsers.generic_csv import GenericCsvParser


def get_parser_for_file(file_path_or_name: Union[str, Path], sample_content: str = "") -> BaseLogParser:
    """
    Intelligently detect and return the suitable parser based on filename and content hints.
    """
    name = Path(file_path_or_name).name.lower()

    # 1. Filename heuristic
    if "auth" in name or "secure" in name or name.endswith(".log"):
        # Could be linux auth
        if "windows" not in name and "event" not in name:
            return LinuxAuthParser()

    if "windows" in name or "winevent" in name or "security_event" in name:
        return WindowsEventParser()

    # 2. Content heuristic
    sample = sample_content.strip()
    if sample:
        # Check if sample looks like Windows CSV with EventID
        if "eventid" in sample.lower() or "targetusername" in sample.lower():
            return WindowsEventParser()

        # Check if sample looks like Linux auth log
        if "sshd[" in sample or "pam_unix" in sample or "sudo:" in sample:
            return LinuxAuthParser()

        # JSON detection
        if sample.startswith("{") or sample.startswith("["):
            if "EventID" in sample or "TargetUserName" in sample:
                return WindowsEventParser()
            return GenericJsonParser()

        # CSV detection
        first_line = sample.splitlines()[0] if sample.splitlines() else ""
        if "," in first_line:
            return GenericCsvParser()

    # 3. Extension fallback
    if name.endswith(".json") or name.endswith(".ndjson") or name.endswith(".jsonl"):
        return GenericJsonParser()
    elif name.endswith(".csv"):
        return GenericCsvParser()
    elif name.endswith(".log") or name.endswith(".txt"):
        return LinuxAuthParser()

    return GenericCsvParser()
