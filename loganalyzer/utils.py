"""Utility functions for robust datetime handling, formatting, and validation."""

import re
import pandas as pd
from typing import Any, Union, List, Dict
from datetime import datetime, timezone


def safe_to_datetime(data: Any) -> pd.Series:
    """
    Robustly parse and normalize timestamp data into UTC datetime64[ns, UTC].

    Handles:
    - ISO 8601 timestamps without fractional seconds (e.g. '2026-11-05T02:25:00+00:00', '2026-11-05 02:25:00')
    - ISO 8601 timestamps with fractional seconds (e.g. '2026-11-05T02:25:00.123456+00:00', '2026-11-05T02:25:00.123456Z')
    - Timezone offsets (+05:30, -05:00, Z) converted to UTC
    - Naive and aware datetimes
    - Mixed timestamp formats in the same Series/DataFrame
    - Invalid timestamps coerced to NaT without raising exceptions
    - Empty strings, whitespace, and null/None values coerced to NaT

    Returns:
        pd.Series with dtype 'datetime64[ns, UTC]'
    """
    if not isinstance(data, pd.Series):
        s = pd.Series(data)
    else:
        s = data

    if s.empty:
        return pd.Series(dtype="datetime64[ns, UTC]", index=s.index)

    # 1. Primary pass: Strict ISO 8601 parsing with UTC normalization and error coercion
    try:
        dt = pd.to_datetime(s, format="ISO8601", errors="coerce", utc=True)
    except Exception:
        dt = pd.to_datetime(s, errors="coerce", utc=True)

    # 2. Secondary pass: Fallback for non-ISO formats (e.g. syslog, slash-separated)
    mask = dt.isna() & s.notna()
    if mask.any():
        s_str = s.astype(str).str.strip()
        non_empty = mask & (s_str != "") & (~s_str.str.lower().isin(["none", "nan", "nat", "null"]))
        if non_empty.any():
            try:
                fallback = pd.to_datetime(s[non_empty], format="mixed", errors="coerce", utc=True)
                dt.loc[non_empty] = fallback
            except Exception:
                try:
                    fallback = pd.to_datetime(s[non_empty], errors="coerce", utc=True)
                    dt.loc[non_empty] = fallback
                except Exception:
                    pass

    return dt


_EMAIL_PATTERN = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')
_USER_PATH_PATTERN = re.compile(r'[cC]:\\Users\\[A-Za-z0-9_.-]+', re.IGNORECASE)
_PERSONAL_USER_PATTERN = re.compile(r'\baadit\b', re.IGNORECASE)


def sanitize_privacy(val: Any) -> Any:
    """
    Sanitize sensitive personal identifiers (PII) such as personal email addresses,
    local user profile paths, and personal usernames from exported reports and views.

    Leaves stored forensic database evidence intact while protecting confidentiality in exports.
    """
    if isinstance(val, str):
        val = _EMAIL_PATTERN.sub("operator@corp.internal", val)
        val = _USER_PATH_PATTERN.sub(r"C:\\Users\\<operator>", val)
        val = _PERSONAL_USER_PATTERN.sub("operator_admin", val)
        return val
    elif isinstance(val, list):
        return [sanitize_privacy(item) for item in val]
    elif isinstance(val, dict):
        return {k: sanitize_privacy(v) for k, v in val.items()}
    return val

