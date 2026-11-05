"""Regression tests for robust timestamp parsing, mixed ISO 8601 formats, and UTC normalization."""

import pytest
import pandas as pd
import numpy as np
from datetime import datetime, timezone, timedelta
from loganalyzer.utils import safe_to_datetime
from loganalyzer.schema import NormalizedEvent, EventStatus, ActionType


def test_safe_to_datetime_without_fractional_seconds():
    """Verify parsing of ISO 8601 timestamps without fractional seconds."""
    inputs = [
        "2026-11-05T02:25:00+00:00",
        "2026-11-05 02:25:00",
        "2026-11-05T02:25:00Z"
    ]
    series = safe_to_datetime(pd.Series(inputs))
    assert str(series.dtype) == "datetime64[ns, UTC]"
    assert series.isna().sum() == 0

    expected_epoch = pd.Timestamp("2026-11-05 02:25:00", tz="UTC")
    for val in series:
        assert val == expected_epoch


def test_safe_to_datetime_with_fractional_seconds():
    """Verify parsing of ISO 8601 timestamps with fractional seconds and microsecond precision."""
    inputs = [
        "2026-11-05T02:25:00.123456+00:00",
        "2026-11-05T02:25:00.123456Z",
        "2026-11-05 02:25:00.123456"
    ]
    series = safe_to_datetime(pd.Series(inputs))
    assert str(series.dtype) == "datetime64[ns, UTC]"
    assert series.isna().sum() == 0

    expected_epoch = pd.Timestamp("2026-11-05 02:25:00.123456", tz="UTC")
    for val in series:
        assert val == expected_epoch
        assert val.microsecond == 123456


def test_safe_to_datetime_with_utc_offsets():
    """Verify that different positive and negative UTC offsets normalize to the exact UTC timestamp."""
    inputs = [
        "2026-11-05T07:55:00+05:30",  # 02:25:00 UTC
        "2026-11-04T21:25:00-05:00",  # 02:25:00 UTC
        "2026-11-05T03:25:00+01:00",  # 02:25:00 UTC
        "2026-11-05T02:25:00+00:00"   # 02:25:00 UTC
    ]
    series = safe_to_datetime(pd.Series(inputs))
    assert str(series.dtype) == "datetime64[ns, UTC]"
    assert series.isna().sum() == 0

    target_utc = pd.Timestamp("2026-11-05 02:25:00", tz="UTC")
    for val in series:
        assert val == target_utc


def test_safe_to_datetime_mixed_formats_same_dataframe():
    """Verify handling of heterogeneous timestamp formats within the exact same DataFrame."""
    mixed_data = [
        {"id": 1, "timestamp": "2026-11-05T02:25:00+00:00", "status": "FAILURE"},
        {"id": 2, "timestamp": "2026-11-05T02:25:00.123456+00:00", "status": "FAILURE"},
        {"id": 3, "timestamp": "2026-11-05 02:26:00", "status": "SUCCESS"},
        {"id": 4, "timestamp": "2026-11-05T07:56:00+05:30", "status": "FAILURE"},
        {"id": 5, "timestamp": "2026/11/05 02:27:00", "status": "SUCCESS"}
    ]
    df = pd.DataFrame(mixed_data)
    df["timestamp"] = safe_to_datetime(df["timestamp"])

    assert str(df["timestamp"].dtype) == "datetime64[ns, UTC]"
    assert df["timestamp"].isna().sum() == 0

    # Ensure sorting and time-based resampling succeed without error
    df_sorted = df.sort_values("timestamp")
    df_grouped = df_sorted.set_index("timestamp").resample("5min").agg({
        "id": "count",
        "status": lambda s: (s == "FAILURE").sum()
    }).reset_index()

    assert len(df_grouped) >= 1
    assert df_grouped["id"].sum() == 5
    assert df_grouped["status"].sum() == 3


def test_safe_to_datetime_invalid_timestamps():
    """Verify that malformed or non-date strings become NaT rather than raising exceptions."""
    invalid_inputs = [
        "not-a-timestamp",
        "9999-99-99T99:99:99",
        "random text payload",
        "2026-02-31T00:00:00",  # invalid day of month
    ]
    series = safe_to_datetime(pd.Series(invalid_inputs))
    assert str(series.dtype) == "datetime64[ns, UTC]"
    assert series.isna().sum() == len(invalid_inputs)
    for val in series:
        assert pd.isna(val)


def test_safe_to_datetime_empty_values():
    """Verify that empty strings, whitespace-only strings, None, and NaN become NaT."""
    empty_inputs = [
        "",
        "   ",
        None,
        np.nan,
        "None",
        "null"
    ]
    series = safe_to_datetime(pd.Series(empty_inputs))
    assert str(series.dtype) == "datetime64[ns, UTC]"
    assert series.isna().sum() == len(empty_inputs)


def test_timeline_resampling_with_all_invalid_timestamps():
    """Verify dashboard timeline logic does not crash when all timestamps are NaT."""
    df = pd.DataFrame({
        "id": [1, 2, 3],
        "timestamp": ["invalid", "", None],
        "status": ["FAILURE", "SUCCESS", "FAILURE"]
    })
    df["timestamp"] = safe_to_datetime(df["timestamp"])
    df_valid = df.dropna(subset=["timestamp"])

    # df_valid must be empty and timeline gracefully handles empty dataset
    assert df_valid.empty


def test_normalized_event_naive_and_aware_compatibility():
    """Verify that NormalizedEvent ensures UTC awareness so subtraction never fails."""
    e_naive = NormalizedEvent(
        timestamp=datetime(2026, 11, 5, 2, 0, 0),
        source_type="linux_auth",
        event_type="auth",
        action=ActionType.FAILED_LOGIN.value,
        status=EventStatus.FAILURE.value,
        username="admin"
    )

    e_aware = NormalizedEvent(
        timestamp=datetime(2026, 11, 5, 2, 5, 0, tzinfo=timezone.utc),
        source_type="windows_events",
        event_type="auth",
        action=ActionType.LOGIN.value,
        status=EventStatus.SUCCESS.value,
        username="admin"
    )

    assert e_naive.timestamp.tzinfo is not None
    assert e_aware.timestamp.tzinfo is not None

    diff = e_aware.timestamp - e_naive.timestamp
    assert diff == timedelta(minutes=5)
