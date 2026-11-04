"""Log ingestion view supporting file upload, validation, synthetic data, and parsing telemetry."""

import streamlit as st
import pandas as pd
from pathlib import Path
from typing import Optional

from loganalyzer.config import DATA_DIR
from loganalyzer.database import DatabaseManager
from loganalyzer.parsers.factory import get_parser_for_file
from loganalyzer.detection.engine import DetectionEngine
from loganalyzer.correlation.correlator import CorrelationEngine
from loganalyzer.schema import IngestionStats


def render_ingestion(db: DatabaseManager, det_engine: DetectionEngine, correlator: CorrelationEngine):
    st.markdown("### Multi-Source Security Log Ingestion")
    st.caption("Upload and normalize security logs across Linux, Windows, and generic enterprise schemas.")

    col1, col2 = st.columns([3, 2])

    with col1:
        st.markdown("##### 1. File Upload & Ingestion")
        uploaded_file = st.file_uploader(
            "Choose a log file to ingest",
            type=["log", "txt", "csv", "json", "ndjson"],
            help="Supports Linux auth.log, Windows Security CSV/JSON, Generic CSV, and Generic JSON."
        )

        manual_type = st.selectbox(
            "Log Format Detection Mode",
            ["Auto-Detect", "Linux auth.log / secure", "Windows Event Log (CSV/JSON)", "Generic JSON", "Generic CSV"],
            index=0
        )

        if st.button("Ingest Uploaded File", type="primary", disabled=uploaded_file is None):
            if uploaded_file:
                with st.spinner("Parsing, normalizing, and evaluating security rules..."):
                    raw_content = uploaded_file.getvalue().decode("utf-8", errors="replace")
                    filename = uploaded_file.name

                    # Select parser
                    if manual_type == "Linux auth.log / secure":
                        from loganalyzer.parsers.linux_auth import LinuxAuthParser
                        parser = LinuxAuthParser()
                    elif manual_type == "Windows Event Log (CSV/JSON)":
                        from loganalyzer.parsers.windows_events import WindowsEventParser
                        parser = WindowsEventParser()
                    elif manual_type == "Generic JSON":
                        from loganalyzer.parsers.generic_json import GenericJsonParser
                        parser = GenericJsonParser()
                    elif manual_type == "Generic CSV":
                        from loganalyzer.parsers.generic_csv import GenericCsvParser
                        parser = GenericCsvParser()
                    else:
                        parser = get_parser_for_file(filename, raw_content[:1000])

                    # Parse events
                    events, stats = parser.parse_content(raw_content, filename)

                    # Persist events with deduplication
                    inserted, dups = db.insert_events(events)
                    stats.duplicate_events = dups

                    # Run Detection Engine on all chronologically sorted events
                    all_events = [ev for ev in events]  # Or db.get_all_events_sorted()
                    # Assign event IDs
                    detections = det_engine.analyze_events(all_events, persist=True)

                    # Run Correlation Engine
                    incidents = correlator.correlate(all_events, detections, persist=True)

                    # Record Ingestion Job
                    db.record_ingestion(stats)

                    st.success(f"Successfully processed **{filename}**!")
                    st.toast(f"Ingested {inserted} new events, {len(detections)} alerts, {len(incidents)} incidents.", icon="✅")

    with col2:
        st.markdown("##### 2. Demo Synthetic Datasets")
        st.caption("Load realistic test logs to demonstrate attack detections:")

        sample_files = [
            ("Linux auth.log (SSH Brute Force, Spray, Privileged)", "linux_auth.log"),
            ("Windows Security Events (CSV - 4624/4625/4672/4740)", "windows_events.csv"),
            ("Windows Security Events (JSON - Remote RDP Compromise)", "windows_events.json"),
            ("Generic JSON (High Burst Rate API Stuffing)", "generic_security.json"),
            ("Generic CSV (VPN MFA Failure Spray)", "generic_security.csv"),
        ]

        for label, fname in sample_files:
            file_path = DATA_DIR / fname
            if file_path.exists():
                if st.button(f"Load {label}", key=f"btn_{fname}"):
                    with st.spinner(f"Ingesting sample {fname}..."):
                        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                            content = f.read()

                        parser = get_parser_for_file(fname, content[:1000])
                        events, stats = parser.parse_content(content, fname)
                        inserted, dups = db.insert_events(events)
                        stats.duplicate_events = dups

                        # Run detection and correlation
                        detections = det_engine.analyze_events(events, persist=True)
                        correlator.correlate(events, detections, persist=True)
                        db.record_ingestion(stats)

                        st.success(f"Loaded **{fname}** ({inserted} events, {len(detections)} alerts generated)!")
                        st.rerun()

        st.markdown("---")
        if st.button("Reset / Clear Database", type="secondary", help="Purges all events, detections, and incidents."):
            db.clear_database()
            st.warning("All records in database have been cleared.")
            st.rerun()

    # Ingestion History Table
    st.markdown("---")
    st.markdown("##### Ingestion History & Processing Statistics")
    history = db.get_ingestion_history()
    if history:
        df_hist = pd.DataFrame(history)
        cols_order = [
            "ingested_at", "source_file", "source_type", "total_records",
            "parsed_events", "duplicate_events", "invalid_records", "duration_seconds"
        ]
        df_hist = df_hist[[c for c in cols_order if c in df_hist.columns]]
        st.dataframe(df_hist, use_container_width=True)
    else:
        st.info("No ingestion history yet.")
