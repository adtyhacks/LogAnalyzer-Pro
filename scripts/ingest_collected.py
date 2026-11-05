"""CLI tool to ingest collected Windows Security or Sysmon events into LogAnalyzer Pro."""

import sys
import argparse
from pathlib import Path
from typing import Optional

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from loganalyzer.database import DatabaseManager
from loganalyzer.parsers.factory import get_parser_for_file
from loganalyzer.detection.engine import DetectionEngine
from loganalyzer.correlation.correlator import CorrelationEngine
from loganalyzer.config import utc_now


def ingest_file(file_path: Path, db: DatabaseManager, analyze: bool = True, is_synthetic: Optional[bool] = None):
    print(f"\n[*] Processing file: {file_path.name}")
    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        print(f"[-] Could not read {file_path}: {e}")
        return

    parser = get_parser_for_file(file_path, sample_content=content[:1000])
    print(f"[*] Detected parser: {parser.__class__.__name__} (Source: {parser.SOURCE_TYPE})")

    events, stats = parser.parse_content(content, filename=file_path.name)
    print(f"[+] Parsed {stats.parsed_events}/{stats.total_records} events in {stats.duration_seconds}s (Invalid: {stats.invalid_records})")

    if not events:
        print("[-] No events to insert.")
        return

    # Check synthetic tagging
    if is_synthetic is None:
        name_lower = file_path.name.lower()
        is_synthetic = "demo" in name_lower or "synthetic" in name_lower or "fixture" in name_lower

    if is_synthetic:
        for ev in events:
            ev.is_synthetic = True
            ev.event_hash = ev.compute_hash()
        print(f"[*] Marked {len(events)} events as SYNTHETIC telemetry (Lab Simulation).")

    inserted, dups = db.insert_events(events)
    stats.duplicate_events = dups
    print(f"[+] Database: {inserted} inserted, {dups} duplicates skipped.")

    # Record history
    db.record_ingestion(stats)

    # Update channel checkpoints if applicable
    max_record_id = 0
    channel_name = None
    latest_ts = None
    hostname = None

    for ev in events:
        channel_name = ev.channel or channel_name
        hostname = ev.hostname or hostname
        if ev.timestamp:
            ts_iso = ev.timestamp.isoformat()
            if latest_ts is None or ts_iso > latest_ts:
                latest_ts = ts_iso
        if ev.record_id and ev.record_id > max_record_id:
            max_record_id = ev.record_id

    if not channel_name:
        channel_name = parser.SOURCE_TYPE

    if channel_name:
        db.update_channel_checkpoint(
            channel=channel_name,
            last_record_id=max_record_id,
            last_timestamp=latest_ts,
            computer_name=hostname,
            new_events_count=inserted
        )
        rec_info = f"Last RecordID: {max_record_id}" if max_record_id > 0 else f"Latest TS: {latest_ts}"
        print(f"[+] Updated DB checkpoint: {channel_name} -> {rec_info}")

    # Run detection and correlation analysis on newly ingested batch
    if analyze and inserted > 0:
        det_engine = DetectionEngine(db_manager=db)
        correlator = CorrelationEngine(db_manager=db)
        detections = det_engine.analyze_events(events, persist=True)
        incidents = correlator.correlate(events, detections, persist=True)
        print(f"[+] Security Analysis: {len(detections)} detection alert(s), {len(incidents)} incident(s) correlated.")


def main():
    parser = argparse.ArgumentParser(description="Ingest collected log files into LogAnalyzer Pro")
    parser.add_argument("--file", "-f", type=str, help="Path to a collected log file")
    parser.add_argument("--dir", "-d", type=str, default="data/collected", help="Directory of collected logs")
    parser.add_argument("--channel", "-c", type=str, help="Optional channel name (for compatibility)")
    parser.add_argument("--synthetic", "--demo", action="store_true", help="Explicitly mark all ingested events as synthetic lab data")
    parser.add_argument("--no-analyze", action="store_true", help="Skip detection and correlation analysis")
    args = parser.parse_args()

    db = DatabaseManager()
    analyze = not args.no_analyze
    synth_flag = True if args.synthetic else None

    if args.file:
        target = Path(args.file)
        if target.exists():
            ingest_file(target, db, analyze=analyze, is_synthetic=synth_flag)
        else:
            print(f"[-] File not found: {target}")
            sys.exit(1)
    else:
        target_dir = Path(args.dir)
        if not target_dir.exists():
            print(f"[*] Directory {target_dir} does not exist yet. No files to ingest.")
            return

        files = list(target_dir.glob("*.xml")) + list(target_dir.glob("*.json")) + list(target_dir.glob("*.csv")) + list(target_dir.glob("*.log"))
        if not files:
            print(f"[*] No log files found in {target_dir}")
            return

        print(f"[+] Found {len(files)} file(s) in {target_dir}")
        for f in files:
            ingest_file(f, db, analyze=analyze, is_synthetic=synth_flag)


if __name__ == "__main__":
    main()
