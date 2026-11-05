"""CSV Export utility for detections, incidents, and events."""

import csv
import io
from typing import List, Dict, Any
from loganalyzer.utils import sanitize_privacy


class CsvExporter:
    """Exports structured data to CSV strings."""

    @staticmethod
    def export_detections(detections: List[Dict[str, Any]]) -> str:
        output = io.StringIO()
        fieldnames = [
            "id", "timestamp", "rule_id", "rule_name", "severity",
            "source_ip", "username", "event_count", "mitre_technique_id",
            "mitre_technique_name", "description"
        ]
        writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()

        for det in detections:
            row = dict(det)
            if row.get("username"):
                row["username"] = sanitize_privacy(row["username"])
            if row.get("description"):
                row["description"] = sanitize_privacy(row["description"])
            writer.writerow(row)

        return output.getvalue()

    @staticmethod
    def export_incidents(incidents: List[Dict[str, Any]]) -> str:
        output = io.StringIO()
        fieldnames = [
            "incident_id", "title", "severity", "risk_score", "status",
            "telemetry_nature", "created_at", "updated_at", "source_ip", "affected_accounts",
            "mitre_techniques", "description"
        ]
        writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()

        for inc in incidents:
            row = dict(inc)
            if "telemetry_nature" not in row:
                row["telemetry_nature"] = "GENUINE"
            if isinstance(row.get("affected_accounts"), list):
                row["affected_accounts"] = "; ".join(sanitize_privacy(row["affected_accounts"]))
            elif row.get("affected_accounts"):
                row["affected_accounts"] = sanitize_privacy(row["affected_accounts"])
            if isinstance(row.get("mitre_techniques"), list):
                row["mitre_techniques"] = "; ".join(row["mitre_techniques"])
            if row.get("title"):
                row["title"] = sanitize_privacy(row["title"])
            if row.get("description"):
                row["description"] = sanitize_privacy(row["description"])
            writer.writerow(row)

        return output.getvalue()

    @staticmethod
    def export_events(events: List[Dict[str, Any]]) -> str:
        output = io.StringIO()
        fieldnames = [
            "id", "timestamp", "hostname", "source_type", "event_type", "action",
            "status", "username", "source_ip", "port", "service", "is_synthetic", "telemetry_type", "message"
        ]
        writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()

        for ev in events:
            row = dict(ev)
            is_synth = bool(row.get("is_synthetic", 0))
            row["is_synthetic"] = 1 if is_synth else 0
            row["telemetry_type"] = "SYNTHETIC (Lab)" if is_synth else "GENUINE (Live Host)"
            if row.get("username"):
                row["username"] = sanitize_privacy(row["username"])
            if row.get("message"):
                row["message"] = sanitize_privacy(row["message"])
            writer.writerow(row)

        return output.getvalue()
