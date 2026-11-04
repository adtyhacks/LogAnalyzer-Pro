"""CSV Export utility for detections, incidents, and events."""

import csv
import io
from typing import List, Dict, Any


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
            writer.writerow(row)

        return output.getvalue()

    @staticmethod
    def export_incidents(incidents: List[Dict[str, Any]]) -> str:
        output = io.StringIO()
        fieldnames = [
            "incident_id", "title", "severity", "risk_score", "status",
            "created_at", "updated_at", "source_ip", "affected_accounts",
            "mitre_techniques", "description"
        ]
        writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()

        for inc in incidents:
            row = dict(inc)
            if isinstance(row.get("affected_accounts"), list):
                row["affected_accounts"] = "; ".join(row["affected_accounts"])
            if isinstance(row.get("mitre_techniques"), list):
                row["mitre_techniques"] = "; ".join(row["mitre_techniques"])
            writer.writerow(row)

        return output.getvalue()

    @staticmethod
    def export_events(events: List[Dict[str, Any]]) -> str:
        output = io.StringIO()
        fieldnames = [
            "id", "timestamp", "source_type", "event_type", "action",
            "status", "username", "source_ip", "port", "service", "message"
        ]
        writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()

        for ev in events:
            row = dict(ev)
            writer.writerow(row)

        return output.getvalue()
