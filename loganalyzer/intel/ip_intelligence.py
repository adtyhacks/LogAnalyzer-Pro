"""Offline IP Intelligence and RFC classification."""

import ipaddress
from typing import Dict, Any, List, Optional
from loganalyzer.database import DatabaseManager


class IpIntelligence:
    """Provides offline IP analysis, classification, and behavioural aggregation."""

    def __init__(self, db_manager: Optional[DatabaseManager] = None):
        self.db = db_manager or DatabaseManager()

    @staticmethod
    def classify_ip(ip_str: Optional[str]) -> Dict[str, Any]:
        """Classify an IP address into scope and type without external network lookups."""
        if not ip_str or ip_str in ("-", "unknown", ""):
            return {
                "ip": ip_str or "N/A",
                "is_valid": False,
                "scope": "Unknown",
                "is_private": False,
                "is_public": False,
                "is_loopback": False,
                "is_reserved": False,
                "is_multicast": False,
                "enrichment_status": "Invalid IP"
            }

        try:
            ip_obj = ipaddress.ip_address(ip_str.strip())
            is_priv = ip_obj.is_private
            is_loop = ip_obj.is_loopback
            is_res = ip_obj.is_reserved
            is_multi = ip_obj.is_multicast
            is_pub = not (is_priv or is_loop or is_res or is_multi or ip_obj.is_link_local)

            scope = "Public Internet"
            if is_loop:
                scope = "Loopback (Localhost)"
            elif is_priv:
                scope = "Private RFC 1918 / Local Network"
            elif is_res:
                scope = "IETF Reserved"
            elif is_multi:
                scope = "Multicast"
            elif ip_obj.is_link_local:
                scope = "Link-Local"

            return {
                "ip": ip_str,
                "is_valid": True,
                "version": f"IPv{ip_obj.version}",
                "scope": scope,
                "is_private": is_priv,
                "is_public": is_pub,
                "is_loopback": is_loop,
                "is_reserved": is_res,
                "is_multicast": is_multi,
                "enrichment_status": "[Offline Mode - External Enrichment Not Available (No paid APIs/external lookups)]"
            }
        except ValueError:
            return {
                "ip": ip_str,
                "is_valid": False,
                "scope": "Unparseable IP String",
                "is_private": False,
                "is_public": False,
                "is_loopback": False,
                "is_reserved": False,
                "is_multicast": False,
                "enrichment_status": "Invalid IP Format"
            }

    def investigate_ip(self, ip_str: str) -> Dict[str, Any]:
        """Aggregate all activity, statistics, detections, and incidents associated with an IP."""
        classification = self.classify_ip(ip_str)

        with self.db.get_connection() as conn:
            cursor = conn.cursor()

            # Event counts
            cursor.execute("""
                SELECT
                    COUNT(*) as total_events,
                    SUM(CASE WHEN status = 'FAILURE' OR action = 'FAILED_LOGIN' THEN 1 ELSE 0 END) as failed_logins,
                    SUM(CASE WHEN status = 'SUCCESS' OR action = 'LOGIN' THEN 1 ELSE 0 END) as successful_logins,
                    MIN(timestamp) as first_seen,
                    MAX(timestamp) as last_seen
                FROM events
                WHERE source_ip = ?
            """, (ip_str,))
            row = cursor.fetchone()

            total_events = row["total_events"] or 0
            failed_logins = row["failed_logins"] or 0
            successful_logins = row["successful_logins"] or 0
            first_seen = row["first_seen"]
            last_seen = row["last_seen"]

            # Associated accounts
            cursor.execute("""
                SELECT username, COUNT(*) as count,
                       SUM(CASE WHEN status = 'FAILURE' THEN 1 ELSE 0 END) as fails
                FROM events
                WHERE source_ip = ? AND username IS NOT NULL AND username != ''
                GROUP BY username
                ORDER BY count DESC
            """, (ip_str,))
            associated_users = [dict(r) for r in cursor.fetchall()]

            # Associated Detections
            cursor.execute("""
                SELECT id, rule_id, rule_name, severity, description, timestamp, mitre_technique_id
                FROM detections
                WHERE source_ip = ?
                ORDER BY timestamp DESC
            """, (ip_str,))
            detections = [dict(r) for r in cursor.fetchall()]

            # Associated Incidents
            cursor.execute("""
                SELECT id, incident_id, title, severity, risk_score, status, created_at
                FROM incidents
                WHERE source_ip = ?
                ORDER BY risk_score DESC
            """, (ip_str,))
            incidents = [dict(r) for r in cursor.fetchall()]

        # Generate behavioural indicators
        indicators: List[str] = []
        if classification.get("is_public"):
            indicators.append("Traffic originates from Public Internet")
        if failed_logins > 0 and successful_logins == 0:
            indicators.append("Exclusively authentication failures (No successful sessions)")
        if len(associated_users) > 3:
            indicators.append(f"Multi-account targeting ({len(associated_users)} distinct usernames accessed)")
        if failed_logins >= 5 and successful_logins >= 1:
            indicators.append("Potential credential compromise (Successful authentication following repeated failures)")
        if detections:
            indicators.append(f"Triggered {len(detections)} security detection alerts")

        # Failure ratio
        failure_ratio = round((failed_logins / total_events) * 100, 1) if total_events > 0 else 0.0

        return {
            "classification": classification,
            "total_events": total_events,
            "failed_logins": failed_logins,
            "successful_logins": successful_logins,
            "failure_ratio_pct": failure_ratio,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "associated_users": associated_users,
            "detections": detections,
            "incidents": incidents,
            "indicators": indicators
        }
