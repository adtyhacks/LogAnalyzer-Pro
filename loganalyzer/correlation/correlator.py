"""Event correlation engine grouping detections and events into cohesive security incidents."""

from collections import defaultdict
from datetime import datetime, timedelta
import hashlib
from typing import List, Dict, Any, Optional, Set
from loganalyzer.schema import NormalizedEvent, DetectionRecord, IncidentRecord, IncidentStatus
from loganalyzer.database import DatabaseManager
from loganalyzer.intel.risk_scorer import RiskScorer
from loganalyzer.intel.ip_intelligence import IpIntelligence
from loganalyzer.config import utc_now


class CorrelationEngine:
    """Correlates multiple detections and security events across time and identity axes."""

    def __init__(self, db_manager: Optional[DatabaseManager] = None):
        self.db = db_manager or DatabaseManager()
        self.risk_scorer = RiskScorer()
        self.ip_intel = IpIntelligence(self.db)
        # Default correlation window: findings within 60 minutes of each other
        self.correlation_window = timedelta(minutes=60)

    def correlate(
        self,
        events: List[NormalizedEvent],
        detections: List[DetectionRecord],
        persist: bool = True
    ) -> List[IncidentRecord]:
        """Group related detections into distinct incidents avoiding duplicate incident creation."""
        if not detections:
            return []

        # Group detections primarily by source_ip (or username if IP is absent)
        groups = defaultdict(list)
        for det in detections:
            key = det.source_ip if det.source_ip else f"user:{det.username or 'unknown'}"
            groups[key].append(det)

        incidents: List[IncidentRecord] = []

        for entity_key, det_list in groups.items():
            # Cluster detections by time window
            sorted_dets = sorted(det_list, key=lambda d: d.timestamp)
            clusters: List[List[DetectionRecord]] = []
            current_cluster = [sorted_dets[0]]

            for i in range(1, len(sorted_dets)):
                prev = sorted_dets[i - 1]
                curr = sorted_dets[i]
                if (curr.timestamp - prev.timestamp) <= self.correlation_window:
                    current_cluster.append(curr)
                else:
                    clusters.append(current_cluster)
                    current_cluster = [curr]
            clusters.append(current_cluster)

            for cluster in clusters:
                inc = self._create_incident_from_cluster(cluster, events)
                if inc:
                    if persist:
                        self.db.insert_or_update_incident(inc)
                    incidents.append(inc)

        return incidents

    def _create_incident_from_cluster(
        self,
        cluster: List[DetectionRecord],
        all_events: List[NormalizedEvent]
    ) -> IncidentRecord:
        # Determine primary source IP
        ips = [d.source_ip for d in cluster if d.source_ip]
        primary_ip = ips[0] if ips else None

        # Gather all affected accounts
        accounts_set: Set[str] = set()
        for d in cluster:
            accounts_set.update(d.affected_accounts)
            if d.username:
                accounts_set.add(d.username)
        affected_accounts = sorted(list(accounts_set))

        # Gather related detection IDs
        det_ids = [d.detection_id for d in cluster if d.detection_id is not None]

        # Gather all related event IDs from detections
        event_ids_set: Set[int] = set()
        for d in cluster:
            event_ids_set.update(d.related_event_ids)
        related_event_ids = sorted(list(event_ids_set))

        # MITRE techniques involved
        mitre_set: Set[str] = set()
        for d in cluster:
            if d.mitre_technique_id:
                mitre_set.add(d.mitre_technique_id)
        mitre_techniques = sorted(list(mitre_set))

        # Check for suspicious success
        has_suspicious_success = any(
            d.rule_id == "RULE_SUSPICIOUS_SUCCESS" for d in cluster
        )

        # Check total failure count in correlated events
        failure_count = sum(
            1 for eid in related_event_ids
            for ev in all_events
            if ev.event_id == eid and ev.status == "FAILURE"
        )
        if failure_count == 0:
            failure_count = sum(d.event_count for d in cluster)

        # IP scope analysis
        ip_classification = self.ip_intel.classify_ip(primary_ip)
        is_public_ip = ip_classification.get("is_public", False)

        # Determine highest severity among detections
        severity_order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        max_sev = "LOW"
        for d in cluster:
            if severity_order.get(d.severity, 1) > severity_order.get(max_sev, 1):
                max_sev = d.severity

        # Calculate explainable risk score
        risk_score, risk_factors = self.risk_scorer.calculate_score(
            severity=max_sev,
            affected_accounts=affected_accounts,
            failure_count=failure_count,
            has_suspicious_success=has_suspicious_success,
            is_public_ip=is_public_ip,
            technique_count=len(mitre_techniques),
            detection_count=len(cluster)
        )

        # Overall incident severity derived from risk score
        overall_severity = self.risk_scorer.map_score_to_severity(risk_score)

        # Generate deterministic incident ID to prevent duplicate incidents for same correlated event sequence
        earliest_ts = cluster[0].timestamp
        latest_ts = cluster[-1].timestamp
        date_prefix = earliest_ts.strftime("%Y%m%d")
        hash_seed = f"{primary_ip}|{','.join(affected_accounts)}|{date_prefix}|{earliest_ts.strftime('%H%M')}"
        digest = hashlib.md5(hash_seed.encode()).hexdigest()[:6].upper()
        incident_id = f"INC-{date_prefix}-{digest}"

        # Build Title and Description
        rule_names = sorted(list({d.rule_name for d in cluster}))
        if has_suspicious_success:
            title = f"Credential Compromise Following Multi-Stage Attack ({primary_ip or 'Internal'})"
        elif "Password Spraying Attack" in rule_names:
            title = f"Distributed Password Spray Campaign ({primary_ip or 'Unknown IP'})"
        elif "Brute-Force Authentication Attempt" in rule_names:
            title = f"Targeted Brute-Force Attack against {len(affected_accounts)} Account(s)"
        else:
            title = f"Correlated Authentication Security Anomaly ({primary_ip or 'Host'})"

        desc = (
            f"Correlated {len(cluster)} detection alerts involving {len(affected_accounts)} account(s) "
            f"from IP '{primary_ip or 'Unknown'}'. Observed attack patterns: {', '.join(rule_names)}. "
            f"Techniques identified: {', '.join(mitre_techniques) if mitre_techniques else 'None'}."
        )

        return IncidentRecord(
            incident_id=incident_id,
            title=title,
            severity=overall_severity,
            risk_score=risk_score,
            description=desc,
            status=IncidentStatus.OPEN.value,
            created_at=earliest_ts,
            updated_at=latest_ts,
            source_ip=primary_ip,
            affected_accounts=affected_accounts,
            related_detection_ids=det_ids,
            related_event_ids=related_event_ids,
            mitre_techniques=mitre_techniques,
            risk_factors=risk_factors,
            investigation_notes=f"Initial automated correlation triage completed at {utc_now().strftime('%Y-%m-%d %H:%M:%S UTC')}."
        )
