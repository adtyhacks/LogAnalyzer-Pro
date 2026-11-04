"""SQLite database management, schema creation, indexes, and parameterized queries."""

import sqlite3
import json
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple
from loganalyzer.config import DATABASE_PATH, utc_now
from loganalyzer.schema import NormalizedEvent, DetectionRecord, IncidentRecord, IngestionStats


class DatabaseManager:
    """Manages SQLite connection, schema migrations, and optimized security event queries."""

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or DATABASE_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.init_database()

    def get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        return conn

    def init_database(self):
        """Initialize database schema with tables and indexes."""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            # 1. Events Table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source_type TEXT NOT NULL,
                event_type TEXT NOT NULL,
                action TEXT NOT NULL,
                status TEXT NOT NULL,
                username TEXT,
                source_ip TEXT,
                destination_ip TEXT,
                port INTEGER,
                service TEXT,
                message TEXT,
                raw_log TEXT,
                metadata TEXT,
                event_hash TEXT UNIQUE NOT NULL
            );
            """)

            cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(source_ip);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_user ON events(username);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_action_status ON events(action, status);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_hash ON events(event_hash);")

            # 2. Detections Table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS detections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id TEXT NOT NULL,
                rule_name TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                source_ip TEXT,
                username TEXT,
                affected_accounts TEXT, -- JSON list
                event_count INTEGER DEFAULT 1,
                related_event_ids TEXT, -- JSON list
                mitre_technique_id TEXT,
                mitre_technique_name TEXT,
                evidence TEXT           -- JSON object
            );
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_detections_rule ON detections(rule_id);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_detections_severity ON detections(severity);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_detections_ip ON detections(source_ip);")

            # 3. Incidents Table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id TEXT UNIQUE NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                risk_score REAL NOT NULL,
                description TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'OPEN',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                source_ip TEXT,
                affected_accounts TEXT,   -- JSON list
                related_detection_ids TEXT, -- JSON list
                related_event_ids TEXT,     -- JSON list
                mitre_techniques TEXT,      -- JSON list
                risk_factors TEXT,          -- JSON list
                investigation_notes TEXT DEFAULT ''
            );
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_incidents_ip ON incidents(source_ip);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);")

            # 4. Investigation Notes Table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS investigation_notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id TEXT NOT NULL,
                author TEXT NOT NULL,
                created_at TEXT NOT NULL,
                note TEXT NOT NULL,
                FOREIGN KEY (incident_id) REFERENCES incidents (incident_id) ON DELETE CASCADE
            );
            """)

            # 5. Ingestion History Table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS ingestion_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_file TEXT NOT NULL,
                source_type TEXT NOT NULL,
                total_records INTEGER NOT NULL,
                parsed_events INTEGER NOT NULL,
                duplicate_events INTEGER NOT NULL,
                invalid_records INTEGER NOT NULL,
                ingested_at TEXT NOT NULL,
                duration_seconds REAL NOT NULL
            );
            """)

            conn.commit()

    # --- Event Methods ---

    def insert_events(self, events: List[NormalizedEvent]) -> Tuple[int, int]:
        """
        Bulk insert events, skipping duplicates via event_hash uniqueness.
        Ensures ev.event_id is populated for both newly inserted and existing events.
        Returns: (inserted_count, duplicate_count)
        """
        inserted_count = 0
        duplicate_count = 0

        with self.get_connection() as conn:
            cursor = conn.cursor()
            for ev in events:
                try:
                    ts_str = ev.timestamp.isoformat() if isinstance(ev.timestamp, datetime) else str(ev.timestamp)
                    cursor.execute("""
                        INSERT INTO events (
                            timestamp, source_type, event_type, action, status,
                            username, source_ip, destination_ip, port, service,
                            message, raw_log, metadata, event_hash
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        ts_str,
                        ev.source_type,
                        ev.event_type,
                        ev.action,
                        ev.status,
                        ev.username,
                        ev.source_ip,
                        ev.destination_ip,
                        ev.port,
                        ev.service,
                        ev.message,
                        ev.raw_log,
                        json.dumps(ev.metadata),
                        ev.event_hash
                    ))
                    ev.event_id = cursor.lastrowid
                    inserted_count += 1
                except sqlite3.IntegrityError:
                    duplicate_count += 1
                    cursor.execute("SELECT id FROM events WHERE event_hash = ?", (ev.event_hash,))
                    row = cursor.fetchone()
                    if row:
                        ev.event_id = row[0]

            conn.commit()
        return inserted_count, duplicate_count

    def get_events(
        self,
        limit: int = 1000,
        offset: int = 0,
        source_ip: Optional[str] = None,
        username: Optional[str] = None,
        status: Optional[str] = None,
        action: Optional[str] = None,
        source_type: Optional[str] = None,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Retrieve filtered events using parameterized queries."""
        query = "SELECT * FROM events WHERE 1=1"
        params: List[Any] = []

        if source_ip:
            query += " AND source_ip = ?"
            params.append(source_ip)
        if username:
            query += " AND username = ?"
            params.append(username)
        if status:
            query += " AND status = ?"
            params.append(status)
        if action:
            query += " AND action = ?"
            params.append(action)
        if source_type:
            query += " AND source_type = ?"
            params.append(source_type)
        if start_date:
            query += " AND timestamp >= ?"
            params.append(start_date)
        if end_date:
            query += " AND timestamp <= ?"
            params.append(end_date)

        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()
            return [dict(row) for row in rows]

    def get_all_events_sorted(self) -> List[Dict[str, Any]]:
        """Retrieve all events sorted chronologically for detection and correlation engines."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM events ORDER BY timestamp ASC")
            return [dict(row) for row in cursor.fetchall()]

    # --- Detection Methods ---

    def insert_detection(self, det: DetectionRecord) -> int:
        """Insert a detection record."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            ts_str = det.timestamp.isoformat() if isinstance(det.timestamp, datetime) else str(det.timestamp)
            cursor.execute("""
                INSERT INTO detections (
                    rule_id, rule_name, severity, description, timestamp,
                    source_ip, username, affected_accounts, event_count,
                    related_event_ids, mitre_technique_id, mitre_technique_name, evidence
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                det.rule_id,
                det.rule_name,
                det.severity,
                det.description,
                ts_str,
                det.source_ip,
                det.username,
                json.dumps(det.affected_accounts),
                det.event_count,
                json.dumps(det.related_event_ids),
                det.mitre_technique_id,
                det.mitre_technique_name,
                json.dumps(det.evidence)
            ))
            det_id = cursor.lastrowid
            conn.commit()
            return det_id

    def get_detections(self, severity: Optional[str] = None, source_ip: Optional[str] = None) -> List[Dict[str, Any]]:
        """Fetch all detections matching criteria."""
        query = "SELECT * FROM detections WHERE 1=1"
        params = []
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if source_ip:
            query += " AND source_ip = ?"
            params.append(source_ip)
        query += " ORDER BY timestamp DESC"

        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            results = []
            for row in cursor.fetchall():
                d = dict(row)
                d["affected_accounts"] = json.loads(d["affected_accounts"]) if d["affected_accounts"] else []
                d["related_event_ids"] = json.loads(d["related_event_ids"]) if d["related_event_ids"] else []
                d["evidence"] = json.loads(d["evidence"]) if d["evidence"] else {}
                results.append(d)
            return results

    # --- Incident Methods ---

    def insert_or_update_incident(self, inc: IncidentRecord) -> int:
        """Insert a new incident or update if incident_id already exists."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            created_str = inc.created_at.isoformat() if isinstance(inc.created_at, datetime) else str(inc.created_at)
            updated_str = inc.updated_at.isoformat() if isinstance(inc.updated_at, datetime) else str(inc.updated_at)

            cursor.execute("SELECT id FROM incidents WHERE incident_id = ?", (inc.incident_id,))
            existing = cursor.fetchone()

            if existing:
                cursor.execute("""
                    UPDATE incidents SET
                        title = ?, severity = ?, risk_score = ?, description = ?,
                        status = ?, updated_at = ?, source_ip = ?, affected_accounts = ?,
                        related_detection_ids = ?, related_event_ids = ?,
                        mitre_techniques = ?, risk_factors = ?, investigation_notes = ?
                    WHERE incident_id = ?
                """, (
                    inc.title, inc.severity, inc.risk_score, inc.description,
                    inc.status, updated_str, inc.source_ip,
                    json.dumps(inc.affected_accounts),
                    json.dumps(inc.related_detection_ids),
                    json.dumps(inc.related_event_ids),
                    json.dumps(inc.mitre_techniques),
                    json.dumps(inc.risk_factors),
                    inc.investigation_notes,
                    inc.incident_id
                ))
                inc_id = existing["id"]
            else:
                cursor.execute("""
                    INSERT INTO incidents (
                        incident_id, title, severity, risk_score, description,
                        status, created_at, updated_at, source_ip, affected_accounts,
                        related_detection_ids, related_event_ids, mitre_techniques,
                        risk_factors, investigation_notes
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    inc.incident_id, inc.title, inc.severity, inc.risk_score, inc.description,
                    inc.status, created_str, updated_str, inc.source_ip,
                    json.dumps(inc.affected_accounts),
                    json.dumps(inc.related_detection_ids),
                    json.dumps(inc.related_event_ids),
                    json.dumps(inc.mitre_techniques),
                    json.dumps(inc.risk_factors),
                    inc.investigation_notes
                ))
                inc_id = cursor.lastrowid
            conn.commit()
            return inc_id

    def update_incident_status(self, incident_id: str, new_status: str, notes: Optional[str] = None):
        """Update status and notes for an incident."""
        now_str = utc_now().isoformat()
        with self.get_connection() as conn:
            cursor = conn.cursor()
            if notes is not None:
                cursor.execute("""
                    UPDATE incidents
                    SET status = ?, investigation_notes = ?, updated_at = ?
                    WHERE incident_id = ?
                """, (new_status, notes, now_str, incident_id))
            else:
                cursor.execute("""
                    UPDATE incidents
                    SET status = ?, updated_at = ?
                    WHERE incident_id = ?
                """, (new_status, now_str, incident_id))
            conn.commit()

    def get_incidents(
        self,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        search_query: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Retrieve incidents with filtering and search support."""
        query = "SELECT * FROM incidents WHERE 1=1"
        params = []
        if status:
            query += " AND status = ?"
            params.append(status)
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if search_query:
            query += " AND (incident_id LIKE ? OR title LIKE ? OR description LIKE ? OR source_ip LIKE ? OR affected_accounts LIKE ?)"
            term = f"%{search_query}%"
            params.extend([term, term, term, term, term])

        query += " ORDER BY risk_score DESC, updated_at DESC"

        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            results = []
            for row in cursor.fetchall():
                d = dict(row)
                d["affected_accounts"] = json.loads(d["affected_accounts"]) if d["affected_accounts"] else []
                d["related_detection_ids"] = json.loads(d["related_detection_ids"]) if d["related_detection_ids"] else []
                d["related_event_ids"] = json.loads(d["related_event_ids"]) if d["related_event_ids"] else []
                d["mitre_techniques"] = json.loads(d["mitre_techniques"]) if d["mitre_techniques"] else []
                d["risk_factors"] = json.loads(d["risk_factors"]) if d["risk_factors"] else []
                results.append(d)
            return results

    def add_investigation_note(self, incident_id: str, author: str, note: str):
        """Add an analyst note to an incident."""
        now_str = utc_now().isoformat()
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO investigation_notes (incident_id, author, created_at, note)
                VALUES (?, ?, ?, ?)
            """, (incident_id, author, now_str, note))
            conn.commit()

    def get_investigation_notes(self, incident_id: str) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM investigation_notes WHERE incident_id = ? ORDER BY created_at ASC",
                (incident_id,)
            )
            return [dict(row) for row in cursor.fetchall()]

    # --- Ingestion History ---

    def record_ingestion(self, stats: IngestionStats):
        """Save ingestion job results."""
        now_str = utc_now().isoformat()
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO ingestion_history (
                    source_file, source_type, total_records, parsed_events,
                    duplicate_events, invalid_records, ingested_at, duration_seconds
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                stats.source_file,
                stats.source_type,
                stats.total_records,
                stats.parsed_events,
                stats.duplicate_events,
                stats.invalid_records,
                now_str,
                stats.duration_seconds
            ))
            conn.commit()

    def get_ingestion_history(self) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM ingestion_history ORDER BY ingested_at DESC LIMIT 50")
            return [dict(row) for row in cursor.fetchall()]

    # --- Analytics & Aggregations ---

    def get_stats_summary(self) -> Dict[str, Any]:
        """Produce comprehensive SOC summary metrics."""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            # Total events
            cursor.execute("SELECT COUNT(*) FROM events")
            total_events = cursor.fetchone()[0]

            # Total detections
            cursor.execute("SELECT COUNT(*) FROM detections")
            total_detections = cursor.fetchone()[0]

            # Severity counts for detections
            cursor.execute("""
                SELECT severity, COUNT(*) FROM detections GROUP BY severity
            """)
            det_severities = dict(cursor.fetchall())

            # Incidents summary
            cursor.execute("SELECT COUNT(*) FROM incidents WHERE status = 'OPEN'")
            open_incidents = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM incidents WHERE severity = 'CRITICAL'")
            critical_incidents = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM incidents WHERE severity = 'HIGH'")
            high_incidents = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(DISTINCT source_ip) FROM detections WHERE source_ip IS NOT NULL")
            suspicious_ips_count = cursor.fetchone()[0]

            # Top targeted accounts
            cursor.execute("""
                SELECT username, COUNT(*) as cnt FROM events
                WHERE action IN ('FAILED_LOGIN', 'LOGIN') AND username IS NOT NULL AND username != ''
                GROUP BY username ORDER BY cnt DESC LIMIT 10
            """)
            top_accounts = [dict(row) for row in cursor.fetchall()]

            # Top suspicious IPs
            cursor.execute("""
                SELECT source_ip, COUNT(*) as cnt FROM events
                WHERE action = 'FAILED_LOGIN' AND source_ip IS NOT NULL AND source_ip != ''
                GROUP BY source_ip ORDER BY cnt DESC LIMIT 10
            """)
            top_ips = [dict(row) for row in cursor.fetchall()]

            # MITRE technique distribution
            cursor.execute("""
                SELECT mitre_technique_id, mitre_technique_name, COUNT(*) as cnt
                FROM detections
                WHERE mitre_technique_id IS NOT NULL
                GROUP BY mitre_technique_id, mitre_technique_name
                ORDER BY cnt DESC
            """)
            mitre_dist = [dict(row) for row in cursor.fetchall()]

            return {
                "total_events": total_events,
                "total_detections": total_detections,
                "critical_count": det_severities.get("CRITICAL", 0),
                "high_count": det_severities.get("HIGH", 0),
                "medium_count": det_severities.get("MEDIUM", 0),
                "low_count": det_severities.get("LOW", 0),
                "open_incidents": open_incidents,
                "critical_incidents": critical_incidents,
                "high_incidents": high_incidents,
                "unique_suspicious_ips": suspicious_ips_count,
                "top_accounts": top_accounts,
                "top_ips": top_ips,
                "mitre_distribution": mitre_dist
            }

    def clear_database(self):
        """Purge all records (for testing or reset)."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM events;")
            cursor.execute("DELETE FROM detections;")
            cursor.execute("DELETE FROM incidents;")
            cursor.execute("DELETE FROM investigation_notes;")
            cursor.execute("DELETE FROM ingestion_history;")
            conn.commit()
