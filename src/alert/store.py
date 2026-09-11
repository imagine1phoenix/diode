"""
Alert Store — SQLite-backed persistence for alerts.

PRD §4: SQLite for alert storage (simple schema, appropriate for prototype scale).
rules.md R3: SQLite or Postgres — no MongoDB, no Redis as primary store.
rules.md R6.5: Dashboard reads from here via the API.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from pathlib import Path
from typing import Any

from src.alert.schema import Alert

logger = logging.getLogger(__name__)


class AlertStore:
    """
    SQLite-backed alert storage with the schema matching PRD §6.

    Thread-safe: uses a new connection per operation (SQLite handles
    concurrent reads but requires care with writes).
    """

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        """Get a new database connection."""
        conn = sqlite3.connect(str(self._db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_db(self) -> None:
        """Create the alerts table if it doesn't exist."""
        conn = self._get_conn()
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    alert_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    flow_id TEXT NOT NULL,
                    threat_class TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    severity TEXT NOT NULL,
                    evidence TEXT NOT NULL,
                    detector_version TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_alerts_threat_class
                ON alerts(threat_class)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_alerts_severity
                ON alerts(severity)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_alerts_timestamp
                ON alerts(timestamp)
            """)
            conn.commit()
            logger.info("Alert store initialized at %s", self._db_path)
        finally:
            conn.close()

    def save(self, alert: Alert) -> None:
        """
        Persist a single alert to the database.

        Args:
            alert: Validated Alert object.
        """
        conn = self._get_conn()
        try:
            conn.execute(
                """
                INSERT OR REPLACE INTO alerts
                (alert_id, timestamp, flow_id, threat_class, confidence,
                 severity, evidence, detector_version)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert.alert_id,
                    alert.timestamp,
                    alert.flow_id,
                    alert.threat_class.value,
                    alert.confidence,
                    alert.severity.value,
                    alert.evidence.model_dump_json(),
                    alert.detector_version,
                ),
            )
            conn.commit()
        finally:
            conn.close()

    def save_batch(self, alerts: list[Alert]) -> int:
        """
        Persist multiple alerts in a single transaction.

        Args:
            alerts: List of validated Alert objects.

        Returns:
            Number of alerts saved.
        """
        if not alerts:
            return 0

        conn = self._get_conn()
        try:
            conn.executemany(
                """
                INSERT OR REPLACE INTO alerts
                (alert_id, timestamp, flow_id, threat_class, confidence,
                 severity, evidence, detector_version)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        a.alert_id, a.timestamp, a.flow_id,
                        a.threat_class.value, a.confidence,
                        a.severity.value, a.evidence.model_dump_json(),
                        a.detector_version,
                    )
                    for a in alerts
                ],
            )
            conn.commit()
            if len(alerts) > 0:
                conn.execute(
                    """
                    DELETE FROM alerts
                    WHERE alert_id NOT IN (
                        SELECT alert_id FROM alerts
                        ORDER BY timestamp DESC
                        LIMIT 200
                    )
                    """
                )
                conn.commit()
            return len(alerts)
        finally:
            conn.close()

    def prune_stale(self, keep_limit: int = 200) -> int:
        """Keep the database responsive and aligned with the latest alert telemetry."""
        conn = self._get_conn()
        try:
            cursor = conn.execute(
                """
                DELETE FROM alerts
                WHERE alert_id NOT IN (
                    SELECT alert_id FROM alerts
                    ORDER BY timestamp DESC
                    LIMIT ?
                )
                """,
                (keep_limit,),
            )
            deleted = cursor.rowcount
            conn.commit()
            return max(0, deleted)
        finally:
            conn.close()

    def _row_to_dict(self, row: sqlite3.Row) -> dict[str, Any]:
        """Convert a database row to a dictionary matching the Alert schema."""
        d = dict(row)
        d["evidence"] = json.loads(d["evidence"])
        return d

    def get_recent(self, limit: int = 50) -> list[dict[str, Any]]:
        """Get the most recent alerts, ordered by timestamp descending."""
        conn = self._get_conn()
        try:
            cursor = conn.execute(
                "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            )
            return [self._row_to_dict(row) for row in cursor.fetchall()]
        finally:
            conn.close()

    def get_by_id(self, alert_id: str) -> dict[str, Any] | None:
        """Get a single alert by its ID."""
        conn = self._get_conn()
        try:
            cursor = conn.execute(
                "SELECT * FROM alerts WHERE alert_id = ?",
                (alert_id,),
            )
            row = cursor.fetchone()
            return self._row_to_dict(row) if row else None
        finally:
            conn.close()

    def get_by_threat_class(
        self, threat_class: str, limit: int = 50
    ) -> list[dict[str, Any]]:
        """Get alerts filtered by threat class."""
        conn = self._get_conn()
        try:
            cursor = conn.execute(
                "SELECT * FROM alerts WHERE threat_class = ? ORDER BY timestamp DESC LIMIT ?",
                (threat_class, limit),
            )
            return [self._row_to_dict(row) for row in cursor.fetchall()]
        finally:
            conn.close()

    def get_by_severity(
        self, severity: str, limit: int = 50
    ) -> list[dict[str, Any]]:
        """Get alerts filtered by severity level."""
        conn = self._get_conn()
        try:
            cursor = conn.execute(
                "SELECT * FROM alerts WHERE severity = ? ORDER BY timestamp DESC LIMIT ?",
                (severity, limit),
            )
            return [self._row_to_dict(row) for row in cursor.fetchall()]
        finally:
            conn.close()

    def get_stats(self) -> dict[str, Any]:
        """
        Get aggregated alert statistics.

        Returns:
            Dict with counts by threat_class and severity, plus total count.
        """
        conn = self._get_conn()
        try:
            # Total count
            total = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]

            # By threat class
            by_threat = {}
            cursor = conn.execute(
                "SELECT threat_class, COUNT(*) as count FROM alerts GROUP BY threat_class"
            )
            for row in cursor.fetchall():
                by_threat[row["threat_class"]] = row["count"]

            # By severity
            by_severity = {}
            cursor = conn.execute(
                "SELECT severity, COUNT(*) as count FROM alerts GROUP BY severity"
            )
            for row in cursor.fetchall():
                by_severity[row["severity"]] = row["count"]

            # Recent rate (alerts in last 60 seconds)
            cursor = conn.execute(
                """SELECT COUNT(*) FROM alerts
                   WHERE timestamp >= datetime('now', '-60 seconds')"""
            )
            recent_rate = cursor.fetchone()[0]

            return {
                "total_alerts": total,
                "by_threat_class": by_threat,
                "by_severity": by_severity,
                "alerts_last_60s": recent_rate,
            }
        finally:
            conn.close()

    def get_timeline(self, minutes: int = 30, bucket_seconds: int = 60) -> list[dict[str, Any]]:
        """
        Get alert counts bucketed by time interval for timeline chart.

        Args:
            minutes: How many minutes of history to return.
            bucket_seconds: Size of each time bucket in seconds.

        Returns:
            List of {bucket, count} dicts ordered by time.
        """
        conn = self._get_conn()
        try:
            cursor = conn.execute(
                """
                SELECT
                    strftime('%%Y-%%m-%%dT%%H:%%M:00', timestamp) as bucket,
                    COUNT(*) as count
                FROM alerts
                WHERE timestamp >= datetime('now', ? || ' minutes')
                GROUP BY bucket
                ORDER BY bucket ASC
                """,
                (f"-{minutes}",),
            )
            return [dict(row) for row in cursor.fetchall()]
        finally:
            conn.close()
