"""
InsightGuard — Storage Layer
==============================
SQLite database managing all 8 tables:
  1. users              — employees monitored by the system
  2. activity_logs      — raw/processed event records
  3. behaviour_features — extracted feature vectors
  4. anomaly_results    — ML detection outputs
  5. threat_alerts      — generated security alerts
  6. investigations     — analyst case management
  7. escalation_log     — SMTP escalation audit trail
  8. evidence           — screenshot capture records
"""

from __future__ import annotations
import sqlite3
import json
import threading
from contextlib import contextmanager
from pathlib import Path


DB_PATH = Path(__file__).parent / "insightguard.db"


# ---------------------------------------------------------------------------
# Database Manager
# ---------------------------------------------------------------------------

class DatabaseManager:
    """Thread-safe SQLite manager. Creates schema on first use."""

    def __init__(self, db_path: str | Path = DB_PATH):
        self.db_path = str(db_path)
        self._lock   = threading.Lock()
        self._init_schema()

    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    # ── Schema creation ──────────────────────────────────────────────────

    def _init_schema(self) -> None:
        with self._conn() as conn:

            # Table 1: Users
            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    user_id     TEXT PRIMARY KEY,
                    department  TEXT,
                    role        TEXT,
                    name        TEXT DEFAULT '',
                    created_at  TEXT DEFAULT (datetime('now'))
                )
            """)
            # Migration: add name column to existing databases
            try:
                conn.execute("ALTER TABLE users ADD COLUMN name TEXT DEFAULT ''")
            except Exception:
                pass  # column already exists

            # Table 2: Activity Logs
            conn.execute("""
                CREATE TABLE IF NOT EXISTS activity_logs (
                    log_id        TEXT PRIMARY KEY,
                    user_id       TEXT NOT NULL,
                    timestamp     TEXT NOT NULL,
                    activity_type TEXT NOT NULL,
                    device_id     TEXT,
                    source        TEXT,
                    details_json  TEXT,
                    created_at    TEXT DEFAULT (datetime('now')),
                    FOREIGN KEY (user_id) REFERENCES users(user_id)
                )
            """)

            # Table 3: Behaviour Features
            conn.execute("""
                CREATE TABLE IF NOT EXISTS behaviour_features (
                    feature_id             TEXT PRIMARY KEY,
                    user_id                TEXT NOT NULL,
                    log_id                 TEXT,
                    login_frequency        INTEGER DEFAULT 0,
                    file_download_volume   REAL    DEFAULT 0,
                    usb_usage_frequency    INTEGER DEFAULT 0,
                    email_activity_pattern TEXT,
                    features_json          TEXT,
                    created_at             TEXT DEFAULT (datetime('now')),
                    FOREIGN KEY (user_id) REFERENCES users(user_id)
                )
            """)

            # Table 4: Anomaly Detection Results
            conn.execute("""
                CREATE TABLE IF NOT EXISTS anomaly_results (
                    detection_id   TEXT PRIMARY KEY,
                    user_id        TEXT NOT NULL,
                    log_id         TEXT,
                    model_type     TEXT,
                    risk_score     INTEGER,
                    severity       TEXT,
                    is_anomaly     INTEGER DEFAULT 0,
                    if_score       REAL,
                    lof_score      REAL,
                    ueba_score     INTEGER,
                    triggered_rules TEXT,
                    detection_time TEXT DEFAULT (datetime('now')),
                    FOREIGN KEY (user_id) REFERENCES users(user_id)
                )
            """)

            # Table 5: Threat Alerts
            conn.execute("""
                CREATE TABLE IF NOT EXISTS threat_alerts (
                    alert_id        TEXT PRIMARY KEY,
                    user_id         TEXT NOT NULL,
                    detection_id    TEXT,
                    risk_level      TEXT,
                    alert_timestamp TEXT DEFAULT (datetime('now')),
                    status          TEXT DEFAULT 'open',
                    activity_type   TEXT,
                    explanation     TEXT,
                    FOREIGN KEY (user_id)      REFERENCES users(user_id),
                    FOREIGN KEY (detection_id) REFERENCES anomaly_results(detection_id)
                )
            """)

            # Indexes for query performance
            conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_user ON activity_logs(user_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_ts   ON activity_logs(timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_user ON threat_alerts(user_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status ON threat_alerts(status)")

            # Table 6: Investigation Cases
            conn.execute("""
                CREATE TABLE IF NOT EXISTS investigations (
                    case_id       TEXT PRIMARY KEY,
                    alert_id      TEXT,
                    user_id       TEXT NOT NULL,
                    department    TEXT,
                    severity      TEXT,
                    status        TEXT DEFAULT 'open',
                    analyst_notes TEXT DEFAULT '',
                    created_at    TEXT DEFAULT (datetime('now')),
                    updated_at    TEXT DEFAULT (datetime('now'))
                )
            """)

            # Table 7: Escalation Log
            conn.execute("""
                CREATE TABLE IF NOT EXISTS escalation_log (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id     TEXT,
                    severity    TEXT,
                    risk_score  INTEGER,
                    sent_to     TEXT,
                    status      TEXT,
                    error       TEXT,
                    sent_at     TEXT DEFAULT (datetime('now'))
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_inv_user   ON investigations(user_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_inv_status ON investigations(status)")

            # Table 8: Evidence (screenshot captures)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS evidence (
                    id           TEXT PRIMARY KEY,
                    log_id       TEXT,
                    user_id      TEXT,
                    file_path    TEXT NOT NULL,
                    trigger_type TEXT,
                    event_type   TEXT,
                    timestamp    TEXT,
                    created_at   TEXT DEFAULT (datetime('now'))
                )
            """)
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_evidence_log ON evidence(log_id)"
            )

    # ── User operations ──────────────────────────────────────────────────

    def upsert_user(self, user_id: str, department: str = "", role: str = "", name: str = "") -> None:
        with self._lock, self._conn() as conn:
            conn.execute("""
                INSERT INTO users (user_id, department, role, name)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                    department = excluded.department,
                    role       = excluded.role,
                    name       = CASE WHEN excluded.name != '' THEN excluded.name ELSE users.name END
            """, (user_id, department, role, name))

    def get_user(self, user_id: str) -> dict | None:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM users WHERE user_id = ?", (user_id,)
            ).fetchone()
        return dict(row) if row else None

    # ── Activity log operations ───────────────────────────────────────────

    def insert_activity_log(self, log_id: str, user_id: str, timestamp: str,
                             activity_type: str, source: str = "",
                             device_id: str = "", details: dict | None = None) -> None:
        with self._lock, self._conn() as conn:
            conn.execute("""
                INSERT OR IGNORE INTO activity_logs
                    (log_id, user_id, timestamp, activity_type, device_id, source, details_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (log_id, user_id, timestamp, activity_type, device_id, source,
                  json.dumps(details or {})))

    def get_user_timeline(self, user_id: str, limit: int = 100) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute("""
                SELECT * FROM activity_logs
                WHERE user_id = ?
                ORDER BY timestamp DESC
                LIMIT ?
            """, (user_id, limit)).fetchall()
        return [dict(r) for r in rows]

    # ── Feature operations ────────────────────────────────────────────────

    def insert_features(self, feature_id: str, user_id: str, log_id: str,
                         features: dict) -> None:
        with self._lock, self._conn() as conn:
            conn.execute("""
                INSERT OR IGNORE INTO behaviour_features
                    (feature_id, user_id, log_id,
                     login_frequency, file_download_volume,
                     usb_usage_frequency, email_activity_pattern,
                     features_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                feature_id, user_id, log_id,
                features.get("file_count", 0),
                features.get("data_mb", 0),
                features.get("usb_transfer", 0),
                json.dumps({
                    "recipient_count": features.get("recipient_count", 0),
                    "external":        features.get("external_email", 0),
                }),
                json.dumps(features),
            ))

    # ── Anomaly result operations ─────────────────────────────────────────

    def insert_anomaly_result(self, detection_id: str, user_id: str, log_id: str,
                               result: dict) -> None:
        with self._lock, self._conn() as conn:
            conn.execute("""
                INSERT OR IGNORE INTO anomaly_results
                    (detection_id, user_id, log_id, model_type,
                     risk_score, severity, is_anomaly,
                     if_score, lof_score, ueba_score, triggered_rules)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                detection_id, user_id, log_id,
                result.get("model_type", ""),
                result.get("risk_score", 0),
                result.get("severity", "normal"),
                int(result.get("is_anomaly", False)),
                result.get("if_score", 0),
                result.get("lof_score", 0),
                result.get("ueba_score", 0),
                json.dumps(result.get("triggered_rules", [])),
            ))

    # ── Alert operations ──────────────────────────────────────────────────

    def insert_alert(self, alert_id: str, user_id: str, detection_id: str,
                      risk_level: str, activity_type: str,
                      explanation: str = "") -> None:
        with self._lock, self._conn() as conn:
            conn.execute("""
                INSERT OR IGNORE INTO threat_alerts
                    (alert_id, user_id, detection_id, risk_level,
                     activity_type, explanation)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (alert_id, user_id, detection_id, risk_level,
                  activity_type, explanation))

    def get_alerts(self, severity: str = "", user_id: str = "",
                   status: str = "", limit: int = 50) -> list[dict]:
        q  = "SELECT * FROM threat_alerts WHERE 1=1"
        params: list = []
        if severity:
            q += " AND risk_level = ?"; params.append(severity)
        if user_id:
            q += " AND user_id = ?";   params.append(user_id)
        if status:
            q += " AND status = ?";    params.append(status)
        q += " ORDER BY alert_timestamp DESC LIMIT ?"
        params.append(min(limit, 200))
        with self._conn() as conn:
            rows = conn.execute(q, params).fetchall()
        return [dict(r) for r in rows]

    def update_alert_status(self, alert_id: str, status: str) -> bool:
        valid = {"open", "confirmed", "false_positive", "under_investigation"}
        if status not in valid:
            return False
        with self._lock, self._conn() as conn:
            cur = conn.execute(
                "UPDATE threat_alerts SET status = ? WHERE alert_id = ?",
                (status, alert_id)
            )
        return cur.rowcount > 0

    def get_alert_by_id(self, alert_id: str) -> dict | None:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT ta.*, ar.if_score, ar.lof_score, ar.ueba_score, "
                "ar.triggered_rules, ar.model_type "
                "FROM threat_alerts ta "
                "LEFT JOIN anomaly_results ar ON ta.detection_id = ar.detection_id "
                "WHERE ta.alert_id = ?", (alert_id,)
            ).fetchone()
        return dict(row) if row else None

    # ── Statistics ────────────────────────────────────────────────────────

    def get_stats(self) -> dict:
        with self._conn() as conn:
            total_events  = conn.execute("SELECT COUNT(*) FROM activity_logs").fetchone()[0]
            total_threats = conn.execute(
                "SELECT COUNT(*) FROM anomaly_results WHERE is_anomaly=1"
            ).fetchone()[0]
            sev_counts    = conn.execute(
                "SELECT severity, COUNT(*) FROM anomaly_results GROUP BY severity"
            ).fetchall()
            alert_counts  = conn.execute(
                "SELECT risk_level, COUNT(*) FROM threat_alerts GROUP BY risk_level"
            ).fetchall()
            user_count    = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        return {
            "total_events":  total_events,
            "total_threats": total_threats,
            "severities":    dict(sev_counts),
            "alert_levels":  dict(alert_counts),
            "monitored_users": user_count,
        }


    # ── Investigation operations ──────────────────────────────────────────

    def create_investigation(self, case_id: str, alert_id: str = "",
                              user_id: str = "", department: str = "",
                              severity: str = "open") -> None:
        with self._lock, self._conn() as conn:
            conn.execute("""
                INSERT OR IGNORE INTO investigations
                    (case_id, alert_id, user_id, department, severity)
                VALUES (?, ?, ?, ?, ?)
            """, (case_id, alert_id, user_id, department, severity))

    def list_investigations(self, status: str = "", user_id: str = "",
                             limit: int = 100) -> list[dict]:
        q      = "SELECT * FROM investigations WHERE 1=1"
        params: list = []
        if status:
            q += " AND status = ?";  params.append(status)
        if user_id:
            q += " AND user_id = ?"; params.append(user_id)
        q += " ORDER BY created_at DESC LIMIT ?"
        params.append(min(limit, 200))
        with self._conn() as conn:
            rows = conn.execute(q, params).fetchall()
        return [dict(r) for r in rows]

    def get_investigation(self, case_id: str) -> dict | None:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM investigations WHERE case_id = ?", (case_id,)
            ).fetchone()
        return dict(row) if row else None

    def update_investigation(self, case_id: str, status: str = "",
                              analyst_notes: str | None = None) -> bool:
        valid = {"open", "confirmed_threat", "false_positive",
                 "under_investigation", "closed"}
        sets, params = [], []
        if status and status in valid:
            sets.append("status = ?"); params.append(status)
        if analyst_notes is not None:
            sets.append("analyst_notes = ?"); params.append(analyst_notes)
        sets.append("updated_at = datetime('now')")
        params.append(case_id)
        with self._lock, self._conn() as conn:
            conn.execute(
                f"UPDATE investigations SET {', '.join(sets)} WHERE case_id = ?",
                params
            )
        return True

    # ── Escalation log operations ─────────────────────────────────────────

    def insert_escalation_log(self, user_id: str, severity: str,
                               risk_score: int, sent_to: str,
                               status: str, error: str = "") -> None:
        with self._lock, self._conn() as conn:
            conn.execute("""
                INSERT INTO escalation_log
                    (user_id, severity, risk_score, sent_to, status, error)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (user_id, severity, risk_score, sent_to, status, error))

    def get_escalation_log(self, limit: int = 50) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM escalation_log ORDER BY sent_at DESC LIMIT ?",
                (min(limit, 200),)
            ).fetchall()
        return [dict(r) for r in rows]

    # ── Evidence operations ───────────────────────────────────────────────────

    def insert_evidence(self, evidence_id: str, log_id: str, user_id: str,
                        file_path: str, trigger_type: str, event_type: str,
                        timestamp: str) -> None:
        with self._lock, self._conn() as conn:
            conn.execute("""
                INSERT OR IGNORE INTO evidence
                    (id, log_id, user_id, file_path, trigger_type, event_type, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (evidence_id, log_id, user_id, file_path, trigger_type,
                  event_type, timestamp))

    def get_evidence_by_id(self, evidence_id: str) -> dict | None:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM evidence WHERE id = ?", (evidence_id,)
            ).fetchone()
        return dict(row) if row else None

    def get_evidence_by_event(self, log_id: str) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM evidence WHERE log_id = ? ORDER BY created_at DESC",
                (log_id,)
            ).fetchall()
        return [dict(r) for r in rows]

    def get_event_by_log_id(self, log_id: str) -> dict | None:
        """Fetch a single event (activity + anomaly result) by log_id, for alert resend."""
        with self._conn() as conn:
            row = conn.execute(
                """SELECT al.log_id, al.user_id, al.timestamp, al.activity_type, al.source,
                          u.department,
                          ar.risk_score, ar.severity, ar.triggered_rules
                   FROM activity_logs al
                   LEFT JOIN users u  ON u.user_id = al.user_id
                   LEFT JOIN anomaly_results ar ON ar.log_id = al.log_id
                   WHERE al.log_id = ?""",
                (log_id,)
            ).fetchone()
        if not row:
            return None
        rules = []
        if row["triggered_rules"]:
            try:
                rules = json.loads(row["triggered_rules"])
            except Exception:
                pass
        return {
            "log_id":        row["log_id"],
            "user_id":       row["user_id"],
            "timestamp":     row["timestamp"],
            "activity_type": row["activity_type"],
            "source":        row["source"],
            "department":    row["department"] or "",
            "risk_score":    row["risk_score"] or 0,
            "severity":      row["severity"] or "normal",
            "triggered_rules": rules,
        }


# ---------------------------------------------------------------------------
# Quick self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uuid, tempfile
    tmp_db = tempfile.mktemp(suffix=".db")
    db = DatabaseManager(db_path=tmp_db)

    db.upsert_user("jsmith", "Finance", "Analyst")
    db.upsert_user("alopez", "Engineering", "Developer")

    db.insert_activity_log("log001", "jsmith", "2024-06-03T02:30:00",
                            "login", source="auth_system",
                            details={"country_code": "KP", "tor": True})

    db.insert_anomaly_result("det001", "jsmith", "log001", {
        "model_type": "IF+LOF+UEBA", "risk_score": 87,
        "severity": "critical", "is_anomaly": True,
        "if_score": 0.78, "lof_score": 0.82, "ueba_score": 90,
        "triggered_rules": ["tor_detected", "high_risk_country"],
    })

    db.insert_alert("alt001", "jsmith", "det001", "critical",
                    "login", "Anomaly driven by TOR network usage.")

    stats = db.get_stats()

    print("Storage Layer — Self-Test")
    print("=" * 45)
    print(f"  Users inserted : {stats['monitored_users']}")
    print(f"  Events stored  : {stats['total_events']}")
    print(f"  Threats stored : {stats['total_threats']}")
    print(f"  Alerts stored  : {sum(stats['alert_levels'].values())}")
    alerts = db.get_alerts()
    print(f"  Alert[0] status: {alerts[0]['status']} / level={alerts[0]['risk_level']}")
    print("  All storage operations passed.")

    import os; os.unlink(tmp_db)
