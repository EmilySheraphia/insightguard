"""
InsightGuard — Alert Escalation Engine
=======================================
Runs a background thread that drains a queue of alert payloads and sends
emails via Gmail SMTP_SSL when escalation is enabled.
"""

from __future__ import annotations
import json
import queue
import smtplib
import ssl
import threading
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from html import escape
from pathlib import Path

_SEV_ORDER = {"normal": 0, "suspicious": 1, "high_risk": 2, "critical": 3}

_DEFAULT_CONFIG = {
    "enabled": False,
    "smtp_host": "smtp.gmail.com",
    "smtp_port": 465,
    "smtp_user": "",
    "smtp_password": "",
    "recipient_email": "",
    "min_severity": "critical",
    "severities": [],        # if non-empty, overrides min_severity
    "dashboard_url": "http://localhost:5000",
}


class EscalationEngine:
    """
    Background email escalation thread.

    Usage:
        engine = EscalationEngine(config_path="storage/escalation_config.json")
        engine.start()
        engine.enqueue(event_payload)   # called from _process_event()
    """

    def __init__(self, config_path=None):
        if config_path is None:
            config_path = Path(__file__).parent / "storage" / "escalation_config.json"
        self._config_path = Path(config_path)
        self.config: dict = dict(_DEFAULT_CONFIG)
        self._load_config()
        self._queue: queue.Queue = queue.Queue(maxsize=200)
        self._config_lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._db = None

    def set_db(self, db) -> None:
        """Inject the DatabaseManager so escalation log can be written."""
        self._db = db

    def _load_config(self) -> None:
        if self._config_path.exists():
            try:
                with open(self._config_path) as f:
                    loaded = json.load(f)
                self.config.update(loaded)
            except Exception as e:
                print(f"[Escalation] Config load error: {e}")

    def _save_config(self) -> None:
        self._config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._config_path, "w") as f:
            json.dump(self.config, f, indent=4)

    def update_config(self, new_config: dict) -> None:
        """Replace config in memory and persist to disk."""
        with self._config_lock:
            self.config.update(new_config)
            self._save_config()

    def start(self) -> None:
        """Start the background drain thread (idempotent)."""
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._drain_loop, daemon=True)
        self._thread.start()
        print("[Escalation] Background thread started.")

    def enqueue(self, event_payload: dict) -> None:
        """
        Called from _process_event() when severity meets the threshold.
        Drops silently if queue is full or escalation is disabled.
        """
        with self._config_lock:
            enabled    = self.config.get("enabled")
            min_sev    = self.config.get("min_severity", "critical")
            severities = self.config.get("severities", [])
        if not enabled:
            return
        sev = event_payload.get("severity", "normal")
        if severities:
            # Explicit list mode: email only for the selected severities
            if sev not in severities:
                return
        else:
            # Legacy min_severity mode
            if _SEV_ORDER.get(sev, 0) < _SEV_ORDER.get(min_sev, 3):
                return
        try:
            self._queue.put_nowait(event_payload)
        except queue.Full:
            pass

    def send_test_email(self) -> dict:
        """Send a test email immediately. Returns {status, error}."""
        payload = {
            "user_id":       "test_user",
            "department":    "Test",
            "severity":      "critical",
            "risk_score":    99,
            "activity_type": "test",
            "triggered_rules": ["test_rule"],
            "timestamp":     datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        return self._send_email(payload)

    def _drain_loop(self) -> None:
        while True:
            try:
                payload = self._queue.get(timeout=5)
                result  = self._send_email(payload)
                self._log_escalation(payload, result["status"], result.get("error", ""))
            except queue.Empty:
                continue
            except Exception as e:
                print(f"[Escalation] Drain error: {e}")

    def _send_email(self, payload: dict) -> dict:
        with self._config_lock:
            cfg = dict(self.config)  # snapshot under lock
        if not cfg.get("smtp_user") or not cfg.get("smtp_password") or not cfg.get("recipient_email"):
            return {"status": "skipped", "error": "SMTP credentials not configured"}
        user_id       = escape(payload.get("user_id", ""))
        department    = escape(payload.get("department", ""))
        activity_type = escape(payload.get("activity_type", ""))
        timestamp     = escape(payload.get("timestamp", ""))
        subject = (
            f"[InsightGuard ALERT] {payload.get('severity','').upper()} — "
            f"{user_id} @ {department}"
        )
        rules_html = "".join(
            f"<li>{escape(r)}</li>" for r in (payload.get("triggered_rules") or [])
        )
        sev   = payload.get("severity", "normal")
        color = {"critical": "#f85149", "high_risk": "#db6d28",
                 "suspicious": "#e3b341", "normal": "#3fb950"}.get(sev, "#8b949e")
        dashboard_url = cfg.get("dashboard_url", "http://localhost:5000")
        body_html = f"""
        <div style="font-family:Arial,sans-serif;max-width:600px">
          <div style="background:#161b22;padding:20px;border-radius:8px">
            <h2 style="color:#e6edf3;margin:0 0 16px">InsightGuard — Insider Threat Alert</h2>
            <div style="background:#21262d;border-radius:6px;padding:16px;margin-bottom:12px">
              <div style="font-size:13px;color:#8b949e;margin-bottom:4px">Risk Score</div>
              <div style="font-size:32px;font-weight:700;color:{color}">{payload.get('risk_score', 0)}</div>
              <div style="display:inline-block;background:{color}22;border:1px solid {color}44;
                          border-radius:4px;padding:2px 10px;font-size:12px;color:{color};margin-top:6px">
                {sev.upper().replace('_', ' ')}
              </div>
            </div>
            <table style="width:100%;font-size:13px;color:#e6edf3;border-collapse:collapse">
              <tr><td style="padding:6px 0;color:#8b949e;width:140px">User ID</td>
                  <td style="padding:6px 0;font-family:monospace">{user_id}</td></tr>
              <tr><td style="padding:6px 0;color:#8b949e">Department</td>
                  <td style="padding:6px 0">{department}</td></tr>
              <tr><td style="padding:6px 0;color:#8b949e">Activity</td>
                  <td style="padding:6px 0">{activity_type}</td></tr>
              <tr><td style="padding:6px 0;color:#8b949e">Timestamp</td>
                  <td style="padding:6px 0;font-family:monospace">{timestamp}</td></tr>
            </table>
            {f'<div style="margin-top:12px"><div style="font-size:12px;color:#8b949e;margin-bottom:6px">Triggered Rules</div><ul style="color:#f85149;font-family:monospace;font-size:12px;margin:0;padding-left:20px">{rules_html}</ul></div>' if rules_html else ''}
            <div style="margin-top:16px;padding-top:12px;border-top:1px solid #30363d">
              <a href="{dashboard_url}/" style="background:#58a6ff;color:#fff;
                 padding:8px 16px;border-radius:6px;text-decoration:none;font-size:13px">
                View Dashboard
              </a>
            </div>
          </div>
        </div>
        """
        try:
            ctx = ssl.create_default_context()
            with smtplib.SMTP_SSL(cfg["smtp_host"], int(cfg["smtp_port"]), context=ctx) as server:
                server.login(cfg["smtp_user"], cfg["smtp_password"])
                msg = MIMEMultipart("alternative")
                msg["Subject"] = subject
                msg["From"]    = cfg["smtp_user"]
                msg["To"]      = cfg["recipient_email"]
                msg.attach(MIMEText(body_html, "html"))
                server.sendmail(cfg["smtp_user"], cfg["recipient_email"], msg.as_string())
            print(f"[Escalation] Email sent → {cfg['recipient_email']} for {payload.get('user_id')}")
            return {"status": "sent", "error": ""}
        except Exception as e:
            print(f"[Escalation] Email failed: {e}")
            return {"status": "failed", "error": str(e)}

    def send_immediate(self, payload: dict) -> dict:
        """Send an email immediately, bypassing the queue. Logs the result."""
        result = self._send_email(payload)
        self._log_escalation(payload, result["status"], result.get("error", ""))
        return result

    def _log_escalation(self, payload: dict, status: str, error: str = "") -> None:
        if self._db is None:
            return
        try:
            self._db.insert_escalation_log(
                user_id    = payload.get("user_id", ""),
                severity   = payload.get("severity", ""),
                risk_score = int(payload.get("risk_score", 0)),
                sent_to    = self.config.get("recipient_email", ""),
                status     = status,
                error      = error,
            )
        except Exception as e:
            print(f"[Escalation] Log write error: {e}")
