"""
InsightGuard — Correlation Engine
===================================
Per-user rolling window (last 20 events) pattern matching.

When an attack pattern fires:
  - Returns current_score + BOOST (capped at 100)
  - Calls on_alert(alert_dict) callback if one was provided at construction

Thread-safe. reset() clears windows for one or all users.
"""

from __future__ import annotations
import threading
import time
from collections import deque
from datetime import datetime, timezone
from typing import Callable

_CLOUD_DESTINATIONS = {"cloud", "gdrive", "onedrive", "dropbox", "s3"}


class CorrelationEngine:

    BOOST       = 15
    WINDOW_SIZE = 20

    def __init__(self, on_alert: Callable[[dict], None] | None = None):
        self._windows: dict[str, deque] = {}
        self._lock    = threading.Lock()
        self._on_alert = on_alert

    # ── Public API ─────────────────────────────────────────────────────────

    def process(self, user_id: str, event: dict, current_score: float) -> float:
        """
        Add event to window, check patterns, return (possibly boosted) score.
        on_alert callback is invoked outside the lock when a pattern fires.
        """
        stamped = {**event, "_ts": time.time()}
        with self._lock:
            if user_id not in self._windows:
                self._windows[user_id] = deque(maxlen=self.WINDOW_SIZE)
            self._windows[user_id].append(stamped)
            snapshot = list(self._windows[user_id])

        alert = self._check_patterns(user_id, snapshot, stamped, current_score)
        if alert and self._on_alert:
            self._on_alert(alert)
        return min(current_score + self.BOOST, 100.0) if alert else current_score

    def reset(self, user_id: str | None = None) -> None:
        """Clear window(s). Pass user_id to clear one user; None clears all."""
        with self._lock:
            if user_id is not None:
                self._windows.pop(user_id, None)
            else:
                self._windows.clear()

    # ── Pattern detection ───────────────────────────────────────────────────

    def _check_patterns(
        self, user_id: str, window: list[dict], current: dict, score: float
    ) -> dict | None:
        """Check all patterns. Return first matching alert dict, or None."""
        now   = current["_ts"]
        prior = window[:-1]   # all events before the current one

        def recent(secs: float) -> list[dict]:
            return [e for e in prior if now - e["_ts"] <= secs]

        def make_alert(name: str, severity: str, matched: list) -> dict:
            return {
                "user_id":        user_id,
                "timestamp":      datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "source":         "correlation",
                "activity_type":  "correlation_alert",
                "pattern_name":   name,
                "severity":       severity,
                "matched_events": matched,
                "score":          min(score + self.BOOST, 100),
            }

        # 1. sensitive_file_then_usb — sensitive file access → USB within 5 min
        if current.get("source") in ("usb", "endpoint_agent"):
            for ev in recent(300):
                if ev.get("sensitivity") in ("critical", "confidential"):
                    return make_alert("sensitive_file_then_usb", "critical",
                                      [ev["_ts"], current["_ts"]])

        # 2. sensitive_file_then_cloud — sensitive file access → cloud upload within 10 min
        if (current.get("destination") in _CLOUD_DESTINATIONS
                or current.get("category") == "cloud_storage"):
            for ev in recent(600):
                if ev.get("sensitivity") in ("critical", "confidential"):
                    return make_alert("sensitive_file_then_cloud", "critical",
                                      [ev["_ts"], current["_ts"]])

        # 3. bulk_file_then_email — bulk file access → outbound email with attachment within 10 min
        if (current.get("source") in ("email", "mail_gateway")
                and current.get("direction") in ("outbound", "sent")
                and float(current.get("attachment_mb", 0)) > 0):
            for ev in recent(600):
                if (ev.get("source") in ("file", "dlp_system", "endpoint_agent")
                        and (int(ev.get("file_count", 0)) >= 5
                             or float(ev.get("data_mb", 0)) >= 50)):
                    return make_alert("bulk_file_then_email", "high_risk",
                                      [ev["_ts"], current["_ts"]])

        # 4. off_hours_multi_event — 3+ off-hours events within 30 min
        if current.get("is_off_hours") in (1, True):
            off_prior = [e for e in recent(1800) if e.get("is_off_hours") in (1, True)]
            if len(off_prior) >= 2:
                return make_alert("off_hours_multi_event", "high_risk",
                                  [e["_ts"] for e in off_prior[:2]] + [current["_ts"]])

        # 5. process_abuse_then_file — process kill/log-clear → file operation within 5 min
        if current.get("source") in ("file", "dlp_system", "endpoint_agent"):
            for ev in recent(300):
                if (ev.get("is_process_abuse")
                        or ev.get("activity_type") in ("process_kill", "log_clear")):
                    return make_alert("process_abuse_then_file", "critical",
                                      [ev["_ts"], current["_ts"]])

        return None
