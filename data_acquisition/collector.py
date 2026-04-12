"""
InsightGuard — Layer 1: Data Acquisition
=========================================
Collects and normalises raw activity logs from five enterprise sources:
  - Login / logoff records
  - File access events
  - Email communication logs
  - USB device usage
  - Web browsing history

Each collector parses its source into a canonical ActivityLog dict
ready for the Data Processing Layer.

Canonical schema:
  user_id        str
  timestamp      ISO-8601
  activity_type  login | logoff | file_access | email | usb | web
  source         str   (originating system)
  details        dict  (source-specific payload)
"""

from __future__ import annotations
import uuid
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import Any


# ---------------------------------------------------------------------------
# Canonical activity log record
# ---------------------------------------------------------------------------

@dataclass
class RawActivityLog:
    user_id:       str
    timestamp:     str
    activity_type: str
    source:        str
    details:       dict = field(default_factory=dict)
    log_id:        str  = field(default_factory=lambda: str(uuid.uuid4())[:12])

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# Base collector
# ---------------------------------------------------------------------------

class BaseCollector:
    """All collectors inherit from this; override collect()."""
    source_name: str = "unknown"

    def collect(self, raw: dict) -> RawActivityLog:
        raise NotImplementedError

    def _ts(self, raw: dict, key: str = "timestamp") -> str:
        v = raw.get(key, datetime.utcnow().isoformat())
        # normalise to ISO-8601 if needed
        if isinstance(v, datetime):
            return v.isoformat()
        return str(v)


# ---------------------------------------------------------------------------
# Layer 1a: Login / Logoff Collector
# ---------------------------------------------------------------------------

class LoginCollector(BaseCollector):
    """
    Parses login and logoff events from Active Directory / SIEM logs.

    Input fields:
      user_id, timestamp, event ('login'|'logoff'),
      country_code, device_id, failed_attempts, vpn, tor, new_device
    """
    source_name = "auth_system"

    def collect(self, raw: dict) -> RawActivityLog:
        event = raw.get("event", "login")
        return RawActivityLog(
            user_id       = str(raw["user_id"]),
            timestamp     = self._ts(raw),
            activity_type = event,
            source        = self.source_name,
            details = {
                "country_code":    raw.get("country_code", "US"),
                "device_id":       raw.get("device_id", "unknown"),
                "failed_attempts": int(raw.get("failed_attempts", 0)),
                "vpn":             bool(raw.get("vpn", False)),
                "tor":             bool(raw.get("tor", False)),
                "new_device":      bool(raw.get("new_device", False)),
            },
        )


# ---------------------------------------------------------------------------
# Layer 1b: File Access Collector
# ---------------------------------------------------------------------------

class FileAccessCollector(BaseCollector):
    """
    Parses file access events from DLP / file-system audit logs.

    Input fields:
      user_id, timestamp, file_path, operation (read|write|delete|copy),
      file_count, data_mb, destination (local|usb|cloud|email)
    """
    source_name = "dlp_system"

    def collect(self, raw: dict) -> RawActivityLog:
        return RawActivityLog(
            user_id       = str(raw["user_id"]),
            timestamp     = self._ts(raw),
            activity_type = "file_access",
            source        = self.source_name,
            details = {
                "file_path":   raw.get("file_path", ""),
                "operation":   raw.get("operation", "read"),
                "file_count":  int(raw.get("file_count", 1)),
                "data_mb":     float(raw.get("data_mb", 0)),
                "destination": raw.get("destination", "local"),
            },
        )


# ---------------------------------------------------------------------------
# Layer 1c: Email Communication Collector
# ---------------------------------------------------------------------------

class EmailCollector(BaseCollector):
    """
    Parses email activity from mail gateway / Exchange logs.

    Input fields:
      user_id, timestamp, direction (sent|received),
      recipient_count, attachment_count, attachment_mb, external
    """
    source_name = "mail_gateway"

    def collect(self, raw: dict) -> RawActivityLog:
        return RawActivityLog(
            user_id       = str(raw["user_id"]),
            timestamp     = self._ts(raw),
            activity_type = "email",
            source        = self.source_name,
            details = {
                "direction":        raw.get("direction", "sent"),
                "recipient_count":  int(raw.get("recipient_count", 1)),
                "attachment_count": int(raw.get("attachment_count", 0)),
                "attachment_mb":    float(raw.get("attachment_mb", 0)),
                "external":         bool(raw.get("external", False)),
            },
        )


# ---------------------------------------------------------------------------
# Layer 1d: USB Device Collector
# ---------------------------------------------------------------------------

class USBCollector(BaseCollector):
    """
    Parses USB device events from endpoint security agents.

    Input fields:
      user_id, timestamp, device_id, operation (insert|remove|transfer),
      data_mb
    """
    source_name = "endpoint_agent"

    def collect(self, raw: dict) -> RawActivityLog:
        return RawActivityLog(
            user_id       = str(raw["user_id"]),
            timestamp     = self._ts(raw),
            activity_type = "usb",
            source        = self.source_name,
            details = {
                "device_id": raw.get("device_id", "unknown"),
                "operation": raw.get("operation", "insert"),
                "data_mb":   float(raw.get("data_mb", 0)),
            },
        )


# ---------------------------------------------------------------------------
# Layer 1e: Web Browsing Collector
# ---------------------------------------------------------------------------

class WebCollector(BaseCollector):
    """
    Parses web proxy / DNS logs.

    Input fields:
      user_id, timestamp, url, category, bytes_out, blocked
    """
    source_name = "web_proxy"

    RISKY_CATEGORIES = {"cloud_storage", "file_sharing", "tor", "vpn", "darkweb"}

    def collect(self, raw: dict) -> RawActivityLog:
        category = raw.get("category", "general")
        return RawActivityLog(
            user_id       = str(raw["user_id"]),
            timestamp     = self._ts(raw),
            activity_type = "web",
            source        = self.source_name,
            details = {
                "url":       raw.get("url", ""),
                "category":  category,
                "bytes_out": int(raw.get("bytes_out", 0)),
                "blocked":   bool(raw.get("blocked", False)),
                "risky":     category in self.RISKY_CATEGORIES,
            },
        )


# ---------------------------------------------------------------------------
# Layer 1f: Process Monitoring Collector
# ---------------------------------------------------------------------------

class ProcessCollector(BaseCollector):
    """
    Parses process monitoring events from endpoint agents.

    Input fields:
      user_id, timestamp, activity_type (process_launch|process_kill|log_clear),
      process_name, command_line, pid, device_id, off_hours
    """
    source_name = "process"

    def collect(self, raw: dict) -> RawActivityLog:
        return RawActivityLog(
            user_id       = str(raw["user_id"]),
            timestamp     = self._ts(raw),
            activity_type = raw.get("activity_type", "process_launch"),
            source        = self.source_name,
            details = {
                "process_name": raw.get("process_name", ""),
                "command_line": raw.get("command_line", ""),
                "pid":          int(raw.get("pid", 0)),
                "device_id":    raw.get("device_id", "unknown"),
                "off_hours":    bool(raw.get("off_hours", False)),
            },
        )


# ---------------------------------------------------------------------------
# Acquisition Router — dispatches to the correct collector
# ---------------------------------------------------------------------------

class AcquisitionRouter:
    """
    Entry point for Layer 1.
    Routes a raw log dict to the correct collector based on 'source' field.
    """

    _collectors = {
        "auth_system":    LoginCollector(),
        "dlp_system":     FileAccessCollector(),
        "mail_gateway":   EmailCollector(),
        "endpoint_agent": USBCollector(),
        "web_proxy":      WebCollector(),
        "process":        ProcessCollector(),
        # convenience aliases
        "login":          LoginCollector(),
        "file":           FileAccessCollector(),
        "email":          EmailCollector(),
        "usb":            USBCollector(),
        "web":            WebCollector(),
    }

    def route(self, raw: dict) -> RawActivityLog:
        source = raw.get("source", "login")
        collector = self._collectors.get(source)
        if collector is None:
            raise ValueError(f"Unknown source '{source}'. "
                             f"Valid: {list(self._collectors.keys())}")
        return collector.collect(raw)

    def route_batch(self, raws: list[dict]) -> list[RawActivityLog]:
        return [self.route(r) for r in raws]


# ---------------------------------------------------------------------------
# Quick self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    router = AcquisitionRouter()

    samples = [
        {"source": "login",  "user_id": "jsmith", "timestamp": "2024-06-03T02:30:00",
         "event": "login", "country_code": "KP", "vpn": True, "tor": True,
         "failed_attempts": 5, "new_device": True},
        {"source": "file",   "user_id": "alopez", "timestamp": "2024-06-03T09:10:00",
         "file_path": "/shared/hr/salaries.xlsx", "operation": "copy",
         "file_count": 200, "data_mb": 3000, "destination": "usb"},
        {"source": "email",  "user_id": "mkumar", "timestamp": "2024-06-03T17:45:00",
         "direction": "sent", "recipient_count": 12, "attachment_mb": 45, "external": True},
        {"source": "usb",    "user_id": "twang",  "timestamp": "2024-06-03T14:00:00",
         "operation": "transfer", "data_mb": 800},
        {"source": "web",    "user_id": "rbrown", "timestamp": "2024-06-03T11:20:00",
         "url": "mega.nz/upload", "category": "cloud_storage", "bytes_out": 500000},
    ]

    print("Layer 1 — Data Acquisition Self-Test")
    print("=" * 50)
    for s in samples:
        log = router.route(s)
        print(f"  [{log.activity_type.upper():12s}] user={log.user_id}  "
              f"source={log.source}  details_keys={list(log.details.keys())}")
    print(f"\n  {len(samples)}/{len(samples)} records acquired successfully.")
