"""
InsightGuard — Layer 2: Data Processing
=========================================
ETL pipeline that cleans, parses, and normalises raw activity logs
into a structured behavioral dataset ready for feature extraction.

Steps:
  1. Schema validation
  2. Timestamp normalisation
  3. Null / outlier handling
  4. Type coercion
  5. Activity enrichment (derived fields)
  6. Output: ProcessedLog dict (standardised across all source types)
"""

from __future__ import annotations
import re
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Optional
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from data_acquisition.collector import RawActivityLog


# ---------------------------------------------------------------------------
# Processed log — unified schema after ETL
# ---------------------------------------------------------------------------

@dataclass
class ProcessedLog:
    # Identity
    log_id:        str
    user_id:       str
    timestamp:     datetime
    activity_type: str    # login | logoff | file_access | email | usb | web
    source:        str

    # Temporal derived fields
    hour:          int    = 0
    day_of_week:   int    = 0   # 0=Monday … 6=Sunday
    is_off_hours:  bool   = False
    is_weekend:    bool   = False

    # Login / auth fields
    country_code:     str  = "US"
    failed_attempts:  int  = 0
    vpn:              bool = False
    tor:              bool = False
    new_device:       bool = False
    is_risky_country: bool = False

    # File fields
    file_count:   int   = 0
    data_mb:      float = 0.0
    destination:  str   = "local"

    # Email fields
    recipient_count:  int   = 0
    attachment_mb:    float = 0.0
    external_email:   bool  = False

    # USB fields
    usb_operation: str = ""

    # Web fields
    risky_web: bool = False

    # Quality flag
    is_valid: bool = True

    def to_dict(self) -> dict:
        d = asdict(self)
        d["timestamp"] = self.timestamp.isoformat()
        return d


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BUSINESS_START = 8
BUSINESS_END   = 18
HIGH_RISK_COUNTRIES = {"KP", "IR", "RU", "BY", "CN"}

_TS_FORMATS = [
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d",
]


# ---------------------------------------------------------------------------
# ETL Pipeline
# ---------------------------------------------------------------------------

class ETLPipeline:
    """
    Transforms a RawActivityLog into a ProcessedLog.
    Implements: validation → parse → clean → enrich → output.
    """

    # ------ Step 1: Validate -----------------------------------------------

    def _validate(self, raw: RawActivityLog) -> bool:
        if not raw.user_id or not raw.timestamp:
            return False
        if raw.activity_type not in {
            "login", "logoff", "file_access", "email", "usb", "web"
        }:
            return False
        return True

    # ------ Step 2: Parse timestamp ----------------------------------------

    def _parse_ts(self, ts_str: str) -> datetime:
        ts_str = ts_str.strip().replace("Z", "")
        for fmt in _TS_FORMATS:
            try:
                return datetime.strptime(ts_str, fmt).replace(tzinfo=timezone.utc)
            except ValueError:
                continue
        # fallback: epoch
        return datetime.fromtimestamp(0, tz=timezone.utc)

    # ------ Step 3: Clean / coerce numeric fields --------------------------

    def _safe_int(self, v, default: int = 0) -> int:
        try:
            return max(0, int(float(v)))
        except (TypeError, ValueError):
            return default

    def _safe_float(self, v, default: float = 0.0) -> float:
        try:
            return max(0.0, float(v))
        except (TypeError, ValueError):
            return default

    def _safe_bool(self, v) -> bool:
        if isinstance(v, bool):
            return v
        if isinstance(v, str):
            return v.lower() in ("true", "1", "yes")
        return bool(v)

    def _clean_country(self, code: str) -> str:
        code = str(code).strip().upper()
        return code if re.match(r"^[A-Z]{2}$", code) else "XX"

    # ------ Step 4: Enrich with derived temporal fields --------------------

    def _enrich_temporal(self, ts: datetime, p: ProcessedLog) -> None:
        p.hour        = ts.hour
        p.day_of_week = ts.weekday()
        p.is_weekend  = ts.weekday() >= 5
        p.is_off_hours = not (BUSINESS_START <= ts.hour < BUSINESS_END)

    # ------ Step 5: Map source-specific details ----------------------------

    def _map_details(self, raw: RawActivityLog, p: ProcessedLog) -> None:
        d = raw.details

        if raw.activity_type in ("login", "logoff"):
            p.country_code     = self._clean_country(d.get("country_code", "US"))
            p.failed_attempts  = self._safe_int(d.get("failed_attempts", 0))
            p.vpn              = self._safe_bool(d.get("vpn", False))
            p.tor              = self._safe_bool(d.get("tor", False))
            p.new_device       = self._safe_bool(d.get("new_device", False))
            p.is_risky_country = p.country_code in HIGH_RISK_COUNTRIES

        elif raw.activity_type == "file_access":
            p.file_count  = self._safe_int(d.get("file_count", 1))
            p.data_mb     = self._safe_float(d.get("data_mb", 0))
            p.destination = str(d.get("destination", "local"))

        elif raw.activity_type == "email":
            p.recipient_count = self._safe_int(d.get("recipient_count", 1))
            p.attachment_mb   = self._safe_float(d.get("attachment_mb", 0))
            p.external_email  = self._safe_bool(d.get("external", False))
            # email exfil: treat attachments as data_mb
            p.data_mb         = p.attachment_mb

        elif raw.activity_type == "usb":
            p.data_mb      = self._safe_float(d.get("data_mb", 0))
            p.usb_operation = str(d.get("operation", ""))

        elif raw.activity_type == "web":
            cat = str(d.get("category", "")).lower()
            _risky_cats = {"tor", "cloud_storage", "file_sharing"}
            p.risky_web = self._safe_bool(d.get("risky", False)) or cat in _risky_cats
            p.data_mb   = self._safe_float(d.get("bytes_out", 0)) / 1_048_576

    # ------ Main transform -------------------------------------------------

    def process(self, raw: RawActivityLog) -> ProcessedLog:
        ts = self._parse_ts(raw.timestamp)

        p = ProcessedLog(
            log_id        = raw.log_id,
            user_id       = raw.user_id.strip().lower(),
            timestamp     = ts,
            activity_type = raw.activity_type,
            source        = raw.source,
            is_valid      = self._validate(raw),
        )

        if p.is_valid:
            self._enrich_temporal(ts, p)
            self._map_details(raw, p)

        return p

    def process_batch(self, raws: list[RawActivityLog]) -> list[ProcessedLog]:
        results = [self.process(r) for r in raws]
        valid   = sum(1 for r in results if r.is_valid)
        invalid = len(results) - valid
        if invalid:
            print(f"[ETL] {invalid} invalid records dropped out of {len(results)}")
        return [r for r in results if r.is_valid]


# ---------------------------------------------------------------------------
# Raw event enrichment (mutates raw dict in place, no ETL class needed)
# ---------------------------------------------------------------------------

_ARCHIVE_EXTS = {".zip", ".rar", ".7z", ".tar", ".gz", ".bz2"}
_FILE_SOURCES  = {"file", "dlp_system", "endpoint_agent"}


def enrich_raw(raw: dict) -> None:
    """
    Add is_archive and is_process_abuse flags to a raw event dict.
    Mutates in place. Call before scoring in app.py _process_event.
    """
    src = raw.get("source", "")

    # is_archive: file-source event whose file_path ends in an archive extension
    is_archive = False
    if src in _FILE_SOURCES:
        fp  = raw.get("file_path", raw.get("file_name", ""))
        ext = os.path.splitext(fp)[1].lower() if fp else ""
        is_archive = ext in _ARCHIVE_EXTS or raw.get("operation", "") == "compress"
    raw["is_archive"] = is_archive

    # is_process_abuse: process kill, log clear, or any process event marked critical
    is_process_abuse = False
    if src == "process":
        atype = raw.get("activity_type", raw.get("event", ""))
        is_process_abuse = (atype in ("process_kill", "log_clear")
                            or raw.get("severity", "") == "critical")
    raw["is_process_abuse"] = is_process_abuse


# ---------------------------------------------------------------------------
# Quick self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    from data_acquisition.collector import AcquisitionRouter
    router   = AcquisitionRouter()
    pipeline = ETLPipeline()

    samples = [
        {"source": "login",  "user_id": "jsmith", "timestamp": "2024-06-03T02:30:00",
         "event": "login", "country_code": "KP", "vpn": True, "tor": True,
         "failed_attempts": 5, "new_device": True},
        {"source": "file",   "user_id": "alopez", "timestamp": "2024-06-03T09:10:00",
         "file_path": "/shared/hr", "operation": "copy",
         "file_count": 200, "data_mb": 3000, "destination": "usb"},
        {"source": "email",  "user_id": "mkumar", "timestamp": "2024-06-03T17:45:00",
         "direction": "sent", "recipient_count": 12, "attachment_mb": 45, "external": True},
        {"source": "usb",    "user_id": "twang",  "timestamp": "2024-06-03T14:00:00",
         "operation": "transfer", "data_mb": 800},
        {"source": "web",    "user_id": "rbrown", "timestamp": "2024-06-03T11:20:00",
         "url": "mega.nz", "category": "cloud_storage", "bytes_out": 500000},
    ]

    print("Layer 2 — ETL Pipeline Self-Test")
    print("=" * 55)
    for s in samples:
        raw = router.route(s)
        log = pipeline.process(raw)
        print(f"  [{log.activity_type.upper():12s}] user={log.user_id}  "
              f"hour={log.hour:02d}  off_hours={log.is_off_hours}  "
              f"data_mb={log.data_mb:.1f}  risky_country={log.is_risky_country}")
    print(f"\n  All records processed successfully.")
