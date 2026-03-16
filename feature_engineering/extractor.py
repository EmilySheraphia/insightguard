"""
InsightGuard — Layer 3: Feature Engineering
============================================
Extracts the behavioral feature vector from a ProcessedLog.

Features align exactly with the class diagram's FeatureEngineering class:
  - login_frequency        (derived from activity type)
  - file_download_volume   (file_count + data_mb)
  - usb_usage_frequency    (usb events)
  - email_activity_pattern (recipient count, external flag)

Plus additional UEBA-quality signals used by the ML layer.

Output: FeatureVector (dataclass) + flat numeric array for sklearn.
"""

from __future__ import annotations
from dataclasses import dataclass, asdict, field
from typing import ClassVar
import numpy as np
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from data_processing.etl_pipeline import ProcessedLog


# ---------------------------------------------------------------------------
# Feature vector — matches the class diagram attributes
# ---------------------------------------------------------------------------

@dataclass
class FeatureVector:
    """
    Numeric behavioral feature vector for one activity log event.
    All values are floats/ints — ready for sklearn.
    """

    # ── Temporal ─────────────────────────────────────────────
    hour:           int   = 0
    day_of_week:    int   = 0
    is_off_hours:   int   = 0   # 0/1
    is_weekend:     int   = 0   # 0/1

    # ── Activity type encoding (one-hot compressed to int) ───
    event_type_code: int  = 0   # 0=login,1=logoff,2=file,3=email,4=usb,5=web

    # ── Login / auth signals ──────────────────────────────────
    failed_attempts:   int  = 0
    vpn:               int  = 0   # 0/1
    tor:               int  = 0   # 0/1
    new_device:        int  = 0   # 0/1
    is_risky_country:  int  = 0   # 0/1
    is_unknown_country: int = 0   # 0/1

    # ── File / transfer signals ───────────────────────────────
    file_count:  int   = 0   # login_frequency proxy via file events
    data_mb:     float = 0.0 # file_download_volume

    # ── USB signals ──────────────────────────────────────────
    usb_transfer:    int = 0  # 1 if usb + data moved  (usb_usage_frequency)
    usb_data_mb:     float = 0.0

    # ── Email signals ─────────────────────────────────────────
    recipient_count:  int   = 0   # email_activity_pattern
    attachment_mb:    float = 0.0
    external_email:   int   = 0   # 0/1

    # ── Web signals ───────────────────────────────────────────
    risky_web: int = 0   # 0/1

    # Column order for sklearn (class variable, not an instance field)
    COLUMNS: ClassVar[list[str]] = [
        "hour", "day_of_week", "is_off_hours", "is_weekend",
        "event_type_code",
        "failed_attempts", "vpn", "tor", "new_device",
        "is_risky_country", "is_unknown_country",
        "file_count", "data_mb",
        "usb_transfer", "usb_data_mb",
        "recipient_count", "attachment_mb", "external_email",
        "risky_web",
    ]

    def to_array(self) -> np.ndarray:
        d = asdict(self)
        return np.array([d[c] for c in self.COLUMNS], dtype=float)

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# Feature engineering class (matches class diagram)
# ---------------------------------------------------------------------------

_EVENT_CODE = {
    "login": 0, "logoff": 1, "file_access": 2,
    "email": 3, "usb": 4, "web": 5,
}

KNOWN_COUNTRIES = {"US", "GB", "CA", "AU", "DE", "IN", "SG", "FR", "NL", "JP"}


class FeatureEngineering:
    """
    Extracts behavioral features from a ProcessedLog.

    Implements extractFeatures() from the class diagram.
    """

    def extractFeatures(self, log: ProcessedLog) -> FeatureVector:
        """Convert a ProcessedLog into a FeatureVector."""
        fv = FeatureVector(
            # temporal
            hour          = log.hour,
            day_of_week   = log.day_of_week,
            is_off_hours  = int(log.is_off_hours),
            is_weekend    = int(log.is_weekend),

            # event type
            event_type_code = _EVENT_CODE.get(log.activity_type, 0),

            # auth
            failed_attempts    = min(log.failed_attempts, 20),
            vpn                = int(log.vpn),
            tor                = int(log.tor),
            new_device         = int(log.new_device),
            is_risky_country   = int(log.is_risky_country),
            is_unknown_country = int(
                log.country_code not in KNOWN_COUNTRIES
                and not log.is_risky_country
            ),

            # file / download
            file_count = min(log.file_count, 1000),
            data_mb    = min(log.data_mb, 10_000.0),

            # usb
            usb_transfer = int(log.activity_type == "usb" and log.data_mb > 0),
            usb_data_mb  = min(log.data_mb, 10_000.0) if log.activity_type == "usb" else 0.0,

            # email
            recipient_count = min(log.recipient_count, 200),
            attachment_mb   = min(log.attachment_mb, 5_000.0),
            external_email  = int(log.external_email),

            # web
            risky_web = int(log.risky_web),
        )
        return fv

    def extractFeatures_batch(self, logs: list[ProcessedLog]) -> list[FeatureVector]:
        return [self.extractFeatures(l) for l in logs]

    def to_matrix(self, logs: list[ProcessedLog]) -> np.ndarray:
        """Return (N, n_features) numpy matrix for sklearn."""
        vecs = self.extractFeatures_batch(logs)
        return np.vstack([v.to_array() for v in vecs])


# ---------------------------------------------------------------------------
# Quick self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys, os
    sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
    from data_acquisition.collector import AcquisitionRouter
    from data_processing.etl_pipeline import ETLPipeline

    router   = AcquisitionRouter()
    pipeline = ETLPipeline()
    fe       = FeatureEngineering()

    samples = [
        {"source": "login",  "user_id": "jsmith", "timestamp": "2024-06-03T02:30:00",
         "event": "login", "country_code": "KP", "vpn": True, "tor": True,
         "failed_attempts": 5, "new_device": True},
        {"source": "file",   "user_id": "alopez", "timestamp": "2024-06-03T09:10:00",
         "file_path": "/shared/hr", "operation": "copy",
         "file_count": 200, "data_mb": 3000, "destination": "usb"},
        {"source": "email",  "user_id": "mkumar", "timestamp": "2024-06-03T17:45:00",
         "direction": "sent", "recipient_count": 12,
         "attachment_mb": 45, "external": True},
    ]

    print("Layer 3 — Feature Engineering Self-Test")
    print("=" * 55)
    for s in samples:
        raw = router.route(s)
        log = pipeline.process(raw)
        fv  = fe.extractFeatures(log)
        arr = fv.to_array()
        print(f"  [{log.activity_type.upper():12s}] user={log.user_id}  "
              f"features={arr.shape}  "
              f"tor={fv.tor}  data_mb={fv.data_mb:.1f}  "
              f"risky_country={fv.is_risky_country}")
    print(f"\n  Feature columns ({len(FeatureVector.COLUMNS)}): {FeatureVector.COLUMNS}")
