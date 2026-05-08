"""
InsightGuard — Layer 4: AI Analytics
======================================
Implements the AnomalyDetectionModel class from the system design.

Two-model ensemble as specified in the design document:
  1. Isolation Forest  — global anomaly detection
  2. Local Outlier Factor (LOF) — density-based local anomaly detection

Both models are trained on a synthetic baseline of normal enterprise
traffic, then ensemble-scored on new events.

Final risk score = weighted combination:
  40% Isolation Forest + 30% LOF + 30% UEBA rule engine

Severity thresholds (matches DB schema):
  0-34  → normal
  35-59 → suspicious
  60-79 → high_risk
  80+   → critical
"""

from __future__ import annotations
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from feature_engineering.extractor import FeatureVector, FeatureEngineering, KNOWN_COUNTRIES
from data_processing.etl_pipeline import ProcessedLog


# ---------------------------------------------------------------------------
# UEBA Rule Engine (supports the ML scoring layer)
# ---------------------------------------------------------------------------

_CLOUD_UPLOAD_DOMAINS = frozenset({
    "drive.google.com", "onedrive.live.com", "onedrive.com",
    "dropbox.com", "wetransfer.com", "mega.nz", "s3.amazonaws.com",
})


class UEBAEngine:
    """19 FeatureVector rules + 10 extra-signal rules (read from raw event dict) → 0-100 score."""

    RULES = [
        ("off_hours_login",          12, lambda f: f.event_type_code == 0 and f.is_off_hours),
        ("high_risk_country",        25, lambda f: f.is_risky_country),
        ("unknown_country",          10, lambda f: f.is_unknown_country),
        ("tor_detected",             30, lambda f: f.tor),
        ("vpn_suspicious",            6, lambda f: f.vpn and f.is_off_hours),
        ("new_device",                8, lambda f: f.new_device),
        ("repeated_auth_fail",       12, lambda f: f.failed_attempts >= 3),
        ("bulk_download",            18, lambda f: f.data_mb >= 200),
        ("massive_download",         32, lambda f: f.data_mb >= 1500),
        ("bulk_file_access",         16, lambda f: f.file_count >= 30),
        ("extreme_file_access",      26, lambda f: f.file_count >= 100),
        ("usb_inserted",             18, lambda f: f.event_type_code == 4 and f.usb_data_mb == 0),
        ("usb_exfil",                22, lambda f: f.usb_transfer and f.usb_data_mb >= 10),
        ("usb_large_exfil",          35, lambda f: f.usb_transfer and f.usb_data_mb >= 50),
        ("external_email_bulk",      14, lambda f: f.external_email and f.recipient_count >= 5),
        ("risky_web",                35, lambda f: f.risky_web),
        ("large_attachment",         12, lambda f: f.attachment_mb >= 25),
        ("off_hours_file_access",    15, lambda f: f.event_type_code == 2 and f.is_off_hours),
        ("sensitive_file_bulk",      22, lambda f: f.event_type_code == 2 and f.file_count >= 5),
    ]

    EXTRA_RULES = [
        ("sensitive_file_access",  20, lambda f, e: e.get("sensitivity") in ("critical", "confidential")),
        ("usb_any",                25, lambda f, e: e.get("source") in ("usb", "endpoint_agent")),
        ("cloud_upload",           30, lambda f, e: (e.get("destination") in ("cloud","gdrive","onedrive","dropbox","s3")
                                                    or e.get("category") == "cloud_storage")
                                                    and e.get("activity_type") != "file_upload"),
        ("off_hours_boost",        15, lambda f, e: e.get("is_off_hours") in (1, True)),
        ("archive_created",        65, lambda f, e: e.get("is_archive") is True),
        ("process_abuse",          35, lambda f, e: e.get("is_process_abuse") is True),
        ("large_attachment_exfil", 22, lambda f, e: e.get("source") in ("email", "mail_gateway")
                                                    and e.get("direction") in ("outbound", "sent")
                                                    and float(e.get("attachment_mb", 0)) >= 10),
        ("incognito_session",      20, lambda f, e: e.get("incognito") is True),
        ("file_upload_cloud",      25, lambda f, e: e.get("activity_type") == "file_upload"
                                                    and e.get("destination") in _CLOUD_UPLOAD_DOMAINS),
        ("webmail_outbound",       15, lambda f, e: e.get("activity_type") == "webmail_activity"
                                                    and e.get("compose_detected") is True),
        ("clipboard_credential",   40, lambda f, e: e.get("activity_type") == "clipboard"
                                                    and e.get("pattern_matched") in ("credential_pattern", "api_key_pattern")),
        ("clipboard_card_number",  35, lambda f, e: e.get("activity_type") == "clipboard"
                                                    and e.get("pattern_matched") == "card_number"),
        ("clipboard_email_list",   20, lambda f, e: e.get("activity_type") == "clipboard"
                                                    and e.get("pattern_matched") == "email_list"),
        ("clipboard_bulk_copy",    15, lambda f, e: e.get("activity_type") == "clipboard"
                                                    and e.get("pattern_matched") == "volume"
                                                    and int(e.get("char_count", 0)) >= 2000),
    ]

    def score(self, fv: FeatureVector, extra: dict = None) -> tuple[int, list[str]]:
        extra = extra or {}
        total, triggered = 0, []
        for label, weight, test in self.RULES:
            if test(fv):
                total += weight
                triggered.append(label)
        for label, weight, test in self.EXTRA_RULES:
            if test(fv, extra):
                total += weight
                triggered.append(label)
        return min(total, 100), triggered


# ---------------------------------------------------------------------------
# Isolation Forest Detector
# ---------------------------------------------------------------------------

class IsolationForestDetector:

    def __init__(self, contamination: float = 0.05, n_estimators: int = 150):
        self.model   = IsolationForest(contamination=contamination,
                                       n_estimators=n_estimators,
                                       random_state=42)
        self.scaler  = StandardScaler()
        self.trained = False

    def train(self, X: np.ndarray) -> None:
        Xs = self.scaler.fit_transform(X)
        self.model.fit(Xs)
        self.trained = True

    def score(self, x: np.ndarray) -> float:
        """Return anomaly probability [0,1]. 1 = most anomalous."""
        if not self.trained:
            return 0.0
        Xs = self.scaler.transform(x.reshape(1, -1))
        raw = self.model.decision_function(Xs)[0]
        s   = float(1 - (raw - (-0.5)) / (0.5 - (-0.5)))
        return max(0.0, min(1.0, s))


# ---------------------------------------------------------------------------
# LOF Detector
# ---------------------------------------------------------------------------

class LOFDetector:
    """Local Outlier Factor — novelty=True for online scoring."""

    def __init__(self, n_neighbors: int = 20, contamination: float = 0.05):
        self.model   = LocalOutlierFactor(n_neighbors=n_neighbors,
                                          contamination=contamination,
                                          novelty=True)
        self.scaler  = StandardScaler()
        self.trained = False

    def train(self, X: np.ndarray) -> None:
        Xs = self.scaler.fit_transform(X)
        self.model.fit(Xs)
        self.trained = True

    def score(self, x: np.ndarray) -> float:
        """Return anomaly probability [0,1]."""
        if not self.trained:
            return 0.0
        Xs  = self.scaler.transform(x.reshape(1, -1))
        raw = self.model.decision_function(Xs)[0]   # negative_outlier_factor
        s   = float(1 - (raw - (-2.0)) / (0.5 - (-2.0)))
        return max(0.0, min(1.0, s))


# ---------------------------------------------------------------------------
# AnomalyDetectionModel — class diagram implementation
# ---------------------------------------------------------------------------

class AnomalyDetectionModel:
    """
    Implements trainModel() and detectAnomaly() from the class diagram.

    Attributes:
      model_type  str
      risk_score  int (last computed)
    """

    IF_WEIGHT   = 0.40
    LOF_WEIGHT  = 0.30
    UEBA_WEIGHT = 0.30

    SEVERITY_MAP = {
        (0,  45): "normal",
        (45, 60): "suspicious",
        (60, 80): "high_risk",
        (80, 101): "critical",
    }

    def __init__(self):
        self.model_type = "IsolationForest+LOF+UEBA"
        self.risk_score = 0
        self._if   = IsolationForestDetector()
        self._lof  = LOFDetector()
        self._ueba = UEBAEngine()
        self._fe   = FeatureEngineering()

        self.trainModel()   # bootstrap on synthetic baseline

    def trainModel(self, baseline_logs: list[ProcessedLog] | None = None) -> None:
        """Train on provided logs, or fall back to synthetic baseline."""
        if baseline_logs:
            X = self._fe.to_matrix(baseline_logs)
        else:
            X = self._generate_baseline()
        self._if.train(X)
        self._lof.train(X)
        print(f"[AnomalyDetectionModel] Trained on {len(X)} baseline samples.")

    def detectAnomaly(self, log: ProcessedLog) -> dict:
        """
        Analyse one ProcessedLog and return a detection result.

        Returns:
          model_type       str
          risk_score       int 0-100
          severity         normal | suspicious | high_risk | critical
          is_anomaly       bool
          if_score         float
          lof_score        float
          ueba_score       int
          triggered_rules  list[str]
          feature_vector   dict
        """
        fv  = self._fe.extractFeatures(log)
        arr = fv.to_array()

        if_score  = self._if.score(arr)
        lof_score = self._lof.score(arr)
        ueba_s, rules = self._ueba.score(fv)

        composite = int(
            if_score  * 100 * self.IF_WEIGHT +
            lof_score * 100 * self.LOF_WEIGHT +
            ueba_s          * self.UEBA_WEIGHT
        )
        composite = min(composite, 100)
        self.risk_score = composite

        severity = "normal"
        for (lo, hi), label in self.SEVERITY_MAP.items():
            if lo <= composite < hi:
                severity = label
                break

        return {
            "model_type":      self.model_type,
            "risk_score":      composite,
            "severity":        severity,
            "is_anomaly":      composite >= 45,
            "if_score":        round(if_score, 4),
            "lof_score":       round(lof_score, 4),
            "ueba_score":      ueba_s,
            "triggered_rules": rules,
            "feature_vector":  fv.to_dict(),
        }

    # ------ Synthetic baseline generator ----------------------------------

    def _generate_baseline(self) -> np.ndarray:
        rng = np.random.default_rng(0)
        rows = []
        for _ in range(2500):
            hour = int(rng.integers(8, 18))
            dow  = int(rng.integers(0, 5))
            et   = int(rng.choice([0, 2, 3, 5], p=[0.25, 0.40, 0.15, 0.20]))
            row  = [
                hour, dow, 0, 0, et,
                int(rng.integers(0, 2)), 0, 0, 0, 0, 0,
                int(rng.integers(1, 25)),
                float(rng.uniform(0.1, 80)),
                0, 0.0,
                int(rng.integers(1, 5)),
                float(rng.uniform(0, 5)),
                0, 0,
            ]
            rows.append(row)
        return np.array(rows, dtype=float)


# ---------------------------------------------------------------------------
# Quick self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    from data_acquisition.collector import AcquisitionRouter
    from data_processing.etl_pipeline import ETLPipeline

    router   = AcquisitionRouter()
    pipeline = ETLPipeline()
    model    = AnomalyDetectionModel()

    cases = [
        ("Normal morning login",
         {"source": "login",  "user_id": "alice", "timestamp": "2024-06-03T09:15:00",
          "country_code": "US", "failed_attempts": 0, "new_device": False,
          "vpn": False, "tor": False}),
        ("Off-hours bulk file download",
         {"source": "file",   "user_id": "bob",   "timestamp": "2024-06-03T02:30:00",
          "file_count": 400, "data_mb": 4500, "destination": "usb"}),
        ("TOR + high-risk country",
         {"source": "login",  "user_id": "eve",   "timestamp": "2024-06-03T14:00:00",
          "country_code": "KP", "failed_attempts": 7, "tor": True, "new_device": True}),
        ("USB exfiltration",
         {"source": "usb",    "user_id": "carol", "timestamp": "2024-06-08T11:00:00",
          "operation": "transfer", "data_mb": 1200}),
        ("Bulk external email",
         {"source": "email",  "user_id": "dave",  "timestamp": "2024-06-04T16:00:00",
          "recipient_count": 20, "attachment_mb": 80, "external": True}),
    ]

    print("\nLayer 4 — AI Analytics Self-Test")
    print("=" * 65)
    for label, raw in cases:
        log    = pipeline.process(router.route(raw))
        result = model.detectAnomaly(log)
        print(f"\n  [{label}]")
        print(f"    Risk={result['risk_score']:>3}  "
              f"Severity={result['severity'].upper():10s}  "
              f"IF={result['if_score']:.3f}  LOF={result['lof_score']:.3f}")
        print(f"    Rules: {result['triggered_rules'] or 'none'}")
