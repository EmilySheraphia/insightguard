"""
InsightGuard — Layer 5: Explainability Engine
===============================================
Implements the ExplainabilityEngine class from the system design.

Uses LIME (Local Interpretable Model-Agnostic Explanations) to explain
why a specific user activity was flagged as anomalous.

LIME works by:
  1. Perturbing features around the input sample
  2. Scoring each perturbed sample with the underlying model
  3. Fitting a simple linear model on the perturbations
  4. Reporting feature weights as the explanation

Built-in implementation — no external lime package required.
"""

from __future__ import annotations
import numpy as np
from dataclasses import dataclass
from typing import Callable
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from feature_engineering.extractor import FeatureVector


# ---------------------------------------------------------------------------
# LIME explanation result
# ---------------------------------------------------------------------------

@dataclass
class LIMEExplanation:
    """
    Matches ExplainabilityEngine attributes from the class diagram.

    method          str   — always 'LIME'
    feature_weights dict  — {feature_name: contribution_score}
    top_factors     list  — top-N most influential features
    summary         str   — human-readable explanation
    confidence      float — R² of the local linear model
    """
    method:          str
    feature_weights: dict
    top_factors:     list[dict]
    summary:         str
    confidence:      float

    def to_dict(self) -> dict:
        return {
            "method":          self.method,
            "top_factors":     self.top_factors,
            "summary":         self.summary,
            "confidence":      round(self.confidence, 4),
            "feature_weights": {k: round(v, 4)
                                 for k, v in self.feature_weights.items()},
        }


# ---------------------------------------------------------------------------
# ExplainabilityEngine — class diagram implementation
# ---------------------------------------------------------------------------

# Human-readable labels for each feature column
FEATURE_LABELS = {
    "hour":              "Activity hour of day",
    "day_of_week":       "Day of week",
    "is_off_hours":      "Outside business hours",
    "is_weekend":        "Weekend activity",
    "event_type_code":   "Event type",
    "failed_attempts":   "Failed authentication attempts",
    "vpn":               "VPN usage",
    "tor":               "TOR network usage",
    "new_device":        "New/unrecognised device",
    "is_risky_country":  "Login from high-risk country",
    "is_unknown_country":"Login from unknown country",
    "file_count":        "Number of files accessed",
    "data_mb":           "Data volume transferred (MB)",
    "usb_transfer":      "USB data transfer",
    "usb_data_mb":       "USB transfer volume (MB)",
    "recipient_count":   "Email recipient count",
    "attachment_mb":     "Email attachment size (MB)",
    "external_email":    "Email sent externally",
    "risky_web":         "Risky web category visited",
}


class ExplainabilityEngine:
    """
    Generates LIME explanations for anomaly detection results.

    Implements generateExplanation() from the class diagram.

    Attribute:
      method  str  — 'LIME'
    """

    method = "LIME"

    def __init__(self,
                 n_samples:    int   = 1000,
                 n_top_factors: int  = 6,
                 noise_scale:  float = 0.3):
        self.n_samples     = n_samples
        self.n_top_factors = n_top_factors
        self.noise_scale   = noise_scale

    def generateExplanation(
        self,
        feature_vector: FeatureVector,
        score_fn:       Callable[[np.ndarray], float],
    ) -> LIMEExplanation:
        """
        Generate a LIME explanation for why this feature vector received
        the anomaly score it did.

        Args:
          feature_vector  FeatureVector of the event being explained
          score_fn        Callable: np.ndarray → float risk_score [0,1]
                          (typically model.detectAnomaly wrapped)
        """
        x        = feature_vector.to_array()
        columns  = FeatureVector.COLUMNS
        n_feats  = len(columns)

        # ── Step 1: Generate perturbations around x ──────────────────────
        rng      = np.random.default_rng(42)
        perturb  = rng.normal(loc=0.0, scale=self.noise_scale,
                              size=(self.n_samples, n_feats))
        # Binary/integer features — round perturbations to 0/1
        binary_idx = [i for i, c in enumerate(columns)
                      if c not in ("hour", "day_of_week", "file_count",
                                   "data_mb", "usb_data_mb", "recipient_count",
                                   "attachment_mb", "failed_attempts")]
        X_perturb = x + perturb
        for i in binary_idx:
            X_perturb[:, i] = np.clip(np.round(X_perturb[:, i]), 0, 1)
        # Clip negatives
        X_perturb = np.clip(X_perturb, 0, None)

        # ── Step 2: Score perturbations ───────────────────────────────────
        scores = np.array([score_fn(X_perturb[i]) for i in range(self.n_samples)])

        # ── Step 3: Fit local linear model ────────────────────────────────
        # Weighted by proximity to original sample (Gaussian kernel)
        distances = np.linalg.norm(X_perturb - x, axis=1)
        weights   = np.exp(-0.5 * (distances / (self.noise_scale * n_feats)) ** 2)

        # Weighted least squares: Xw β = yw
        W   = np.diag(weights)
        Xw  = np.sqrt(W) @ X_perturb
        yw  = np.sqrt(weights) * scores
        # Add intercept
        Xw_aug = np.hstack([Xw, np.sqrt(weights).reshape(-1, 1)])
        try:
            beta, _, _, _ = np.linalg.lstsq(Xw_aug, yw, rcond=None)
        except np.linalg.LinAlgError:
            beta = np.zeros(n_feats + 1)

        feature_weights = dict(zip(columns, beta[:n_feats].tolist()))

        # ── Step 4: Compute R² confidence ────────────────────────────────
        y_pred = Xw_aug @ beta
        ss_res = np.sum(weights * (yw - y_pred) ** 2)
        ss_tot = np.sum(weights * (yw - np.average(yw, weights=weights)) ** 2)
        r2     = max(0.0, float(1 - ss_res / (ss_tot + 1e-9)))

        # ── Step 5: Select top influential features ───────────────────────
        sorted_feats = sorted(feature_weights.items(),
                              key=lambda kv: abs(kv[1]), reverse=True)
        top_factors  = []
        for feat, weight in sorted_feats[:self.n_top_factors]:
            if abs(weight) < 1e-6:
                continue
            direction = "increases" if weight > 0 else "decreases"
            top_factors.append({
                "feature":     feat,
                "label":       FEATURE_LABELS.get(feat, feat),
                "weight":      round(weight, 4),
                "direction":   direction,
                "value":       float(feature_vector.to_dict().get(feat, 0)),
            })

        # ── Step 6: Generate human-readable summary ───────────────────────
        summary = self._build_summary(top_factors)

        return LIMEExplanation(
            method          = self.method,
            feature_weights = feature_weights,
            top_factors     = top_factors,
            summary         = summary,
            confidence      = r2,
        )

    def _build_summary(self, top_factors: list[dict]) -> str:
        if not top_factors:
            return "No significant behavioral anomalies identified."
        parts = []
        for f in top_factors[:3]:
            label = f["label"]
            val   = f["value"]
            if f["direction"] == "increases":
                if f["feature"] == "tor":
                    parts.append("TOR network usage")
                elif f["feature"] == "is_risky_country":
                    parts.append("access from a high-risk country")
                elif f["feature"] == "data_mb":
                    parts.append(f"large data transfer ({val:.0f} MB)")
                elif f["feature"] == "file_count":
                    parts.append(f"bulk file access ({int(val)} files)")
                elif f["feature"] == "failed_attempts":
                    parts.append(f"repeated authentication failures ({int(val)}x)")
                elif f["feature"] == "is_off_hours":
                    parts.append("activity outside business hours")
                elif f["feature"] == "usb_transfer":
                    parts.append("USB data transfer")
                elif f["feature"] == "external_email":
                    parts.append("external email communication")
                else:
                    parts.append(label.lower())
        if parts:
            return "Anomaly driven by: " + ", ".join(parts) + "."
        return "Unusual behavioral pattern detected."


# ---------------------------------------------------------------------------
# Quick self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    from data_acquisition.collector import AcquisitionRouter
    from data_processing.etl_pipeline import ETLPipeline
    from ai_analytics.anomaly_model import AnomalyDetectionModel
    from feature_engineering.extractor import FeatureEngineering

    router  = AcquisitionRouter()
    pipe    = ETLPipeline()
    model   = AnomalyDetectionModel()
    fe      = FeatureEngineering()
    engine  = ExplainabilityEngine()

    test = {"source": "login", "user_id": "eve", "timestamp": "2024-06-03T02:00:00",
            "country_code": "KP", "failed_attempts": 7, "tor": True, "new_device": True}

    log    = pipe.process(router.route(test))
    result = model.detectAnomaly(log)
    fv     = fe.extractFeatures(log)

    def score_fn(arr: np.ndarray) -> float:
        from data_processing.etl_pipeline import ProcessedLog
        dummy = ProcessedLog(
            log_id="x", user_id="x", timestamp=log.timestamp,
            activity_type=log.activity_type, source=log.source,
        )
        # rebuild fv from array
        from feature_engineering.extractor import FeatureVector
        fv2 = FeatureVector(**dict(zip(FeatureVector.COLUMNS,
                                       [int(v) if c not in ("data_mb","usb_data_mb","attachment_mb")
                                        else float(v) for c, v in zip(FeatureVector.COLUMNS, arr)])))
        r = model._if.score(arr) * 100 * model.IF_WEIGHT + \
            model._lof.score(arr) * 100 * model.LOF_WEIGHT + \
            model._ueba.score(fv2)[0] * model.UEBA_WEIGHT
        return min(r / 100, 1.0)

    explanation = engine.generateExplanation(fv, score_fn)

    print("\nLayer 5 — Explainability Engine Self-Test")
    print("=" * 60)
    print(f"  Risk score : {result['risk_score']}  Severity: {result['severity']}")
    print(f"  LIME R²    : {explanation.confidence:.3f}")
    print(f"  Summary    : {explanation.summary}")
    print(f"\n  Top factors:")
    for f in explanation.top_factors:
        print(f"    {f['label']:40s}  weight={f['weight']:+.4f}  val={f['value']}")
