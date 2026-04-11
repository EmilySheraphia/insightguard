"""
InsightGuard — Analytics Engine
================================
CounterfactualEngine: "what-if" perturbation explanations for UEBA scores.
ConfidenceEngine:     ±margin bands based on how many events have been seen.
"""

from __future__ import annotations
import sys, os
sys.path.insert(0, os.path.dirname(__file__))

from feature_engineering.extractor import FeatureVector
from ai_analytics.anomaly_model import UEBAEngine

_ueba = UEBAEngine()


class CounterfactualEngine:
    """
    For each relevant perturbation, clones the feature dict, applies the change,
    re-runs UEBAEngine.score(), and reports the score delta.
    Returns top-3 by abs(delta), descending.
    """

    UEBA_WEIGHT = 0.30

    PERTURBATIONS = [
        ("during_working_hours", "If this happened during working hours",
         {"is_off_hours": 0}),
        ("no_usb",               "If no USB device was present",
         {"usb_transfer": 0, "usb_data_mb": 0}),
        ("small_file_count",     "If only 1 file was accessed",
         {"file_count": 1}),
        ("no_tor",               "If TOR was not used",
         {"tor": 0}),
        ("no_risky_web",         "If no risky sites were visited",
         {"risky_web": 0}),
        ("small_download",       "If data transferred was under 10MB",
         {"data_mb": 5}),
        ("no_failed_attempts",   "If login had no failed attempts",
         {"failed_attempts": 0}),
        ("known_country",        "If login was from a known safe country",
         {"is_risky_country": 0, "is_unknown_country": 0}),
        ("no_external_email",    "If email was sent internally only",
         {"external_email": 0}),
    ]

    def explain(self, feature_dict: dict, original_score: int) -> list[dict]:
        """
        Return top-3 counterfactuals by absolute score delta.
        Only includes perturbations where at least one feature value would actually change
        and the delta is non-zero. delta is expressed in composite score space
        (UEBA delta × UEBA_WEIGHT=0.30), holding IF and LOF contributions constant.
        """
        # Compute original UEBA score once
        orig_fv = FeatureVector(**{k: feature_dict.get(k, 0) for k in FeatureVector.COLUMNS})
        orig_ueba, _ = _ueba.score(orig_fv)

        results = []
        for label, description, changes in self.PERTURBATIONS:
            # Skip if no feature would actually change
            relevant = any(
                feature_dict.get(k, 0) != v
                for k, v in changes.items()
            )
            if not relevant:
                continue

            # Apply perturbation
            perturbed = dict(feature_dict)
            perturbed.update(changes)

            # Re-score with UEBA only
            fv = FeatureVector(**{k: perturbed.get(k, 0) for k in FeatureVector.COLUMNS})
            new_ueba, _ = _ueba.score(fv)

            # Scale delta to composite score space (UEBA contributes 30%)
            ueba_delta = (new_ueba - orig_ueba) * self.UEBA_WEIGHT
            new_score_estimate = max(0, min(100, original_score + ueba_delta))
            actual_delta = round(new_score_estimate - original_score)
            new_score_estimate = original_score + actual_delta  # keep consistent with rounded delta
            pct = round(actual_delta / original_score * 100, 1) if original_score else 0.0

            results.append({
                "label":       label,
                "description": description,
                "new_score":   max(0, min(100, new_score_estimate)),
                "delta":       actual_delta,
                "pct_change":  pct,
            })

        # Filter zero-delta (perturbation had no effect on score)
        results = [r for r in results if r["delta"] != 0]
        # Sort by abs(delta) descending, return top 3
        results.sort(key=lambda x: abs(x["delta"]), reverse=True)
        return results[:3]


class ConfidenceEngine:
    """
    Returns ±margin confidence band for a risk score based on how many
    PUB events have been seen for this user.
    """

    # (min_events, max_events_exclusive, margin, label, pct)
    BANDS = [
        (0,   10,  25, "low",       40),
        (10,  30,  15, "moderate",  65),
        (30,  100,  8, "high",      85),
        (100, None, 4, "very_high", 96),
    ]

    def score(self, events_seen: int, risk_score: int) -> dict:
        """
        Returns:
          score        int   — the original risk_score (unchanged)
          lower        int   — max(0, score - margin)
          upper        int   — min(100, score + margin)
          margin       int   — the ± margin
          label        str   — low | moderate | high | very_high
          pct          int   — confidence percentage
          events_seen  int   — passed through unchanged
        """
        margin, label, pct = 25, "low", 40  # defaults (0 events)
        for min_e, max_e, m, lbl, p in self.BANDS:
            if max_e is None:
                if events_seen >= min_e:
                    margin, label, pct = m, lbl, p
                    break
            elif min_e <= events_seen < max_e:
                margin, label, pct = m, lbl, p
                break

        return {
            "score":       risk_score,
            "lower":       max(0,   risk_score - margin),
            "upper":       min(100, risk_score + margin),
            "margin":      margin,
            "label":       label,
            "pct":         pct,
            "events_seen": events_seen,
        }
