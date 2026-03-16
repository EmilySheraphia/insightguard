"""
InsightGuard — Psychometric-Enhanced Risk Scoring (PERS)
=========================================================
Novel contribution: combines OCEAN Big Five personality scores
with behavioural anomaly scores for improved insider threat detection.

Research basis:
  - Low Conscientiousness = careless, rule-breaking tendency
  - Low Agreeableness     = hostile, revenge-motivated
  - High Neuroticism      = stress, emotional instability
  - High Openness         = curiosity, explores beyond role

Formula:
  PERS = (ML_Score × 0.70) + (Psychometric_Risk × 0.30)

  Psychometric_Risk =
      (100 - C) × 0.35 +   # low conscientiousness → high risk
      (100 - A) × 0.35 +   # low agreeableness    → high risk
      N         × 0.30     # high neuroticism      → high risk
"""

from __future__ import annotations
import csv
from pathlib import Path
from dataclasses import dataclass


# ── OCEAN profile ─────────────────────────────────────────────────────────────

@dataclass
class OCEANProfile:
    user_id:           str
    name:              str
    openness:          int   # O — 0-100
    conscientiousness: int   # C — 0-100
    extraversion:      int   # E — 0-100
    agreeableness:     int   # A — 0-100
    neuroticism:       int   # N — 0-100
    psychometric_risk: float = 0.0   # computed 0-100

    def __post_init__(self):
        self.psychometric_risk = self._compute_risk()

    def _compute_risk(self) -> float:
        """
        Compute psychometric risk score 0-100.
        Based on CERT research and Big Five insider threat literature.
        """
        risk = (
            (100 - self.conscientiousness) * 0.35 +
            (100 - self.agreeableness)     * 0.35 +
            self.neuroticism               * 0.30
        )
        return round(min(risk, 100), 2)

    def risk_label(self) -> str:
        if self.psychometric_risk >= 70:
            return "high_psychometric_risk"
        elif self.psychometric_risk >= 50:
            return "medium_psychometric_risk"
        else:
            return "low_psychometric_risk"

    def to_dict(self) -> dict:
        return {
            "user_id":           self.user_id,
            "name":              self.name,
            "O":                 self.openness,
            "C":                 self.conscientiousness,
            "E":                 self.extraversion,
            "A":                 self.agreeableness,
            "N":                 self.neuroticism,
            "psychometric_risk": self.psychometric_risk,
            "risk_label":        self.risk_label(),
        }


# ── Psychometric store ────────────────────────────────────────────────────────

class PsychometricStore:
    """
    Loads and stores OCEAN profiles from psychometric.csv.
    Provides lookup by user_id for risk score augmentation.
    """

    def __init__(self):
        self._profiles: dict[str, OCEANProfile] = {}

    def load(self, path: Path) -> int:
        """Load psychometric.csv — returns number of profiles loaded."""
        count = 0
        with open(path, newline="", encoding="utf-8", errors="ignore") as f:
            reader = csv.DictReader(f)
            for row in reader:
                uid = row.get("user_id", "").strip()
                if not uid:
                    continue
                try:
                    profile = OCEANProfile(
                        user_id           = uid,
                        name              = row.get("employee_name", "").strip(),
                        openness          = int(row.get("O", 50) or 50),
                        conscientiousness = int(row.get("C", 50) or 50),
                        extraversion      = int(row.get("E", 50) or 50),
                        agreeableness     = int(row.get("A", 50) or 50),
                        neuroticism       = int(row.get("N", 50) or 50),
                    )
                    self._profiles[uid] = profile
                    count += 1
                except (ValueError, KeyError):
                    continue
        return count

    def get(self, user_id: str) -> OCEANProfile | None:
        return self._profiles.get(user_id)

    def get_risk(self, user_id: str) -> float:
        """Return psychometric risk score for user, or 50.0 (neutral) if unknown."""
        profile = self._profiles.get(user_id)
        return profile.psychometric_risk if profile else 50.0

    def all_profiles(self) -> list[dict]:
        return [p.to_dict() for p in
                sorted(self._profiles.values(),
                       key=lambda x: x.psychometric_risk, reverse=True)]

    def __len__(self):
        return len(self._profiles)


# ── PERS scorer ───────────────────────────────────────────────────────────────

class PERSScorer:
    """
    Psychometric-Enhanced Risk Scorer.

    Combines ML anomaly score with OCEAN psychometric risk
    to produce the final enhanced risk score.

    Novel contribution: real-time integration of personality
    profiling with behavioural analytics.
    """

    ML_WEIGHT   = 0.70
    PSYCH_WEIGHT = 0.30

    def __init__(self, store: PsychometricStore):
        self.store = store

    def enhance(self, user_id: str, ml_score: int) -> dict:
        """
        Enhance an ML risk score with psychometric data.

        Returns:
          ml_score           original ML score
          psychometric_risk  OCEAN-based risk score
          pers_score         combined enhanced score
          enhancement        how much psychometrics changed the score
          ocean_profile      full OCEAN breakdown
          severity           updated severity based on PERS
        """
        psych_risk = self.store.get_risk(user_id)
        profile    = self.store.get(user_id)

        pers_score = int(
            ml_score   * self.ML_WEIGHT +
            psych_risk * self.PSYCH_WEIGHT
        )
        pers_score = min(pers_score, 100)
        enhancement = pers_score - ml_score

        if pers_score >= 80:   severity = "critical"
        elif pers_score >= 60: severity = "high_risk"
        elif pers_score >= 35: severity = "suspicious"
        else:                  severity = "normal"

        return {
            "ml_score":          ml_score,
            "psychometric_risk": round(psych_risk, 2),
            "pers_score":        pers_score,
            "enhancement":       enhancement,
            "severity":          severity,
            "is_anomaly":        pers_score >= 35,
            "ocean_profile":     profile.to_dict() if profile else None,
        }


# ── Module-level singleton (loaded once at startup) ───────────────────────────

_store  = PsychometricStore()
_scorer: PERSScorer | None = None


def init_psychometrics(cert_dir: Path) -> bool:
    """
    Initialise the psychometric store from the CERT dataset.
    Call once at application startup.
    Returns True if loaded successfully.
    """
    global _store, _scorer
    path = cert_dir / "psychometric.csv"
    if not path.exists():
        print(f"[PERS] psychometric.csv not found at {path}")
        return False
    count = _store.load(path)
    _scorer = PERSScorer(_store)
    print(f"[PERS] Loaded {count} OCEAN profiles from {path}")
    return True


def get_pers_score(user_id: str, ml_score: int) -> dict:
    """
    Get the Psychometric-Enhanced Risk Score for a user+ML score pair.
    Falls back gracefully if psychometrics not loaded.
    """
    if _scorer is None:
        return {
            "ml_score":          ml_score,
            "psychometric_risk": 50.0,
            "pers_score":        ml_score,
            "enhancement":       0,
            "severity":          _ml_severity(ml_score),
            "is_anomaly":        ml_score >= 35,
            "ocean_profile":     None,
        }
    return _scorer.enhance(user_id, ml_score)


def get_store() -> PsychometricStore:
    return _store


def _ml_severity(score: int) -> str:
    if score >= 80:   return "critical"
    if score >= 60:   return "high_risk"
    if score >= 35:   return "suspicious"
    return "normal"


# ── Self-test ──────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    from pathlib import Path

    cert_dir = Path.home() / "Downloads" / "r4.2"
    ok       = init_psychometrics(cert_dir)

    if not ok:
        print("Could not load psychometric data.")
        exit(1)

    store = get_store()
    print(f"\nTop 10 highest psychometric risk users:")
    print("-" * 55)
    for p in store.all_profiles()[:10]:
        print(f"  {p['user_id']:10s}  "
              f"C={p['C']:3d}  A={p['A']:3d}  N={p['N']:3d}  "
              f"→ psych_risk={p['psychometric_risk']:5.1f}  "
              f"({p['risk_label']})")

    print(f"\nPERS score examples:")
    print("-" * 55)
    test_cases = [
        ("CEL0561", 30, "Low ML score — does psychometrics raise it?"),
        ("CEL0561", 60, "Medium ML score — enhanced?"),
        ("CEL0561", 85, "High ML score — already critical?"),
    ]
    for uid, ml, label in test_cases:
        result = get_pers_score(uid, ml)
        print(f"\n  [{label}]")
        print(f"    ML score    : {result['ml_score']}")
        print(f"    Psych risk  : {result['psychometric_risk']}")
        print(f"    PERS score  : {result['pers_score']}  ({result['severity']})")
        print(f"    Enhancement : {result['enhancement']:+d}")