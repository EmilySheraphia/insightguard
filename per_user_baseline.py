"""
InsightGuard — Per-User Baseline Detector
==========================================
Second Novel Contribution: Personal Isolation Forest per employee.

Added: save() and load() so pre-trained models persist to disk.
Run pretrain_baselines.py once → models saved → dashboard shows ✓ immediately.
"""

from __future__ import annotations
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from dataclasses import dataclass, field
from typing import Optional
import threading
import pickle
import os
from pathlib import Path

MIN_EVENTS    = 10
RETRAIN_EVERY = 50
CONTAMINATION = 0.05
GLOBAL_W      = 0.40
PERSONAL_W    = 0.60

# Default path where trained models are saved
MODELS_DIR = Path(__file__).parent / "storage" / "user_baselines"


@dataclass
class UserBaseline:
    user_id:      str
    events:       list  = field(default_factory=list)
    model:        Optional[IsolationForest] = None
    scaler:       Optional[StandardScaler]  = None
    is_trained:   bool  = False
    event_count:  int   = 0
    last_trained: int   = 0

    def add_event(self, arr: np.ndarray) -> None:
        self.events.append(arr.copy())
        self.event_count += 1

    def should_train(self) -> bool:
        if len(self.events) < MIN_EVENTS:
            return False
        if not self.is_trained and len(self.events) >= MIN_EVENTS:
            return True
        return (self.event_count - self.last_trained) >= RETRAIN_EVERY

    def train(self) -> None:
        if len(self.events) < MIN_EVENTS:
            return
        X = np.vstack(self.events)
        self.scaler = StandardScaler()
        Xs = self.scaler.fit_transform(X)
        self.model  = IsolationForest(
            contamination=CONTAMINATION, n_estimators=100, random_state=42)
        self.model.fit(Xs)
        self.is_trained   = True
        self.last_trained = self.event_count

    def score(self, arr: np.ndarray) -> float:
        if not self.is_trained:
            return 0.5
        Xs  = self.scaler.transform(arr.reshape(1, -1))
        raw = self.model.decision_function(Xs)[0]
        s   = float(1 - (raw - (-0.5)) / (0.5 - (-0.5)))
        return max(0.0, min(1.0, s))

    def save(self, models_dir: Path) -> None:
        """Save trained model to disk."""
        if not self.is_trained:
            return
        models_dir.mkdir(parents=True, exist_ok=True)
        path = models_dir / f"{self.user_id}.pkl"
        with open(path, "wb") as f:
            pickle.dump({
                "user_id":      self.user_id,
                "model":        self.model,
                "scaler":       self.scaler,
                "event_count":  self.event_count,
                "last_trained": self.last_trained,
                "is_trained":   self.is_trained,
                # Save last 100 events for future retraining
                "events":       self.events[-100:],
            }, f)

    def load(self, models_dir: Path) -> bool:
        """Load pre-trained model from disk. Returns True if loaded."""
        path = models_dir / f"{self.user_id}.pkl"
        if not path.exists():
            return False
        try:
            with open(path, "rb") as f:
                data = pickle.load(f)
            self.model        = data["model"]
            self.scaler       = data["scaler"]
            self.event_count  = data["event_count"]
            self.last_trained = data["last_trained"]
            self.is_trained   = data["is_trained"]
            self.events       = data.get("events", [])
            return True
        except Exception:
            return False

    @property
    def status(self) -> str:
        if not self.is_trained:
            return f"learning ({len(self.events)}/{MIN_EVENTS} events)"
        return f"trained ({self.event_count} events)"


class PerUserBaselineStore:
    """Manages personal Isolation Forest models for all monitored users."""

    def __init__(self, models_dir: Path = MODELS_DIR):
        self._baselines:  dict[str, UserBaseline] = {}
        self._lock        = threading.Lock()
        self._models_dir  = models_dir

    def _load_from_disk(self, user_id: str) -> UserBaseline:
        """Try to load a pre-trained model from disk, else create fresh."""
        b = UserBaseline(user_id=user_id)
        b.load(self._models_dir)
        return b

    def get_or_create(self, user_id: str) -> UserBaseline:
        with self._lock:
            if user_id not in self._baselines:
                # Try loading pre-trained model from disk first
                b = self._load_from_disk(user_id)
                self._baselines[user_id] = b
            return self._baselines[user_id]

    def preload_all(self) -> int:
        """
        Load all pre-trained models from disk at startup.
        Returns number of models loaded.
        """
        if not self._models_dir.exists():
            return 0
        count = 0
        for pkl_file in self._models_dir.glob("*.pkl"):
            user_id = pkl_file.stem
            b = UserBaseline(user_id=user_id)
            if b.load(self._models_dir):
                with self._lock:
                    self._baselines[user_id] = b
                count += 1
        if count:
            print(f"[PUB] Loaded {count} pre-trained personal baselines from disk.")
        return count

    def save_all(self) -> int:
        """Save all trained models to disk. Returns number saved."""
        count = 0
        with self._lock:
            baselines = list(self._baselines.values())
        for b in baselines:
            if b.is_trained:
                b.save(self._models_dir)
                count += 1
        return count

    def ingest_and_score(self, user_id: str,
                          feature_array: np.ndarray,
                          global_score: int) -> dict:
        b = self.get_or_create(user_id)
        b.add_event(feature_array)
        if b.should_train():
            b.train()
            # Auto-save after retraining
            b.save(self._models_dir)

        personal_if   = b.score(feature_array)
        personal_risk = int(personal_if * 100)

        if b.is_trained:
            combined = int(global_score * GLOBAL_W + personal_risk * PERSONAL_W)
        else:
            combined = global_score

        combined = min(combined, 100)

        if combined >= 80:   sev = "critical"
        elif combined >= 60: sev = "high_risk"
        elif combined >= 45: sev = "suspicious"
        else:                sev = "normal"

        return {
            "personal_if_score":   round(personal_if, 4),
            "personal_risk_score": personal_risk,
            "global_score":        global_score,
            "combined_score":      combined,
            "combined_severity":   sev,
            "is_anomaly":          combined >= 45,
            "is_trained":          b.is_trained,
            "events_seen":         b.event_count,
            "status":              b.status,
        }

    def get_all_status(self) -> list[dict]:
        with self._lock:
            return [
                {"user_id": uid, "is_trained": b.is_trained,
                 "events_seen": b.event_count, "status": b.status}
                for uid, b in sorted(self._baselines.items(),
                                     key=lambda x: x[1].event_count, reverse=True)
            ]

    def get_user_status(self, user_id: str) -> dict | None:
        with self._lock:
            b = self._baselines.get(user_id)
        if not b:
            return None
        return {"user_id": user_id, "is_trained": b.is_trained,
                "events_seen": b.event_count, "status": b.status,
                "min_events": MIN_EVENTS}

    def __len__(self):
        return len(self._baselines)

    @property
    def trained_count(self) -> int:
        return sum(1 for b in self._baselines.values() if b.is_trained)


# Module-level singleton — preloads from disk on import
_store = PerUserBaselineStore()
_store.preload_all()   # ← loads pre-trained models automatically at startup


def get_store() -> PerUserBaselineStore:
    return _store

def ingest_and_score(user_id: str, feature_array: np.ndarray,
                      global_score: int) -> dict:
    return _store.ingest_and_score(user_id, feature_array, global_score)