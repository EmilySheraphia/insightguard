# Exfiltration & Correlation Engine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add risk scoring weight boosts, a multi-event correlation engine, and data exfiltration/command-abuse detection to InsightGuard's scoring pipeline.

**Architecture:** Seven new UEBA rules read from a new `extra: dict` parameter on `UEBAEngine.score()` so the ML model schema (FeatureVector, IF/LOF weights) is never touched. A `CorrelationEngine` maintains a per-user rolling window (last 20 events) and fires score boosts + synthetic SSE alerts when 5 attack patterns are matched. ETL enrichment adds `is_archive` and `is_process_abuse` flags to the raw event dict before scoring.

**Tech Stack:** Python 3.10+, threading.Lock, collections.deque, pytest (via `python tests/test_all.py`), Flask test client

---

## File Map

| File | Change |
|------|--------|
| `ai_analytics/anomaly_model.py` | Add `EXTRA_RULES` list + update `UEBAEngine.score()` to accept and process `extra: dict` |
| `ai_analytics/correlation_engine.py` | **NEW** — `CorrelationEngine` class, 5 patterns |
| `data_processing/etl_pipeline.py` | Add module-level `enrich_raw(raw: dict) -> None` |
| `nexon_agent/agent.py` | Add `is_archive` flag to file event payloads for archive extensions |
| `application/app.py` | Import CorrelationEngine + `enrich_raw`; extend `_full_score` and `_process_event`; wire reset endpoint |
| `tests/test_all.py` | Add `test_ueba_new_rules()`, `test_etl_enrichment()`, `test_correlation_engine()` sections |

---

## Task 1: UEBAEngine extra param + 7 new rules

**Files:**
- Modify: `ai_analytics/anomaly_model.py:38-69`
- Modify: `tests/test_all.py` (add `test_ueba_new_rules`, wire to `main`)

### Step 1: Write failing test

Add this function to `tests/test_all.py` (before `def main():`):

```python
def test_ueba_new_rules():
    section("UEBA New Rules — extra param (7 rules)")
    from ai_analytics.anomaly_model import UEBAEngine
    from feature_engineering.extractor import FeatureVector

    ueba = UEBAEngine()
    base = {k: 0 for k in FeatureVector.COLUMNS}
    fv   = FeatureVector(**base)

    def check(label, extra):
        _, triggered = ueba.score(fv, extra=extra)
        assert label in triggered, f"{label} not in triggered={triggered}"
        ok(f"{label} fires")

    check("sensitive_file_access",  {"sensitivity": "critical"})
    check("sensitive_file_access",  {"sensitivity": "confidential"})
    check("usb_any",                {"source": "usb"})
    check("cloud_upload",           {"destination": "gdrive"})
    check("off_hours_boost",        {"is_off_hours": 1})
    check("archive_created",        {"is_archive": True})
    check("process_abuse",          {"is_process_abuse": True})
    check("large_attachment_exfil", {"source": "email", "direction": "outbound",
                                     "attachment_mb": 15})

    _, triggered = ueba.score(fv, extra={})
    for label in ("sensitive_file_access", "usb_any", "cloud_upload",
                  "off_hours_boost", "archive_created", "process_abuse",
                  "large_attachment_exfil"):
        assert label not in triggered, f"{label} should not fire on empty extra"
    ok("no new rules fire on empty extra dict")

    print(f"\n  9/9 passed")
    return True
```

Wire it into `main()` — add `"UEBA New Rules": test_ueba_new_rules(),` to the `results` dict alongside the other entries.

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /Users/emilysheraphia/Downloads/insightguard && python tests/test_all.py 2>&1 | grep -A5 "UEBA New Rules"
```

Expected: `TypeError: score() got an unexpected keyword argument 'extra'`

- [ ] **Step 3: Implement — add `EXTRA_RULES` and update `score()`**

In `ai_analytics/anomaly_model.py`, after the closing `]` of `RULES` (after line 61) and before `def score(`, add:

```python
    EXTRA_RULES = [
        ("sensitive_file_access",  20, lambda f, e: e.get("sensitivity") in ("critical", "confidential")),
        ("usb_any",                25, lambda f, e: e.get("source") in ("usb", "endpoint_agent")),
        ("cloud_upload",           30, lambda f, e: e.get("destination") in ("cloud","gdrive","onedrive","dropbox","s3")
                                                    or e.get("category") == "cloud_storage"),
        ("off_hours_boost",        15, lambda f, e: e.get("is_off_hours") in (1, True)),
        ("archive_created",        28, lambda f, e: e.get("is_archive") is True),
        ("process_abuse",          35, lambda f, e: e.get("is_process_abuse") is True),
        ("large_attachment_exfil", 22, lambda f, e: e.get("source") in ("email", "mail_gateway")
                                                    and e.get("direction") in ("outbound", "sent")
                                                    and float(e.get("attachment_mb", 0)) >= 10),
    ]
```

Replace the existing `score` method (lines 63-69):

```python
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
```

- [ ] **Step 4: Run test to verify it passes**

```bash
cd /Users/emilysheraphia/Downloads/insightguard && python tests/test_all.py 2>&1 | grep -A15 "UEBA New Rules"
```

Expected: `9/9 passed` and `[PASS] UEBA New Rules` in final summary.

- [ ] **Step 5: Verify no regressions**

```bash
cd /Users/emilysheraphia/Downloads/insightguard && python tests/test_all.py 2>&1 | tail -20
```

Expected: all previously-passing sections still show `[PASS]`.

- [ ] **Step 6: Commit**

```bash
cd /Users/emilysheraphia/Downloads/insightguard
git add ai_analytics/anomaly_model.py tests/test_all.py
git commit -m "feat: add EXTRA_RULES to UEBAEngine for enriched signal scoring"
```

---

## Task 2: ETL enrichment flags + agent archive flag

**Files:**
- Modify: `data_processing/etl_pipeline.py` (add `enrich_raw` function)
- Modify: `nexon_agent/agent.py` (add `is_archive` to file payloads)
- Modify: `tests/test_all.py` (add `test_etl_enrichment`, wire to `main`)

- [ ] **Step 1: Write failing test**

Add this function to `tests/test_all.py` (before `def main():`):

```python
def test_etl_enrichment():
    section("ETL Enrichment — is_archive + is_process_abuse flags")
    from data_processing.etl_pipeline import enrich_raw

    # Archive detection: zip file
    raw = {"source": "file", "file_path": "/home/bob/backup.zip"}
    enrich_raw(raw)
    assert raw["is_archive"] is True, "zip should be flagged as archive"
    ok("is_archive: .zip file flagged")

    # Archive detection: rar file
    raw2 = {"source": "file", "file_path": "/home/alice/export.rar"}
    enrich_raw(raw2)
    assert raw2["is_archive"] is True, "rar should be flagged"
    ok("is_archive: .rar file flagged")

    # Non-archive file
    raw3 = {"source": "file", "file_path": "/home/bob/report.pdf"}
    enrich_raw(raw3)
    assert raw3["is_archive"] is False, "pdf should not be archive"
    ok("is_archive: .pdf not flagged")

    # Email source: zip attachment should NOT flag is_archive
    raw4 = {"source": "email", "file_path": "/tmp/attachment.zip"}
    enrich_raw(raw4)
    assert raw4["is_archive"] is False, "email source should not flag is_archive"
    ok("is_archive: email source not flagged even with .zip path")

    # Process abuse: process_kill
    raw5 = {"source": "process", "activity_type": "process_kill"}
    enrich_raw(raw5)
    assert raw5["is_process_abuse"] is True, "process_kill should flag is_process_abuse"
    ok("is_process_abuse: process_kill flagged")

    # Process abuse: log_clear
    raw6 = {"source": "process", "activity_type": "log_clear"}
    enrich_raw(raw6)
    assert raw6["is_process_abuse"] is True, "log_clear should flag is_process_abuse"
    ok("is_process_abuse: log_clear flagged")

    # Not abuse: process_launch
    raw7 = {"source": "process", "activity_type": "process_launch", "severity": "normal"}
    enrich_raw(raw7)
    assert raw7["is_process_abuse"] is False, "process_launch should not flag"
    ok("is_process_abuse: process_launch not flagged")

    # Process abuse via severity=critical
    raw8 = {"source": "process", "activity_type": "process_launch", "severity": "critical"}
    enrich_raw(raw8)
    assert raw8["is_process_abuse"] is True, "severity=critical process should flag"
    ok("is_process_abuse: severity=critical process flagged")

    print(f"\n  8/8 passed")
    return True
```

Wire into `main()`: add `"ETL Enrichment": test_etl_enrichment(),` to the `results` dict.

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /Users/emilysheraphia/Downloads/insightguard && python tests/test_all.py 2>&1 | grep -A5 "ETL Enrichment"
```

Expected: `ImportError: cannot import name 'enrich_raw'`

- [ ] **Step 3: Implement `enrich_raw` in etl_pipeline.py**

Add these lines at the end of `data_processing/etl_pipeline.py` (before the `if __name__ == "__main__":` block):

```python
# ---------------------------------------------------------------------------
# Raw event enrichment (mutates raw dict in place, no ETL class needed)
# ---------------------------------------------------------------------------

_ARCHIVE_EXTS = {".zip", ".rar", ".7z", ".tar", ".gz", ".bz2"}
_FILE_SOURCES = {"file", "dlp_system", "endpoint_agent"}


def enrich_raw(raw: dict) -> None:
    """
    Add is_archive and is_process_abuse flags to a raw event dict.
    Mutates the dict in place. Called in app.py before scoring.
    """
    src = raw.get("source", "")

    # is_archive: file-source event whose path ends in an archive extension
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
```

- [ ] **Step 4: Run ETL enrichment test**

```bash
cd /Users/emilysheraphia/Downloads/insightguard && python tests/test_all.py 2>&1 | grep -A15 "ETL Enrichment"
```

Expected: `8/8 passed`

- [ ] **Step 5: Add `is_archive` to agent file event payloads**

Read `nexon_agent/agent.py` and find the `_ARCHIVE_EXTS` constant near the top (or add it if not present), and the `_FileEventHandler._handle()` method and `_RecentFilesHandler._fire()` method.

Add near the top of `nexon_agent/agent.py` (after existing constants):

```python
_AGENT_ARCHIVE_EXTS = {".zip", ".rar", ".7z", ".tar", ".gz", ".bz2"}
```

In `_FileEventHandler._handle()`, where the payload dict is built, add `"is_archive"` alongside `"sensitivity"`:

```python
"is_archive": os.path.splitext(filename)[1].lower() in _AGENT_ARCHIVE_EXTS,
```

In `_RecentFilesHandler._fire()`, same addition to the payload dict:

```python
"is_archive": os.path.splitext(filename)[1].lower() in _AGENT_ARCHIVE_EXTS,
```

In `_FileEventHandler.on_moved()`, same addition:

```python
"is_archive": os.path.splitext(dest_filename)[1].lower() in _AGENT_ARCHIVE_EXTS,
```

- [ ] **Step 6: Verify no regressions**

```bash
cd /Users/emilysheraphia/Downloads/insightguard && python tests/test_all.py 2>&1 | tail -20
```

Expected: all prior `[PASS]` sections still pass.

- [ ] **Step 7: Commit**

```bash
cd /Users/emilysheraphia/Downloads/insightguard
git add data_processing/etl_pipeline.py nexon_agent/agent.py tests/test_all.py
git commit -m "feat: add ETL enrichment flags is_archive + is_process_abuse"
```

---

## Task 3: CorrelationEngine

**Files:**
- Create: `ai_analytics/correlation_engine.py`
- Modify: `tests/test_all.py` (add `test_correlation_engine`, wire to `main`)

- [ ] **Step 1: Write failing test**

Add this function to `tests/test_all.py` (before `def main():`):

```python
def test_correlation_engine():
    section("CorrelationEngine — 5 attack pattern detections")
    from ai_analytics.correlation_engine import CorrelationEngine

    alerts_fired = []
    engine = CorrelationEngine(on_alert=lambda a: alerts_fired.append(a))
    uid = "corr_test_user"

    # Pattern 1: sensitive_file_then_usb (5 min window)
    engine.reset(uid); alerts_fired.clear()
    engine.process(uid, {"source": "file", "sensitivity": "critical",
                         "activity_type": "file_access"}, 50.0)
    score = engine.process(uid, {"source": "usb", "activity_type": "usb"}, 60.0)
    assert len(alerts_fired) == 1, f"sensitive_file_then_usb: expected 1 alert, got {len(alerts_fired)}"
    assert alerts_fired[0]["pattern_name"] == "sensitive_file_then_usb"
    assert score == 75.0, f"score should be 75.0 (60+15), got {score}"
    ok("sensitive_file_then_usb: fires + boosts score by 15")

    # Pattern 2: sensitive_file_then_cloud (10 min window)
    engine.reset(uid); alerts_fired.clear()
    engine.process(uid, {"source": "file", "sensitivity": "confidential",
                         "activity_type": "file_access"}, 50.0)
    score = engine.process(uid, {"source": "file", "destination": "gdrive",
                                 "activity_type": "file_access"}, 55.0)
    assert len(alerts_fired) == 1, f"sensitive_file_then_cloud: expected 1 alert, got {len(alerts_fired)}"
    assert alerts_fired[0]["pattern_name"] == "sensitive_file_then_cloud"
    assert score == 70.0, f"score should be 70.0 (55+15), got {score}"
    ok("sensitive_file_then_cloud: fires + boosts score by 15")

    # Pattern 3: bulk_file_then_email (10 min window)
    engine.reset(uid); alerts_fired.clear()
    engine.process(uid, {"source": "file", "file_count": 10,
                         "activity_type": "file_access"}, 40.0)
    score = engine.process(uid, {"source": "email", "direction": "outbound",
                                 "attachment_mb": 5.0, "activity_type": "email"}, 45.0)
    assert len(alerts_fired) == 1, f"bulk_file_then_email: expected 1 alert, got {len(alerts_fired)}"
    assert alerts_fired[0]["pattern_name"] == "bulk_file_then_email"
    ok("bulk_file_then_email: fires on file_count>=5 + outbound email with attachment")

    # Pattern 4: off_hours_multi_event (30 min window, 3+ events)
    engine.reset(uid); alerts_fired.clear()
    engine.process(uid, {"is_off_hours": 1, "activity_type": "file_access"}, 30.0)
    engine.process(uid, {"is_off_hours": 1, "activity_type": "web"}, 35.0)
    score = engine.process(uid, {"is_off_hours": 1, "activity_type": "email"}, 40.0)
    assert len(alerts_fired) == 1, f"off_hours_multi_event: expected 1 alert, got {len(alerts_fired)}"
    assert alerts_fired[0]["pattern_name"] == "off_hours_multi_event"
    ok("off_hours_multi_event: fires on 3rd consecutive off-hours event")

    # Pattern 5: process_abuse_then_file (5 min window)
    engine.reset(uid); alerts_fired.clear()
    engine.process(uid, {"source": "process", "is_process_abuse": True,
                         "activity_type": "process_kill"}, 70.0)
    score = engine.process(uid, {"source": "file", "activity_type": "file_access"}, 50.0)
    assert len(alerts_fired) == 1, f"process_abuse_then_file: expected 1 alert, got {len(alerts_fired)}"
    assert alerts_fired[0]["pattern_name"] == "process_abuse_then_file"
    ok("process_abuse_then_file: fires when process_kill precedes file access")

    # Verify reset() clears all windows
    engine.reset()
    alerts_fired.clear()
    score = engine.process("any_user", {"source": "usb"}, 60.0)
    assert score == 60.0, "score should be unchanged after reset"
    assert len(alerts_fired) == 0
    ok("reset() clears all windows — no false-positive after reset")

    print(f"\n  6/6 passed")
    return True
```

Wire into `main()`: add `"CorrelationEngine": test_correlation_engine(),` to the `results` dict.

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /Users/emilysheraphia/Downloads/insightguard && python tests/test_all.py 2>&1 | grep -A5 "CorrelationEngine"
```

Expected: `ModuleNotFoundError: No module named 'ai_analytics.correlation_engine'`

- [ ] **Step 3: Create `ai_analytics/correlation_engine.py`**

```python
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
```

- [ ] **Step 4: Run correlation engine test**

```bash
cd /Users/emilysheraphia/Downloads/insightguard && python tests/test_all.py 2>&1 | grep -A20 "CorrelationEngine"
```

Expected: `6/6 passed`

- [ ] **Step 5: Verify no regressions**

```bash
cd /Users/emilysheraphia/Downloads/insightguard && python tests/test_all.py 2>&1 | tail -25
```

Expected: all prior `[PASS]` sections still show `[PASS]`.

- [ ] **Step 6: Commit**

```bash
cd /Users/emilysheraphia/Downloads/insightguard
git add ai_analytics/correlation_engine.py tests/test_all.py
git commit -m "feat: add CorrelationEngine with 5 attack pattern detections"
```

---

## Task 4: Wire app.py

**Files:**
- Modify: `application/app.py`

Wire `enrich_raw`, `extra` param, and `CorrelationEngine` into the live scoring pipeline.

- [ ] **Step 1: Import CorrelationEngine and enrich_raw**

At the top of `application/app.py`, find the existing import block and add:

```python
from ai_analytics.correlation_engine import CorrelationEngine
from data_processing.etl_pipeline import ETLPipeline, enrich_raw
```

(The `ETLPipeline` import is likely already present — only add `enrich_raw` if so.)

- [ ] **Step 2: Instantiate CorrelationEngine with DB + SSE callback**

After the line where `db`, `profile_lock`, and `sse_queues` are defined (near the module-level setup), add:

```python
def _on_correlation_alert(alert: dict) -> None:
    """Store synthetic correlation alert to DB and broadcast via SSE."""
    try:
        import uuid as _uuid
        lid = "corr_" + str(_uuid.uuid4())[:10]
        db.insert_activity_log(
            lid, alert["user_id"], alert["timestamp"],
            "correlation_alert", "correlation", details=alert,
        )
        _broadcast_sse(alert)
    except Exception as _e:
        print(f"[CorrelationEngine] alert error: {_e}")

correlation_engine = CorrelationEngine(on_alert=_on_correlation_alert)
```

> Note: `_broadcast_sse` is defined further down in app.py. Python resolves the name at call time, not at definition time, so this forward reference is fine.

- [ ] **Step 3: Update `_full_score` to accept and pass `raw_event`**

Find `_full_score` (currently at line ~187). Change its signature from:

```python
def _full_score(fv_dict: dict, user_id: str, feature_array=None, role: str = "") -> dict:
```

to:

```python
def _full_score(fv_dict: dict, user_id: str, feature_array=None, role: str = "",
                raw_event: dict = None) -> dict:
```

Inside `_full_score`, find the line:

```python
    raw_ueba_score, raw_rules = ueba.score(fv)
```

Replace it with:

```python
    _extra = raw_event if raw_event is not None else fv_dict
    raw_ueba_score, raw_rules = ueba.score(fv, extra=_extra)
```

- [ ] **Step 4: Update `_process_event` to call `enrich_raw` and pass `raw_event`**

Find `_process_event` (currently at line ~269). After the line `log = pipeline.process(activity)` and before `fv = fe_eng.extractFeatures(log)`, add:

```python
    enrich_raw(raw)
    raw["is_off_hours"] = int(log.is_off_hours)
```

Then find the `_full_score(...)` call within `_process_event`:

```python
    result  = _full_score(fv.to_dict(), uid, fv.to_array(), role=raw.get("role",""))
```

Replace with:

```python
    result  = _full_score(fv.to_dict(), uid, fv.to_array(), role=raw.get("role",""), raw_event=raw)
```

- [ ] **Step 5: Wire CorrelationEngine after PERS scoring in `_process_event`**

In `_process_event`, find the block that builds `final_sev` (after `result = _full_score(...)`). Insert the correlation engine call **after** the `severity_override` logic (after `result["is_anomaly"] = True`) and **before** building the `pay` dict:

```python
    # Correlation pattern check — may boost score and fire synthetic alert
    boosted = correlation_engine.process(uid, raw, result["risk_score"])
    if boosted > result["risk_score"]:
        result["risk_score"] = int(boosted)
        result["severity"] = (
            "critical"   if boosted >= 80 else
            "high_risk"  if boosted >= 60 else
            "suspicious" if boosted >= 45 else "normal"
        )
        result["is_anomaly"] = True
        final_sev = result["severity"]
```

- [ ] **Step 6: Wire CorrelationEngine reset in `reset_database` endpoint**

Find the `reset_database()` function (at line ~852). Inside it, after `user_profiles.clear()`, add:

```python
    correlation_engine.reset()
```

- [ ] **Step 7: Run full test suite**

```bash
cd /Users/emilysheraphia/Downloads/insightguard && python tests/test_all.py
```

Expected: all sections pass including `UEBA New Rules`, `ETL Enrichment`, `CorrelationEngine`. Final output shows `[PASS]` for every section.

- [ ] **Step 8: Quick smoke test via Flask client (API layer)**

Verify the real event endpoint still scores correctly by checking that the existing `test_api` section passes (it calls `POST /api/events` with real events). If it passed in step 7, you're done.

- [ ] **Step 9: Commit**

```bash
cd /Users/emilysheraphia/Downloads/insightguard
git add application/app.py
git commit -m "feat: wire CorrelationEngine and ETL enrichment into scoring pipeline"
```

---

## Self-Review

After writing this plan, checked against the spec:

**Spec coverage:**
- ✅ Section 1: 7 EXTRA_RULES (`sensitive_file_access`, `usb_any`, `cloud_upload`, `off_hours_boost`, `archive_created`, `process_abuse`, `large_attachment_exfil`) — Task 1
- ✅ `extra: dict = {}` param on `score()` — Task 1
- ✅ Section 2: `CorrelationEngine` with 5 patterns, BOOST=15, `on_alert` callback, `reset()` — Task 3
- ✅ Synthetic alert stored in DB + broadcast SSE — Task 4 Step 2 (`_on_correlation_alert`)
- ✅ Section 3: `enrich_raw` with `is_archive` + `is_process_abuse` — Task 2
- ✅ `large_attachment_exfil` rule — included in Task 1 EXTRA_RULES
- ✅ Agent-side `is_archive` flag — Task 2 Step 5
- ✅ `reset_database` calls `correlation_engine.reset()` — Task 4 Step 6
- ✅ Tests: `test_ueba_new_rules` (9 assertions), `test_etl_enrichment` (8 assertions), `test_correlation_engine` (6 assertions)

**Type consistency verified:**
- `CorrelationEngine.process(user_id, event, current_score)` → `float` — consistent across Task 3 and Task 4
- `enrich_raw(raw: dict) -> None` — consistent across Task 2 and Task 4
- `UEBAEngine.score(fv, extra=None)` — consistent across Task 1 and Task 4
- `correlation_engine.reset(user_id=None)` — consistent across Task 3 and Task 4

**Placeholders:** none found.
