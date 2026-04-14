# Sub-project 2: Exfiltration & Correlation Engine — Design Spec

**Date:** 2026-04-14  
**Status:** Approved  
**Scope:** Risk scoring weight boosts, multi-event correlation engine, data exfiltration detection, command abuse detection

---

## Overview

This sub-project extends InsightGuard's scoring pipeline to detect sophisticated insider threat patterns that span multiple events over time. It adds:

1. **Risk scoring weight boosts** — new UEBAEngine rules for enriched event signals
2. **Event correlation engine** — per-user rolling window pattern matching; fires score boost + synthetic alert
3. **Data exfiltration & command abuse detection** — ETL enrichment flags + new UEBA rules

The ML model schema (FeatureVector, IF/LOF weights) is NOT changed. All new signals flow through a new `extra: dict` parameter on `UEBAEngine.score()`.

---

## Section 1 — Risk Scoring Weight Boosts

### New UEBA Rules

Six new entries appended to `UEBAEngine.RULES` in `ai_analytics/anomaly_model.py`:

| Label | Weight | Trigger (via `extra` dict) |
|-------|--------|---------------------------|
| `sensitive_file_access` | 20 | `extra.get("sensitivity") in ("critical","confidential")` |
| `usb_any` | 25 | `extra.get("source") == "usb"` or `extra.get("usb_event") == True` |
| `cloud_upload` | 30 | `extra.get("destination") in ("cloud","gdrive","onedrive","dropbox","s3")` or category in cloud_storage |
| `off_hours_boost` | 15 | `extra.get("is_off_hours") == 1` |
| `archive_created` | 28 | `extra.get("is_archive") == True` |
| `process_abuse` | 35 | `extra.get("is_process_abuse") == True` |

### API Change

```python
# Before
def score(self, fv: FeatureVector) -> tuple[float, list[str]]:

# After
def score(self, fv: FeatureVector, extra: dict = {}) -> tuple[float, list[str]]:
```

Rules that read from `extra` use `extra.get(key)` — they receive the full raw event dict (`fv_dict`) passed from `app.py`. Rules that read from `fv` are unchanged.

### Call Site (app.py)

```python
ueba_score, triggered = anomaly_model.score(fv, extra=fv_dict)
```

`fv_dict` is the raw event dict already present in app.py's pipeline. No new data extraction needed.

---

## Section 2 — Event Correlation Engine

### File

`ai_analytics/correlation_engine.py` — NEW

### Architecture

- **Per-user rolling window**: last 20 events stored in `_windows: dict[str, deque]` (maxlen=20)
- **Thread-safe**: single `threading.Lock`
- **Stateless reset**: `reset(user_id=None)` clears one or all windows (used by `/api/database/reset`)

### Patterns (5 total)

| Name | Description | Window | Severity |
|------|-------------|--------|----------|
| `sensitive_file_then_usb` | Sensitive file access followed by USB event | 5 min | critical |
| `sensitive_file_then_cloud` | Sensitive file access followed by cloud upload | 10 min | critical |
| `bulk_file_then_email` | file_count ≥ 5 or data_mb ≥ 50 followed by outbound email with attachment | 10 min | high_risk |
| `off_hours_multi_event` | 3+ events during off-hours within 30 min | 30 min | high_risk |
| `process_abuse_then_file` | Process abuse (kill/log-clear) followed by file operation | 5 min | critical |

### Output When Pattern Fires

1. **Score boost**: `+15` added to current event's final score (after PERS)
2. **Synthetic correlation alert**: dict with keys:
   - `user_id`, `timestamp`, `source="correlation"`, `activity_type="correlation_alert"`
   - `pattern_name`, `severity`, `matched_events` (list of event IDs or timestamps)
   - `score` (boosted score)
   - Inserted into DB via `database.store_event()`
   - Broadcast via SSE stream (same channel as regular events)

### Interface

```python
class CorrelationEngine:
    def process(self, user_id: str, event: dict, current_score: float) -> float:
        """Add event to window, check patterns, return (possibly boosted) score."""

    def reset(self, user_id: str = None) -> None:
        """Clear window(s). Called on DB reset."""
```

---

## Section 3 — Data Exfiltration & Command Abuse Detection

### ETL Enrichment (data_processing/etl_pipeline.py)

Two new flags computed in ETL and stored in `fv_dict` (NOT in FeatureVector):

**`is_archive`** — set to `True` when:
- `source == "file"` AND `file_path` extension in `{.zip, .rar, .7z, .tar, .gz, .tar.gz, .bz2}`
- OR `operation == "compress"` (future-proofing)

**`is_process_abuse`** — set to `True` when:
- `source == "process"` AND `activity_type in ("process_kill", "log_clear")`
- OR `source == "process"` AND `severity == "critical"` (from ProcessMonitor classification)

Both default to `False` if not triggered.

### New UEBA Rule

**`large_attachment_exfil`** (weight 22):
- Trigger: `source == "email"` AND `direction == "outbound"` AND `attachment_mb >= 10`
- Read from `extra.get("attachment_mb", 0)` and `extra.get("direction")`

### Agent-Side Enrichment (nexon_agent/agent.py)

The agent already sets `is_archive` implicitly through the file extension. However, to make this explicit, the file event handler will check if a newly-created file has an archive extension and add `"is_archive": True` to the payload. This allows the server ETL to confirm or set the flag independently.

---

## Section 4 — Files & Integration

### Files Changed

| File | Change |
|------|--------|
| `ai_analytics/anomaly_model.py` | Add `extra: dict = {}` param to `score()`. Append 6 new RULES entries. |
| `ai_analytics/correlation_engine.py` | NEW. `CorrelationEngine` class. |
| `data_processing/etl_pipeline.py` | Add `is_archive` and `is_process_abuse` flags to `fv_dict`. |
| `application/app.py` | Pass `extra=fv_dict` to `anomaly_model.score()`. Instantiate `CorrelationEngine`. Call `correlation_engine.process()` after PERS scoring. Wire `/api/database/reset` to call `correlation_engine.reset()`. |

### Data Flow (Updated)

```
Raw event (fv_dict)
  → ETL: adds is_archive, is_process_abuse flags to fv_dict
  → FeatureEngineering: extracts FeatureVector (unchanged)
  → UEBAEngine.score(fv, extra=fv_dict)   ← NEW extra param
      └─ 6 new rules read from extra
  → _role_adjusted_ueba()
  → PUB scoring (personal IF)
  → PERS scoring (psychometric)
  → CorrelationEngine.process(user_id, fv_dict, final_score)  ← NEW
      └─ may return boosted score + synthetic alert
  → store_event() + SSE broadcast
```

### Tests (tests/test_all.py)

Three new test sections:

**`test_ueba_new_rules()`**:
- 6 assertions, one per new rule
- Each: construct minimal FeatureVector + `extra` dict with trigger condition, call `score()`, assert label in triggered list

**`test_etl_enrichment()`**:
- 4 assertions: archive extension detected, non-archive not flagged, process_kill flagged, normal process not flagged
- Calls ETL pipeline directly on synthetic raw events

**`test_correlation_engine()`**:
- 5 assertions, one per pattern
- Feed synthetic event sequences to `CorrelationEngine.process()`
- Assert correct pattern fires and score is boosted

---

## Acceptance Criteria

- [ ] `UEBAEngine.score()` accepts `extra` param; existing callers without `extra` continue to work
- [ ] All 6 new UEBA rules produce non-zero contribution when triggered
- [ ] `CorrelationEngine` fires correct pattern for each of the 5 attack sequences
- [ ] Synthetic correlation alert is broadcast via SSE and stored in DB
- [ ] `is_archive` set correctly for zip/rar/7z/tar/gz files in ETL
- [ ] `is_process_abuse` set correctly for process_kill/log_clear events in ETL
- [ ] `large_attachment_exfil` rule fires for outbound email with attachment_mb ≥ 10
- [ ] All new test sections pass (15 total new assertions)
- [ ] No regressions in existing test sections
- [ ] `/api/database/reset` calls `correlation_engine.reset()`

---

## Out of Scope

- Changes to FeatureVector dataclass (preserve IF/LOF model weights)
- Dashboard UI changes for correlation alerts (correlation_alert events appear in Detection Log via existing SSE handler)
- Persistence of correlation windows across server restarts
