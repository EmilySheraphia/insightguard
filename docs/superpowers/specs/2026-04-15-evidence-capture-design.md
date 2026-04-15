# Sub-project 4: Evidence Capture — Design Spec

**Date:** 2026-04-15  
**Status:** Approved  
**Scope:** Screenshot capture on the Windows agent at severity and pattern trigger points; server-side storage and retrieval; dashboard camera icon and modal thumbnail

---

## Overview

When the Nexon endpoint agent detects a high-severity event or fires a threat pattern, it takes a screenshot of the employee's screen, saves it locally, and uploads it to InsightGuard. Analysts can view screenshots directly in the Detection Log and in the alert detail modal.

---

## Section 1 — Architecture

```
nexon_agent/
  screenshot_capture.py    NEW  — ScreenshotCapture class
  agent.py                 MOD  — call capture() at two trigger points; init _screenshot in main()
  requirements.txt         MOD  — add mss>=9.0, Pillow>=10.0

application/
  app.py                   MOD  — POST /api/evidence/upload
                                    GET  /api/evidence/<evidence_id>
                                    GET  /api/evidence/by-event/<log_id>
  dashboard.html           MOD  — camera icon on high-risk/critical rows
                                    evidence thumbnail in alert detail modal

storage/
  database.py              MOD  — evidence table + CRUD methods
  evidence/                NEW dir — JPEG files, created at Flask startup
```

**Data flow:**

```
Agent detects high-risk event OR threat pattern fires
  → ScreenshotCapture.capture(trigger_type, event_type, log_id)
      → mss captures full screen → save JPEG to C:\NexonAgent\evidence\
      → POST /api/evidence/upload (multipart: file + metadata)
          → server saves to storage/evidence/
          → DB insert into evidence table
          → returns evidence_id
  → On modal open / row render: GET /api/evidence/by-event/<log_id>
      → dashboard renders thumbnail or camera icon
```

---

## Section 2 — ScreenshotCapture Module

**File:** `nexon_agent/screenshot_capture.py`

```python
class ScreenshotCapture:
    EVIDENCE_DIR = Path("evidence")   # relative to agent dir, created on __init__

    def __init__(self, cfg: dict, server_url: str) -> None:
        """Creates local evidence dir if missing."""

    def capture(self, trigger_type: str, event_type: str, log_id: str = "") -> bool:
        """
        Take screenshot, save locally, upload to server.
        trigger_type: "severity" | "pattern"
        event_type:   activity_type of triggering event (e.g. "usb", "process_kill")
        log_id:       server-side log ID to link screenshot to event (empty string if unknown)
        Returns True if upload succeeded, False otherwise.
        Local file is kept on disk regardless of upload result.
        """
```

**Screenshot capture:** `mss.mss()` captures all monitors combined. Result is saved as JPEG at 75% quality using `Pillow`. Both `mss` and `Pillow` are imported inside the method body (not at module level) so that `screenshot_capture.py` can be imported on macOS/Linux without crashing. If either import fails, `capture()` logs a warning and returns `False`.

**Filename format:** `<UTC-ISO-timestamp>_<trigger_type>_<event_type>.jpg`  
Example: `2026-04-15T14-32-01_severity_usb.jpg`

**Upload:** multipart POST to `<server_url>/api/evidence/upload` with fields:
- `file` — JPEG bytes
- `user_id` — from cfg
- `trigger_type` — "severity" or "pattern"
- `event_type` — activity type string
- `log_id` — linked event ID (may be empty)

On upload failure: log warning, return `False`. No retry. Local file remains.

**New dependency:** `mss>=9.0` for screen capture, `Pillow>=10.0` for JPEG encoding.

---

## Section 3 — Agent Trigger Points

**Module-level sentinel:** `_screenshot: ScreenshotCapture | None = None`  
Set in `main()` after config is loaded:
```python
_screenshot = ScreenshotCapture(cfg, cfg["server_url"])
```

Both trigger sites guard with `if _screenshot:`.

### Trigger 1 — Severity threshold

In `_sender_thread`, after a successful server response:

```python
resp_data = resp.json()
if resp_data.get("risk_score", 0) >= 60:
    if _screenshot:
        _screenshot.capture(
            trigger_type="severity",
            event_type=payload.get("activity_type", payload.get("source", "unknown")),
            log_id=resp_data.get("log_id", ""),
        )
```

Threshold: `risk_score >= 60` (maps to `high_risk` and `critical` severity).

### Trigger 2 — Threat pattern

In `_check_threat_patterns()`, once per fired threat (inside the `for threat in threats:` loop, after `enqueue_event(payload)`):

```python
if _screenshot:
    _screenshot.capture(
        trigger_type="pattern",
        event_type=threat["threat_type"],
        log_id="",
    )
```

One screenshot per pattern fire. No deduplication needed — patterns fire infrequently.

---

## Section 4 — Server-Side API + Database

### New Routes (`application/app.py`)

```
POST /api/evidence/upload
  Content-Type: multipart/form-data
  Fields: file (JPEG), user_id (str), trigger_type (str), event_type (str), log_id (str)
  → saves file to storage/evidence/<user_id>_<ts>_<event_type>.jpg
  → inserts row into evidence table
  → returns 200: {"evidence_id": "<id>", "status": "ok"}
  → returns 400 if file missing

GET /api/evidence/<evidence_id>
  → serves JPEG file via send_file (mimetype image/jpeg)
  → returns 404 if evidence_id not found in DB

GET /api/evidence/by-event/<log_id>
  → queries evidence table WHERE log_id = ?
  → returns 200: {"evidence": [{"evidence_id": "...", "trigger_type": "...",
                                 "event_type": "...", "timestamp": "..."}]}
  → returns {"evidence": []} if none found
```

`storage/evidence/` is created at Flask startup (`os.makedirs`) if missing.

### Database (`storage/database.py`)

New table, created in `DatabaseManager.__init__()`:

```sql
CREATE TABLE IF NOT EXISTS evidence (
    id           TEXT PRIMARY KEY,
    log_id       TEXT,
    user_id      TEXT,
    file_path    TEXT NOT NULL,
    trigger_type TEXT,
    event_type   TEXT,
    timestamp    TEXT,
    created_at   REAL
)
```

New methods on `DatabaseManager`:

```python
def insert_evidence(self, evidence_id: str, log_id: str, user_id: str,
                    file_path: str, trigger_type: str, event_type: str,
                    timestamp: str) -> None: ...

def get_evidence_by_id(self, evidence_id: str) -> dict | None: ...

def get_evidence_by_event(self, log_id: str) -> list[dict]: ...
```

---

## Section 5 — Dashboard

**File:** `application/dashboard.html`

### Camera icon on Detection Log rows

When rendering a Detection Log event row with `severity` of `"critical"` or `"high_risk"`, append a small camera button to the row's action area. On click:

1. Call `GET /api/evidence/by-event/<log_id>`
2. If evidence returned: open lightbox modal displaying the JPEG (`<img src="/api/evidence/<evidence_id>">`)
3. If empty: show a small toast "No screenshot available"

### Evidence thumbnail in alert detail modal

The existing alert detail modal gets a new `div.evidence-section` at the bottom. On modal open:

1. Call `GET /api/evidence/by-event/<log_id>`
2. If evidence returned: render thumbnails (`<img style="max-width:100%">`) — click to open full-size in new tab
3. If empty: hide `div.evidence-section` entirely (no empty section shown)

No new nav items or sections — additive only to existing UI elements.

---

## Section 6 — Tests

**`test_evidence()`** — 5 assertions added to `tests/test_all.py`, wired into `main()`:

1. `POST /api/evidence/upload` with a minimal 1×1 JPEG returns 200 and a non-empty `evidence_id`
2. `GET /api/evidence/<evidence_id>` returns 200 with `Content-Type: image/jpeg`
3. `GET /api/evidence/by-event/<log_id>` returns the linked evidence record with correct `trigger_type` and `event_type`
4. `GET /api/evidence/<unknown-id>` returns 404
5. `POST /api/evidence/upload` without a `file` field returns 400

---

## Acceptance Criteria

- [ ] `ScreenshotCapture.capture()` saves JPEG locally (does not crash if `mss` unavailable on macOS/Linux test runner — skip gracefully)
- [ ] `POST /api/evidence/upload` stores file and returns `evidence_id`
- [ ] `GET /api/evidence/<id>` serves the correct file
- [ ] `GET /api/evidence/by-event/<log_id>` returns linked records
- [ ] `DELETE /api/database/reset` does NOT delete evidence files (evidence is permanent)
- [ ] Camera icon appears on `critical`/`high_risk` rows in Detection Log
- [ ] Evidence thumbnail renders in alert detail modal when screenshot exists
- [ ] All 5 test assertions pass; no regressions in existing 16 sections

---

## Out of Scope

- Automatic cleanup / retention policy for evidence files
- Screenshot annotation or markup
- Video/screen recording
- Agent-side retry queue for failed uploads
- Evidence for events below `high_risk` threshold
