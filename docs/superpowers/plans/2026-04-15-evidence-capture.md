# Evidence Capture Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add screenshot capture on the Windows agent at severity/pattern trigger points, server-side JPEG storage and retrieval, and a dashboard camera icon + evidence modal thumbnail.

**Architecture:** Five tasks in strict dependency order: DB layer → server API routes → agent screenshot module → agent trigger wiring → dashboard UI. Tasks 1–2 are server-side only and can be verified with the existing test runner. Tasks 3–4 are agent-side. Task 5 is pure front-end.

**Tech Stack:** Flask (`request.files`, `send_file`), SQLite (new `evidence` table), `mss>=9.0` + `Pillow>=10.0` (Windows screen capture), JavaScript (camera icon + lightbox + modal section).

---

## File Map

| File | Change |
|------|--------|
| `storage/database.py` | Add `evidence` table in `_init_schema()`; add `insert_evidence`, `get_evidence_by_id`, `get_evidence_by_event` |
| `application/app.py` | Add `send_file` to Flask imports; add `EVIDENCE_DIR` constant + `mkdir`; add 3 routes |
| `tests/test_all.py` | Add `import io, uuid` at top; add `test_evidence()` (5 assertions); wire into `main()` |
| `nexon_agent/screenshot_capture.py` | New file — `ScreenshotCapture` class |
| `nexon_agent/agent.py` | Import `ScreenshotCapture`; add `_screenshot` module sentinel; init in `main()`; two trigger sites |
| `nexon_agent/requirements.txt` | Add `mss>=9.0`, `Pillow>=10.0` |
| `application/dashboard.html` | Add `<th>` camera column; modify `addLogRow`; add `fetchEvidence` + lightbox; add evidence section to `openModal` |

---

## Task 1: DB evidence table + CRUD methods

**Files:**
- Modify: `storage/database.py`
- Modify: `tests/test_all.py` (write failing test first)

- [ ] **Step 1: Write the failing test**

Add `import io, uuid` to the top of `tests/test_all.py` (alongside existing `import sys, os, json, tempfile`):

```python
import sys, os, json, tempfile, io, uuid
```

Add this function anywhere before `main()` in `tests/test_all.py`:

```python
def test_evidence():
    section("Evidence Capture — API (upload + retrieve)")
    import importlib
    import application.app as app_module
    importlib.reload(app_module)
    client = app_module.app.test_client()

    passed = 0; total = 0

    def chk(label, resp, exp_status):
        nonlocal passed, total
        total += 1
        ok_flag = resp.status_code == exp_status
        passed += ok_flag
        print(f"  [{'PASS' if ok_flag else 'FAIL'}] {label}  → HTTP {resp.status_code}")
        if not ok_flag:
            print(f"         {resp.data[:150]}")
        return resp

    MINIMAL_JPEG = b'\xff\xd8\xff\xe0' + b'\x00' * 16 + b'\xff\xd9'
    log_id = "log_ev_" + str(uuid.uuid4())[:8]

    # 1. Upload JPEG → 200 + non-empty evidence_id
    r = chk("POST /api/evidence/upload → 200 + evidence_id",
            client.post("/api/evidence/upload", data={
                "file":         (io.BytesIO(MINIMAL_JPEG), "test.jpg"),
                "user_id":      "testuser",
                "trigger_type": "severity",
                "event_type":   "usb",
                "log_id":       log_id,
            }, content_type="multipart/form-data"), 200)
    d = r.get_json() or {}
    eid = d.get("evidence_id", "")
    assert eid, "evidence_id must be non-empty"
    ok(f"evidence_id = {eid[:8]}…")

    # 2. Serve JPEG → 200 + image/jpeg
    r = chk("GET /api/evidence/<id> → 200 + image/jpeg",
            client.get(f"/api/evidence/{eid}"), 200)
    assert "image/jpeg" in r.content_type, f"Expected image/jpeg, got {r.content_type}"
    ok("Content-Type: image/jpeg confirmed")

    # 3. By-event lookup → linked record with correct fields
    r = chk("GET /api/evidence/by-event/<log_id> → linked record",
            client.get(f"/api/evidence/by-event/{log_id}"), 200)
    d = r.get_json() or {}
    evs = d.get("evidence", [])
    match = any(e.get("evidence_id") == eid
                and e.get("trigger_type") == "severity"
                and e.get("event_type") == "usb"
                for e in evs)
    assert match, f"Expected linked record, got {evs}"
    ok("linked record has correct trigger_type + event_type")

    # 4. Unknown ID → 404
    chk("GET /api/evidence/<unknown-id> → 404",
        client.get("/api/evidence/nonexistent_id_xyz"), 404)

    # 5. Upload without file → 400
    chk("POST /api/evidence/upload (no file) → 400",
        client.post("/api/evidence/upload", data={
            "user_id":      "testuser",
            "trigger_type": "severity",
            "event_type":   "usb",
        }, content_type="multipart/form-data"), 400)

    print(f"\n  {passed}/{total} passed")
    return passed == total
```

Add `"Evidence Capture": test_evidence()` to the `results` dict in `main()`:

```python
    results = {
        "Layer 1 (Acquisition)":   test_layer1(),
        "Layer 2 (ETL)":           test_layer2(),
        "Layer 3 (Features)":      test_layer3(),
        "Layer 4 (AI Analytics)":  test_layer4(),
        "Layer 5 (Explainability)":test_layer5(),
        "Storage Layer":           test_storage(),
        "Layer 6 (Flask API)":     test_api(),
        "Analytics":               test_analytics(),
        "DB Investigations":       test_investigations_db(),
        "EscalationEngine":        test_escalation_engine(),
        "Session Route Logic":     test_session_route_logic(),
        "AgentModules":            test_agent_modules(),
        "UEBA New Rules":          test_ueba_new_rules(),
        "ETL Enrichment":          test_etl_enrichment(),
        "CorrelationEngine":       test_correlation_engine(),
        "Browser Intelligence":    test_browser_intelligence(),
        "Evidence Capture":        test_evidence(),
    }
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /Users/emilysheraphia/Downloads/insightguard && python tests/test_all.py 2>&1 | grep -A5 "Evidence Capture"
```

Expected: FAIL — `404` on `POST /api/evidence/upload` (route not registered yet).

- [ ] **Step 3: Add the evidence table to `storage/database.py`**

Update the module docstring from `7 tables` to `8 tables` and add the evidence entry:

```python
"""
InsightGuard — Storage Layer
==============================
SQLite database managing all 8 tables:
  1. users              — employees monitored by the system
  2. activity_logs      — raw/processed event records
  3. behaviour_features — extracted feature vectors
  4. anomaly_results    — ML detection outputs
  5. threat_alerts      — generated security alerts
  6. investigations     — analyst case management
  7. escalation_log     — SMTP escalation audit trail
  8. evidence           — screenshot capture records
"""
```

In `_init_schema()`, append this block immediately after the `escalation_log` table and its index (after line 169 in the current file):

```python
            # Table 8: Evidence (screenshot captures)
            conn.execute("""
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
            """)
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_evidence_log ON evidence(log_id)"
            )
```

- [ ] **Step 4: Add the three CRUD methods to `DatabaseManager`**

Append these three methods at the end of the `DatabaseManager` class (before the `if __name__ == "__main__":` block):

```python
    # ── Evidence operations ───────────────────────────────────────────────────

    def insert_evidence(self, evidence_id: str, log_id: str, user_id: str,
                        file_path: str, trigger_type: str, event_type: str,
                        timestamp: str) -> None:
        with self._lock, self._conn() as conn:
            conn.execute("""
                INSERT OR IGNORE INTO evidence
                    (id, log_id, user_id, file_path, trigger_type, event_type,
                     timestamp, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (evidence_id, log_id, user_id, file_path, trigger_type,
                  event_type, timestamp,
                  datetime.utcnow().timestamp()))

    def get_evidence_by_id(self, evidence_id: str) -> dict | None:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM evidence WHERE id = ?", (evidence_id,)
            ).fetchone()
        return dict(row) if row else None

    def get_evidence_by_event(self, log_id: str) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM evidence WHERE log_id = ? ORDER BY created_at DESC",
                (log_id,)
            ).fetchall()
        return [dict(r) for r in rows]
```

Note: `datetime` is already imported at the top of `database.py` as `from datetime import datetime`.

- [ ] **Step 5: Run test again — DB is ready, API still fails**

```bash
cd /Users/emilysheraphia/Downloads/insightguard && python tests/test_all.py 2>&1 | grep -A5 "Evidence Capture"
```

Expected: still FAIL on `POST /api/evidence/upload` (404) — API routes don't exist yet. No `AttributeError` on DB methods.

- [ ] **Step 6: Commit the DB layer**

```bash
cd /Users/emilysheraphia/Downloads/insightguard
git add storage/database.py tests/test_all.py
git commit -m "feat: add evidence table + CRUD methods + test stub"
```

---

## Task 2: Server API routes + evidence directory

**Files:**
- Modify: `application/app.py`

- [ ] **Step 1: Add `send_file` to Flask imports and create the evidence directory constant**

At line 13 in `application/app.py`, change:

```python
from flask import Flask, request, jsonify, Response, stream_with_context
```

to:

```python
from flask import Flask, request, jsonify, Response, stream_with_context, send_file
```

Then, immediately after the `_ROLE_CONFIG_PATH` definition (around line 57), add:

```python
EVIDENCE_DIR = Path(__file__).parent.parent / "storage" / "evidence"
EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
```

- [ ] **Step 2: Add the three evidence routes**

Add these three routes anywhere after the `reset_database` route (around line 897). Place the `by-event` route before the `<evidence_id>` route so Flask matches the static segment `by-event` first:

```python
@app.post("/api/evidence/upload")
def evidence_upload():
    if "file" not in request.files:
        return jsonify({"error": "file required"}), 400
    f        = request.files["file"]
    user_id  = request.form.get("user_id", "unknown")
    trigger  = request.form.get("trigger_type", "")
    evt_type = request.form.get("event_type", "")
    log_id   = request.form.get("log_id", "")
    ts       = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%S")
    eid      = str(uuid.uuid4())
    fname    = f"{user_id}_{ts}_{evt_type}.jpg"
    fpath    = EVIDENCE_DIR / fname
    f.save(str(fpath))
    db.insert_evidence(eid, log_id, user_id, str(fpath), trigger, evt_type, ts)
    return jsonify({"evidence_id": eid, "status": "ok"}), 200


@app.get("/api/evidence/by-event/<log_id>")
def evidence_by_event(log_id):
    rows = db.get_evidence_by_event(log_id)
    return jsonify({"evidence": [
        {"evidence_id": r["id"], "trigger_type": r["trigger_type"],
         "event_type": r["event_type"], "timestamp": r["timestamp"]}
        for r in rows
    ]}), 200


@app.get("/api/evidence/<evidence_id>")
def evidence_serve(evidence_id):
    row = db.get_evidence_by_id(evidence_id)
    if not row:
        return jsonify({"error": "not found"}), 404
    return send_file(row["file_path"], mimetype="image/jpeg")
```

Note: `datetime`, `timezone`, `uuid`, and `Path` are already imported at the top of `app.py`.

- [ ] **Step 3: Run tests and verify all 5 assertions pass**

```bash
cd /Users/emilysheraphia/Downloads/insightguard && python tests/test_all.py 2>&1 | grep -A12 "Evidence Capture"
```

Expected output:
```
═════════════════════════════════════════════════════════════════
  Evidence Capture — API (upload + retrieve)
═════════════════════════════════════════════════════════════════
  [PASS] POST /api/evidence/upload → 200 + evidence_id  → HTTP 200
  [PASS] GET /api/evidence/<id> → 200 + image/jpeg  → HTTP 200
  [PASS] GET /api/evidence/by-event/<log_id> → linked record  → HTTP 200
  [PASS] GET /api/evidence/<unknown-id> → 404  → HTTP 404
  [PASS] POST /api/evidence/upload (no file) → 400  → HTTP 400

  5/5 passed
```

Also run the full suite and confirm the existing 16 sections still pass:

```bash
cd /Users/emilysheraphia/Downloads/insightguard && python tests/test_all.py 2>&1 | tail -30
```

Expected: 17/17 sections pass (16 existing + Evidence Capture).

- [ ] **Step 4: Verify `DELETE /api/database/reset` does NOT delete evidence rows**

The existing reset route at `app.py:884` only deletes `threat_alerts`, `anomaly_results`, `behaviour_features`, `activity_logs`, and `users` — the `evidence` table is not touched. Confirm by reading lines 884–896 of `app.py` — no `DELETE FROM evidence` should be present. This acceptance criterion is satisfied by the existing code.

- [ ] **Step 5: Commit**

```bash
cd /Users/emilysheraphia/Downloads/insightguard
git add application/app.py
git commit -m "feat: add evidence upload/serve/by-event API routes"
```

---

## Task 3: ScreenshotCapture module + agent requirements

**Files:**
- Create: `nexon_agent/screenshot_capture.py`
- Modify: `nexon_agent/requirements.txt`

- [ ] **Step 1: Add `mss` and `Pillow` to agent requirements**

In `nexon_agent/requirements.txt`, append:

```
mss>=9.0
Pillow>=10.0
```

Full file should be:

```
requests>=2.31.0
watchdog>=3.0.0
psutil>=5.9.0
pywin32>=306; sys_platform == "win32"
pyperclip>=1.8.2
websockets>=12.0
mss>=9.0
Pillow>=10.0
```

- [ ] **Step 2: Create `nexon_agent/screenshot_capture.py`**

```python
"""
ScreenshotCapture — takes a JPEG screenshot and uploads it to InsightGuard.

mss and Pillow are imported inside capture() so this module can be imported
on macOS/Linux test runners without crashing. If either import fails,
capture() logs a warning and returns False; the local file is never created.
"""

import logging
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)


class ScreenshotCapture:
    """Capture the full screen and POST the JPEG to /api/evidence/upload."""

    EVIDENCE_DIR = Path("evidence")   # relative to agent working directory

    def __init__(self, cfg: dict, server_url: str) -> None:
        """Create local evidence directory if missing."""
        self._cfg        = cfg
        self._server_url = server_url.rstrip("/")
        self.EVIDENCE_DIR.mkdir(exist_ok=True)

    def capture(self, trigger_type: str, event_type: str,
                log_id: str = "") -> bool:
        """
        Take screenshot, save locally as JPEG, upload to server.

        trigger_type: "severity" | "pattern"
        event_type:   activity_type of the triggering event (e.g. "usb")
        log_id:       server-side log ID to link screenshot to event;
                      empty string if unknown
        Returns True if upload succeeded, False otherwise.
        Local file is kept on disk regardless of upload result.
        """
        try:
            mss_module = __import__("mss")
            Image      = __import__("PIL.Image", fromlist=["Image"]).Image
        except ImportError as exc:
            logger.warning("[ScreenshotCapture] Import failed (%s) — skipped", exc)
            return False

        try:
            ts    = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%S")
            fname = f"{ts}_{trigger_type}_{event_type}.jpg"
            fpath = self.EVIDENCE_DIR / fname

            with mss_module.mss() as sct:
                shot = sct.grab(sct.monitors[0])   # monitors[0] = all monitors combined
                img  = Image.frombytes("RGB", shot.size, shot.bgra, "raw", "BGRX")
                img.save(str(fpath), format="JPEG", quality=75)

            logger.info("[ScreenshotCapture] Saved %s", fname)
            return self._upload(fpath, trigger_type, event_type, log_id)

        except Exception as exc:
            logger.warning("[ScreenshotCapture] Capture failed: %s", exc)
            return False

    def _upload(self, fpath: Path, trigger_type: str,
                event_type: str, log_id: str) -> bool:
        """POST the JPEG to the server. Returns True on HTTP 200, False otherwise."""
        try:
            import requests as _req
            with open(fpath, "rb") as fh:
                resp = _req.post(
                    f"{self._server_url}/api/evidence/upload",
                    files={"file": (fpath.name, fh, "image/jpeg")},
                    data={
                        "user_id":      self._cfg.get("user_id", ""),
                        "trigger_type": trigger_type,
                        "event_type":   event_type,
                        "log_id":       log_id,
                    },
                    timeout=10,
                )
            if resp.status_code == 200:
                return True
            logger.warning("[ScreenshotCapture] Upload failed: HTTP %s", resp.status_code)
            return False
        except Exception as exc:
            logger.warning("[ScreenshotCapture] Upload error: %s", exc)
            return False
```

- [ ] **Step 3: Verify the module imports cleanly on macOS/Linux**

```bash
cd /Users/emilysheraphia/Downloads/insightguard/nexon_agent && python -c "from screenshot_capture import ScreenshotCapture; print('import OK')"
```

Expected output: `import OK` — no crash because `mss`/`Pillow` are only imported inside `capture()`.

- [ ] **Step 4: Commit**

```bash
cd /Users/emilysheraphia/Downloads/insightguard
git add nexon_agent/screenshot_capture.py nexon_agent/requirements.txt
git commit -m "feat: add ScreenshotCapture module + mss/Pillow dependencies"
```

---

## Task 4: Agent trigger points

**Files:**
- Modify: `nexon_agent/agent.py`

- [ ] **Step 1: Add import and module-level sentinel**

At the top of `nexon_agent/agent.py`, after the existing local imports (`from process_monitor import ProcessMonitor`, etc.), add:

```python
from screenshot_capture import ScreenshotCapture
```

After the `_stats` dict definition (around line 105), add the module-level sentinel:

```python
_screenshot = None   # ScreenshotCapture | None — set in main() after config loads
```

- [ ] **Step 2: Initialise `_screenshot` in `main()`**

In `main()`, add `global _screenshot` alongside the existing `global _start_time`, and initialise it right after `cfg = load_config()`:

```python
def main():
    global _start_time, _screenshot
    _start_time = time.time()

    # ...banner print...

    cfg = load_config()
    _screenshot = ScreenshotCapture(cfg, cfg["server_url"])

    # ...rest of main() unchanged...
```

- [ ] **Step 3: Add Trigger 1 — severity threshold in `_sender_thread`**

Current code in `_sender_thread` (around line 239–244):

```python
        try:
            resp = session.post(url, json=payload, timeout=5)
            if resp.status_code == 200:
                _stats["sent"] += 1
                score = resp.json().get("risk_score", "?")
                _add_log(f"{G}[SENT]{RST} {payload.get('source','?')} → score {score}")
```

Replace with (note: `resp.json()` is called once and cached in `resp_data`):

```python
        try:
            resp = session.post(url, json=payload, timeout=5)
            if resp.status_code == 200:
                _stats["sent"] += 1
                resp_data = resp.json()
                score = resp_data.get("risk_score", "?")
                _add_log(f"{G}[SENT]{RST} {payload.get('source','?')} → score {score}")
                if resp_data.get("risk_score", 0) >= 60:
                    if _screenshot:
                        _screenshot.capture(
                            trigger_type="severity",
                            event_type=payload.get(
                                "activity_type", payload.get("source", "unknown")
                            ),
                            log_id=resp_data.get("log_id", ""),
                        )
```

- [ ] **Step 4: Add Trigger 2 — pattern match in `_check_threat_patterns`**

In `_check_threat_patterns`, inside the `for threat in threats:` loop, after the `enqueue_event(payload)` call (around line 207) and before `_stats["alerts"] += 1`:

```python
    for threat in threats:
        payload = _base(cfg, "dlp_system")
        payload.update({
            "source":      "file",
            "operation":   "threat_pattern",
            "file_count":  threat["file_count"],
            "data_mb":     0,
            "destination": "local",
            "threat_type": threat["threat_type"],
            "description": threat["description"],
            "files":       threat.get("files", []),
            "file_path":   ", ".join(threat.get("files", [])[-3:]),
            "severity_override": threat["severity_hint"],
        })
        enqueue_event(payload)
        if _screenshot:
            _screenshot.capture(
                trigger_type="pattern",
                event_type=threat["threat_type"],
                log_id="",
            )
        _stats["alerts"] += 1
        _add_log(f"{R}[THREAT]{RST} {threat['threat_type']}: {threat['description']}")
```

- [ ] **Step 5: Verify agent.py imports cleanly**

```bash
cd /Users/emilysheraphia/Downloads/insightguard/nexon_agent && python -c "import agent; print('import OK')"
```

Expected: `import OK` (the `ScreenshotCapture` import and `_screenshot = None` sentinel are fine at module level since mss/Pillow are not imported until `capture()` is called).

- [ ] **Step 6: Run full test suite to confirm no regressions**

```bash
cd /Users/emilysheraphia/Downloads/insightguard && python tests/test_all.py 2>&1 | tail -25
```

Expected: all 17 sections pass.

- [ ] **Step 7: Commit**

```bash
cd /Users/emilysheraphia/Downloads/insightguard
git add nexon_agent/agent.py
git commit -m "feat: wire ScreenshotCapture into agent severity + pattern triggers"
```

---

## Task 5: Dashboard — camera icon + evidence modal

**Files:**
- Modify: `application/dashboard.html`

- [ ] **Step 1: Add camera column header to the Detection Log table**

Find the table header at around line 543:

```html
<thead><tr>
  <th>Time</th><th>User</th><th>Dept</th><th>Event</th><th>File</th>
  <th>ML</th><th>PUB</th><th>PERS</th><th>Severity</th><th>Rules</th>
</tr></thead>
```

Change to:

```html
<thead><tr>
  <th>Time</th><th>User</th><th>Dept</th><th>Event</th><th>File</th>
  <th>ML</th><th>PUB</th><th>PERS</th><th>Severity</th><th>Rules</th><th></th>
</tr></thead>
```

- [ ] **Step 2: Add camera icon cell to `addLogRow`**

In the `addLogRow` function (around line 1050), the `tr.innerHTML=` template ends with the Rules `<td>`. Append a new camera `<td>` at the end, just before the closing backtick:

Current last two cells of `tr.innerHTML`:

```javascript
    <td><span class="badge badge-${sev}">${sev.replace('_',' ')}</span></td>
    <td style="font-size:10px;color:var(--text-muted);font-family:var(--mono)">${(d.triggered_rules||[]).slice(0,2).join(', ')||'—'}</td>
  `;
```

Change to:

```javascript
    <td><span class="badge badge-${sev}">${sev.replace('_',' ')}</span></td>
    <td style="font-size:10px;color:var(--text-muted);font-family:var(--mono)">${(d.triggered_rules||[]).slice(0,2).join(', ')||'—'}</td>
    <td style="width:28px;text-align:center" onclick="event.stopPropagation()">${(sev==='high_risk'||sev==='critical')?`<button data-log-id="${esc(d.log_id||'')}" onclick="fetchEvidence(this.dataset.logId)" style="background:none;border:none;cursor:pointer;padding:2px;font-size:14px;opacity:.65;line-height:1" title="View screenshot">📷</button>`:''}</td>
  `;
```

- [ ] **Step 3: Add `fetchEvidence` + lightbox helper functions**

Add these functions after the `addLogRow` function (around line 1069), before `_fetchConfForLogRow`:

```javascript
function fetchEvidence(logId){
  const base=document.getElementById('apiUrl').value.trim()||window.location.origin;
  fetch(base+'/api/evidence/by-event/'+encodeURIComponent(logId))
    .then(r=>r.json())
    .then(d=>{
      if(!d.evidence||!d.evidence.length){
        toast('No Screenshot','No screenshot captured for this event','info');
        return;
      }
      openEvidenceLightbox(d.evidence[0],base);
    })
    .catch(()=>toast('Error','Failed to fetch evidence','danger'));
}

function openEvidenceLightbox(ev,base){
  let overlay=document.getElementById('evidenceLightbox');
  if(!overlay){
    overlay=document.createElement('div');
    overlay.id='evidenceLightbox';
    overlay.style.cssText='display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,.85);z-index:10000;align-items:center;justify-content:center;cursor:pointer';
    overlay.innerHTML='<img id="evidenceLightboxImg" style="max-width:90%;max-height:90vh;border-radius:6px;box-shadow:0 8px 32px rgba(0,0,0,.6)" />';
    overlay.onclick=()=>{overlay.style.display='none';};
    document.body.appendChild(overlay);
  }
  document.getElementById('evidenceLightboxImg').src=base+'/api/evidence/'+ev.evidence_id;
  overlay.style.display='flex';
}
```

- [ ] **Step 4: Add evidence section to the alert detail modal**

In `openModal(d)`, the `document.getElementById('modalBody').innerHTML=` template (around line 1160) ends with:

```javascript
    ${d.description?`<div class="pipe-row"><span class="pipe-label">Details</span><span class="pipe-val" style="font-size:11px">${d.description}</span></div>`:''}
  `;
```

Append a new evidence section div before the closing backtick:

```javascript
    ${d.description?`<div class="pipe-row"><span class="pipe-label">Details</span><span class="pipe-val" style="font-size:11px">${d.description}</span></div>`:''}
    <div id="modalEvidenceSection" style="margin-top:12px;display:none">
      <div style="font-size:11px;font-weight:600;color:var(--text-secondary);margin-bottom:6px;font-family:var(--mono);text-transform:uppercase;letter-spacing:.08em">Screenshot Evidence</div>
      <div id="modalEvidenceThumbs"></div>
    </div>
  `;
```

Then, after `document.getElementById('riskModal').classList.add('open');` in `openModal(d)`, add the lazy evidence fetch:

```javascript
  // Lazy fetch: evidence thumbnails
  if(d.log_id){
    fetch(base+'/api/evidence/by-event/'+encodeURIComponent(d.log_id))
      .then(r=>r.json())
      .then(ev=>{
        if(!ev.evidence||!ev.evidence.length)return;
        const section=document.getElementById('modalEvidenceSection');
        const thumbs=document.getElementById('modalEvidenceThumbs');
        if(!section||!thumbs)return;
        thumbs.innerHTML=ev.evidence.map(e=>
          `<a href="${base}/api/evidence/${e.evidence_id}" target="_blank" style="display:block;margin-bottom:8px">
             <img src="${base}/api/evidence/${e.evidence_id}" style="max-width:100%;border-radius:4px;border:1px solid var(--border)" title="${esc(e.trigger_type+' — '+e.event_type)}">
           </a>`
        ).join('');
        section.style.display='block';
      })
      .catch(()=>{});
  }
```

- [ ] **Step 5: Verify dashboard renders without JS errors**

Start the Flask server:

```bash
cd /Users/emilysheraphia/Downloads/insightguard && python application/app.py
```

Open `http://localhost:5000` in a browser. Open the browser console (F12). Confirm:
- No JS errors on page load
- Detection Log table has an extra empty column on the right
- For a `critical` or `high_risk` row (send a test event if needed), the 📷 button appears in the last column
- Clicking 📷 shows toast "No screenshot captured for this event" (no agent running)
- Opening a row's detail modal shows the modal without errors; the `div#modalEvidenceSection` is hidden (no screenshots in DB)

- [ ] **Step 6: Run the full test suite one final time**

```bash
cd /Users/emilysheraphia/Downloads/insightguard && python tests/test_all.py
```

Expected: all 17/17 sections pass with no regressions.

- [ ] **Step 7: Commit**

```bash
cd /Users/emilysheraphia/Downloads/insightguard
git add application/dashboard.html
git commit -m "feat: add evidence camera icon to Detection Log + evidence section in alert modal"
```

---

## Self-Review

**Spec coverage:**
- [x] Sec 2 (ScreenshotCapture module) → Task 3
- [x] Sec 3, Trigger 1 (severity ≥60 in `_sender_thread`) → Task 4 Step 3
- [x] Sec 3, Trigger 2 (pattern fire in `_check_threat_patterns`) → Task 4 Step 4
- [x] Sec 4, `POST /api/evidence/upload` → Task 2
- [x] Sec 4, `GET /api/evidence/<id>` → Task 2
- [x] Sec 4, `GET /api/evidence/by-event/<log_id>` → Task 2
- [x] Sec 4, DB evidence table → Task 1
- [x] Sec 4, DB 3 methods → Task 1
- [x] Sec 4, `storage/evidence/` dir at startup → Task 2 Step 1
- [x] Sec 5, camera icon on critical/high_risk rows → Task 5 Steps 1–3
- [x] Sec 5, thumbnail in alert detail modal → Task 5 Step 4
- [x] Sec 6, 5 test assertions → Task 1 Step 1 + Task 2 Step 3
- [x] Acceptance: `DELETE /api/database/reset` does not delete evidence → Task 2 Step 4 (confirmed by reading existing code)

**Type consistency check:**
- `insert_evidence` signature in Task 1 matches usage in Task 2 (`eid, log_id, user_id, str(fpath), trigger, evt_type, ts`) ✓
- `get_evidence_by_id` returns `dict | None`; used with `row["file_path"]` in `evidence_serve` ✓
- `get_evidence_by_event` returns `list[dict]`; iterated with `r["id"]` etc. in `evidence_by_event` ✓
- `ScreenshotCapture.__init__(cfg, server_url)` matches `ScreenshotCapture(cfg, cfg["server_url"])` in Task 4 ✓
- `capture(trigger_type, event_type, log_id="")` matches both call sites in Task 4 ✓
- `fetchEvidence(logId)` referenced in camera button `onclick` matches function definition in Task 5 ✓
- `openEvidenceLightbox(ev, base)` called from `fetchEvidence` with `d.evidence[0]` ✓
