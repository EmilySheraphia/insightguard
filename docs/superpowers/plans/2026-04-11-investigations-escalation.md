# Investigations & Escalation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add analyst case management (open/track/close investigation cases on alerts) and automated email escalation (background thread sends Gmail alerts for critical/high_risk events), both backed by two new DB tables.

**Architecture:** Two new DB tables (`investigations`, `escalation_log`) added in `storage/database.py` via `_init_schema()`. New `escalation.py` module in project root runs a background thread. All API routes added to `application/app.py`. Dashboard gains an "Investigations" section with case table + slide-in panel, an "Open Case" button on each alert/log row, and an escalation config card in the Configuration section.

**Tech Stack:** Python 3.11, Flask, SQLite, `smtplib` SMTP_SSL (stdlib), `threading.Thread`, vanilla JS.

---

## File Map

| Action | File | What changes |
|--------|------|-------------|
| Create | `escalation.py` | `EscalationEngine` class |
| Create | `storage/escalation_config.json` | Default SMTP config |
| Modify | `storage/database.py` | `investigations` + `escalation_log` tables + CRUD |
| Modify | `application/app.py` | Import escalation.py, 8 new routes |
| Modify | `application/dashboard.html` | Investigations section + escalation config card |
| Modify | `tests/test_all.py` | New test section |

---

### Task 1: Add `investigations` and `escalation_log` tables to `storage/database.py`

**Files:**
- Modify: `storage/database.py`
- Test: `tests/test_all.py`

- [ ] **Step 1: Write the failing test**

Add this function to `tests/test_all.py` before the `if __name__ == "__main__":` block:

```python
def test_investigations_db():
    section("DB — investigations + escalation_log tables")
    import tempfile, os
    from storage.database import DatabaseManager

    tmp = tempfile.mktemp(suffix=".db")
    db  = DatabaseManager(db_path=tmp)

    # Create investigation
    db.create_investigation("case-001", alert_id="al_abc", user_id="jsmith",
                             department="Finance", severity="critical")
    ok("create_investigation() succeeds")

    # List investigations
    cases = db.list_investigations()
    assert len(cases) == 1,                  f"Expected 1 case, got {len(cases)}"
    assert cases[0]["case_id"] == "case-001"
    assert cases[0]["status"] == "open"
    ok("list_investigations() returns 1 open case")

    # Get single investigation
    case = db.get_investigation("case-001")
    assert case is not None
    assert case["user_id"] == "jsmith"
    ok("get_investigation() returns case detail")

    # Update investigation
    db.update_investigation("case-001", status="confirmed_threat", analyst_notes="Verified exfil")
    updated = db.get_investigation("case-001")
    assert updated["status"] == "confirmed_threat"
    assert updated["analyst_notes"] == "Verified exfil"
    ok("update_investigation() sets status + notes")

    # Escalation log
    db.insert_escalation_log(user_id="jsmith", severity="critical", risk_score=92,
                              sent_to="analyst@example.com", status="sent", error="")
    logs = db.get_escalation_log(limit=10)
    assert len(logs) == 1
    assert logs[0]["status"] == "sent"
    ok("insert_escalation_log() + get_escalation_log() work")

    os.unlink(tmp)
    return True
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /Users/emilysheraphia/Downloads/insightguard
python tests/test_all.py 2>&1 | grep -A10 "investigations.*escalation\|AttributeError.*create_investigation"
```

Expected: `AttributeError: 'DatabaseManager' object has no attribute 'create_investigation'`

- [ ] **Step 3: Add the two tables and CRUD methods to `storage/database.py`**

In `storage/database.py`, inside `_init_schema()`, after the last existing `conn.execute("CREATE INDEX ...")` line (after line 138), add:

```python
            # Table 6: Investigation Cases
            conn.execute("""
                CREATE TABLE IF NOT EXISTS investigations (
                    case_id       TEXT PRIMARY KEY,
                    alert_id      TEXT,
                    user_id       TEXT NOT NULL,
                    department    TEXT,
                    severity      TEXT,
                    status        TEXT DEFAULT 'open',
                    analyst_notes TEXT DEFAULT '',
                    created_at    TEXT DEFAULT (datetime('now')),
                    updated_at    TEXT DEFAULT (datetime('now'))
                )
            """)

            # Table 7: Escalation Log
            conn.execute("""
                CREATE TABLE IF NOT EXISTS escalation_log (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id     TEXT,
                    severity    TEXT,
                    risk_score  INTEGER,
                    sent_to     TEXT,
                    status      TEXT,
                    error       TEXT,
                    sent_at     TEXT DEFAULT (datetime('now'))
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_inv_user   ON investigations(user_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_inv_status ON investigations(status)")
```

Then add these CRUD methods at the end of the `DatabaseManager` class (before the `if __name__ == "__main__":` block):

```python
    # ── Investigation operations ──────────────────────────────────────────

    def create_investigation(self, case_id: str, alert_id: str = "",
                              user_id: str = "", department: str = "",
                              severity: str = "open") -> None:
        with self._lock, self._conn() as conn:
            conn.execute("""
                INSERT OR IGNORE INTO investigations
                    (case_id, alert_id, user_id, department, severity)
                VALUES (?, ?, ?, ?, ?)
            """, (case_id, alert_id, user_id, department, severity))

    def list_investigations(self, status: str = "", user_id: str = "",
                             limit: int = 100) -> list[dict]:
        q      = "SELECT * FROM investigations WHERE 1=1"
        params: list = []
        if status:
            q += " AND status = ?";  params.append(status)
        if user_id:
            q += " AND user_id = ?"; params.append(user_id)
        q += " ORDER BY created_at DESC LIMIT ?"
        params.append(min(limit, 200))
        with self._conn() as conn:
            rows = conn.execute(q, params).fetchall()
        return [dict(r) for r in rows]

    def get_investigation(self, case_id: str) -> dict | None:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM investigations WHERE case_id = ?", (case_id,)
            ).fetchone()
        return dict(row) if row else None

    def update_investigation(self, case_id: str, status: str = "",
                              analyst_notes: str | None = None) -> bool:
        valid = {"open", "confirmed_threat", "false_positive",
                 "under_investigation", "closed"}
        sets, params = [], []
        if status:
            if status not in valid:
                return False
            sets.append("status = ?"); params.append(status)
        if analyst_notes is not None:
            sets.append("analyst_notes = ?"); params.append(analyst_notes)
        if not sets:
            return False
        sets.append("updated_at = datetime('now')")
        params.append(case_id)
        with self._lock, self._conn() as conn:
            cur = conn.execute(
                f"UPDATE investigations SET {', '.join(sets)} WHERE case_id = ?",
                params
            )
        return cur.rowcount > 0

    # ── Escalation log operations ─────────────────────────────────────────

    def insert_escalation_log(self, user_id: str, severity: str,
                               risk_score: int, sent_to: str,
                               status: str, error: str = "") -> None:
        with self._lock, self._conn() as conn:
            conn.execute("""
                INSERT INTO escalation_log
                    (user_id, severity, risk_score, sent_to, status, error)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (user_id, severity, risk_score, sent_to, status, error))

    def get_escalation_log(self, limit: int = 50) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM escalation_log ORDER BY sent_at DESC LIMIT ?",
                (min(limit, 200),)
            ).fetchall()
        return [dict(r) for r in rows]
```

- [ ] **Step 4: Run test to verify it passes**

```bash
cd /Users/emilysheraphia/Downloads/insightguard
python tests/test_all.py 2>&1 | grep -A10 "investigations.*escalation\|PASS.*create_investigation\|PASS.*list_inv\|PASS.*update_inv\|PASS.*escalation_log"
```

Expected: 5 `[PASS]` lines.

- [ ] **Step 5: Commit**

```bash
cd /Users/emilysheraphia/Downloads/insightguard
git add storage/database.py tests/test_all.py
git commit -m "feat: add investigations and escalation_log tables with CRUD to DatabaseManager"
```

---

### Task 2: Create `escalation.py` and `storage/escalation_config.json`

**Files:**
- Create: `escalation.py`
- Create: `storage/escalation_config.json`
- Test: `tests/test_all.py`

- [ ] **Step 1: Write the failing test**

Add to `tests/test_all.py` before `if __name__ == "__main__":`:

```python
def test_escalation_engine():
    section("EscalationEngine — config + enqueue logic")
    import tempfile, json, os
    from escalation import EscalationEngine

    # Write a temp config
    cfg = {
        "enabled": False,
        "smtp_host": "smtp.gmail.com",
        "smtp_port": 465,
        "smtp_user": "",
        "smtp_password": "",
        "recipient_email": "",
        "min_severity": "critical"
    }
    tmp_cfg = tempfile.mktemp(suffix=".json")
    with open(tmp_cfg, "w") as f:
        json.dump(cfg, f)

    eng = EscalationEngine(config_path=tmp_cfg)
    assert eng.config["enabled"] == False
    assert eng.config["min_severity"] == "critical"
    ok("EscalationEngine loads config correctly")

    # enqueue should not crash when disabled
    eng.enqueue({
        "user_id": "jsmith", "department": "Finance",
        "severity": "critical", "risk_score": 92,
        "activity_type": "file_access", "triggered_rules": ["usb_exfil"],
        "timestamp": "2026-04-11T03:00:00Z"
    })
    ok("enqueue() accepts payload without crash (disabled mode)")

    # update_config
    eng.update_config({"enabled": False, "min_severity": "high_risk"})
    assert eng.config["min_severity"] == "high_risk"
    ok("update_config() updates min_severity")

    os.unlink(tmp_cfg)
    return True
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /Users/emilysheraphia/Downloads/insightguard
python tests/test_all.py 2>&1 | grep -A5 "EscalationEngine\|No module named 'escalation'"
```

Expected: `ModuleNotFoundError: No module named 'escalation'`

- [ ] **Step 3: Create `storage/escalation_config.json`**

Create `/Users/emilysheraphia/Downloads/insightguard/storage/escalation_config.json`:

```json
{
    "enabled": false,
    "smtp_host": "smtp.gmail.com",
    "smtp_port": 465,
    "smtp_user": "",
    "smtp_password": "",
    "recipient_email": "",
    "min_severity": "critical"
}
```

- [ ] **Step 4: Create `escalation.py`**

Create `/Users/emilysheraphia/Downloads/insightguard/escalation.py`:

```python
"""
InsightGuard — Alert Escalation Engine
=======================================
Runs a background thread that drains a queue of alert payloads and sends
emails via Gmail SMTP_SSL when escalation is enabled.
"""

from __future__ import annotations
import json
import queue
import smtplib
import ssl
import threading
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

_SEV_ORDER = {"normal": 0, "suspicious": 1, "high_risk": 2, "critical": 3}

_DEFAULT_CONFIG = {
    "enabled": False,
    "smtp_host": "smtp.gmail.com",
    "smtp_port": 465,
    "smtp_user": "",
    "smtp_password": "",
    "recipient_email": "",
    "min_severity": "critical",
}


class EscalationEngine:
    """
    Background email escalation thread.

    Usage:
        engine = EscalationEngine(config_path="storage/escalation_config.json")
        engine.start()
        engine.enqueue(event_payload)   # called from _process_event()
    """

    def __init__(self, config_path: str | Path | None = None):
        if config_path is None:
            config_path = Path(__file__).parent / "storage" / "escalation_config.json"
        self._config_path = Path(config_path)
        self.config: dict = dict(_DEFAULT_CONFIG)
        self._load_config()
        self._queue: queue.Queue = queue.Queue(maxsize=200)
        self._thread: threading.Thread | None = None
        self._db = None   # injected after DB is ready via set_db()

    def set_db(self, db) -> None:
        """Inject the DatabaseManager so escalation log can be written."""
        self._db = db

    def _load_config(self) -> None:
        if self._config_path.exists():
            try:
                with open(self._config_path) as f:
                    loaded = json.load(f)
                self.config.update(loaded)
            except Exception as e:
                print(f"[Escalation] Config load error: {e}")

    def _save_config(self) -> None:
        self._config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._config_path, "w") as f:
            json.dump(self.config, f, indent=4)

    def update_config(self, new_config: dict) -> None:
        """Replace config in memory and persist to disk."""
        self.config.update(new_config)
        self._save_config()

    def start(self) -> None:
        """Start the background drain thread (idempotent)."""
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._drain_loop, daemon=True)
        self._thread.start()
        print("[Escalation] Background thread started.")

    def enqueue(self, event_payload: dict) -> None:
        """
        Called from _process_event() when severity meets the threshold.
        Drops silently if queue is full (non-blocking).
        """
        if not self.config.get("enabled"):
            return
        sev = event_payload.get("severity", "normal")
        min_sev = self.config.get("min_severity", "critical")
        if _SEV_ORDER.get(sev, 0) < _SEV_ORDER.get(min_sev, 3):
            return
        try:
            self._queue.put_nowait(event_payload)
        except queue.Full:
            pass

    def send_test_email(self) -> dict:
        """Send a test email immediately. Returns {status, error}."""
        payload = {
            "user_id":       "test_user",
            "department":    "Test",
            "severity":      "critical",
            "risk_score":    99,
            "activity_type": "test",
            "triggered_rules": ["test_rule"],
            "timestamp":     datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        return self._send_email(payload)

    # ── Internal ──────────────────────────────────────────────────────────

    def _drain_loop(self) -> None:
        while True:
            try:
                payload = self._queue.get(timeout=5)
                result  = self._send_email(payload)
                self._log_escalation(payload, result["status"], result.get("error", ""))
            except queue.Empty:
                continue
            except Exception as e:
                print(f"[Escalation] Drain error: {e}")

    def _send_email(self, payload: dict) -> dict:
        cfg = self.config
        if not cfg.get("smtp_user") or not cfg.get("smtp_password") or not cfg.get("recipient_email"):
            return {"status": "skipped", "error": "SMTP credentials not configured"}
        subject = (
            f"[InsightGuard ALERT] {payload.get('severity','').upper()} — "
            f"{payload.get('user_id','')} @ {payload.get('department','')}"
        )
        rules_html = "".join(
            f"<li>{r}</li>" for r in (payload.get("triggered_rules") or [])
        )
        sev   = payload.get("severity", "normal")
        color = {"critical": "#f85149", "high_risk": "#db6d28",
                 "suspicious": "#e3b341", "normal": "#3fb950"}.get(sev, "#8b949e")
        body_html = f"""
        <div style="font-family:Arial,sans-serif;max-width:600px">
          <div style="background:#161b22;padding:20px;border-radius:8px">
            <h2 style="color:#e6edf3;margin:0 0 16px">
              InsightGuard — Insider Threat Alert
            </h2>
            <div style="background:#21262d;border-radius:6px;padding:16px;margin-bottom:12px">
              <div style="font-size:13px;color:#8b949e;margin-bottom:4px">Risk Score</div>
              <div style="font-size:32px;font-weight:700;color:{color}">{payload.get('risk_score', 0)}</div>
              <div style="display:inline-block;background:{color}22;border:1px solid {color}44;
                          border-radius:4px;padding:2px 10px;font-size:12px;color:{color};margin-top:6px">
                {sev.upper().replace('_', ' ')}
              </div>
            </div>
            <table style="width:100%;font-size:13px;color:#e6edf3;border-collapse:collapse">
              <tr><td style="padding:6px 0;color:#8b949e;width:140px">User ID</td>
                  <td style="padding:6px 0;font-family:monospace">{payload.get('user_id', '')}</td></tr>
              <tr><td style="padding:6px 0;color:#8b949e">Department</td>
                  <td style="padding:6px 0">{payload.get('department', '')}</td></tr>
              <tr><td style="padding:6px 0;color:#8b949e">Activity</td>
                  <td style="padding:6px 0">{payload.get('activity_type', '')}</td></tr>
              <tr><td style="padding:6px 0;color:#8b949e">Timestamp</td>
                  <td style="padding:6px 0;font-family:monospace">{payload.get('timestamp', '')}</td></tr>
            </table>
            {f'<div style="margin-top:12px"><div style="font-size:12px;color:#8b949e;margin-bottom:6px">Triggered Rules</div><ul style="color:#f85149;font-family:monospace;font-size:12px;margin:0;padding-left:20px">{rules_html}</ul></div>' if rules_html else ''}
            <div style="margin-top:16px;padding-top:12px;border-top:1px solid #30363d">
              <a href="http://localhost:5000/" style="background:#58a6ff;color:#fff;
                 padding:8px 16px;border-radius:6px;text-decoration:none;font-size:13px">
                View Dashboard
              </a>
            </div>
          </div>
        </div>
        """
        try:
            ctx = ssl.create_default_context()
            with smtplib.SMTP_SSL(cfg["smtp_host"], int(cfg["smtp_port"]), context=ctx) as server:
                server.login(cfg["smtp_user"], cfg["smtp_password"])
                msg = MIMEMultipart("alternative")
                msg["Subject"] = subject
                msg["From"]    = cfg["smtp_user"]
                msg["To"]      = cfg["recipient_email"]
                msg.attach(MIMEText(body_html, "html"))
                server.sendmail(cfg["smtp_user"], cfg["recipient_email"], msg.as_string())
            print(f"[Escalation] Email sent → {cfg['recipient_email']} for {payload.get('user_id')}")
            return {"status": "sent", "error": ""}
        except Exception as e:
            print(f"[Escalation] Email failed: {e}")
            return {"status": "failed", "error": str(e)}

    def _log_escalation(self, payload: dict, status: str, error: str = "") -> None:
        if self._db is None:
            return
        try:
            self._db.insert_escalation_log(
                user_id    = payload.get("user_id", ""),
                severity   = payload.get("severity", ""),
                risk_score = int(payload.get("risk_score", 0)),
                sent_to    = self.config.get("recipient_email", ""),
                status     = status,
                error      = error,
            )
        except Exception as e:
            print(f"[Escalation] Log write error: {e}")
```

- [ ] **Step 5: Run test to verify it passes**

```bash
cd /Users/emilysheraphia/Downloads/insightguard
python tests/test_all.py 2>&1 | grep -A10 "EscalationEngine\|PASS.*enqueue\|PASS.*update_config"
```

Expected: 3 `[PASS]` lines.

- [ ] **Step 6: Commit**

```bash
cd /Users/emilysheraphia/Downloads/insightguard
git add escalation.py storage/escalation_config.json tests/test_all.py
git commit -m "feat: add EscalationEngine with background SMTP thread and escalation_config.json"
```

---

### Task 3: Wire `EscalationEngine` into `application/app.py` (6 new routes)

**Files:**
- Modify: `application/app.py`

- [ ] **Step 1: Add import and startup in `app.py`**

After the existing `from analytics import CounterfactualEngine, ConfidenceEngine` import (or after `from nexon_psychometrics import load_nexon_profiles` if analytics plan hasn't been merged yet), add:

```python
from escalation import EscalationEngine
_escalation = EscalationEngine()
```

Then find the line `db = DatabaseManager()` (around line 117) and after it add:

```python
_escalation.set_db(db)
_escalation.start()
```

- [ ] **Step 2: Hook escalation into `_process_event()`**

In `_process_event()`, after the `_broadcast_sse(pay)` call (around line 310), add:

```python
    # Escalation
    _escalation.enqueue({**pay, "triggered_rules": result["triggered_rules"]})
```

- [ ] **Step 3: Add escalation + investigations API routes**

Add the following 8 routes after the existing `@app.get("/api/events/recent")` block (after line 778):

```python
# ── Escalation routes ─────────────────────────────────────────────────────────

@app.get("/api/escalation/config")
def get_escalation_config():
    cfg = dict(_escalation.config)
    cfg.pop("smtp_password", None)   # never send password back to browser
    return jsonify(cfg), 200

@app.put("/api/escalation/config")
def update_escalation_config():
    body = request.get_json(silent=True) or {}
    if not body:
        return jsonify({"error": "JSON body required"}), 400
    _escalation.update_config(body)
    cfg = dict(_escalation.config)
    cfg.pop("smtp_password", None)
    return jsonify({"message": "Escalation config saved", "config": cfg}), 200

@app.post("/api/escalation/test")
def test_escalation():
    result = _escalation.send_test_email()
    code = 200 if result["status"] in ("sent", "skipped") else 500
    return jsonify(result), code

@app.get("/api/escalation/log")
def escalation_log():
    limit = min(int(request.args.get("limit", 50)), 200)
    entries = db.get_escalation_log(limit=limit)
    return jsonify({"count": len(entries), "entries": entries}), 200


# ── Investigations routes ──────────────────────────────────────────────────────

@app.post("/api/investigations")
def create_investigation():
    import uuid as _uuid
    body = request.get_json(silent=True) or {}
    user_id = body.get("user_id", "")
    if not user_id:
        return jsonify({"error": "user_id required"}), 400
    case_id = "case_" + str(_uuid.uuid4())[:8]
    db.create_investigation(
        case_id    = case_id,
        alert_id   = body.get("alert_id", ""),
        user_id    = user_id,
        department = body.get("department", ""),
        severity   = body.get("severity", "open"),
    )
    return jsonify({"case_id": case_id, "status": "open"}), 201

@app.get("/api/investigations")
def list_investigations():
    status  = request.args.get("status", "")
    user_id = request.args.get("user_id", "")
    limit   = min(int(request.args.get("limit", 100)), 200)
    cases   = db.list_investigations(status=status, user_id=user_id, limit=limit)
    open_count = sum(1 for c in db.list_investigations(status="open", limit=200))
    return jsonify({"count": len(cases), "open_count": open_count, "cases": cases}), 200

@app.get("/api/investigations/<case_id>")
def get_investigation(case_id):
    case = db.get_investigation(case_id)
    if not case:
        return jsonify({"error": "Case not found"}), 404
    return jsonify(case), 200

@app.patch("/api/investigations/<case_id>")
def update_investigation(case_id):
    body = request.get_json(silent=True) or {}
    status        = body.get("status", "")
    analyst_notes = body.get("analyst_notes")
    ok = db.update_investigation(case_id, status=status, analyst_notes=analyst_notes)
    if not ok:
        return jsonify({"error": "Invalid update or case not found"}), 400
    return jsonify({"case_id": case_id, "updated": True}), 200
```

- [ ] **Step 4: Smoke-test the routes**

```bash
cd /Users/emilysheraphia/Downloads/insightguard
python application/app.py &
sleep 3

# List investigations (empty)
curl -s http://localhost:5000/api/investigations | python3 -m json.tool

# Create a case
curl -s -X POST http://localhost:5000/api/investigations \
  -H "Content-Type: application/json" \
  -d '{"user_id":"jsmith","department":"Finance","severity":"critical","alert_id":"al_test01"}' | python3 -m json.tool

# List again (1 open case)
curl -s http://localhost:5000/api/investigations | python3 -m json.tool

# Get escalation config
curl -s http://localhost:5000/api/escalation/config | python3 -m json.tool
```

Expected output: `{"case_id": "case_XXXXXXXX", "status": "open"}`, then list shows 1 case.

- [ ] **Step 5: Commit**

```bash
cd /Users/emilysheraphia/Downloads/insightguard
git add application/app.py
git commit -m "feat: wire EscalationEngine into app.py + add 8 investigations/escalation routes"
```

---

### Task 4: Dashboard — Investigations section and escalation config card

**Files:**
- Modify: `application/dashboard.html`

- [ ] **Step 1: Add "Investigations" and "Timeline" nav items to the sidebar**

In `dashboard.html`, find the sidebar nav section labeled "Monitoring" (around line 336). After the existing last nav item (`Detection Log` button, line 352–353), add two new nav buttons before the `<div class="sb-nav-section" style="margin-top:8px">System</div>` line:

```html
      <button class="nav-item" data-section="Investigations" onclick="showSection('Investigations')">
        <svg class="ni-icon" viewBox="0 0 24 24" fill="currentColor"><path d="M19 3H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zm-7 3c1.93 0 3.5 1.57 3.5 3.5S13.93 13 12 13s-3.5-1.57-3.5-3.5S10.07 6 12 6zm7 13H5v-.23c0-.62.28-1.2.76-1.58C7.47 15.82 9.64 15 12 15s4.53.82 6.24 2.19c.48.38.76.97.76 1.58V19z"/></svg>
        Investigations
        <span class="nav-badge" id="invBadge" style="display:none">0</span>
      </button>
```

- [ ] **Step 2: Add the Investigations section HTML**

After the `</section>` closing tag of the Detection Log section (find `id="sectionLog"` and its closing `</section>`), add the new Investigations section:

```html
    <!-- ════ INVESTIGATIONS ════ -->
    <section class="section" id="sectionInvestigations">
      <div class="page-hdr" style="border-bottom:1px solid var(--border)">
        <div>
          <div class="page-hdr-title">Investigations</div>
          <div class="page-hdr-sub">Analyst case management — open, track and close threat cases</div>
        </div>
        <div style="margin-left:auto;display:flex;gap:8px;align-items:center">
          <select id="invFilterStatus" onchange="loadInvestigations()" style="background:var(--card);border:1px solid var(--border);border-radius:var(--r);padding:6px 10px;color:var(--text);font-size:12px;font-family:var(--mono);cursor:pointer">
            <option value="">All statuses</option>
            <option value="open">Open</option>
            <option value="under_investigation">Under Investigation</option>
            <option value="confirmed_threat">Confirmed Threat</option>
            <option value="false_positive">False Positive</option>
            <option value="closed">Closed</option>
          </select>
          <button onclick="loadInvestigations()" style="background:var(--card);border:1px solid var(--border);border-radius:var(--r);padding:6px 12px;color:var(--text);font-size:12px;cursor:pointer">Refresh</button>
        </div>
      </div>
      <div style="padding:16px 20px;display:flex;gap:16px;overflow:hidden;height:calc(100% - 61px)">
        <!-- Case table -->
        <div style="flex:1;overflow-y:auto">
          <table style="width:100%;border-collapse:collapse;font-size:12px" id="invTable">
            <thead>
              <tr style="border-bottom:1px solid var(--border)">
                <th style="text-align:left;padding:8px 10px;color:var(--text-muted);font-size:11px;font-family:var(--mono);font-weight:500">Case ID</th>
                <th style="text-align:left;padding:8px 10px;color:var(--text-muted);font-size:11px;font-family:var(--mono);font-weight:500">User</th>
                <th style="text-align:left;padding:8px 10px;color:var(--text-muted);font-size:11px;font-family:var(--mono);font-weight:500">Dept</th>
                <th style="text-align:left;padding:8px 10px;color:var(--text-muted);font-size:11px;font-family:var(--mono);font-weight:500">Severity</th>
                <th style="text-align:left;padding:8px 10px;color:var(--text-muted);font-size:11px;font-family:var(--mono);font-weight:500">Status</th>
                <th style="text-align:left;padding:8px 10px;color:var(--text-muted);font-size:11px;font-family:var(--mono);font-weight:500">Opened</th>
                <th style="text-align:left;padding:8px 10px;color:var(--text-muted);font-size:11px;font-family:var(--mono);font-weight:500">Notes Preview</th>
              </tr>
            </thead>
            <tbody id="invTableBody">
              <tr><td colspan="7" style="text-align:center;padding:40px;color:var(--text-muted)">No investigation cases yet</td></tr>
            </tbody>
          </table>
        </div>
        <!-- Case detail panel -->
        <div id="invPanel" style="width:320px;flex-shrink:0;background:var(--card);border:1px solid var(--border);border-radius:var(--r-lg);padding:16px;overflow-y:auto;display:none">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">
            <div style="font-family:var(--mono);font-size:13px;font-weight:600" id="invPanelTitle">Case Detail</div>
            <button onclick="document.getElementById('invPanel').style.display='none'" style="background:transparent;border:none;cursor:pointer;color:var(--text-secondary);font-size:16px">✕</button>
          </div>
          <div id="invPanelBody"></div>
        </div>
      </div>
    </section>
```

- [ ] **Step 3: Add Investigations JS**

Find the `showSection` function in the dashboard JS (around line 709). Add `if(name==='Investigations')loadInvestigations();` to it:

```javascript
  if(name==='Investigations')loadInvestigations();
```

Then add the Investigations JS block after the existing `closeModal` function (after line 1050):

```javascript
// ══════════════════════════════════════════════════════
//  INVESTIGATIONS
// ══════════════════════════════════════════════════════
function loadInvestigations(){
  const base=document.getElementById('apiUrl').value.trim()||window.location.origin;
  const status=document.getElementById('invFilterStatus')?.value||'';
  fetch(base+'/api/investigations?status='+encodeURIComponent(status)+'&limit=100')
    .then(r=>r.json()).then(data=>{
      const tbody=document.getElementById('invTableBody');
      if(!tbody)return;
      // Update badge
      const badge=document.getElementById('invBadge');
      if(badge){
        const openCount=data.open_count||0;
        badge.textContent=openCount>99?'99+':openCount;
        badge.style.display=openCount?'':'none';
      }
      if(!data.cases||!data.cases.length){
        tbody.innerHTML='<tr><td colspan="7" style="text-align:center;padding:40px;color:var(--text-muted)">No investigation cases</td></tr>';
        return;
      }
      const statusColors={open:'var(--blue)',confirmed_threat:'var(--red)',false_positive:'var(--green)',under_investigation:'var(--amber)',closed:'var(--text-muted)'};
      tbody.innerHTML=data.cases.map(c=>`
        <tr onclick="openInvPanel('${c.case_id}')" style="border-bottom:1px solid var(--border-subtle);cursor:pointer" onmouseover="this.style.background='var(--card-hover)'" onmouseout="this.style.background=''">
          <td style="padding:8px 10px;font-family:var(--mono);font-size:11px;color:var(--text-muted)">${c.case_id}</td>
          <td style="padding:8px 10px;font-family:var(--mono)">${c.user_id||'—'}</td>
          <td style="padding:8px 10px">${c.department||'—'}</td>
          <td style="padding:8px 10px"><span class="badge badge-${c.severity||'normal'}">${(c.severity||'—').replace('_',' ')}</span></td>
          <td style="padding:8px 10px"><span style="color:${statusColors[c.status]||'var(--text-secondary)'}; font-size:11px;font-family:var(--mono)">${(c.status||'open').replace(/_/g,' ')}</span></td>
          <td style="padding:8px 10px;font-size:11px;color:var(--text-muted)">${(c.created_at||'').slice(0,16)}</td>
          <td style="padding:8px 10px;font-size:11px;color:var(--text-secondary);max-width:120px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${c.analyst_notes||'—'}</td>
        </tr>`).join('');
    }).catch(e=>console.error('Investigations load error:',e));
}

function openInvPanel(caseId){
  const base=document.getElementById('apiUrl').value.trim()||window.location.origin;
  fetch(base+'/api/investigations/'+caseId)
    .then(r=>r.json()).then(c=>{
      document.getElementById('invPanel').style.display='block';
      document.getElementById('invPanelTitle').textContent='Case: '+c.case_id;
      document.getElementById('invPanelBody').innerHTML=`
        <div style="display:flex;flex-direction:column;gap:8px">
          <div class="pipe-row"><span class="pipe-label">User</span><span class="pipe-val mono">${c.user_id||'—'}</span></div>
          <div class="pipe-row"><span class="pipe-label">Department</span><span class="pipe-val">${c.department||'—'}</span></div>
          <div class="pipe-row"><span class="pipe-label">Alert ID</span><span class="pipe-val mono" style="font-size:10px">${c.alert_id||'—'}</span></div>
          <div class="pipe-row"><span class="pipe-label">Opened</span><span class="pipe-val" style="font-size:11px">${(c.created_at||'').slice(0,16)}</span></div>
          <div style="margin-top:8px">
            <label style="font-size:11px;color:var(--text-muted);font-family:var(--mono)">STATUS</label>
            <select id="invPanelStatus" onchange="_saveInvPanel('${c.case_id}')"
              style="width:100%;margin-top:4px;background:var(--card);border:1px solid var(--border);border-radius:var(--r-sm);padding:6px 8px;color:var(--text);font-size:12px;font-family:var(--mono)">
              ${['open','under_investigation','confirmed_threat','false_positive','closed'].map(s=>`<option value="${s}"${c.status===s?' selected':''}>${s.replace(/_/g,' ')}</option>`).join('')}
            </select>
          </div>
          <div style="margin-top:8px">
            <label style="font-size:11px;color:var(--text-muted);font-family:var(--mono)">ANALYST NOTES</label>
            <textarea id="invPanelNotes" onblur="_saveInvPanel('${c.case_id}')"
              style="width:100%;margin-top:4px;background:var(--card);border:1px solid var(--border);border-radius:var(--r-sm);padding:8px;color:var(--text);font-size:12px;font-family:var(--mono);resize:vertical;min-height:80px"
              placeholder="Add analyst notes…">${c.analyst_notes||''}</textarea>
          </div>
        </div>`;
    }).catch(e=>console.error('Case load error:',e));
}

function _saveInvPanel(caseId){
  const base=document.getElementById('apiUrl').value.trim()||window.location.origin;
  const status=document.getElementById('invPanelStatus')?.value||'';
  const notes=document.getElementById('invPanelNotes')?.value??null;
  fetch(base+'/api/investigations/'+caseId,{
    method:'PATCH',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify({status,analyst_notes:notes})
  }).then(()=>loadInvestigations()).catch(()=>{});
}

function openCaseFromAlert(alertId, userId, dept, severity){
  const base=document.getElementById('apiUrl').value.trim()||window.location.origin;
  fetch(base+'/api/investigations',{
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify({alert_id:alertId,user_id:userId,department:dept,severity:severity})
  }).then(r=>r.json()).then(data=>{
    if(data.case_id){
      showSection('Investigations');
      loadInvestigations();
    }
  }).catch(()=>{});
}
```

- [ ] **Step 4: Add "Open Case" button to alert rows and log rows**

In `addAlertRow(d)` function, find where the alert row HTML template ends (the closing backtick before `feed.insertBefore`). Add an "Open Case" button at the end of the card HTML, just before the closing `</div>` of the alert row:

```javascript
<button onclick="openCaseFromAlert('${d.alert_id||''}','${d.user_id||''}','${d.department||''}','${d.severity||'normal'}');event.stopPropagation()"
  style="margin-top:6px;background:var(--blue-d);border:1px solid rgba(88,166,255,.3);border-radius:var(--r-sm);padding:3px 10px;font-size:10px;color:var(--blue);cursor:pointer;font-family:var(--mono)">
  Open Case
</button>
```

- [ ] **Step 5: Add Escalation config card to Configuration section**

Find the Configuration section in the HTML (`id="sectionConfig"`). After the last existing config card closing `</div>`, before the section's closing `</div></section>`, add:

```html
          <!-- Escalation config -->
          <div class="card" style="margin-top:16px">
            <div class="card-hdr"><h3>Alert Escalation</h3><span style="font-size:11px;color:var(--text-muted)">Gmail SMTP / email alerts</span></div>
            <div class="card-body" style="display:flex;flex-direction:column;gap:10px;padding:16px" id="escalationCfgBody">
              <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px">
                <div><label class="fl">SMTP User (Gmail)</label><input class="fi" id="escSmtpUser" type="email" placeholder="you@gmail.com"></div>
                <div><label class="fl">App Password</label><input class="fi" id="escSmtpPass" type="password" placeholder="Gmail app password"></div>
                <div><label class="fl">Recipient Email</label><input class="fi" id="escRecipient" type="email" placeholder="analyst@company.com"></div>
                <div><label class="fl">Min Severity</label>
                  <select class="fi" id="escMinSev" style="cursor:pointer">
                    <option value="suspicious">Suspicious</option>
                    <option value="high_risk">High Risk</option>
                    <option value="critical" selected>Critical</option>
                  </select>
                </div>
              </div>
              <div style="display:flex;align-items:center;gap:10px">
                <label style="display:flex;align-items:center;gap:8px;cursor:pointer;font-size:12px;font-family:var(--mono)">
                  <input type="checkbox" id="escEnabled" style="width:14px;height:14px">
                  Enable email escalation
                </label>
              </div>
              <div style="display:flex;gap:8px">
                <button onclick="saveEscalationConfig()" style="background:var(--blue);border:none;border-radius:var(--r);padding:8px 16px;color:#fff;font-size:12px;font-family:var(--mono);cursor:pointer">Save Config</button>
                <button onclick="testEscalation()" style="background:var(--card);border:1px solid var(--border);border-radius:var(--r);padding:8px 16px;color:var(--text);font-size:12px;font-family:var(--mono);cursor:pointer">Send Test Email</button>
              </div>
              <div id="escStatus" style="font-size:11px;font-family:var(--mono);color:var(--text-muted)"></div>
              <!-- Escalation log -->
              <div style="margin-top:8px">
                <div style="font-size:11px;color:var(--text-muted);font-family:var(--mono);margin-bottom:6px">Recent escalation emails</div>
                <div id="escLogTable" style="font-size:11px;font-family:var(--mono)">
                  <div style="color:var(--text-muted);padding:10px 0">No escalations sent yet</div>
                </div>
              </div>
            </div>
          </div>
```

- [ ] **Step 6: Add Escalation JS**

After the `loadInvestigations` / `openInvPanel` / `_saveInvPanel` / `openCaseFromAlert` functions, add:

```javascript
// ══════════════════════════════════════════════════════
//  ESCALATION CONFIG
// ══════════════════════════════════════════════════════
function loadEscalationConfig(){
  const base=document.getElementById('apiUrl').value.trim()||window.location.origin;
  fetch(base+'/api/escalation/config').then(r=>r.json()).then(cfg=>{
    document.getElementById('escSmtpUser').value=cfg.smtp_user||'';
    document.getElementById('escRecipient').value=cfg.recipient_email||'';
    document.getElementById('escEnabled').checked=!!cfg.enabled;
    document.getElementById('escMinSev').value=cfg.min_severity||'critical';
    loadEscalationLog();
  }).catch(()=>{});
}

function saveEscalationConfig(){
  const base=document.getElementById('apiUrl').value.trim()||window.location.origin;
  const body={
    enabled: document.getElementById('escEnabled').checked,
    smtp_user: document.getElementById('escSmtpUser').value.trim(),
    smtp_password: document.getElementById('escSmtpPass').value,
    recipient_email: document.getElementById('escRecipient').value.trim(),
    min_severity: document.getElementById('escMinSev').value,
    smtp_host:'smtp.gmail.com', smtp_port:465
  };
  fetch(base+'/api/escalation/config',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)})
    .then(r=>r.json()).then(()=>{
      document.getElementById('escStatus').textContent='Config saved ✓';
      document.getElementById('escStatus').style.color='var(--green)';
      setTimeout(()=>{document.getElementById('escStatus').textContent='';},3000);
    }).catch(()=>{});
}

function testEscalation(){
  const base=document.getElementById('apiUrl').value.trim()||window.location.origin;
  document.getElementById('escStatus').textContent='Sending test email…';
  document.getElementById('escStatus').style.color='var(--text-muted)';
  fetch(base+'/api/escalation/test',{method:'POST'})
    .then(r=>r.json()).then(r=>{
      document.getElementById('escStatus').textContent=r.status==='sent'?'Test email sent ✓':(r.error||r.status);
      document.getElementById('escStatus').style.color=r.status==='sent'?'var(--green)':'var(--red)';
      loadEscalationLog();
    }).catch(()=>{});
}

function loadEscalationLog(){
  const base=document.getElementById('apiUrl').value.trim()||window.location.origin;
  fetch(base+'/api/escalation/log?limit=20').then(r=>r.json()).then(data=>{
    const el=document.getElementById('escLogTable');
    if(!el)return;
    if(!data.entries||!data.entries.length){
      el.innerHTML='<div style="color:var(--text-muted);padding:10px 0">No escalations sent yet</div>';
      return;
    }
    el.innerHTML='<table style="width:100%;border-collapse:collapse">'
      +'<tr style="border-bottom:1px solid var(--border)">'
      +'<th style="text-align:left;padding:4px 6px;color:var(--text-muted);font-weight:500">Time</th>'
      +'<th style="text-align:left;padding:4px 6px;color:var(--text-muted);font-weight:500">User</th>'
      +'<th style="text-align:left;padding:4px 6px;color:var(--text-muted);font-weight:500">Score</th>'
      +'<th style="text-align:left;padding:4px 6px;color:var(--text-muted);font-weight:500">Recipient</th>'
      +'<th style="text-align:left;padding:4px 6px;color:var(--text-muted);font-weight:500">Status</th></tr>'
      +data.entries.map(e=>`<tr style="border-bottom:1px solid var(--border-subtle)">
        <td style="padding:4px 6px;color:var(--text-muted)">${(e.sent_at||'').slice(11,19)}</td>
        <td style="padding:4px 6px">${e.user_id||'—'}</td>
        <td style="padding:4px 6px">${e.risk_score||0}</td>
        <td style="padding:4px 6px;font-size:10px;color:var(--text-muted)">${e.sent_to||'—'}</td>
        <td style="padding:4px 6px;color:${e.status==='sent'?'var(--green)':'var(--red)'}">${e.status||'—'}</td>
      </tr>`).join('')+'</table>';
  }).catch(()=>{});
}
```

Also update the `showSection` function to load escalation config when Config section opens. Find `if(name==='Config')loadConfig();` and change it to:

```javascript
  if(name==='Config'){loadConfig();loadEscalationConfig();}
```

- [ ] **Step 7: Verify visually**

Open the dashboard. Navigate to Investigations. The case table should be empty. Trigger a high/critical event:
```bash
curl -s "http://localhost:5000/api/events/simulate?type=critical" | python3 -m json.tool
```

In the Live Activity feed, the new alert row should have an "Open Case" button. Click it. The Investigations section should open with 1 case. Click the case row to open the slide-in panel. Change the status to "confirmed_threat". The table should update after blur.

Navigate to Configuration, scroll to Alert Escalation. The card should show the fields and "Send Test Email" button.

- [ ] **Step 8: Commit**

```bash
cd /Users/emilysheraphia/Downloads/insightguard
git add application/dashboard.html
git commit -m "feat: add Investigations section and Escalation config card to dashboard"
```

---

## Self-Review Checklist

**Spec coverage:**
- [x] `investigations` DB table (case_id, alert_id, user_id, department, severity, status, analyst_notes, timestamps) → Task 1
- [x] `escalation_log` DB table → Task 1
- [x] CRUD: `create_investigation`, `list_investigations`, `get_investigation`, `update_investigation` → Task 1
- [x] `EscalationEngine` class with `start()`, `enqueue()`, `_send_email()`, `_log_escalation()` → Task 2
- [x] `storage/escalation_config.json` default config → Task 2
- [x] `escalation.enqueue()` called from `_process_event()` → Task 3
- [x] `POST /api/investigations` → Task 3
- [x] `GET /api/investigations` → Task 3
- [x] `GET /api/investigations/<id>` → Task 3
- [x] `PATCH /api/investigations/<id>` → Task 3
- [x] `GET /api/escalation/config` → Task 3
- [x] `PUT /api/escalation/config` → Task 3
- [x] `POST /api/escalation/test` → Task 3
- [x] `GET /api/escalation/log` → Task 3
- [x] Investigations sidebar nav item with open case count badge → Task 4
- [x] Case table (case_id, user, dept, severity badge, status, opened, notes preview) → Task 4
- [x] "Open Case" button on alert rows → Task 4
- [x] Slide-in panel with status dropdown + analyst notes textarea (auto-saves on blur) → Task 4
- [x] Configuration section escalation card (enable toggle, SMTP, recipient, min severity, save + test buttons) → Task 4
- [x] Escalation log table last 20 entries → Task 4
- [x] Status values: open / confirmed_threat / false_positive / under_investigation / closed → Task 1 + Task 4

**Placeholders:** None found.

**Type consistency:** `update_investigation(case_id, status, analyst_notes)` — used consistently in DB and API. `EscalationEngine.update_config(dict)` — used consistently in route + tests.
