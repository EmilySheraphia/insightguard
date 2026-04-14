# Browser Intelligence (Sub-project 3) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `BrowserIntelligenceMonitor` to the Windows endpoint agent that detects incognito sessions (psutil), captures file upload filenames (Chrome DevTools Protocol), and tracks webmail activity with subject lines (CDP title polling) — plus three new UEBA EXTRA_RULES that score these signals.

**Architecture:** Server-side: three new entries appended to `UEBAEngine.EXTRA_RULES` (`incognito_session`, `file_upload_cloud`, `webmail_outbound`) read from the raw event dict via the existing `extra` param. Agent-side: `BrowserIntelligenceMonitor` runs two threads — a psutil poller (incognito detection + webmail title polling via CDP `/json` HTTP) and an asyncio thread (CDP WebSocket for Network.requestWillBeSent upload events). All events POST to `/api/events` via the existing `enqueue_event()` queue.

**Tech Stack:** Python 3.10+, psutil (already installed), websockets>=12.0 (new), asyncio (stdlib), Chrome DevTools Protocol over WebSocket at localhost:9222

---

## File Map

| File | Change |
|------|--------|
| `ai_analytics/anomaly_model.py` | Add `_CLOUD_UPLOAD_DOMAINS` constant + 3 new EXTRA_RULES entries |
| `tests/test_all.py` | Add `test_browser_intelligence()` (9 assertions) + wire into `main()` |
| `nexon_agent/agent.py` | Add `import re` to imports; add constants, `_parse_upload_filename()`, `_parse_webmail_title()`, `BrowserIntelligenceMonitor` class; wire into `main()` |
| `nexon_agent/requirements.txt` | Add `websockets>=12.0` |

---

### Task 1: UEBA Browser Intelligence Rules + Tests

**Files:**
- Modify: `ai_analytics/anomaly_model.py` — add constant + 3 EXTRA_RULES entries
- Modify: `tests/test_all.py` — add test function + wire into `main()`

- [ ] **Step 1: Write the failing test**

In `tests/test_all.py`, insert this function immediately before the `# ─── Main ───` comment at the bottom of the file:

```python
# ─── Browser Intelligence ─────────────────────────────────────────────────

def test_browser_intelligence():
    section("Browser Intelligence — UEBA rules (incognito_session, file_upload_cloud, webmail_outbound)")
    from ai_analytics.anomaly_model import UEBAEngine
    from feature_engineering.extractor import FeatureVector

    ueba = UEBAEngine()
    base = {k: 0 for k in FeatureVector.COLUMNS}
    fv   = FeatureVector(**base)

    # incognito_session fires
    _, triggered = ueba.score(fv, extra={"incognito": True})
    assert "incognito_session" in triggered, f"incognito_session not triggered: {triggered}"
    ok("incognito_session: fires when incognito=True")

    # incognito_session does NOT fire when False
    _, triggered = ueba.score(fv, extra={"incognito": False})
    assert "incognito_session" not in triggered, "incognito_session should not fire when False"
    ok("incognito_session: does not fire when incognito=False")

    # file_upload_cloud fires for drive.google.com
    _, triggered = ueba.score(fv, extra={"activity_type": "file_upload",
                                          "destination": "drive.google.com"})
    assert "file_upload_cloud" in triggered, f"file_upload_cloud not triggered: {triggered}"
    ok("file_upload_cloud: fires for drive.google.com")

    # file_upload_cloud fires for dropbox.com
    _, triggered = ueba.score(fv, extra={"activity_type": "file_upload",
                                          "destination": "dropbox.com"})
    assert "file_upload_cloud" in triggered, f"file_upload_cloud not triggered: {triggered}"
    ok("file_upload_cloud: fires for dropbox.com")

    # file_upload_cloud does NOT fire for internal domain
    _, triggered = ueba.score(fv, extra={"activity_type": "file_upload",
                                          "destination": "internal-sharepoint.nexon.com"})
    assert "file_upload_cloud" not in triggered, "file_upload_cloud should not fire for internal domain"
    ok("file_upload_cloud: does not fire for internal domain")

    # webmail_outbound fires when compose_detected=True
    _, triggered = ueba.score(fv, extra={"activity_type": "webmail_activity",
                                          "compose_detected": True})
    assert "webmail_outbound" in triggered, f"webmail_outbound not triggered: {triggered}"
    ok("webmail_outbound: fires when compose_detected=True")

    # webmail_outbound does NOT fire when compose_detected=False
    _, triggered = ueba.score(fv, extra={"activity_type": "webmail_activity",
                                          "compose_detected": False})
    assert "webmail_outbound" not in triggered, "webmail_outbound should not fire when False"
    ok("webmail_outbound: does not fire when compose_detected=False")

    # webmail_outbound does NOT fire for wrong activity_type
    _, triggered = ueba.score(fv, extra={"activity_type": "web", "compose_detected": True})
    assert "webmail_outbound" not in triggered, "webmail_outbound should not fire for activity_type=web"
    ok("webmail_outbound: does not fire when activity_type != webmail_activity")

    # Combined: incognito + file_upload_cloud + off_hours_boost all trigger
    _, triggered = ueba.score(fv, extra={
        "incognito":     True,
        "activity_type": "file_upload",
        "destination":   "drive.google.com",
        "is_off_hours":  1,
    })
    assert "incognito_session" in triggered, "incognito_session missing from combined"
    assert "file_upload_cloud" in triggered, "file_upload_cloud missing from combined"
    assert "off_hours_boost"   in triggered, "off_hours_boost missing from combined"
    ok("combined: incognito_session + file_upload_cloud + off_hours_boost all trigger")

    print(f"\n  9/9 passed")
    return True
```

- [ ] **Step 2: Wire test into `main()`**

In `tests/test_all.py`, find the `results = {` dict in `main()` (around line 896). Add one entry at the end of the dict, before the closing `}`:

```python
        "Browser Intelligence":    test_browser_intelligence(),
```

The dict should end:
```python
        "UEBA New Rules":          test_ueba_new_rules(),
        "ETL Enrichment":          test_etl_enrichment(),
        "CorrelationEngine":       test_correlation_engine(),
        "Browser Intelligence":    test_browser_intelligence(),
    }
```

- [ ] **Step 3: Run test to verify it fails**

```bash
cd /Users/emilysheraphia/Downloads/insightguard && python tests/test_all.py 2>&1 | tail -30
```

Expected: `AssertionError` on `"incognito_session" not in triggered` — the rule doesn't exist yet.

- [ ] **Step 4: Add `_CLOUD_UPLOAD_DOMAINS` constant to `anomaly_model.py`**

In `ai_analytics/anomaly_model.py`, insert before the `class UEBAEngine:` line (around line 38):

```python
_CLOUD_UPLOAD_DOMAINS = frozenset({
    "drive.google.com", "onedrive.live.com", "onedrive.com",
    "dropbox.com", "wetransfer.com", "mega.nz", "s3.amazonaws.com",
})


```

- [ ] **Step 5: Append 3 entries to `UEBAEngine.EXTRA_RULES`**

In `ai_analytics/anomaly_model.py`, find the end of `EXTRA_RULES`. The current last entry is `"large_attachment_exfil"`. Change:

```python
        ("large_attachment_exfil", 22, lambda f, e: e.get("source") in ("email", "mail_gateway")
                                                    and e.get("direction") in ("outbound", "sent")
                                                    and float(e.get("attachment_mb", 0)) >= 10),
    ]
```

to:

```python
        ("large_attachment_exfil", 22, lambda f, e: e.get("source") in ("email", "mail_gateway")
                                                    and e.get("direction") in ("outbound", "sent")
                                                    and float(e.get("attachment_mb", 0)) >= 10),
        ("incognito_session",      20, lambda f, e: e.get("incognito") is True),
        ("file_upload_cloud",      25, lambda f, e: e.get("activity_type") == "file_upload"
                                                    and e.get("destination") in _CLOUD_UPLOAD_DOMAINS),
        ("webmail_outbound",       15, lambda f, e: e.get("activity_type") == "webmail_activity"
                                                    and e.get("compose_detected") is True),
    ]
```

- [ ] **Step 6: Run tests to verify they pass**

```bash
cd /Users/emilysheraphia/Downloads/insightguard && python tests/test_all.py 2>&1 | tail -35
```

Expected: All 16 sections pass including `[PASS] Browser Intelligence`.

- [ ] **Step 7: Commit**

```bash
cd /Users/emilysheraphia/Downloads/insightguard && git add ai_analytics/anomaly_model.py tests/test_all.py && git commit -m "$(cat <<'EOF'
feat: add browser intelligence UEBA rules (incognito_session, file_upload_cloud, webmail_outbound)

3 new EXTRA_RULES scoring browser_intel events from the agent.
9/9 test assertions passing.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

### Task 2: BrowserIntelligenceMonitor — Helper Functions + Class

**Files:**
- Modify: `nexon_agent/agent.py` — add `import re`; add module-level constants and two helper functions; add `BrowserIntelligenceMonitor` class

**Context:** This is Windows-only agent code. It runs on the employee's laptop and POSTs events to InsightGuard. The existing monitors (`BrowserMonitor`, `USBMonitor`, etc.) follow the same pattern: a class with a `start()` method that launches a daemon thread. `enqueue_event()`, `_base()`, `_add_log()`, `_stats` are all module-level and accessible here. The `BrowserMonitor` class ends around line 824 and the terminal status display section begins around line 826 — insert the new code between them.

- [ ] **Step 1: Add `import re` to top-level imports**

In `nexon_agent/agent.py`, find the existing imports block (lines 14–35). Add `import re` after `import ctypes`:

```python
import ctypes
import re
```

- [ ] **Step 2: Add constants and helper functions after `BrowserMonitor` class**

In `nexon_agent/agent.py`, find the line that reads:

```python
# ══════════════════════════════════════════════════════════════════════════════
# Terminal status display
```

Insert the following block immediately before it:

```python
# ══════════════════════════════════════════════════════════════════════════════
# Browser Intelligence Monitor — incognito, file uploads, webmail
# ══════════════════════════════════════════════════════════════════════════════

_INCOGNITO_FLAGS = {
    "chrome.exe":  "--incognito",
    "msedge.exe":  "--inprivate",
    "firefox.exe": ("-private", "--private-window"),
}

_WEBMAIL_PROVIDERS = {
    "mail.google.com":    ("gmail",   " - "),
    "mail.yahoo.com":     ("yahoo",   " - "),
    "outlook.live.com":   ("outlook", " - "),
    "outlook.office.com": ("outlook", " - "),
    "mail.proton.me":     ("proton",  " | "),
}

_COMPOSE_PATTERNS = ("#compose", "#sent", "/mail/compose", "/mail/sentitems", "/compose")

_UPLOAD_FILENAME_RE = re.compile(
    r'Content-Disposition\s*:\s*form-data[^;]*;\s*(?:[^;]*;\s*)?filename\s*=\s*"([^"]+)"',
    re.IGNORECASE,
)


def _parse_upload_filename(post_data: str) -> str | None:
    """Return filename from multipart/form-data postData string, or None if absent."""
    if not post_data:
        return None
    m = _UPLOAD_FILENAME_RE.search(post_data)
    return m.group(1) if m else None


def _parse_webmail_title(url: str, title: str) -> dict | None:
    """Return {"provider", "email_subject", "compose_detected"} if URL is a webmail tab, else None."""
    from urllib.parse import urlparse
    domain = urlparse(url).netloc.lower().lstrip("www.")
    for d, (provider, sep) in _WEBMAIL_PROVIDERS.items():
        if d in domain:
            subject = title.split(sep)[0].strip() if (title and sep in title) else ""
            return {
                "provider":         provider,
                "email_subject":    subject,
                "compose_detected": any(p in url for p in _COMPOSE_PATTERNS),
            }
    return None


class BrowserIntelligenceMonitor:
    """
    Two-thread browser intelligence monitor:
      - psutil thread: incognito detection every 5 s + webmail title polling via CDP /json
      - CDP thread:    asyncio WebSocket to localhost:9222, listens for Network.requestWillBeSent
                       to detect file uploads and extract filenames from multipart/form-data

    Requires Chrome/Edge launched with --remote-debugging-port=9222.
    If CDP is unavailable, the psutil thread still runs (incognito detection works independently).
    """

    CDP_PORT      = 9222
    POLL_INTERVAL = 5

    def __init__(self, cfg: dict):
        self._cfg              = cfg
        self._incognito_active = False
        self._last_titles: dict[str, str] = {}   # target_id → last seen title
        self._psutil_thread = threading.Thread(
            target=self._run_psutil, daemon=True, name="browser-intel-psutil"
        )
        self._cdp_thread = threading.Thread(
            target=self._run_cdp, daemon=True, name="browser-intel-cdp"
        )

    def start(self):
        self._psutil_thread.start()
        self._cdp_thread.start()
        _add_log(f"{G}[BROWSER INTEL]{RST} Started — incognito polling + CDP on :{self.CDP_PORT}")

    # ── psutil thread ─────────────────────────────────────────────────────────

    def _run_psutil(self):
        while True:
            time.sleep(self.POLL_INTERVAL)
            try:
                self._poll_incognito()
                self._poll_webmail_titles()
            except Exception as exc:
                _add_log(f"{DIM}[BROWSER INTEL]{RST} psutil error: {exc}")

    def _poll_incognito(self):
        found, browser_name = False, None
        try:
            for proc in psutil.process_iter(["name", "cmdline"]):
                name = (proc.info.get("name") or "").lower()
                flag = _INCOGNITO_FLAGS.get(name)
                if not flag:
                    continue
                cmdline_str = " ".join(proc.info.get("cmdline") or []).lower()
                match = (any(f in cmdline_str for f in flag)
                         if isinstance(flag, tuple) else flag in cmdline_str)
                if match:
                    found, browser_name = True, name.replace(".exe", "")
                    break
        except Exception:
            pass

        if found and not self._incognito_active:
            self._incognito_active = True
            payload = _base(self._cfg, "browser_intel")
            payload.update({"activity_type": "incognito_detected",
                            "browser": browser_name, "incognito": True})
            enqueue_event(payload)
            _stats["alerts"] += 1
            _add_log(f"{R}[INCOGNITO]{RST} {browser_name} private/incognito mode detected")
        elif not found:
            self._incognito_active = False

    def _poll_webmail_titles(self):
        import urllib.request
        try:
            with urllib.request.urlopen(
                f"http://localhost:{self.CDP_PORT}/json", timeout=1
            ) as resp:
                targets = json.loads(resp.read().decode())
        except Exception:
            return
        for target in targets:
            if target.get("type") != "page":
                continue
            tid   = target.get("id", "")
            url   = target.get("url", "")
            title = target.get("title", "")
            info  = _parse_webmail_title(url, title)
            if info is None or self._last_titles.get(tid) == title:
                continue
            self._last_titles[tid] = title
            payload = _base(self._cfg, "browser_intel")
            payload.update({
                "activity_type":    "webmail_activity",
                "email_provider":   info["provider"],
                "page_title":       title,
                "email_subject":    info["email_subject"],
                "compose_detected": info["compose_detected"],
                "incognito":        self._incognito_active,
            })
            enqueue_event(payload)
            _add_log(f"{M}[WEBMAIL]{RST} {info['provider']}: "
                     f"{info['email_subject'][:50] or title[:40]}")

    # ── CDP thread ────────────────────────────────────────────────────────────

    def _run_cdp(self):
        import asyncio
        asyncio.run(self._cdp_loop())

    async def _cdp_loop(self):
        import asyncio
        while True:
            try:
                await self._cdp_session()
            except Exception as exc:
                _add_log(f"{DIM}[CDP]{RST} {exc} — retry in 10 s")
            await asyncio.sleep(10)

    async def _cdp_session(self):
        import asyncio
        import urllib.request
        import websockets

        with urllib.request.urlopen(
            f"http://localhost:{self.CDP_PORT}/json", timeout=2
        ) as resp:
            targets = json.loads(resp.read().decode())

        pages = [t for t in targets
                 if t.get("type") == "page" and "webSocketDebuggerUrl" in t]
        if not pages:
            await asyncio.sleep(5)
            return

        async with websockets.connect(pages[0]["webSocketDebuggerUrl"]) as ws:
            await ws.send(json.dumps({"id": 1, "method": "Network.enable"}))
            _add_log(f"{G}[CDP]{RST} Connected — monitoring file uploads")
            async for raw in ws:
                msg = json.loads(raw)
                if msg.get("method") == "Network.requestWillBeSent":
                    self._handle_network_request(msg.get("params", {}))

    def _handle_network_request(self, params: dict):
        req     = params.get("request", {})
        headers = {k.lower(): v for k, v in (req.get("headers") or {}).items()}
        if "multipart/form-data" not in headers.get("content-type", ""):
            return
        from urllib.parse import urlparse
        url    = req.get("url", "")
        domain = urlparse(url).netloc.lower().lstrip("www.")
        fname  = _parse_upload_filename(req.get("postData", ""))
        payload = _base(self._cfg, "browser_intel")
        payload.update({
            "activity_type": "file_upload",
            "file_name":     fname,
            "destination":   domain,
            "url":           url,
            "incognito":     self._incognito_active,
        })
        enqueue_event(payload)
        _stats["alerts"] += 1
        _add_log(f"{R}[UPLOAD]{RST} {fname or '(unknown)'} → {domain}"
                 + (" [INCOGNITO]" if self._incognito_active else ""))

```

- [ ] **Step 3: Verify helpers parse correctly (quick inline check)**

```bash
cd /Users/emilysheraphia/Downloads/insightguard/nexon_agent && python -c "
import sys; sys.path.insert(0,'.')
from agent import _parse_upload_filename, _parse_webmail_title

# Upload filename extraction
post = 'Content-Disposition: form-data; name=\"file\"; filename=\"salary.csv\"\r\nContent-Type: text/csv'
assert _parse_upload_filename(post) == 'salary.csv', f'got {_parse_upload_filename(post)}'
assert _parse_upload_filename('') is None
print('_parse_upload_filename: OK')

# Webmail title parsing - Gmail
r = _parse_webmail_title('https://mail.google.com/mail/u/0/#compose', 'Q1 Budget - alice@nexon.com - Gmail')
assert r['provider'] == 'gmail'
assert r['email_subject'] == 'Q1 Budget'
assert r['compose_detected'] is True
print('_parse_webmail_title Gmail compose: OK')

# Webmail title parsing - non-webmail returns None
assert _parse_webmail_title('https://github.com', 'GitHub') is None
print('_parse_webmail_title non-webmail: OK')
print('All helper checks passed')
"
```

Expected output: `All helper checks passed`

- [ ] **Step 4: Run full test suite to confirm no regressions**

```bash
cd /Users/emilysheraphia/Downloads/insightguard && python tests/test_all.py 2>&1 | tail -25
```

Expected: All 16 sections PASS (test_all.py doesn't import the agent so no Windows dependency issues).

- [ ] **Step 5: Commit**

```bash
cd /Users/emilysheraphia/Downloads/insightguard && git add nexon_agent/agent.py && git commit -m "$(cat <<'EOF'
feat: add BrowserIntelligenceMonitor to nexon agent

psutil incognito detection, CDP file upload filename capture,
webmail title polling. Helpers: _parse_upload_filename,
_parse_webmail_title.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

### Task 3: Wire into main() + Add websockets Dependency

**Files:**
- Modify: `nexon_agent/agent.py` — instantiate `BrowserIntelligenceMonitor` in `main()`
- Modify: `nexon_agent/requirements.txt` — add `websockets>=12.0`

- [ ] **Step 1: Instantiate and start in `main()`**

In `nexon_agent/agent.py`, find these lines in `main()`:

```python
    # Start browser monitor
    browser_mon = BrowserMonitor(cfg)
    browser_mon.start()
```

Add immediately after:

```python
    # Start browser intelligence monitor (incognito + CDP upload/webmail)
    browser_intel = BrowserIntelligenceMonitor(cfg)
    browser_intel.start()
```

- [ ] **Step 2: Add websockets to requirements**

In `nexon_agent/requirements.txt`, append:

```
websockets>=12.0
```

The full file should now be:

```
requests>=2.31.0
watchdog>=3.0.0
psutil>=5.9.0
pywin32>=306; sys_platform == "win32"
pyperclip>=1.8.2
websockets>=12.0
```

- [ ] **Step 3: Run full test suite to confirm no regressions**

```bash
cd /Users/emilysheraphia/Downloads/insightguard && python tests/test_all.py 2>&1 | tail -25
```

Expected: All 16 sections PASS.

- [ ] **Step 4: Verify `websockets` installs (on the Windows agent machine)**

On the Windows laptop running the agent:

```bat
cd C:\NexonAgent
venv\Scripts\pip install websockets>=12.0
```

Expected: `Successfully installed websockets-X.X`

- [ ] **Step 5: Commit**

```bash
cd /Users/emilysheraphia/Downloads/insightguard && git add nexon_agent/agent.py nexon_agent/requirements.txt && git commit -m "$(cat <<'EOF'
feat: wire BrowserIntelligenceMonitor into agent main() + add websockets dep

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```
