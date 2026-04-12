# Enhanced Endpoint Agent Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add process monitoring, clipboard monitoring, server-driven working hours, file sensitivity classification, and USB sensitivity summary to the Nexon endpoint agent.

**Architecture:** Three new standalone modules (`process_monitor.py`, `clipboard_monitor.py`, `config_sync.py`) live in `nexon_agent/` and follow the same daemon-thread pattern as existing monitors. `agent.py` imports and starts them. Server-side adds `working_hours` to `role_config.json`; dashboard adds a Working Hours config card.

**Tech Stack:** Python 3.10+, psutil (process listing), pyperclip (clipboard), fnmatch (glob patterns), Flask (server unchanged), SQLite (storage unchanged).

---

## File Map

| File | Action | Responsibility |
|---|---|---|
| `nexon_agent/config_sync.py` | Create | Polls `/api/config` every 5 min, exposes `get_working_hours()` and `is_off_hours()` |
| `nexon_agent/process_monitor.py` | Create | Polls `psutil.process_iter()` every 2 s; sends process/file events |
| `nexon_agent/clipboard_monitor.py` | Create | Polls clipboard every 3 s; detects volume + sensitive patterns |
| `nexon_agent/agent.py` | Modify | Add `_classify_sensitivity()`, update `_is_sensitive()`, wire new monitors, USB sensitivity summary |
| `nexon_agent/config.json` | Modify | Add `sensitivity_rules` and `working_hours` fallback |
| `nexon_agent/requirements.txt` | Modify | Add `pyperclip` |
| `storage/role_config.json` | Modify | Add `"working_hours": {"start": 8, "end": 18}` |
| `application/dashboard.html` | Modify | Add Working Hours card to Config section |
| `tests/test_all.py` | Modify | Add `test_agent_modules()` |

---

## Task 1: File sensitivity classification

**Files:**
- Modify: `nexon_agent/agent.py`
- Modify: `nexon_agent/config.json`
- Test: `tests/test_all.py`

- [ ] **Step 1: Write the failing test**

Add this function to `tests/test_all.py` (before the `if __name__ == "__main__":` block):

```python
def test_agent_modules():
    section("Agent Modules — Sensitivity + Process + Clipboard")
    import sys as _sys
    _sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "nexon_agent"))

    # ── Sensitivity classification ──
    from agent import _classify_sensitivity

    cfg = {
        "sensitivity_rules": {
            "critical":     ["*salary*", "*password*"],
            "confidential": ["*invoice*", "*contract*"],
            "internal":     ["*report*"],
            "public":       ["*readme*"],
        },
        "sensitive_extensions": [".csv"],
    }

    assert _classify_sensitivity("salary_2024.csv", cfg) == "critical",    "salary → critical"
    assert _classify_sensitivity("Invoice_Q1.pdf", cfg)  == "confidential","invoice → confidential"
    assert _classify_sensitivity("weekly_report.docx", cfg) == "internal", "report → internal"
    assert _classify_sensitivity("README.md", cfg)       == "public",      "readme → public"
    assert _classify_sensitivity("notes.txt", cfg)       == "internal",    "no match → internal default"
    ok("_classify_sensitivity: all 5 cases pass")

    return True
```

Also add `"AgentModules": test_agent_modules()` to the `results` dict in `main`.

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /Users/emilysheraphia/Downloads/insightguard
python tests/test_all.py 2>&1 | tail -20
```

Expected: FAIL — `ImportError: cannot import name '_classify_sensitivity' from 'agent'`

- [ ] **Step 3: Add `_classify_sensitivity` and update `_is_sensitive` in `agent.py`**

Add this function immediately after the existing `_is_sensitive` function (around line 278 in `nexon_agent/agent.py`). Also add `import fnmatch` at the top of the file with the other stdlib imports.

```python
import fnmatch
```

```python
def _classify_sensitivity(filename: str, cfg: dict) -> str:
    """Return 'critical' | 'confidential' | 'internal' | 'public'."""
    rules = cfg.get("sensitivity_rules", {})
    name = Path(filename).name.lower()
    for level in ("critical", "confidential", "internal", "public"):
        for pattern in rules.get(level, []):
            if fnmatch.fnmatch(name, pattern.lower()):
                return level
    return "internal"  # safe default — unknown files treated as internal
```

Replace the existing `_is_sensitive` function:

```python
def _is_sensitive(filename: str, cfg: dict) -> bool:
    sensitivity = _classify_sensitivity(filename, cfg)
    if sensitivity in ("critical", "confidential"):
        return True
    ext = Path(filename).suffix.lower()
    return ext in cfg.get("sensitive_extensions", [])
```

- [ ] **Step 4: Add `sensitivity` field to `_RecentFilesHandler._fire()` payload**

Find the payload block in `_RecentFilesHandler._fire()` (around line 434) and update it:

```python
        sensitivity = _classify_sensitivity(opened_name, self._cfg)
        sensitive = _is_sensitive(opened_name, self._cfg)
        payload = _base(self._cfg, "dlp_system")
        payload.update({
            "source":      "file",
            "file_path":   opened_name,
            "file_name":   opened_name,
            "operation":   "read",
            "file_count":  1,
            "data_mb":     0.01,
            "destination": "local",
            "sensitive":   sensitive,
            "sensitivity": sensitivity,
        })
```

- [ ] **Step 5: Add `sensitivity` field to `_FileEventHandler._handle()` payload**

Find the payload block in `_FileEventHandler._handle()` (around line 322) and update it:

```python
        size_mb = _file_size_mb(path)
        sensitivity = _classify_sensitivity(path, self._cfg)
        sensitive = _is_sensitive(path, self._cfg)
        fname = Path(path).name
        payload = _base(self._cfg, "dlp_system")
        payload.update({
            "source":      "file",
            "file_path":   path,
            "file_name":   fname,
            "operation":   operation,
            "file_count":  1,
            "data_mb":     size_mb,
            "destination": "local",
            "sensitive":   sensitive,
            "sensitivity": sensitivity,
        })
```

- [ ] **Step 6: Update `config.json` with `sensitivity_rules`**

Add this block to `nexon_agent/config.json` after the `"sensitive_extensions"` array:

```json
    "sensitivity_rules": {
        "critical":     ["*salary*", "*payroll*", "*password*", "*credentials*", "*masterkey*", "*backup*", "*private_key*"],
        "confidential": ["*invoice*", "*contract*", "*financial*", "*hr_data*", "*personal*", "*confidential*"],
        "internal":     ["*report*", "*project*", "*internal*", "*draft*", "*memo*"],
        "public":       ["*readme*", "*license*", "*changelog*"]
    }
```

- [ ] **Step 7: Run tests to verify pass**

```bash
cd /Users/emilysheraphia/Downloads/insightguard
python tests/test_all.py 2>&1 | tail -20
```

Expected: `[PASS] AgentModules` and all previous tests still pass.

- [ ] **Step 8: Commit**

```bash
git add nexon_agent/agent.py nexon_agent/config.json tests/test_all.py
git commit -m "feat: add file sensitivity classification to endpoint agent"
```

---

## Task 2: ConfigSync module

**Files:**
- Create: `nexon_agent/config_sync.py`
- Test: `tests/test_all.py`

- [ ] **Step 1: Write the failing test**

Extend `test_agent_modules()` in `tests/test_all.py` — add these assertions after the sensitivity block (before `return True`):

```python
    # ── ConfigSync fallback ──
    import config_sync

    # Reset module cache to known state
    with config_sync._lock:
        config_sync._cache["working_hours"] = {"start": 8, "end": 18}

    start, end = config_sync.get_working_hours()
    assert start == 8 and end == 18, f"Expected (8,18), got ({start},{end})"
    ok("ConfigSync.get_working_hours: returns default (8, 18)")

    config_sync._init_cache({"working_hours": {"start": 9, "end": 17}})
    start, end = config_sync.get_working_hours()
    assert start == 9 and end == 17, f"Expected (9,17), got ({start},{end})"
    ok("ConfigSync._init_cache: applies local fallback override")

    config_sync._do_fetch("http://localhost:1")   # unreachable — should not crash
    start, end = config_sync.get_working_hours()
    assert start == 9 and end == 17, "Cache unchanged after failed fetch"
    ok("ConfigSync._do_fetch: unreachable server leaves cache intact")
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /Users/emilysheraphia/Downloads/insightguard
python tests/test_all.py 2>&1 | grep "AgentModules\|ImportError\|ModuleNotFound"
```

Expected: FAIL — `ModuleNotFoundError: No module named 'config_sync'`

- [ ] **Step 3: Create `nexon_agent/config_sync.py`**

```python
"""
ConfigSync — polls GET /api/config every 5 minutes and caches
working_hours so all agent monitors can call is_off_hours() without
making HTTP calls themselves.

Public API
----------
start(server_url, local_fallback)  — start background polling thread
get_working_hours() -> (int, int)  — returns (start_hour, end_hour)
is_off_hours() -> bool             — True if current hour is outside window
_init_cache(local_fallback)        — exposed for testing
_do_fetch(server_url)              — exposed for testing
"""

import datetime
import threading
import time

import requests

_lock: threading.Lock = threading.Lock()
_cache: dict = {"working_hours": {"start": 8, "end": 18}}


def _init_cache(local_fallback: dict) -> None:
    """Seed the cache from config.json values before the first server fetch."""
    wh = local_fallback.get("working_hours", {"start": 8, "end": 18})
    with _lock:
        _cache["working_hours"] = {
            "start": int(wh.get("start", 8)),
            "end":   int(wh.get("end", 18)),
        }


def _do_fetch(server_url: str) -> None:
    """Fetch /api/config and update cache. Silently ignores errors."""
    try:
        resp = requests.get(
            server_url.rstrip("/") + "/api/config",
            timeout=5,
        )
        if resp.status_code == 200:
            data = resp.json()
            wh = data.get("working_hours", {})
            if "start" in wh and "end" in wh:
                with _lock:
                    _cache["working_hours"] = {
                        "start": int(wh["start"]),
                        "end":   int(wh["end"]),
                    }
    except Exception:
        pass   # keep last known value


def _poll_loop(server_url: str) -> None:
    while True:
        time.sleep(300)   # 5 minutes
        _do_fetch(server_url)


def start(server_url: str, local_fallback: dict) -> None:
    """Seed cache, do one immediate fetch, then start background thread."""
    _init_cache(local_fallback)
    _do_fetch(server_url)   # best-effort on startup
    t = threading.Thread(
        target=_poll_loop,
        args=(server_url,),
        daemon=True,
        name="config-sync",
    )
    t.start()


def get_working_hours() -> tuple[int, int]:
    """Return (start_hour, end_hour) as 24-hour integers."""
    with _lock:
        wh = _cache["working_hours"]
        return wh["start"], wh["end"]


def is_off_hours() -> bool:
    """Return True if the current local hour is outside working hours."""
    start, end = get_working_hours()
    hour = datetime.datetime.now().hour
    return hour < start or hour >= end
```

- [ ] **Step 4: Run tests to verify pass**

```bash
cd /Users/emilysheraphia/Downloads/insightguard
python tests/test_all.py 2>&1 | tail -20
```

Expected: `[PASS] AgentModules` with 6 assertions passing.

- [ ] **Step 5: Wire ConfigSync into `agent.py`**

Add the import near the top of `nexon_agent/agent.py` (after the existing imports):

```python
import config_sync
```

In the `main()` function, after `cfg = load_config()` and before `sender = threading.Thread(...)`, add:

```python
    # Start config sync (working hours from server)
    config_sync.start(cfg["server_url"], cfg)
    _add_log(f"{G}[CONFIG SYNC]{RST} Working hours synced from server")
```

Also update `_check_threat_patterns` to use `config_sync.is_off_hours()` instead of the hardcoded `hour < 8 or hour >= 18`:

Replace:
```python
    hour = datetime.datetime.now().hour
    is_off_hours = hour < 8 or hour >= 18
```

With:
```python
    is_off_hours = config_sync.is_off_hours()
```

Also update `config.json` to add the fallback working_hours:

```json
    "working_hours": {"start": 8, "end": 18}
```

(Add this anywhere in the JSON object, e.g. after `"usb_poll_interval_seconds": 5`.)

- [ ] **Step 6: Commit**

```bash
git add nexon_agent/config_sync.py nexon_agent/agent.py nexon_agent/config.json tests/test_all.py
git commit -m "feat: add ConfigSync module for server-driven working hours"
```

---

## Task 3: Working hours on server and dashboard

**Files:**
- Modify: `storage/role_config.json`
- Modify: `application/dashboard.html`

- [ ] **Step 1: Add `working_hours` to `storage/role_config.json`**

Open `storage/role_config.json`. Add this field immediately after the `"_comment"` line (before `"global"`):

```json
  "working_hours": {"start": 8, "end": 18},
```

The file should begin:
```json
{
  "_comment": "...",
  "working_hours": {"start": 8, "end": 18},
  "global": {
```

- [ ] **Step 2: Verify `GET /api/config` returns the new field**

Start the server if not running:
```bash
cd /Users/emilysheraphia/Downloads/insightguard
python application/app.py &
sleep 2
curl -s http://localhost:5000/api/config | python3 -c "import sys,json; d=json.load(sys.stdin); print('working_hours:', d.get('working_hours'))"
```

Expected: `working_hours: {'start': 8, 'end': 18}`

Kill the background server with `kill %1` after verifying.

- [ ] **Step 3: Add Working Hours HTML card to `dashboard.html`**

In `application/dashboard.html`, find the block that ends with:
```html
        <div style="font-size:12px;color:var(--text-secondary);padding:0 2px;line-height:1.6">
          <strong>How thresholds work:</strong>
```

Insert this new card block **immediately after** the closing `</div>` of that "How thresholds work" div (before the `<!-- Escalation config -->` comment):

```html
        <!-- Working Hours -->
        <div class="card">
          <div class="card-hdr">
            <h3>Working Hours</h3>
            <span style="font-size:11px;color:var(--text-muted)">endpoint agent uses these for off-hours detection (24h clock)</span>
          </div>
          <div class="card-body" style="display:flex;align-items:center;gap:20px;padding:14px 16px">
            <div>
              <div style="font-size:11px;color:var(--text-muted);margin-bottom:6px">Start Hour</div>
              <input class="config-input" id="whStart" type="number" min="0" max="23" value="8" style="width:70px">
            </div>
            <div>
              <div style="font-size:11px;color:var(--text-muted);margin-bottom:6px">End Hour</div>
              <input class="config-input" id="whEnd" type="number" min="0" max="23" value="18" style="width:70px">
            </div>
            <div style="font-size:11px;color:var(--text-secondary);align-self:flex-end;padding-bottom:8px">
              Events outside this window are flagged as off-hours activity
            </div>
          </div>
        </div>
```

- [ ] **Step 4: Update `renderConfig()` in `dashboard.html`**

Find `function renderConfig(cfg){` in `dashboard.html`. After the three lines that set `thSuspicious`, `thHighRisk`, `thCritical`, add:

```javascript
  const wh = cfg.working_hours || {};
  document.getElementById('whStart').value = wh.start ?? 8;
  document.getElementById('whEnd').value   = wh.end   ?? 18;
```

- [ ] **Step 5: Update `saveConfig()` in `dashboard.html`**

Find `function saveConfig(){` in `dashboard.html`. After the block that sets `_rawConfig.global.severity_thresholds` (and before the `document.querySelectorAll('#configBody input[data-role]')` line), add:

```javascript
  // Read working hours
  _rawConfig.working_hours = {
    start: parseInt(document.getElementById('whStart').value) ?? 8,
    end:   parseInt(document.getElementById('whEnd').value)   ?? 18,
  };
```

- [ ] **Step 6: Manual verify**

Start the server (`python application/app.py`), open the dashboard, navigate to Configuration. Confirm the Working Hours card appears with Start=8 / End=18. Change to Start=9 / End=17, click Save Config, then Reload — values should persist.

- [ ] **Step 7: Commit**

```bash
git add storage/role_config.json application/dashboard.html
git commit -m "feat: add configurable working hours to server config and dashboard"
```

---

## Task 4: ProcessMonitor module

**Files:**
- Create: `nexon_agent/process_monitor.py`
- Modify: `nexon_agent/agent.py`
- Test: `tests/test_all.py`

- [ ] **Step 1: Write the failing test**

Extend `test_agent_modules()` — add these assertions before `return True`:

```python
    # ── ProcessMonitor command classification ──
    from process_monitor import _classify_cmd, _extract_file_path

    assert _classify_cmd("wevtutil cl System")                  == ("log_clear",      "critical"),   "wevtutil cl"
    assert _classify_cmd("taskkill /f /pid 1234")               == ("process_kill",   "critical"),   "taskkill /f"
    assert _classify_cmd("del C:\\Users\\john\\salary.csv")     == ("file",           "suspicious"), "del"
    assert _classify_cmd("move file.txt C:\\backup\\file.txt")  == ("file",           "suspicious"), "move"
    assert _classify_cmd("copy C:\\src\\a.txt C:\\dst\\a.txt")  == ("file",           "suspicious"), "copy"
    assert _classify_cmd("mkdir C:\\Users\\john\\NewFolder")    == ("file",           "normal"),     "mkdir"
    assert _classify_cmd("powershell.exe -NoProfile")           == ("process_launch", "normal"),     "plain launch"
    ok("_classify_cmd: all 7 command patterns correct")

    fpath = _extract_file_path("del C:\\Users\\john\\salary.csv")
    assert fpath == "C:\\Users\\john\\salary.csv", f"got: {fpath}"
    ok("_extract_file_path: extracts path from del command")
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /Users/emilysheraphia/Downloads/insightguard
python tests/test_all.py 2>&1 | grep "AgentModules\|ImportError\|ModuleNotFound"
```

Expected: FAIL — `ModuleNotFoundError: No module named 'process_monitor'`

- [ ] **Step 3: Create `nexon_agent/process_monitor.py`**

```python
"""
ProcessMonitor — tracks CMD/PowerShell/script launches on Windows.

Sends events:
  - process_launch  (normal)   for any terminal/script process first seen
  - process_kill    (critical)  for taskkill /f or tskill
  - log_clear       (critical)  for wevtutil cl / Clear-EventLog
  - file operation  (suspicious/normal) for del/move/copy/rename/mkdir/rd
"""

import datetime
import re
import threading
import time
from pathlib import Path

import psutil

import config_sync

# ── Process name targets ──────────────────────────────────────────────────────
_TARGET_NAMES = frozenset([
    "cmd.exe", "powershell.exe", "pwsh.exe",
    "wscript.exe", "cscript.exe",
])
_SCRIPT_EXTS = frozenset([".ps1", ".bat", ".vbs", ".cmd"])

# ── File operation patterns ───────────────────────────────────────────────────
_FILE_OPS: dict[str, re.Pattern] = {
    "command_delete": re.compile(r'\b(del|rm|erase)\b',       re.IGNORECASE),
    "command_move":   re.compile(r'\b(move|mv|rename|ren)\b', re.IGNORECASE),
    "command_copy":   re.compile(r'\b(copy|xcopy|robocopy)\b',re.IGNORECASE),
    "command_dir":    re.compile(r'\b(mkdir|md|rd|rmdir)\b',  re.IGNORECASE),
}


# ── Pure functions (tested) ───────────────────────────────────────────────────

def _classify_cmd(cmdline_str: str) -> tuple[str, str]:
    """Return (event_type, severity_override) for a command string."""
    cl = cmdline_str.lower()

    if "wevtutil" in cl and " cl" in cl:
        return "log_clear", "critical"
    if "clear-eventlog" in cl:
        return "log_clear", "critical"
    if "taskkill" in cl and "/f" in cl:
        return "process_kill", "critical"
    if "tskill" in cl:
        return "process_kill", "critical"

    for op, pattern in _FILE_OPS.items():
        if pattern.search(cmdline_str):
            severity = "normal" if op == "command_dir" else "suspicious"
            return "file", severity

    return "process_launch", "normal"


def _extract_file_path(cmdline_str: str) -> str:
    """Best-effort: return last token that looks like a file path."""
    tokens = cmdline_str.split()
    for token in reversed(tokens[1:]):
        t = token.strip('"\'')
        if "\\" in t or "/" in t or (len(t) > 2 and t[1] == ":"):
            return t
    return ""


def _is_target(proc_name: str, cmdline: list[str]) -> bool:
    if proc_name.lower() in _TARGET_NAMES:
        return True
    for arg in cmdline:
        if Path(arg).suffix.lower() in _SCRIPT_EXTS:
            return True
    return False


def _make_base(cfg: dict, source: str) -> dict:
    return {
        "user_id":    cfg["user_id"],
        "timestamp":  datetime.datetime.utcnow().isoformat() + "Z",
        "source":     source,
        "department": cfg["department"],
        "role":       cfg["role"],
        "device_id":  cfg["device_id"],
    }


# ── ProcessMonitor class ──────────────────────────────────────────────────────

class ProcessMonitor:
    def __init__(self, cfg: dict, enqueue_fn, add_log_fn):
        self._cfg     = cfg
        self._enqueue = enqueue_fn
        self._log     = add_log_fn
        self._seen: set[int] = set()
        self._thread  = threading.Thread(
            target=self._run, daemon=True, name="process-monitor"
        )

    def start(self):
        self._thread.start()
        self._log("\033[92m[PROCESS MONITOR]\033[0m Started (polling every 2s)")

    def _run(self):
        while True:
            time.sleep(2)
            self._poll()

    def _poll(self):
        try:
            current_pids: set[int] = set()
            for proc in psutil.process_iter(["pid", "name", "cmdline"]):
                try:
                    pid     = proc.info["pid"]
                    name    = proc.info["name"] or ""
                    cmdline = proc.info["cmdline"] or []
                    current_pids.add(pid)
                    if pid in self._seen:
                        continue
                    if not _is_target(name, cmdline):
                        continue
                    self._seen.add(pid)
                    self._handle(pid, name, cmdline)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            # Prune dead PIDs to prevent unbounded set growth
            self._seen &= current_pids
        except Exception as e:
            self._log(f"\033[91m[PROCESS MONITOR]\033[0m Poll error: {e}")

    def _handle(self, pid: int, name: str, cmdline: list[str]):
        cmdline_str = " ".join(cmdline)[:500]
        event_type, severity = _classify_cmd(cmdline_str)

        payload = _make_base(self._cfg, "endpoint_agent")
        payload["process_name"] = name
        payload["command_line"] = cmdline_str
        payload["pid"]          = pid
        payload["off_hours"]    = config_sync.is_off_hours()

        if event_type == "file":
            op    = next((o for o, p in _FILE_OPS.items() if p.search(cmdline_str)), "command_file")
            fpath = _extract_file_path(cmdline_str)
            payload.update({
                "source":            "file",
                "activity_type":     "file",
                "operation":         op,
                "file_path":         fpath,
                "file_name":         Path(fpath).name if fpath else "",
                "file_count":        1,
                "data_mb":           0,
                "destination":       "local",
                "severity_override": severity,
            })
        else:
            payload.update({
                "source":            "endpoint_agent",
                "activity_type":     event_type,
                "severity_override": severity,
            })

        self._enqueue(payload)

        colours = {"critical": "\033[91m", "suspicious": "\033[93m", "normal": "\033[2m"}
        c   = colours.get(severity, "")
        RST = "\033[0m"
        self._log(f"{c}[PROCESS]{RST} {event_type.upper()} — {name} (PID {pid}): {cmdline_str[:80]}")
```

- [ ] **Step 4: Run tests to verify pass**

```bash
cd /Users/emilysheraphia/Downloads/insightguard
python tests/test_all.py 2>&1 | tail -20
```

Expected: `[PASS] AgentModules` with all 9 assertions passing.

- [ ] **Step 5: Wire ProcessMonitor into `agent.py`**

Add the import near the top of `nexon_agent/agent.py` (after `import config_sync`):

```python
from process_monitor import ProcessMonitor
```

In the `main()` function, after `browser_mon.start()`, add:

```python
    # Start process monitor
    proc_mon = ProcessMonitor(cfg, enqueue_event, _add_log)
    proc_mon.start()
```

- [ ] **Step 6: Commit**

```bash
git add nexon_agent/process_monitor.py nexon_agent/agent.py tests/test_all.py
git commit -m "feat: add ProcessMonitor for CMD/PowerShell/script tracking"
```

---

## Task 5: ClipboardMonitor module

**Files:**
- Create: `nexon_agent/clipboard_monitor.py`
- Modify: `nexon_agent/requirements.txt`
- Modify: `nexon_agent/agent.py`
- Test: `tests/test_all.py`

- [ ] **Step 1: Write the failing test**

Extend `test_agent_modules()` — add these assertions before `return True`:

```python
    # ── ClipboardMonitor pattern detection ──
    from clipboard_monitor import ClipboardMonitor

    events_fired = []
    cm = ClipboardMonitor(
        cfg={"user_id": "test", "department": "IT", "role": "Analyst",
             "device_id": "TEST-01"},
        enqueue_fn=lambda p: events_fired.append(p),
        add_log_fn=lambda _: None,
    )

    # Volume trigger
    cm._check("A" * 600)
    assert events_fired and events_fired[-1]["pattern_matched"] == "volume", "volume trigger"
    ok("ClipboardMonitor: volume (>500 chars) triggers event")

    # Credential pattern
    events_fired.clear()
    cm._last_hash = ""   # reset dedup
    cm._check("db_password=hunter2 host=prod.db.internal")
    assert events_fired and events_fired[-1]["pattern_matched"] == "credential_pattern", "credential pattern"
    ok("ClipboardMonitor: credential_pattern triggers event")

    # API key pattern
    events_fired.clear()
    cm._last_hash = ""
    cm._check("api_key=sk-abc123xyz987")
    assert events_fired and events_fired[-1]["pattern_matched"] == "api_key_pattern", "api key"
    ok("ClipboardMonitor: api_key_pattern triggers event")

    # Email list
    events_fired.clear()
    cm._last_hash = ""
    cm._check("alice@corp.com\nbob@corp.com\ncharlie@corp.com")
    assert events_fired and events_fired[-1]["pattern_matched"] == "email_list", "email list"
    ok("ClipboardMonitor: email_list (3+ emails) triggers event")

    # Deduplication — same content within 60 s should not re-fire
    events_fired.clear()
    # (last_hash is now set from the email_list check — same text)
    cm._check("alice@corp.com\nbob@corp.com\ncharlie@corp.com")
    assert len(events_fired) == 0, "dedup failed — same content fired twice"
    ok("ClipboardMonitor: dedup suppresses same content within 60 s")

    # Content preview truncated to 80 chars
    events_fired.clear()
    cm._last_hash = ""
    long_text = "password=x " + "B" * 200
    cm._check(long_text)
    assert len(events_fired[-1]["content_preview"]) <= 80, "preview not truncated"
    ok("ClipboardMonitor: content_preview truncated to 80 chars")
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /Users/emilysheraphia/Downloads/insightguard
python tests/test_all.py 2>&1 | grep "AgentModules\|ModuleNotFound\|ImportError"
```

Expected: FAIL — `ModuleNotFoundError: No module named 'clipboard_monitor'`

- [ ] **Step 3: Create `nexon_agent/clipboard_monitor.py`**

```python
"""
ClipboardMonitor — detects suspicious clipboard content on Windows.

Fires an event when clipboard text exceeds 500 characters (bulk copy)
or matches a sensitive data pattern (credentials, API keys, card numbers,
bulk email lists). Deduplicates by content hash within a 60-second window
so persistent clipboard content does not produce repeated events.

Requires: pyperclip  (pip install pyperclip)
"""

import datetime
import hashlib
import re
import threading
import time


# ── Detection patterns ────────────────────────────────────────────────────────
_PATTERNS: dict[str, re.Pattern] = {
    "credential_pattern": re.compile(r'(?i)password\s*[=:]\s*\S+'),
    "api_key_pattern":    re.compile(r'(?i)api[_\-]?key\s*[=:]\s*\S+'),
    "card_number":        re.compile(r'\b[45][0-9]{15}\b'),
    "email_list":         re.compile(r'\S+@\S+\.\S+'),
}
_VOLUME_THRESHOLD = 500
_EMAIL_LIST_MIN   = 3
_DEDUP_SECONDS    = 60


def _make_base(cfg: dict, source: str) -> dict:
    return {
        "user_id":    cfg["user_id"],
        "timestamp":  datetime.datetime.utcnow().isoformat() + "Z",
        "source":     source,
        "department": cfg["department"],
        "role":       cfg["role"],
        "device_id":  cfg["device_id"],
    }


class ClipboardMonitor:
    def __init__(self, cfg: dict, enqueue_fn, add_log_fn):
        self._cfg          = cfg
        self._enqueue      = enqueue_fn
        self._log          = add_log_fn
        self._last_hash:  str   = ""
        self._last_hash_time: float = 0.0
        self._thread       = threading.Thread(
            target=self._run, daemon=True, name="clipboard-monitor"
        )

    def start(self):
        self._thread.start()
        self._log("\033[92m[CLIPBOARD MONITOR]\033[0m Started (polling every 3s)")

    def _run(self):
        try:
            import pyperclip
        except ImportError:
            self._log(
                "\033[93m[CLIPBOARD MONITOR]\033[0m "
                "pyperclip not installed — clipboard monitoring disabled. "
                "Run: pip install pyperclip"
            )
            return

        while True:
            time.sleep(3)
            try:
                text = pyperclip.paste()
                if isinstance(text, str):
                    self._check(text)
            except Exception:
                pass

    def _check(self, text: str) -> None:
        """Check text for triggers. Exposed directly so tests can call it."""
        if not text:
            return

        # ── Deduplication ──
        h   = hashlib.sha256(text.encode()).hexdigest()
        now = time.time()
        if h == self._last_hash and (now - self._last_hash_time) < _DEDUP_SECONDS:
            return

        # ── Pattern matching ──
        pattern_matched: str | None = None

        if len(text) > _VOLUME_THRESHOLD:
            pattern_matched = "volume"
        else:
            for name, pat in _PATTERNS.items():
                if name == "email_list":
                    if len(pat.findall(text)) >= _EMAIL_LIST_MIN:
                        pattern_matched = name
                        break
                elif pat.search(text):
                    pattern_matched = name
                    break

        if not pattern_matched:
            return

        # ── Record and fire ──
        self._last_hash      = h
        self._last_hash_time = now

        payload = _make_base(self._cfg, "endpoint_agent")
        payload.update({
            "activity_type":   "clipboard",
            "char_count":      len(text),
            "pattern_matched": pattern_matched,
            "content_preview": text[:80],
        })
        self._enqueue(payload)

        R   = "\033[91m"
        RST = "\033[0m"
        self._log(f"{R}[CLIPBOARD]{RST} {pattern_matched} — {len(text)} chars copied")
```

- [ ] **Step 4: Add `pyperclip` to `nexon_agent/requirements.txt`**

Open `nexon_agent/requirements.txt`. Add `pyperclip` on its own line.

If the file does not exist, create it with:

```
requests
psutil
pywin32; sys_platform == "win32"
watchdog
pyperclip
```

- [ ] **Step 5: Run tests to verify pass**

```bash
cd /Users/emilysheraphia/Downloads/insightguard
python tests/test_all.py 2>&1 | tail -25
```

Expected: `[PASS] AgentModules` with all 15 assertions passing.

- [ ] **Step 6: Wire ClipboardMonitor into `agent.py`**

Add the import in `nexon_agent/agent.py` (after the ProcessMonitor import):

```python
from clipboard_monitor import ClipboardMonitor
```

In `main()`, after `proc_mon.start()`, add:

```python
    # Start clipboard monitor
    clip_mon = ClipboardMonitor(cfg, enqueue_event, _add_log)
    clip_mon.start()
```

- [ ] **Step 7: Commit**

```bash
git add nexon_agent/clipboard_monitor.py nexon_agent/requirements.txt nexon_agent/agent.py tests/test_all.py
git commit -m "feat: add ClipboardMonitor for credential and bulk-copy detection"
```

---

## Task 6: USB sensitivity summary

**Files:**
- Modify: `nexon_agent/agent.py`
- Test: `tests/test_all.py`

- [ ] **Step 1: Write the failing test**

Extend `test_agent_modules()` — add these assertions before `return True`:

```python
    # ── USB sensitivity summary ──
    # Test that _classify_sensitivity builds a correct summary dict
    files = ["salary_2024.csv", "invoice_q1.pdf", "notes.txt", "password_list.txt"]
    cfg_usb = {
        "sensitivity_rules": {
            "critical":     ["*salary*", "*password*"],
            "confidential": ["*invoice*"],
            "internal":     [],
            "public":       [],
        },
        "sensitive_extensions": [],
    }
    summary: dict[str, int] = {}
    for f in files:
        from agent import _classify_sensitivity as cs
        level = cs(f, cfg_usb)
        summary[level] = summary.get(level, 0) + 1

    assert summary.get("critical", 0)     == 2, f"critical count: {summary}"
    assert summary.get("confidential", 0) == 1, f"confidential count: {summary}"
    assert summary.get("internal", 0)     == 1, f"internal count (notes.txt): {summary}"
    ok("USB sensitivity_summary: correct per-level counts")
```

- [ ] **Step 2: Run test to verify it passes already**

(This test uses `_classify_sensitivity` from Task 1 — it should already pass.)

```bash
cd /Users/emilysheraphia/Downloads/insightguard
python tests/test_all.py 2>&1 | grep "sensitivity_summary\|AgentModules"
```

Expected: `[PASS] AgentModules`

- [ ] **Step 3: Update `USBMonitor._check_transfers()` in `agent.py`**

Find the `_check_transfers` method in `USBMonitor`. Replace the existing `if transferred_files:` block with:

```python
        if transferred_files:
            fnames = [os.path.basename(f) for f in transferred_files[:20]]

            # Build per-sensitivity-level counts
            sensitivity_summary: dict[str, int] = {}
            for fname in fnames:
                level = _classify_sensitivity(fname, self._cfg)
                sensitivity_summary[level] = sensitivity_summary.get(level, 0) + 1

            payload = _base(self._cfg, "endpoint_agent")
            payload.update({
                "source":               "usb",
                "device_id":            drive,
                "operation":            "file_transfer",
                "data_mb":              round(total_mb, 3),
                "usb_data_mb":          round(total_mb, 3),
                "usb_transfer":         True,
                "file_count":           len(transferred_files),
                "files":                fnames,
                "file_name":            ", ".join(fnames[:5]),
                "file_path":            ", ".join(fnames[:5]),
                "sensitivity_summary":  sensitivity_summary,
            })
            enqueue_event(payload)
            for f in fnames:
                _record_behaviour("usb_transfer", sensitive=_is_sensitive(f, self._cfg), path=f)
            _check_threat_patterns(self._cfg)
            _add_log(
                f"{R}[USB TRANSFER]{RST} {len(transferred_files)} file(s) → {drive} "
                f"({total_mb:.2f} MB): {', '.join(fnames[:3])}"
            )
```

- [ ] **Step 4: Run full test suite**

```bash
cd /Users/emilysheraphia/Downloads/insightguard
python tests/test_all.py
```

Expected: All tests pass including `[PASS] AgentModules`.

- [ ] **Step 5: Commit**

```bash
git add nexon_agent/agent.py tests/test_all.py
git commit -m "feat: add sensitivity_summary to USB file transfer events"
```

---

## Self-Review Checklist

**Spec coverage:**
- [x] File sensitivity classification — Tasks 1 + 6
- [x] ConfigSync / working hours (agent side) — Task 2
- [x] Working hours server + dashboard — Task 3
- [x] ProcessMonitor — Task 4
- [x] ClipboardMonitor — Task 5
- [x] USB sensitivity summary — Task 6
- [x] `pyperclip` added to requirements — Task 5 Step 4
- [x] `config.json` `sensitivity_rules` and `working_hours` — Task 1 Step 6 + Task 2 Step 5
- [x] `PUT /api/config` merge-safe (dashboard reads full config before saving) — Task 3 Step 5

**Type consistency:**
- `_classify_sensitivity(filename, cfg) -> str` defined in Task 1, used in Tasks 1, 4, 6 ✓
- `_classify_cmd(cmdline_str) -> tuple[str,str]` defined in Task 4, tested in Task 4 ✓
- `config_sync.is_off_hours() -> bool` defined in Task 2, used in Task 4 ✓
- `ClipboardMonitor._check(text)` public method, tested in Task 5 ✓
- `sensitivity_summary: dict[str, int]` built in Task 6 ✓
