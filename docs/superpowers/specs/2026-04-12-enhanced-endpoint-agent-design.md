# Enhanced Endpoint Agent — Design Spec

## Goal

Extend the Nexon Technologies Windows endpoint agent with five new capabilities:
process monitoring, clipboard monitoring, configurable working hours (server-driven),
file sensitivity classification, and improved USB filename reporting.

## Architecture

Three new modules are added to `nexon_agent/`. Each follows the same pattern as the
existing `USBMonitor` and `BrowserMonitor`: a class with a `start()` method that
spins up a daemon thread. `agent.py` imports and starts them alongside the existing
monitors.

```
nexon_agent/
  process_monitor.py     NEW  — ProcessMonitor class
  clipboard_monitor.py   NEW  — ClipboardMonitor class
  config_sync.py         NEW  — ConfigSync class + get_working_hours()
  agent.py               MOD  — import new monitors, add _classify_sensitivity(), USB filenames
  config.json            MOD  — add sensitivity_rules section

application/
  app.py                 MOD  — add working_hours to config GET/PUT
  dashboard.html         MOD  — Working Hours inputs in Configuration section
storage/
  role_config.json       MOD  — add "working_hours": {"start": 8, "end": 18}
```

---

## Module 1 — ProcessMonitor (`process_monitor.py`)

### Behaviour

Polls `psutil.process_iter(['pid', 'name', 'cmdline', 'create_time'])` every 2 seconds.
Maintains a `_seen_pids: set[int]` so each process is logged exactly once on first
appearance. Cleans up dead PIDs from the set on every poll.

### Target processes

Monitors any process whose name matches (case-insensitive):
`cmd.exe`, `powershell.exe`, `pwsh.exe`, `wscript.exe`, `cscript.exe`, and any
process launching a file with extension `.ps1`, `.bat`, `.vbs`, `.cmd`.

### Classification rules (applied in order)

| Rule | Match | Event type | `severity_override` |
|---|---|---|---|
| Log clear | `wevtutil cl` or `Clear-EventLog` in cmdline | `log_clear` | `critical` |
| Process kill | `taskkill` + `/f` flag, or `tskill` in cmdline | `process_kill` | `critical` |
| File delete | `del `, `rm `, `erase ` in cmdline | `file` op=`command_delete` | `suspicious` |
| File move | `move `, `mv `, `rename `, `ren ` in cmdline | `file` op=`command_move` | `suspicious` |
| File copy | `copy `, `xcopy `, `robocopy ` in cmdline | `file` op=`command_copy` | `suspicious` |
| Directory op | `mkdir `, `md `, `rd `, `rmdir ` in cmdline | `file` op=`command_dir` | `normal` |
| Default | Any other matched process | `process_launch` | `normal` |

### Event payload

```json
{
  "source": "endpoint_agent",
  "activity_type": "process",
  "process_name": "powershell.exe",
  "command_line": "powershell.exe -c del C:\\Users\\john\\salary.csv",
  "pid": 4821,
  "file_path": "C:\\Users\\john\\salary.csv",
  "operation": "command_delete",
  "severity_override": "suspicious"
}
```

`file_path` is extracted by taking the last token of the command line that looks
like a path (contains `\\`, `/`, or a drive letter). `command_line` is truncated
to 500 characters. `file_path` is omitted for non-file events.

### Off-hours boost

If `get_working_hours()` indicates the event is outside working hours, appends
`"off_hours": true` to the payload so the UEBA engine can apply its weight.

---

## Module 2 — ClipboardMonitor (`clipboard_monitor.py`)

### Behaviour

Polls the clipboard every 3 seconds using `pyperclip.paste()`. On Windows with no
display server issues this is reliable; non-text clipboard contents (images, files)
return an empty string and are silently skipped.

### Trigger conditions (OR logic — any one is enough)

| Condition | Description |
|---|---|
| Volume | `len(text) > 500` |
| Credential pattern | `(?i)password\s*[=:]\s*\S+` |
| API key pattern | `(?i)api[_-]?key\s*[=:]\s*\S+` |
| Card number | `\b4[0-9]{15}\b` or `\b5[0-9]{15}\b` |
| Email list | 3 or more distinct `\S+@\S+\.\S+` matches |

### Deduplication

SHA-256 of the full clipboard text is stored. If the same hash is seen within
60 seconds the event is suppressed. This prevents repeated firing while unchanged
text remains on the clipboard.

### Event payload

```json
{
  "source": "endpoint_agent",
  "activity_type": "clipboard",
  "char_count": 1240,
  "pattern_matched": "credential_pattern",
  "content_preview": "password=hunter2 db_host=prod-db..."
}
```

`content_preview` is the first 80 characters only. The full clipboard text is
never sent to the server.

---

## Module 3 — ConfigSync (`config_sync.py`)

### Behaviour

Polls `GET /api/config` on the InsightGuard server every 5 minutes in a daemon
thread. Parses `working_hours.start` and `working_hours.end` (integers 0–23) from
the response and stores them in a thread-safe module-level cache.

### Public API

```python
def start(server_url: str, local_fallback: dict) -> None: ...
def get_working_hours() -> tuple[int, int]: ...   # returns (start, end)
def is_off_hours() -> bool: ...
```

`start()` launches the background thread and performs one immediate fetch so
working hours are available before the first event is sent.

### Fallback chain

1. Server response (authoritative)
2. Last successful server response (in-memory cache)
3. `config.json` field `working_hours.start` / `working_hours.end`
4. Hard default: `(8, 18)`

---

## File Sensitivity Classification (in `agent.py`)

### Config structure (added to `config.json`)

```json
"sensitivity_rules": {
  "critical":     ["*salary*", "*payroll*", "*password*", "*credentials*", "*backup*", "*masterkey*"],
  "confidential": ["*invoice*", "*contract*", "*financial*", "*hr_data*", "*personal*"],
  "internal":     ["*report*", "*project*", "*internal*", "*draft*"],
  "public":       []
}
```

Patterns use `fnmatch` glob syntax. Matching is against the lowercase filename only
(not the full path). Rules are evaluated in order: critical → confidential →
internal → public. If nothing matches, returns `"internal"` as a safe default.

### Function signature

```python
def _classify_sensitivity(filename: str, cfg: dict) -> str:
    """Return 'critical' | 'confidential' | 'internal' | 'public'."""
```

### Integration points

- `_RecentFilesHandler._fire()` — adds `sensitivity` field to payload
- `_FileEventHandler._handle()` — replaces boolean `sensitive` with `sensitivity` string
- `USBMonitor._check_transfers()` — adds `sensitivity` to per-file record
- `_is_sensitive()` — updated to return `True` if sensitivity is `confidential` or `critical`

---

## Server Changes

### `storage/role_config.json`

Add top-level field:
```json
"working_hours": {"start": 8, "end": 18}
```

### `application/app.py`

`GET /api/config` and `PUT /api/config` already read/write the full
`role_config.json` — no route logic changes needed, just the new field in the file.

**Important:** `PUT /api/config` replaces the entire config object. The dashboard
save handler must: (1) fetch `GET /api/config`, (2) set `config.working_hours`,
(3) `PUT` the full merged object back. Sending only `{"working_hours": ...}` would
erase all role thresholds.

### `application/dashboard.html` — Configuration section

Add a "Working Hours" card below the existing Role Config card:

```
Working Hours (24h)
  Start: [8]   End: [18]   [Save]
```

Save handler fetches current config, merges `working_hours`, then calls
`PUT /api/config` with the full merged object.
Inputs are `type="number" min="0" max="23"`.

---

## USB Filename Improvements

`USBMonitor._check_transfers()` already collects `fnames` (list of basenames).
Add `sensitivity` classification per file using `_classify_sensitivity()`, and
include a `sensitivity_summary` field in the payload:

```json
{
  "files": ["salary_backup.csv", "notes.txt"],
  "sensitivity_summary": {"critical": 1, "internal": 1}
}
```

---

## Dependencies

| Package | Already in requirements? | Used by |
|---|---|---|
| `psutil` | yes | ProcessMonitor |
| `pyperclip` | no — add to `nexon_agent/requirements.txt` | ClipboardMonitor |
| `requests` | yes | ConfigSync |
| `fnmatch` | stdlib | sensitivity classification |

`pyperclip` must be added to `nexon_agent/requirements.txt` and `nexon_agent/setup.bat`.

---

## Out of Scope

- Screenshot capture (Sub-project 4)
- Browser file upload detection (Sub-project 3)
- Incognito detection (Sub-project 3)
- Resend email integration (Sub-project 5)
