"""
Nexon Technologies — Endpoint Monitoring Agent
Runs on the employee's Windows laptop. Sends all activity to InsightGuard
via POST /api/events in real time.

Monitored:
  - Login event (on agent start)
  - File operations (create, modify, move, delete) via watchdog
  - USB device insertion and file transfers to USB
  - Browser history (Chrome + Edge SQLite polling)
  - Blocked/suspicious site access flagging
"""

import json
import os
import platform
import queue
import fnmatch

import sqlite3
import sys
import threading
import time
import datetime
import socket
import ctypes
import re
from pathlib import Path

import requests
import psutil

import config_sync
from process_monitor import ProcessMonitor
from clipboard_monitor import ClipboardMonitor
from screenshot_capture import ScreenshotCapture

# ── watchdog import (file system monitoring) ─────────────────────────────────
try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False

# ── Windows-only imports ──────────────────────────────────────────────────────
WIN32_AVAILABLE = False
if platform.system() == "Windows":
    try:
        import win32api
        import win32con
        import win32file
        WIN32_AVAILABLE = True
    except ImportError:
        pass

# ── ANSI colour codes ─────────────────────────────────────────────────────────
R  = "\033[91m"   # red
Y  = "\033[93m"   # yellow
G  = "\033[92m"   # green
B  = "\033[94m"   # blue
M  = "\033[95m"   # magenta
C  = "\033[96m"   # cyan
W  = "\033[97m"   # white
DIM = "\033[2m"
RST = "\033[0m"
BOLD = "\033[1m"

# ── Enable ANSI on Windows ────────────────────────────────────────────────────
if platform.system() == "Windows":
    try:
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except Exception:
        pass


# ══════════════════════════════════════════════════════════════════════════════
# Config
# ══════════════════════════════════════════════════════════════════════════════

def load_config() -> dict:
    cfg_path = Path(__file__).parent / "config.json"
    if not cfg_path.exists():
        print(f"{R}[ERROR]{RST} config.json not found at {cfg_path}")
        sys.exit(1)
    with open(cfg_path, encoding="utf-8") as f:
        return json.load(f)


def expand_paths(paths: list[str]) -> list[Path]:
    result = []
    for p in paths:
        expanded = os.path.expandvars(p)
        result.append(Path(expanded))
    return result


# ══════════════════════════════════════════════════════════════════════════════
# Event queue and sender thread
# ══════════════════════════════════════════════════════════════════════════════

_event_queue: queue.Queue = queue.Queue()
_log_lines: list[str] = []
_log_lock = threading.Lock()
_stats = {"sent": 0, "errors": 0, "alerts": 0}
_screenshot: ScreenshotCapture | None = None

# ── Threat behaviour engine ───────────────────────────────────────────────────
# Tracks recent events in a rolling window to detect multi-step threat patterns.

_threat_lock = threading.Lock()
_recent_events: list[dict] = []   # {"ts": float, "type": str, "sensitive": bool, "path": str}
_WINDOW = 300   # 5-minute rolling window

def _record_behaviour(event_type: str, sensitive: bool = False, path: str = ""):
    now = time.time()
    with _threat_lock:
        _recent_events.append({"ts": now, "type": event_type, "sensitive": sensitive, "path": path})
        # Prune events older than window
        cutoff = now - _WINDOW
        while _recent_events and _recent_events[0]["ts"] < cutoff:
            _recent_events.pop(0)

def _check_threat_patterns(cfg: dict):
    """Analyse the rolling window and fire composite threat events if patterns match."""
    now = time.time()
    with _threat_lock:
        cutoff = now - _WINDOW
        window = [e for e in _recent_events if e["ts"] >= cutoff]

    sensitive_opens  = [e for e in window if e["type"] == "file_open"  and e["sensitive"]]
    file_writes      = [e for e in window if e["type"] == "file_write" and e["sensitive"]]
    usb_inserts      = [e for e in window if e["type"] == "usb_insert"]
    usb_transfers    = [e for e in window if e["type"] == "usb_transfer"]
    blocked_visits   = [e for e in window if e["type"] == "blocked_site"]
    is_off_hours = config_sync.is_off_hours()

    threats = []

    # Pattern 1: Bulk sensitive file opens (≥3 sensitive files in 5 min)
    if len(sensitive_opens) >= 3:
        threats.append({
            "threat_type":  "bulk_sensitive_access",
            "description":  f"{len(sensitive_opens)} sensitive files opened in 5 min",
            "file_count":   len(sensitive_opens),
            "files":        [e["path"] for e in sensitive_opens[-5:]],
            "severity_hint": "high_risk",
        })

    # Pattern 2: Off-hours sensitive file access
    if is_off_hours and sensitive_opens:
        threats.append({
            "threat_type":  "off_hours_sensitive_access",
            "description":  f"Sensitive file accessed outside working hours ({datetime.datetime.now().hour:02d}:xx)",
            "file_count":   len(sensitive_opens),
            "files":        [e["path"] for e in sensitive_opens[-3:]],
            "severity_hint": "suspicious",
        })

    # Pattern 3: Files opened then USB inserted within 5 min (staging → exfil)
    if usb_inserts and (sensitive_opens or file_writes):
        last_usb = usb_inserts[-1]["ts"]
        files_before_usb = [e for e in (sensitive_opens + file_writes) if e["ts"] < last_usb]
        if files_before_usb:
            threats.append({
                "threat_type":  "pre_usb_file_staging",
                "description":  f"{len(files_before_usb)} sensitive file(s) accessed before USB inserted",
                "file_count":   len(files_before_usb),
                "files":        [e["path"] for e in files_before_usb[-5:]],
                "severity_hint": "high_risk",
            })

    # Pattern 4: USB transfer + blocked site in same window (exfil + cover)
    if usb_transfers and blocked_visits:
        threats.append({
            "threat_type":  "usb_transfer_with_risky_browsing",
            "description":  "USB file transfer combined with blocked site access",
            "file_count":   len(usb_transfers),
            "files":        [e["path"] for e in usb_transfers[-3:]],
            "severity_hint": "critical",
        })

    # Pattern 5: Rapid file access (>8 files in 2 min — mass harvesting)
    two_min_files = [e for e in window if e["type"] in ("file_open","file_write") and e["ts"] >= now-120]
    if len(two_min_files) >= 8:
        threats.append({
            "threat_type":  "rapid_mass_file_access",
            "description":  f"{len(two_min_files)} files accessed in under 2 minutes",
            "file_count":   len(two_min_files),
            "files":        [e["path"] for e in two_min_files[-5:]],
            "severity_hint": "high_risk",
        })

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


def _add_log(line: str):
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    entry = f"{DIM}[{ts}]{RST} {line}"
    with _log_lock:
        _log_lines.append(entry)
        if len(_log_lines) > 200:
            _log_lines.pop(0)
    print(entry)


def enqueue_event(payload: dict):
    _event_queue.put(payload)


def _sender_thread(cfg: dict):
    url = cfg["server_url"].rstrip("/") + "/api/events"
    session = requests.Session()
    session.headers.update({"Content-Type": "application/json"})

    while True:
        try:
            payload = _event_queue.get(timeout=1)
        except queue.Empty:
            continue

        try:
            resp = session.post(url, json=payload, timeout=5)
            if resp.status_code == 200:
                _stats["sent"] += 1
                resp_data = resp.json()
                score = resp_data.get("risk_score", "?")
                _add_log(f"{G}[SENT]{RST} {payload.get('source','?')} → score {score}")
                if isinstance(score, (int, float)) and score >= 60 and _screenshot:
                    _screenshot.capture(
                        trigger_type="severity",
                        event_type=payload.get("activity_type", payload.get("source", "unknown")),
                        log_id=resp_data.get("log_id", ""),
                    )
            else:
                _stats["errors"] += 1
                _add_log(f"{Y}[WARN]{RST} Server returned {resp.status_code}")
        except requests.exceptions.ConnectionError:
            _stats["errors"] += 1
            _add_log(f"{R}[ERROR]{RST} Cannot reach InsightGuard at {cfg['server_url']}")
            # Re-queue so we don't lose the event
            _event_queue.put(payload)
            time.sleep(5)
        except Exception as e:
            _stats["errors"] += 1
            _add_log(f"{R}[ERROR]{RST} Sender: {e}")


# ══════════════════════════════════════════════════════════════════════════════
# Helper — build base event payload
# ══════════════════════════════════════════════════════════════════════════════

def _base(cfg: dict, source: str) -> dict:
    return {
        "user_id":    cfg["user_id"],
        "name":       cfg.get("name", ""),
        "timestamp":  datetime.datetime.utcnow().isoformat() + "Z",
        "source":     source,
        "department": cfg["department"],
        "role":       cfg["role"],
        "device_id":  cfg["device_id"],
    }


def _file_size_mb(path: str) -> float:
    try:
        return os.path.getsize(path) / 1_048_576
    except OSError:
        return 0.0


_AGENT_ARCHIVE_EXTS = {".zip", ".rar", ".7z", ".tar", ".gz", ".bz2"}


def _classify_sensitivity(filename: str, cfg: dict) -> str:
    """Return 'critical' | 'confidential' | 'internal' | 'public'."""
    rules = cfg.get("sensitivity_rules", {})
    name = Path(filename).name.lower()
    for level in ("critical", "confidential", "internal", "public"):
        for pattern in rules.get(level, []):
            if fnmatch.fnmatch(name, pattern.lower()):
                return level
    return "internal"  # safe default — unknown files treated as internal


def _is_sensitive(filename: str, cfg: dict) -> bool:
    sensitivity = _classify_sensitivity(filename, cfg)
    if sensitivity == "public":
        return False   # explicit public classification wins
    if sensitivity in ("critical", "confidential"):
        return True
    # "internal" or no rules match — fall back to extension list
    ext = Path(filename).suffix.lower()
    return ext in cfg.get("sensitive_extensions", [])


# ══════════════════════════════════════════════════════════════════════════════
# Login event
# ══════════════════════════════════════════════════════════════════════════════

def send_login_event(cfg: dict):
    payload = _base(cfg, "auth_system")
    payload.update({
        "event":          "login",
        "country_code":   "IE",
        "vpn":            False,
        "tor":            False,
        "new_device":     False,
        "failed_attempts": 0,
        "hostname":       socket.gethostname(),
        "ip_address":     socket.gethostbyname(socket.gethostname()),
    })
    enqueue_event(payload)
    _add_log(f"{B}[LOGIN]{RST} Agent started — login event queued for {cfg['user_id']}")


# ══════════════════════════════════════════════════════════════════════════════
# File monitoring (watchdog)
# ══════════════════════════════════════════════════════════════════════════════

class _FileEventHandler(FileSystemEventHandler):
    def __init__(self, cfg: dict):
        super().__init__()
        self._cfg = cfg
        self._debounce: dict[str, float] = {}

    def _handle(self, event, operation: str):
        if event.is_directory:
            return
        path = event.src_path
        now = time.time()
        # Debounce: same file within 2s → ignore
        if now - self._debounce.get(path, 0) < 2:
            return
        self._debounce[path] = now

        size_mb = _file_size_mb(path)
        sensitivity = _classify_sensitivity(path, self._cfg)
        sensitive   = sensitivity != "public" and (
                          sensitivity in ("critical", "confidential") or
                          Path(path).suffix.lower() in self._cfg.get("sensitive_extensions", [])
                      )
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
            "is_archive":  os.path.splitext(fname)[1].lower() in _AGENT_ARCHIVE_EXTS,
        })
        enqueue_event(payload)
        _record_behaviour("file_write", sensitive=sensitive, path=fname)
        _check_threat_patterns(self._cfg)

        colour = Y if sensitive else DIM
        _add_log(f"{colour}[FILE]{RST} {operation.upper()} {fname} ({size_mb:.2f} MB)")

    def on_created(self, event):
        self._handle(event, "write")

    def on_modified(self, event):
        self._handle(event, "write")

    def on_moved(self, event):
        # Treat moves as copy then delete
        if event.is_directory:
            return
        path = event.src_path
        dest = getattr(event, "dest_path", "unknown")
        dest_filename = os.path.basename(dest)
        size_mb = _file_size_mb(dest)
        sensitive = _is_sensitive(path, self._cfg)
        sensitivity = _classify_sensitivity(path, self._cfg)
        payload = _base(self._cfg, "dlp_system")
        payload.update({
            "source":      "file",
            "file_path":   path,
            "operation":   "copy",
            "file_count":  1,
            "data_mb":     size_mb,
            "destination": dest,
            "sensitive":   sensitive,
            "sensitivity": sensitivity,
            "is_archive":  os.path.splitext(dest_filename)[1].lower() in _AGENT_ARCHIVE_EXTS,
        })
        enqueue_event(payload)
        colour = Y if sensitive else DIM
        _add_log(f"{colour}[FILE]{RST} MOVE {Path(path).name} → {Path(dest).name}")

    def on_deleted(self, event):
        self._handle(event, "delete")


def start_file_monitor(cfg: dict) -> Observer | None:
    if not WATCHDOG_AVAILABLE:
        _add_log(f"{Y}[WARN]{RST} watchdog not installed — file monitoring disabled")
        return None

    paths = expand_paths(cfg.get("monitor_paths", []))
    observer = Observer()
    handler  = _FileEventHandler(cfg)
    watched  = 0
    for p in paths:
        if p.exists():
            observer.schedule(handler, str(p), recursive=True)
            watched += 1
            _add_log(f"{G}[FILE MONITOR]{RST} Watching {p}")
        else:
            _add_log(f"{Y}[WARN]{RST} Monitor path not found: {p}")

    # Windows Recent Files — fires every time ANY file is opened on the machine.
    # Windows writes a .lnk shortcut to this folder on every file open.
    recent_dir = Path(os.environ.get("APPDATA", "")) / "Microsoft" / "Windows" / "Recent"
    if recent_dir.exists():
        observer.schedule(_RecentFilesHandler(cfg), str(recent_dir), recursive=False)
        _add_log(f"{G}[FILE MONITOR]{RST} Watching Recent Files (file-open detection)")
        watched += 1
    else:
        _add_log(f"{Y}[WARN]{RST} Recent Files folder not found — file-open detection disabled")

    if watched == 0:
        _add_log(f"{Y}[WARN]{RST} No valid paths to watch — file monitoring inactive")
        return None

    observer.start()
    return observer


class _RecentFilesHandler(FileSystemEventHandler):
    """Fires a file_access event when Windows creates a .lnk in Recent Files."""
    def __init__(self, cfg: dict):
        super().__init__()
        self._cfg = cfg
        self._debounce: dict[str, float] = {}

    def on_created(self, event):
        self._fire(event)

    def on_modified(self, event):
        self._fire(event)

    def _fire(self, event):
        if event.is_directory:
            return
        path = event.src_path.lower()   # normalise case so double-click dedupes correctly
        if not path.endswith(".lnk"):
            return
        now = time.time()
        if now - self._debounce.get(path, 0) < 10:   # 10 s window covers rapid double-clicks
            return
        self._debounce[path] = now

        # The .lnk filename = opened filename + ".lnk"
        opened_name = Path(path).stem  # strip .lnk
        sensitivity = _classify_sensitivity(opened_name, self._cfg)
        sensitive   = sensitivity != "public" and (
                          sensitivity in ("critical", "confidential") or
                          Path(opened_name).suffix.lower() in self._cfg.get("sensitive_extensions", [])
                      )
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
            "is_archive":  os.path.splitext(opened_name)[1].lower() in _AGENT_ARCHIVE_EXTS,
        })
        enqueue_event(payload)
        _record_behaviour("file_open", sensitive=sensitive, path=opened_name)
        _check_threat_patterns(self._cfg)
        colour = Y if sensitive else C
        _add_log(f"{colour}[FILE OPEN]{RST} {opened_name}")


# ══════════════════════════════════════════════════════════════════════════════
# USB monitoring
# ══════════════════════════════════════════════════════════════════════════════

def _get_usb_drives() -> set[str]:
    """Return set of removable drive letters (e.g. {'E:', 'F:'})."""
    drives = set()
    for part in psutil.disk_partitions(all=True):
        if "removable" in part.opts.lower() or part.fstype in ("FAT32", "FAT", "exFAT", "NTFS"):
            # On Windows, check drive type
            if platform.system() == "Windows" and WIN32_AVAILABLE:
                dtype = win32file.GetDriveType(part.device)
                if dtype == win32con.DRIVE_REMOVABLE:
                    drives.add(part.device.rstrip("\\"))
            elif platform.system() != "Windows":
                # Non-Windows dev environment — treat /media/* as USB
                if "/media/" in part.mountpoint or "/run/media/" in part.mountpoint:
                    drives.add(part.mountpoint)
    return drives


class USBMonitor:
    def __init__(self, cfg: dict):
        self._cfg = cfg
        self._known_drives: set[str] = _get_usb_drives()
        self._file_snapshots: dict[str, dict[str, float]] = {}
        self._interval = cfg.get("usb_poll_interval_seconds", 5)
        self._thread = threading.Thread(target=self._run, daemon=True, name="usb-monitor")

    def start(self):
        self._thread.start()
        _add_log(f"{G}[USB MONITOR]{RST} Started (polling every {self._interval}s)")

    def _snapshot_drive(self, drive: str) -> dict[str, float]:
        """Walk the drive root and record filename → size."""
        snapshot = {}
        try:
            for root, _, files in os.walk(drive):
                for f in files:
                    full = os.path.join(root, f)
                    try:
                        snapshot[full] = os.path.getsize(full)
                    except OSError:
                        pass
        except PermissionError:
            pass
        return snapshot

    def _run(self):
        while True:
            time.sleep(self._interval)
            current_drives = _get_usb_drives()

            # Detect new insertions
            new = current_drives - self._known_drives
            for drive in new:
                self._on_insert(drive)

            # Detect removals
            removed = self._known_drives - current_drives
            for drive in removed:
                self._on_remove(drive)

            # Detect new files written to known drives
            for drive in current_drives:
                self._check_transfers(drive)

            self._known_drives = current_drives

    def _on_insert(self, drive: str):
        payload = _base(self._cfg, "endpoint_agent")
        payload.update({
            "source":          "usb",
            "device_id":       drive,
            "operation":       "insert",
            "data_mb":         0,
            "usb_transfer":    True,   # flag so UEBA usb_insert rule fires
            "usb_data_mb":     0,
            "severity_override": "suspicious",
        })
        enqueue_event(payload)
        _record_behaviour("usb_insert", path=drive)
        _check_threat_patterns(self._cfg)
        _stats["alerts"] += 1
        _add_log(f"{R}[USB INSERTED]{RST} {drive} — flagged suspicious")
        # Take initial snapshot so we can detect new files written
        self._file_snapshots[drive] = self._snapshot_drive(drive)

    def _on_remove(self, drive: str):
        payload = _base(self._cfg, "endpoint_agent")
        payload.update({
            "source":    "usb",
            "device_id": drive,
            "operation": "remove",
            "data_mb":   0,
        })
        enqueue_event(payload)
        _add_log(f"{M}[USB]{RST} Removed: {drive}")
        self._file_snapshots.pop(drive, None)

    def _check_transfers(self, drive: str):
        """Compare current snapshot to baseline — new/grown files = transfer."""
        old_snap = self._file_snapshots.get(drive, {})
        new_snap = self._snapshot_drive(drive)

        transferred_files = []
        total_mb = 0.0

        for fpath, fsize in new_snap.items():
            old_size = old_snap.get(fpath, 0)
            if fsize > old_size:
                transferred_files.append(fpath)
                total_mb += (fsize - old_size) / 1_048_576

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

        self._file_snapshots[drive] = new_snap


# ══════════════════════════════════════════════════════════════════════════════
# Browser history monitoring
# ══════════════════════════════════════════════════════════════════════════════

# Chrome/Edge store history in SQLite. We copy it before reading (file is locked
# while browser is open).

_LOCAL = os.environ.get("LOCALAPPDATA", "")
_ROAMING = os.environ.get("APPDATA", "")

_BROWSER_PROFILES = {
    "Chrome": [
        Path(_LOCAL) / "Google" / "Chrome" / "User Data" / "Default" / "History",
        Path(_LOCAL) / "Google" / "Chrome" / "User Data" / "Profile 1" / "History",
        Path(_LOCAL) / "Google" / "Chrome" / "User Data" / "Profile 2" / "History",
    ],
    "Edge": [
        Path(_LOCAL) / "Microsoft" / "Edge" / "User Data" / "Default" / "History",
        Path(_LOCAL) / "Microsoft" / "Edge" / "User Data" / "Profile 1" / "History",
        Path(_LOCAL) / "Microsoft" / "Edge" / "User Data" / "Profile 2" / "History",
    ],
}


def _find_firefox_history() -> list[Path]:
    base = Path(_ROAMING) / "Mozilla" / "Firefox" / "Profiles"
    paths = []
    if base.exists():
        for profile in base.iterdir():
            db = profile / "places.sqlite"
            if db.exists():
                paths.append(db)
    return paths


def _read_chrome_history(db_path: Path, since_ts: int) -> list[dict]:
    """Read Chrome/Edge history directly in read-only mode — works even when browser is open."""
    rows = []
    try:
        # immutable=1 bypasses locking — safe for read-only access to a live browser DB
        uri = f"file:{db_path.as_posix()}?mode=ro&immutable=1"
        con = sqlite3.connect(uri, uri=True, timeout=2)
        # Chrome/Edge store time as microseconds since 1601-01-01
        chrome_since = since_ts + int(11644473600 * 1_000_000)
        cur = con.execute(
            "SELECT url, title, last_visit_time FROM urls "
            "WHERE last_visit_time > ? ORDER BY last_visit_time",
            (chrome_since,)
        )
        for url, title, _ in cur.fetchall():
            rows.append({"url": url, "title": title or ""})
        con.close()
    except Exception as e:
        _add_log(f"{DIM}[BROWSER]{RST} Could not read {db_path.parent.name}: {e}")
    return rows


def _read_firefox_history(db_path: Path, since_unix_us: int) -> list[dict]:
    """Read Firefox places.sqlite directly in read-only mode."""
    rows = []
    try:
        uri = f"file:{db_path.as_posix()}?mode=ro&immutable=1"
        con = sqlite3.connect(uri, uri=True, timeout=2)
        cur = con.execute(
            "SELECT url, title, last_visit_date FROM moz_places "
            "WHERE last_visit_date > ? ORDER BY last_visit_date",
            (since_unix_us,)
        )
        for url, title, _ in cur.fetchall():
            rows.append({"url": url, "title": title or ""})
        con.close()
    except Exception as e:
        _add_log(f"{DIM}[BROWSER]{RST} Could not read Firefox history: {e}")
    return rows


def _domain(url: str) -> str:
    try:
        from urllib.parse import urlparse
        return urlparse(url).netloc.lower().lstrip("www.")
    except Exception:
        return url


def _classify_url(url: str, cfg: dict) -> tuple[str, bool, bool]:
    """Return (category, is_blocked, is_suspicious)."""
    domain = _domain(url)
    blocked_sites   = [s.lower() for s in cfg.get("blocked_sites",   [])]
    suspicious_sites = [s.lower() for s in cfg.get("suspicious_sites", [])]

    is_blocked    = any(b in domain for b in blocked_sites)
    is_suspicious = any(s in domain for s in suspicious_sites)

    # Category heuristics
    if any(x in domain for x in ["torrent", "pirate", "1337x", "kickass"]):
        cat = "file_sharing"
    elif any(x in domain for x in ["mega.nz", "dropbox", "onedrive", "drive.google", "wetransfer", "box.com"]):
        cat = "cloud_storage"
    elif any(x in domain for x in ["tor2web", ".onion", "zeronet", "i2p"]):
        cat = "tor"
    elif any(x in domain for x in ["vpngate", "nordvpn", "expressvpn", "protonvpn", "hidemyass"]):
        cat = "vpn"
    elif any(x in domain for x in ["youtube", "netflix", "twitch", "tiktok", "spotify"]):
        cat = "streaming"
    elif any(x in domain for x in ["github", "gitlab", "stackoverflow", "docs."]):
        cat = "dev_tools"
    elif any(x in domain for x in ["gmail", "outlook", "yahoo", "protonmail", "tutanota"]):
        cat = "webmail"
    else:
        cat = "general"

    return cat, is_blocked, is_suspicious


class BrowserMonitor:
    def __init__(self, cfg: dict):
        self._cfg = cfg
        self._interval = cfg.get("browser_poll_interval_seconds", 10)
        # Track last seen timestamp (unix microseconds)
        self._last_ts: int = int(time.time() * 1_000_000)
        self._thread = threading.Thread(target=self._run, daemon=True, name="browser-monitor")

    def start(self):
        self._thread.start()
        _add_log(f"{G}[BROWSER MONITOR]{RST} Started (polling every {self._interval}s)")

    def _run(self):
        while True:
            time.sleep(self._interval)
            self._poll()

    def _poll(self):
        visits = []

        # Chrome & Edge
        for browser, paths in [("Chrome", _BROWSER_PROFILES["Chrome"]), ("Edge", _BROWSER_PROFILES["Edge"])]:
            for db_path in paths:
                if db_path.exists():
                    rows = _read_chrome_history(db_path, self._last_ts)
                    for r in rows:
                        visits.append({"url": r["url"], "title": r["title"], "browser": browser})

        # Firefox
        for db_path in _find_firefox_history():
            rows = _read_firefox_history(db_path, self._last_ts)
            for r in rows:
                visits.append({"url": r["url"], "title": r["title"], "browser": "Firefox"})

        self._last_ts = int(time.time() * 1_000_000)

        for visit in visits:
            self._handle_visit(visit)

    def _handle_visit(self, visit: dict):
        url = visit["url"]
        cat, is_blocked, is_suspicious = _classify_url(url, self._cfg)
        risky = is_blocked or cat in ("tor", "cloud_storage", "file_sharing")

        site_name = _domain(url)
        page_title = visit.get("title", "")
        payload = _base(self._cfg, "web_proxy")
        payload.update({
            "source":     "web",
            "url":        url,
            "site_name":  site_name,
            "page_title": page_title or site_name,
            "category":   cat,
            "bytes_out":  0,
            "blocked":    is_blocked,
            "risky":      risky,
            "browser":    visit.get("browser", "unknown"),
        })
        enqueue_event(payload)

        if is_blocked:
            _record_behaviour("blocked_site", path=_domain(url))
            _check_threat_patterns(self._cfg)
            _stats["alerts"] += 1
            _add_log(f"{R}[BLOCKED]{RST} {_domain(url)} — {cat}")
        elif is_suspicious:
            _add_log(f"{Y}[SUSPICIOUS]{RST} {_domain(url)} — {cat}")
        else:
            _add_log(f"{C}[WEB]{RST} {_domain(url)} — {cat}")


# ══════════════════════════════════════════════════════════════════════════════
# Browser Intelligence Monitor — incognito, file uploads, webmail
# ══════════════════════════════════════════════════════════════════════════════

_INCOGNITO_FLAGS = {
    "chrome.exe":  "--incognito",
    "msedge.exe":  "--inprivate",
    "firefox.exe": "--private-window",
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
        if domain == d:
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
        self._incognito_lock = threading.Lock()
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

        with self._incognito_lock:
            was_active = self._incognito_active
            self._incognito_active = found
        if found and not was_active:
            payload = _base(self._cfg, "browser_intel")
            payload.update({"activity_type": "incognito_detected",
                            "browser": browser_name, "incognito": True})
            enqueue_event(payload)
            _stats["alerts"] += 1
            _add_log(f"{R}[INCOGNITO]{RST} {browser_name} private/incognito mode detected")

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
        _logged_unavailable = False
        while True:
            try:
                _logged_unavailable = False   # reset on successful connect
                await self._cdp_session()
            except Exception as exc:
                if not _logged_unavailable:
                    _add_log(f"{DIM}[CDP]{RST} Chrome debug port unavailable — upload detection disabled")
                    _logged_unavailable = True
            await asyncio.sleep(60)   # retry every 60 s, not 10 s

    async def _cdp_session(self):
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


# ══════════════════════════════════════════════════════════════════════════════
# Terminal status display
# ══════════════════════════════════════════════════════════════════════════════

def _status_bar(cfg: dict):
    """Print a live status bar every 30 seconds."""
    while True:
        time.sleep(30)
        uptime = int(time.time() - _start_time)
        h, rem = divmod(uptime, 3600)
        m, s   = divmod(rem, 60)
        print(
            f"\n{BOLD}{C}━━━ Nexon Agent Status ━━━{RST}  "
            f"User: {W}{cfg['user_id']}{RST}  "
            f"Dept: {W}{cfg['department']}{RST}  "
            f"Uptime: {W}{h:02d}:{m:02d}:{s:02d}{RST}  "
            f"Sent: {G}{_stats['sent']}{RST}  "
            f"Errors: {R}{_stats['errors']}{RST}  "
            f"Alerts: {R}{_stats['alerts']}{RST}\n"
        )


# ══════════════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════════════

_start_time = time.time()


def main():
    global _start_time
    _start_time = time.time()

    print(f"\n{BOLD}{C}{'═'*60}{RST}")
    print(f"{BOLD}{W}  Nexon Technologies — Endpoint Monitoring Agent{RST}")
    print(f"{BOLD}{C}{'═'*60}{RST}\n")

    cfg = load_config()
    global _screenshot
    _screenshot = ScreenshotCapture(cfg, cfg["server_url"])

    print(f"  {G}User ID:{RST}    {cfg['user_id']}")
    print(f"  {G}Name:{RST}       {cfg['name']}")
    print(f"  {G}Department:{RST} {cfg['department']}")
    print(f"  {G}Role:{RST}       {cfg['role']}")
    print(f"  {G}Server:{RST}     {cfg['server_url']}")
    print(f"  {G}Device:{RST}     {cfg['device_id']}")
    print(f"\n{DIM}{'─'*60}{RST}\n")

    # Start config sync (working hours from server)
    config_sync.start(cfg["server_url"], cfg)
    _add_log(f"{G}[CONFIG SYNC]{RST} Working hours loaded (server sync attempted)")

    # Start event sender thread
    sender = threading.Thread(target=_sender_thread, args=(cfg,), daemon=True, name="event-sender")
    sender.start()

    # Send login event
    send_login_event(cfg)

    # Start file monitor
    observer = start_file_monitor(cfg)

    # Start USB monitor
    usb_mon = USBMonitor(cfg)
    usb_mon.start()

    # Start browser monitor
    browser_mon = BrowserMonitor(cfg)
    browser_mon.start()

    # Start browser intelligence monitor (incognito + CDP upload/webmail)
    browser_intel = BrowserIntelligenceMonitor(cfg)
    browser_intel.start()

    # Start process monitor
    proc_mon = ProcessMonitor(cfg, enqueue_event, _add_log)
    proc_mon.start()

    # Start clipboard monitor
    clip_mon = ClipboardMonitor(cfg, enqueue_event, _add_log)
    clip_mon.start()

    # Status bar thread
    status_thread = threading.Thread(target=_status_bar, args=(cfg,), daemon=True, name="status-bar")
    status_thread.start()

    print(f"\n{G}[READY]{RST} All monitors active. Events streaming to {cfg['server_url']}\n")
    print(f"{DIM}Press Ctrl+C to stop.{RST}\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n{Y}[STOP]{RST} Shutting down agent...")
        if observer:
            observer.stop()
            observer.join()
        print(f"{G}[DONE]{RST} Agent stopped. Total events sent: {_stats['sent']}")


if __name__ == "__main__":
    main()
