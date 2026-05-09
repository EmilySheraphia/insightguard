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
import subprocess

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

# Screenshot rate-limit: at most one screenshot per user per N seconds.
_screenshot_last: dict[str, float] = {}
_SCREENSHOT_COOLDOWN = 15  # seconds

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


def _trigger_escalation_email(cfg: dict, log_id: str,
                               screenshot_path: "str | None" = None) -> None:
    """
    Send the escalation alert email directly from the agent using Gmail SMTP.
    Runs on a daemon thread so it never blocks the sender thread.

    Why here and not on the server: Render blocks outbound SMTP (ports 465/587),
    so the Windows agent (which has no port restrictions) sends the email instead.
    """
    def _send():
        import smtplib, ssl as _ssl
        from email.mime.multipart import MIMEMultipart as _MMP
        from email.mime.text import MIMEText as _MMT
        from email.mime.image import MIMEImage as _MMI
        from html import escape as _esc

        # 1. Fetch escalation config from server
        try:
            resp = requests.get(
                cfg["server_url"].rstrip("/") + "/api/escalation/config",
                timeout=8,
            )
            ecfg = resp.json()
        except Exception as e:
            _add_log(f"{Y}[EMAIL]{RST} Could not fetch email config: {e}")
            return

        if not ecfg.get("enabled"):
            return

        smtp_user = ecfg.get("smtp_user", "").strip()
        smtp_pass = ecfg.get("smtp_password", "").replace(" ", "").strip()
        recipient = ecfg.get("recipient_email", "").strip()
        smtp_host = ecfg.get("smtp_host", "smtp.gmail.com")
        smtp_port = int(ecfg.get("smtp_port", 587))

        if not smtp_user or not smtp_pass or not recipient:
            _add_log(f"{Y}[EMAIL]{RST} SMTP credentials not configured")
            return

        # 2. Fetch event details for the email body
        try:
            ev_resp = requests.get(
                cfg["server_url"].rstrip("/") + "/api/users/"
                + cfg["user_id"] + "/risk",
                timeout=8,
            )
            ev_data = ev_resp.json().get("profile", {})
        except Exception:
            ev_data = {}

        user_id    = _esc(cfg.get("user_id", ""))
        department = _esc(cfg.get("department", ""))
        sev_colors = {"critical": "#f85149", "high_risk": "#db6d28",
                      "suspicious": "#e3b341", "normal": "#3fb950"}
        sev        = ev_data.get("current_severity", "critical")
        score      = ev_data.get("risk_score", "—")
        color      = sev_colors.get(sev, "#f85149")

        subject = f"[InsightGuard ALERT] {sev.upper()} — {user_id} @ {department}"
        body_html = f"""
        <div style="font-family:Arial,sans-serif;max-width:600px">
          <div style="background:#161b22;padding:20px;border-radius:8px">
            <h2 style="color:#e6edf3;margin:0 0 16px">InsightGuard — Insider Threat Alert</h2>
            <div style="background:#21262d;border-radius:6px;padding:16px;margin-bottom:12px">
              <div style="font-size:13px;color:#8b949e;margin-bottom:4px">Risk Score</div>
              <div style="font-size:32px;font-weight:700;color:{color}">{score}</div>
              <div style="display:inline-block;background:{color}22;border:1px solid {color}44;
                          border-radius:4px;padding:2px 10px;font-size:12px;color:{color};margin-top:6px">
                {sev.upper().replace('_',' ')}
              </div>
            </div>
            <table style="width:100%;font-size:13px;color:#e6edf3;border-collapse:collapse">
              <tr><td style="padding:6px 0;color:#8b949e;width:140px">User ID</td>
                  <td style="padding:6px 0;font-family:monospace">{user_id}</td></tr>
              <tr><td style="padding:6px 0;color:#8b949e">Department</td>
                  <td style="padding:6px 0">{department}</td></tr>
            </table>
            <div style="margin-top:16px;padding-top:12px;border-top:1px solid #30363d">
              <a href="{ecfg.get('dashboard_url','')}" style="background:#58a6ff;color:#fff;
                 padding:8px 16px;border-radius:6px;text-decoration:none;font-size:13px">
                View Dashboard
              </a>
            </div>
          </div>
        </div>
        """

        # 3. Build MIME message
        msg = _MMP("mixed")
        msg["Subject"] = subject
        msg["From"]    = smtp_user
        msg["To"]      = recipient
        msg.attach(_MMT(body_html, "html"))

        # Attach screenshot if path provided
        if screenshot_path:
            try:
                with open(screenshot_path, "rb") as fh:
                    img_part = _MMI(fh.read(), _subtype="jpeg")
                    img_part.add_header("Content-Disposition", "attachment",
                                        filename="screenshot.jpg")
                    msg.attach(img_part)
            except Exception as e:
                _add_log(f"{Y}[EMAIL]{RST} Could not attach screenshot: {e}")

        # 4. Send via Gmail SMTP (runs on Windows — no port restrictions)
        try:
            ctx = _ssl.create_default_context()
            if smtp_port == 465:
                with smtplib.SMTP_SSL(smtp_host, smtp_port, context=ctx) as s:
                    s.login(smtp_user, smtp_pass)
                    s.sendmail(smtp_user, recipient, msg.as_string())
            else:
                with smtplib.SMTP(smtp_host, smtp_port) as s:
                    s.ehlo()
                    s.starttls(context=ctx)
                    s.ehlo()
                    s.login(smtp_user, smtp_pass)
                    s.sendmail(smtp_user, recipient, msg.as_string())
            _add_log(f"{G}[EMAIL]{RST} Alert email sent to {recipient}")
        except Exception as e:
            _add_log(f"{R}[EMAIL]{RST} SMTP failed: {e}")

    threading.Thread(target=_send, daemon=True).start()


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
                if isinstance(score, (int, float)) and _screenshot:
                    uid = payload.get("user_id", "")
                    now = time.time()
                    severity = resp_data.get("severity", "")
                    is_critical = severity == "critical" or score >= 80
                    # Take screenshot for suspicious+ (score≥45) OR any critical event.
                    # severity_override can mark events critical even if score < 45
                    # (e.g. USB insert for a new user with no PUB baseline yet).
                    if score >= 45 or is_critical:
                        cooldown_ok = is_critical or (now - _screenshot_last.get(uid, 0) >= _SCREENSHOT_COOLDOWN)
                    else:
                        cooldown_ok = False
                    if cooldown_ok:
                        _screenshot_last[uid] = now
                        log_id = resp_data.get("log_id", "")
                        ok = _screenshot.capture(
                            trigger_type="severity",
                            event_type=payload.get("activity_type", payload.get("source", "unknown")),
                            log_id=log_id,
                        )
                        if ok:
                            _add_log(f"{G}[SCREENSHOT]{RST} Captured — score {score}, id {log_id}")
                        else:
                            _add_log(f"{Y}[SCREENSHOT]{RST} Capture failed — check mss/Pillow installation")
                        # Send alert email from agent (Render blocks SMTP, Windows doesn't)
                        if is_critical:
                            shot_path = str(ok) if ok else None
                            _trigger_escalation_email(cfg, log_id, shot_path)
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
        "agent":      True,   # marks this as a real endpoint agent event
    }


def _file_size_mb(path: str) -> float:
    try:
        return os.path.getsize(path) / 1_048_576
    except OSError:
        return 0.0


_AGENT_ARCHIVE_EXTS = {".zip", ".rar", ".7z", ".tar", ".gz", ".bz2"}

# Deduplication cache: path → timestamp of last reported event.
# Prevents watchdog and ArchivePollMonitor from both firing for the same file.
_archive_reported: dict[str, float] = {}
_ARCHIVE_DEDUP_TTL = 30  # seconds


def _archive_already_reported(path: str) -> bool:
    return (time.time() - _archive_reported.get(path, 0)) < _ARCHIVE_DEDUP_TTL


def _mark_archive_reported(path: str) -> None:
    _archive_reported[path] = time.time()


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
        # Skip files inside the agent's own directory (e.g. evidence screenshots)
        _agent_dir = str(Path(__file__).parent.resolve())
        try:
            if str(Path(path).resolve()).startswith(_agent_dir):
                return
        except Exception:
            pass
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
        fname   = Path(path).name
        is_arch = os.path.splitext(fname)[1].lower() in _AGENT_ARCHIVE_EXTS
        # Dedup: if another detector already reported this archive, skip entirely
        if is_arch:
            if _archive_already_reported(path):
                return
            _mark_archive_reported(path)
            print(f"[ARCHIVE DETECTED] watchdog on_created/modified: {fname}  is_archive=True  sending to server")
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
            "is_archive":  is_arch,
        })
        enqueue_event(payload)
        _record_behaviour("file_write", sensitive=sensitive, path=fname)
        _check_threat_patterns(self._cfg)
        colour = R if is_arch else (Y if sensitive else DIM)
        label  = "ARCHIVE" if is_arch else operation.upper()
        _add_log(f"{colour}[FILE]{RST} {label} {fname} ({size_mb:.2f} MB)")

    def on_created(self, event):
        self._handle(event, "write")

    def on_modified(self, event):
        self._handle(event, "write")

    def on_moved(self, event):
        if event.is_directory:
            return
        src  = event.src_path
        dest = getattr(event, "dest_path", "")
        dest_filename = os.path.basename(dest) if dest else os.path.basename(src)
        # Rename = same directory; Move = different directory
        is_rename = dest and (os.path.dirname(src) == os.path.dirname(dest))
        operation = "rename" if is_rename else "move"
        size_mb = _file_size_mb(dest or src)
        sensitive = _is_sensitive(src, self._cfg)
        sensitivity = _classify_sensitivity(src, self._cfg)
        is_arch_dest = os.path.splitext(dest_filename)[1].lower() in _AGENT_ARCHIVE_EXTS
        # When the destination is an archive, use the destination filename — temp-rename
        # (e.g. 9A3B.tmp → archive.zip) should show the .zip name, not the temp name.
        display_name = dest_filename if is_arch_dest else os.path.basename(src)
        # Dedup: if another detector already reported this archive, skip entirely
        if is_arch_dest:
            dest_path_str = dest if dest else src
            if _archive_already_reported(dest_path_str):
                return
            _mark_archive_reported(dest_path_str)
            print(f"[ARCHIVE DETECTED] watchdog on_moved→archive: {Path(src).name} → {dest_filename}  is_archive=True  sending to server")
        payload = _base(self._cfg, "dlp_system")
        payload.update({
            "source":      "file",
            "file_path":   dest if (is_arch_dest and dest) else src,
            "file_name":   display_name,
            "operation":   "compress" if is_arch_dest else operation,
            "destination": dest,
            "file_count":  1,
            "data_mb":     size_mb,
            "sensitive":   sensitive,
            "sensitivity": sensitivity,
            "is_archive":  is_arch_dest,
        })
        enqueue_event(payload)
        if is_arch_dest:
            _add_log(f"{R}[FILE]{RST} ARCHIVE {dest_filename} ({size_mb:.2f} MB)")
        else:
            colour = Y if sensitive else DIM
            label = "RENAME" if is_rename else "MOVE"
            _add_log(f"{colour}[FILE]{RST} {label} {Path(src).name} → {Path(dest).name if dest else '?'}")

    def on_deleted(self, event):
        self._handle(event, "delete")


def _get_real_user_folders() -> list[Path]:
    """
    Return the REAL Desktop, Documents, and Downloads paths using the Windows
    registry (User Shell Folders).  This is the only reliable method when
    OneDrive Known Folder Move is enabled — it redirects these folders to
    e.g. C:\\Users\\Emily\\OneDrive\\Desktop, but %USERPROFILE%\\Desktop still
    exists (empty).  The registry always points to the live location.

    Falls back to %USERPROFILE%\\Desktop/Documents/Downloads if winreg fails.
    """
    folders: list[Path] = []
    try:
        import winreg
        # User Shell Folders — values may contain %USERPROFILE% which we expand
        REG_KEY = r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
        # (Desktop, Personal=Documents, Downloads GUID)
        NAMES = [
            "Desktop",
            "Personal",
            "{374DE290-123F-4565-9164-39C4925E467B}",  # Downloads
        ]
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_KEY) as key:
            for name in NAMES:
                try:
                    raw, _ = winreg.QueryValueEx(key, name)
                    expanded = os.path.expandvars(raw)
                    p = Path(expanded)
                    if p.exists():
                        folders.append(p)
                except FileNotFoundError:
                    pass
    except Exception:
        pass

    if not folders:
        # Fallback: standard paths under %USERPROFILE%
        base = Path(os.environ.get("USERPROFILE", os.path.expanduser("~")))
        for sub in ("Desktop", "Documents", "Downloads"):
            p = base / sub
            if p.exists():
                folders.append(p)

    return folders


def _extra_monitor_paths() -> list[Path]:
    """
    Return additional paths to watch beyond what's in config.
    Uses registry to get the real Desktop/Documents/Downloads (handles OneDrive
    Known Folder Move).  Also scans %USERPROFILE%\\OneDrive* subdirectories as
    a belt-and-suspenders fallback.
    """
    seen: set[Path] = set()
    extra: list[Path] = []

    def _add(p: Path):
        rp = p.resolve() if p.exists() else p
        if rp not in seen:
            seen.add(rp)
            extra.append(p)

    # Primary: registry-backed real paths
    for p in _get_real_user_folders():
        _add(p)

    # Belt-and-suspenders: any OneDrive-named subdirs under %USERPROFILE%
    userprofile = Path(os.environ.get("USERPROFILE", os.path.expanduser("~")))
    if userprofile.exists():
        try:
            for entry in userprofile.iterdir():
                if entry.is_dir() and entry.name.lower().startswith("onedrive"):
                    for sub in ("Desktop", "Documents", "Downloads"):
                        p = entry / sub
                        if p.exists():
                            _add(p)
        except (PermissionError, OSError):
            pass

    return extra


def start_file_monitor(cfg: dict) -> Observer | None:
    if not WATCHDOG_AVAILABLE:
        _add_log(f"{Y}[WARN]{RST} watchdog not installed — file monitoring disabled")
        return None

    paths = expand_paths(cfg.get("monitor_paths", []))
    # Also watch OneDrive-redirected folders (Desktop/Documents/Downloads may live there)
    for p in _extra_monitor_paths():
        if p not in paths:
            paths.append(p)

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


class ArchivePollMonitor:
    """
    Polls common Windows user directories every 5 seconds for newly created
    archive files (.zip, .rar, .7z, .tar, .gz, .bz2).  This is a supplement
    to watchdog — it catches archives created outside the three monitored paths
    (e.g. right-clicking on the Desktop when Desktop isn't watched, or using
    7-Zip which may write to a temp location then rename).

    Tracks file mtimes in `_seen` to avoid re-reporting the same archive.
    """

    POLL_INTERVAL = 5    # seconds between scans

    def __init__(self, cfg: dict):
        self._cfg = cfg
        base = Path(os.environ.get("USERPROFILE", os.path.expanduser("~")))
        extra_paths = [
            base,
            base / "Desktop",
            base / "Documents",
            base / "Downloads",
            base / "Music",
            base / "Videos",
            base / "Pictures",
        ]
        # Include OneDrive-redirected Desktop/Documents/Downloads
        for p in _extra_monitor_paths():
            extra_paths.append(p)
        monitored = expand_paths(cfg.get("monitor_paths", []))
        all_paths = list({p.resolve() for p in extra_paths + monitored if p.exists()})
        self._paths = all_paths
        # path → mtime at last report. Seeded at startup so pre-existing archives
        # are never re-reported; only archives that appear AFTER startup fire events.
        self._reported: dict[str, float] = {}
        self._thread = threading.Thread(target=self._run, daemon=True, name="archive-poll")

    def start(self):
        self._thread.start()
        print(f"[ARCHIVE POLL] Starting — watching {len(self._paths)} directories:")
        for p in self._paths:
            print(f"  [ARCHIVE POLL]   {p}")

    def _run(self):
        # Seed: snapshot all archives currently on disk so we don't fire on old files.
        try:
            self._seed()
        except Exception as e:
            print(f"[ARCHIVE POLL] Seed error: {e}")
        while True:
            time.sleep(self.POLL_INTERVAL)
            try:
                self._scan()
            except Exception as e:
                _add_log(f"{DIM}[ARCHIVE POLL]{RST} Scan error: {e}")

    def _iter_archives(self):
        """Yield DirEntry objects for all archives in monitored paths (2 levels deep)."""
        for base_path in self._paths:
            try:
                for entry in os.scandir(base_path):
                    if entry.is_dir(follow_symlinks=False):
                        try:
                            for sub in os.scandir(entry.path):
                                yield sub
                        except (PermissionError, OSError):
                            pass
                    else:
                        yield entry
            except (PermissionError, OSError):
                pass

    def _seed(self):
        """Record mtimes of all existing archives WITHOUT firing events."""
        count = 0
        for entry in self._iter_archives():
            try:
                if not entry.is_file(follow_symlinks=False):
                    continue
                if os.path.splitext(entry.name)[1].lower() not in _AGENT_ARCHIVE_EXTS:
                    continue
                stat = entry.stat(follow_symlinks=False)
                self._reported[entry.path] = stat.st_mtime
                count += 1
            except (PermissionError, OSError):
                pass
        print(f"[ARCHIVE POLL] Seeded {count} existing archives — new ones will be detected within {self.POLL_INTERVAL}s")
        _add_log(f"{G}[ARCHIVE POLL]{RST} Seeded {count} existing archives — new ones will be detected")

    def _scan(self):
        for entry in self._iter_archives():
            self._check_entry(entry)

    def _check_entry(self, entry):
        try:
            if not entry.is_file(follow_symlinks=False):
                return
            ext = os.path.splitext(entry.name)[1].lower()
            if ext not in _AGENT_ARCHIVE_EXTS:
                return
            stat = entry.stat(follow_symlinks=False)
            mtime = stat.st_mtime
            prev_mtime = self._reported.get(entry.path)
            if prev_mtime is None:
                # Archive appeared after startup — always fire
                self._reported[entry.path] = mtime
                self._fire(entry.path, entry.name, stat.st_size)
            elif abs(mtime - prev_mtime) >= 1:
                # Archive was replaced or overwritten
                self._reported[entry.path] = mtime
                self._fire(entry.path, entry.name, stat.st_size)
        except (PermissionError, OSError):
            pass

    def _fire(self, path: str, fname: str, size_bytes: int):
        if _archive_already_reported(path):
            return
        _mark_archive_reported(path)
        size_mb = size_bytes / 1_048_576
        sensitivity = _classify_sensitivity(path, self._cfg)
        sensitive   = sensitivity != "public" and (
                          sensitivity in ("critical", "confidential") or
                          Path(path).suffix.lower() in self._cfg.get("sensitive_extensions", [])
                      )
        payload = _base(self._cfg, "dlp_system")
        payload.update({
            "source":      "file",
            "file_path":   path,
            "file_name":   fname,
            "operation":   "compress",
            "file_count":  1,
            "data_mb":     size_mb,
            "destination": "local",
            "sensitive":   sensitive,
            "sensitivity": sensitivity,
            "is_archive":  True,
        })
        enqueue_event(payload)
        _record_behaviour("file_write", sensitive=True, path=fname)
        _check_threat_patterns(self._cfg)
        print(f"[ARCHIVE POLL DETECTED] {fname}  is_archive=True  sending to server")
        _add_log(f"{R}[ARCHIVE]{RST} New archive detected: {fname} ({size_mb:.2f} MB)")


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
    _TRANSFER_COOLDOWN = 10  # seconds — don't fire repeated transfer events for the same drive

    def __init__(self, cfg: dict):
        self._cfg = cfg
        self._known_drives: set[str] = _get_usb_drives()
        self._file_snapshots: dict[str, dict[str, float]] = {}
        self._last_transfer_time: dict[str, float] = {}
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
            "severity_override": "critical",
        })
        enqueue_event(payload)
        _record_behaviour("usb_insert", path=drive)
        _check_threat_patterns(self._cfg)
        _stats["alerts"] += 1
        _add_log(f"{R}[USB INSERTED]{RST} {drive} — flagged critical")
        # Always capture a screenshot on USB insert — bypass the normal cooldown
        # since physical device insertion is always worth immediate evidence.
        uid = self._cfg.get("user_id", "")
        _screenshot_last[uid] = 0  # reset cooldown so sender thread fires screenshot
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
            # Cooldown: if a transfer event for this drive fired recently, skip to avoid
            # duplicate alerts when a large copy spans multiple poll cycles.
            now = time.time()
            if now - self._last_transfer_time.get(drive, 0) < self._TRANSFER_COOLDOWN:
                self._file_snapshots[drive] = new_snap  # keep snapshot up to date
                return
            self._last_transfer_time[drive] = now
            fnames = [os.path.basename(f) for f in transferred_files[:20]]

            # Build per-sensitivity-level counts
            sensitivity_summary: dict[str, int] = {}
            for fname in fnames:
                level = _classify_sensitivity(fname, self._cfg)
                sensitivity_summary[level] = sensitivity_summary.get(level, 0) + 1

            has_sensitive = any(_is_sensitive(f, self._cfg) for f in fnames)
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
                "sensitive":            has_sensitive,
                # Any file transfer to USB is always at least critical
                "severity_override":    "critical",
            })
            enqueue_event(payload)
            for f in fnames:
                _record_behaviour("usb_transfer", sensitive=_is_sensitive(f, self._cfg), path=f)
            _check_threat_patterns(self._cfg)
            label = f"{R}[USB TRANSFER — CRITICAL]{RST}" if has_sensitive else f"{R}[USB TRANSFER]{RST}"
            _add_log(
                f"{label} {len(transferred_files)} file(s) → {drive} "
                f"({total_mb:.2f} MB): {', '.join(fnames[:3])}"
            )

        self._file_snapshots[drive] = new_snap


# ══════════════════════════════════════════════════════════════════════════════
# DNS Cache Monitor — catches ALL browser visits without touching browser files
# ══════════════════════════════════════════════════════════════════════════════

_CREATE_NO_WINDOW = 0x08000000 if platform.system() == "Windows" else 0

# Domains that are Windows system noise, not user browsing
_DNS_SKIP_SUFFIXES = (
    ".microsoft.com", ".windows.com", ".windowsupdate.com",
    ".msftncsi.com", ".msftconnecttest.com", ".msecnd.net",
    ".akadns.net", ".akamaiedge.net", ".akamaized.net",
    ".doubleclick.net", ".googlesyndication.com",
    ".googletagmanager.com", ".googletagservices.com",
    ".gstatic.com", ".googleapis.com", ".google-analytics.com",
    ".in-addr.arpa", ".arpa", ".local", ".lan",
    # App/extension background traffic
    ".discordapp.com", ".discord.com", ".discord.gg",
    ".steampowered.com", ".steamcontent.com", ".steamstatic.com",
    ".epicgames.com", ".unrealengine.com",
    ".apple.com", ".icloud.com",
    ".office.com", ".office365.com", ".live.com", ".sharepoint.com",
    ".digicert.com", ".sectigo.com", ".letsencrypt.org",
    ".cloudflare.com", ".cloudflare-dns.com",
    ".amazonaws.com", ".awsstatic.com",
    ".fastly.net", ".cloudfront.net",
    ".adobe.com", ".adobedtm.com",
    ".nr-data.net", ".newrelic.com",
    ".sentry.io", ".segment.io",
    # GitHub background / telemetry (VS Code, Copilot, extensions)
    ".githubusercontent.com", ".githubassets.com", ".github.io",
    "copilot-telemetry.githubusercontent.com",
    # Zoom, Teams, Slack background
    ".zoom.us", ".zoomgov.com",
    ".slack.com", ".slack-edge.com",
    ".skype.com", ".teams.microsoft.com",
)
_DNS_SKIP_EXACT = {"localhost", "wpad", "isatap", "teredo"}


def _read_dns_cache_with_ttl() -> dict[str, int]:
    """
    Return domain → max(TTL) mapping from Windows DNS cache.
    TTL is seconds remaining. When a user visits a site, TTL resets to near-max.
    """
    try:
        r = subprocess.run(
            ["powershell", "-NonInteractive", "-NoProfile", "-Command",
             "Get-DnsClientCache | Select-Object Entry,TimeToLive | ConvertTo-Json"],
            capture_output=True, text=True, timeout=8,
            creationflags=_CREATE_NO_WINDOW,
        )
        if r.returncode == 0 and r.stdout.strip():
            raw = r.stdout.strip()
            data = json.loads(raw)
            if isinstance(data, dict):
                data = [data]
            result: dict[str, int] = {}
            for item in data:
                d = str(item.get("Entry") or "").strip().lower().rstrip(".")
                ttl = int(item.get("TimeToLive") or 0)
                if d and "." in d:
                    result[d] = max(result.get(d, 0), ttl)
            return result
    except Exception:
        pass
    # Fallback: no TTL available — return names with TTL=0
    return {d: 0 for d in _read_dns_cache()}


def _read_dns_cache() -> set[str]:
    """
    Return all domain names currently in the Windows DNS cache.
    Tries PowerShell first (cleaner), falls back to ipconfig /displaydns.
    """
    # PowerShell: Get-DnsClientCache (Windows 8+, fast, structured)
    try:
        r = subprocess.run(
            ["powershell", "-NonInteractive", "-NoProfile", "-Command",
             "Get-DnsClientCache | Select-Object -ExpandProperty Entry"],
            capture_output=True, text=True, timeout=8,
            creationflags=_CREATE_NO_WINDOW,
        )
        if r.returncode == 0 and r.stdout.strip():
            domains = set()
            for line in r.stdout.splitlines():
                d = line.strip().lower().rstrip(".")
                if d and "." in d:
                    domains.add(d)
            return domains
    except Exception:
        pass

    # Fallback: ipconfig /displaydns
    try:
        r = subprocess.run(
            ["ipconfig", "/displaydns"],
            capture_output=True, text=True, timeout=8,
            creationflags=_CREATE_NO_WINDOW,
        )
        domains = set()
        for line in r.stdout.splitlines():
            if "Record Name" in line and ":" in line:
                d = line.split(":", 1)[1].strip().lower().rstrip(".")
                if d and "." in d:
                    domains.add(d)
        return domains
    except Exception:
        return set()


def _dns_is_noise(domain: str) -> bool:
    """Return True for system/CDN/tracker domains that aren't user browsing."""
    if domain in _DNS_SKIP_EXACT:
        return True
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", domain):
        return True   # raw IP
    for suffix in _DNS_SKIP_SUFFIXES:
        if domain.endswith(suffix):
            return True
    return False


class DnsMonitor:
    """
    Polls the Windows DNS cache every N seconds.
    Reports any new domain that appears since last poll as a web event.
    Works for ALL browsers (Chrome, Edge, Firefox) and even incognito mode.
    """

    def __init__(self, cfg: dict):
        self._cfg      = cfg
        self._interval = cfg.get("browser_poll_interval_seconds", 10)
        self._seen: set[str] = set()
        self._ttls:  dict[str, int]   = {}   # domain → last seen TTL
        self._blocked_reported: dict[str, float] = {}
        self._thread   = threading.Thread(target=self._run, daemon=True, name="dns-monitor")

    def start(self):
        ttl_data = _read_dns_cache_with_ttl()
        self._seen = set(ttl_data.keys())
        self._ttls = dict(ttl_data)   # baseline TTLs — an increase means fresh visit
        self._thread.start()
        _add_log(f"{G}[DNS MONITOR]{RST} Started — {len(self._seen)} existing entries baselined")

    def _run(self):
        while True:
            time.sleep(self._interval)
            try:
                self._poll()
            except Exception as e:
                _add_log(f"{DIM}[DNS]{RST} Poll error: {e}")

    def _poll(self):
        ttl_data = _read_dns_cache_with_ttl()
        current  = set(ttl_data.keys())
        new_domains = current - self._seen
        self._seen   = current

        blocked_sites = [s.lower() for s in self._cfg.get("blocked_sites", [])]

        # ── Report all new non-noise domains ────────────────────────────────
        # DNS gives the domain name; BrowserMonitor gives the exact URL.
        # We report all new domains so any user navigation shows up, even when
        # browser history is unavailable (locked DB, no browser, incognito).
        for domain in new_domains:
            if _dns_is_noise(domain):
                continue
            self._report(domain)

        # ── TTL-based: blocked domain already in cache was re-visited ────────
        # Fresh DNS lookup resets TTL near-max. If TTL went UP vs last poll
        # the user just visited that domain.
        for domain in current - new_domains:
            if not any(b in domain for b in blocked_sites):
                continue
            new_ttl = ttl_data.get(domain, 0)
            old_ttl = self._ttls.get(domain, 9999)   # high default → won't fire on first poll
            if new_ttl > old_ttl + 5:
                self._report(domain)

        self._ttls = ttl_data

    def _report(self, domain: str):
        url = f"https://{domain}/"
        cat, is_blocked, is_suspicious = _classify_url(url, self._cfg)
        risky = is_blocked or cat in ("tor", "cloud_storage", "file_sharing")

        payload = _base(self._cfg, "web_proxy")
        payload.update({
            "source":     "web",
            "url":        url,
            "site_name":  domain,
            "page_title": domain,
            "category":   cat,
            "bytes_out":  0,
            "blocked":    is_blocked,
            "risky":      risky,
            "browser":    "dns",
        })
        enqueue_event(payload)

        if is_blocked:
            _record_behaviour("blocked_site", path=domain)
            _check_threat_patterns(self._cfg)
            _stats["alerts"] += 1
            # Force screenshot bypass — blocked site always gets a screenshot
            uid = self._cfg.get("user_id", "")
            _screenshot_last[uid] = 0
            print(f"\n{R}{'!'*50}{RST}")
            print(f"{R}  BLOCKED SITE (DNS): {domain}{RST}")
            print(f"{R}  Sending critical event to InsightGuard...{RST}")
            print(f"{R}{'!'*50}{RST}\n")
            _add_log(f"{R}[BLOCKED]{RST} {domain} — {cat}")
        elif is_suspicious or risky:
            _add_log(f"{Y}[DNS]{RST} {domain} — {cat}")
        else:
            _add_log(f"{C}[DNS]{RST} {domain}")


# ══════════════════════════════════════════════════════════════════════════════
# Browser history monitoring
# ══════════════════════════════════════════════════════════════════════════════

# Chrome/Edge store history in SQLite. We copy it before reading (file is locked
# while browser is open).

_LOCAL = os.environ.get("LOCALAPPDATA", "")
_ROAMING = os.environ.get("APPDATA", "")

_CHROME_NON_PROFILE_DIRS = {"System Profile", "GrShaderCache", "ShaderCache",
                            "Crashpad", "BrowserMetrics", "hyphen-data",
                            "PepperFlash", "WidevineCdm", "SSLErrorAssistant"}

def _find_chrome_like_histories(user_data_dir: Path) -> list[Path]:
    """Scan all profile folders under Chrome/Edge User Data for History files.
    Skips internal Chrome system directories that aren't user profiles."""
    paths = []
    if not user_data_dir.exists():
        return paths
    for entry in user_data_dir.iterdir():
        if not entry.is_dir() or entry.name in _CHROME_NON_PROFILE_DIRS:
            continue
        h = entry / "History"
        if h.exists():
            paths.append(h)
    return paths


_CHROME_USER_DATA  = Path(_LOCAL) / "Google" / "Chrome" / "User Data"
_EDGE_USER_DATA    = Path(_LOCAL) / "Microsoft" / "Edge" / "User Data"
_BRAVE_USER_DATA   = Path(_LOCAL) / "BraveSoftware" / "Brave-Browser" / "User Data"
_OPERA_USER_DATA   = Path(_ROAMING) / "Opera Software" / "Opera Stable"
_CHROME_BETA_DATA  = Path(_LOCAL) / "Google" / "Chrome Beta" / "User Data"
_VIVALDI_USER_DATA = Path(_LOCAL) / "Vivaldi" / "User Data"

_ALL_CHROMIUM_PROFILES = [
    ("Chrome",  _CHROME_USER_DATA),
    ("Edge",    _EDGE_USER_DATA),
    ("Brave",   _BRAVE_USER_DATA),
    ("Opera",   _OPERA_USER_DATA),
    ("ChromeBeta", _CHROME_BETA_DATA),
    ("Vivaldi", _VIVALDI_USER_DATA),
]


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
    """
    Read Chrome/Edge history.  Three attempts in order:
      1. immutable=1 URI  — works while Chrome is open (shared read lock), no copy needed
      2. temp-dir copy    — copies History + WAL + SHM, merges WAL automatically
      3. plain read       — last resort fallback
    """
    import shutil, tempfile
    chrome_since = since_ts + int(11644473600 * 1_000_000)

    def _query(con) -> list[dict]:
        cur = con.execute(
            "SELECT url, title, last_visit_time FROM urls "
            "WHERE last_visit_time > ? ORDER BY last_visit_time",
            (chrome_since,)
        )
        return [{"url": u, "title": t or ""} for u, t, _ in cur.fetchall()]

    # ── Method 1: immutable URI (fastest, works with FILE_SHARE_READ) ──────────
    try:
        uri = f"file:{db_path.as_posix()}?mode=ro&immutable=1"
        con = sqlite3.connect(uri, uri=True, timeout=2)
        rows = _query(con)
        con.close()
        return rows
    except Exception:
        pass

    # ── Method 2: temp-dir copy including WAL (gets uncommitted Chrome writes) ──
    tmp_dir = None
    try:
        tmp_dir = Path(tempfile.mkdtemp())
        tmp_db  = tmp_dir / "History"
        shutil.copy2(str(db_path), str(tmp_db))
        for ext in ("-wal", "-shm"):
            src = db_path.with_name(db_path.name + ext)
            if src.exists():
                shutil.copy2(str(src), str(tmp_dir / ("History" + ext)))
        con  = sqlite3.connect(str(tmp_db), timeout=2)
        rows = _query(con)
        con.close()
        return rows
    except Exception:
        pass
    finally:
        if tmp_dir:
            shutil.rmtree(str(tmp_dir), ignore_errors=True)

    # ── Method 3: plain open (last resort) ────────────────────────────────────
    try:
        con  = sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True, timeout=2)
        rows = _query(con)
        con.close()
        return rows
    except Exception as e:
        _add_log(f"{Y}[BROWSER]{RST} Cannot read {db_path.parent.name}: {e}")
        return []


def _read_chrome_history_visits(db_path: Path, since_chrome_ts: int) -> list[dict]:
    """
    Read Chrome/Edge history using the visits table JOIN urls.
    The visits table is updated per-navigation-event (more immediate than last_visit_time).
    since_chrome_ts: Chrome FILETIME (microseconds since 1601-01-01)
    Falls back to urls.last_visit_time if visits table is unavailable.
    """
    import shutil, tempfile

    def _query(con) -> list[dict]:
        try:
            cur = con.execute(
                "SELECT u.url, u.title, v.visit_time "
                "FROM visits v JOIN urls u ON v.url = u.id "
                "WHERE v.visit_time > ? ORDER BY v.visit_time",
                (since_chrome_ts,)
            )
            return [{"url": u, "title": t or "", "visit_time": vt}
                    for u, t, vt in cur.fetchall()]
        except Exception:
            # Fallback to urls table
            cur = con.execute(
                "SELECT url, title, last_visit_time FROM urls "
                "WHERE last_visit_time > ? ORDER BY last_visit_time",
                (since_chrome_ts,)
            )
            return [{"url": u, "title": t or "", "visit_time": vt}
                    for u, t, vt in cur.fetchall()]

    # Method 1: temp-dir copy including WAL (WAL-aware — picks up visits Chrome
    # has written to WAL but not yet checkpointed into the main DB file).
    # This is the correct primary approach for Chrome's WAL-mode database.
    tmp_dir = None
    try:
        tmp_dir = Path(tempfile.mkdtemp())
        tmp_db = tmp_dir / "History"
        shutil.copy2(str(db_path), str(tmp_db))
        for ext in ("-wal", "-shm"):
            src = db_path.with_name(db_path.name + ext)
            if src.exists():
                shutil.copy2(str(src), str(tmp_dir / ("History" + ext)))
        con = sqlite3.connect(str(tmp_db), timeout=2)
        rows = _query(con)
        con.close()
        return rows
    except Exception:
        pass
    finally:
        if tmp_dir:
            shutil.rmtree(str(tmp_dir), ignore_errors=True)

    # Method 2: mode=ro (WAL-aware if Chrome allows shared reads)
    try:
        uri = f"file:{db_path.as_posix()}?mode=ro"
        con = sqlite3.connect(uri, uri=True, timeout=2)
        rows = _query(con)
        con.close()
        return rows
    except Exception:
        pass

    # Method 3: immutable=1 (bypasses WAL — reads stale main DB, last resort only)
    try:
        uri = f"file:{db_path.as_posix()}?mode=ro&immutable=1"
        con = sqlite3.connect(uri, uri=True, timeout=2)
        rows = _query(con)
        con.close()
        return rows
    except Exception as e:
        _add_log(f"{Y}[BROWSER]{RST} Cannot read {db_path.parent.name}: {e}")
        return []


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
        netloc = urlparse(url).netloc.lower()
        if netloc.startswith("www."):
            netloc = netloc[4:]
        return netloc
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
        self._interval = cfg.get("browser_poll_interval_seconds", 3)
        # High-water mark per DB path (Chrome FILETIME). Seeded from the DB's
        # own max visit_time in start() so no epoch arithmetic is needed.
        self._chrome_hwm: dict[str, int] = {}   # db_path_str → max visit_time seen
        # Firefox uses unix microseconds
        self._last_ff_ts: int = int(time.time() * 1_000_000)
        self._thread = threading.Thread(target=self._run, daemon=True, name="browser-monitor")

    def start(self):
        self._thread.start()
        _add_log(f"{G}[BROWSER MONITOR]{RST} Started (polling every {self._interval}s)")
        found_any = False
        for browser, user_data in _ALL_CHROMIUM_PROFILES:
            for db_path in _find_chrome_like_histories(user_data):
                _add_log(f"{G}[BROWSER]{RST} Found {browser} history: {db_path.parent.name}")
                found_any = True
                try:
                    # Read ALL history to seed the high-water mark from the DB's
                    # own timestamps — avoids any system clock / epoch conversion issue.
                    rows = _read_chrome_history_visits(db_path, 0)
                    if rows:
                        max_vt = max(r.get("visit_time", 0) for r in rows)
                        self._chrome_hwm[str(db_path)] = max_vt
                        _add_log(f"{G}[BROWSER]{RST} {browser} ready — "
                                 f"{len(rows)} visits in DB, cutoff set to "
                                 f"last visit ({_domain(rows[-1]['url'])})")
                    else:
                        self._chrome_hwm[str(db_path)] = 0
                        _add_log(f"{Y}[BROWSER]{RST} {browser} DB empty")
                except Exception as e:
                    self._chrome_hwm[str(db_path)] = 0
                    _add_log(f"{Y}[BROWSER]{RST} {browser} read failed: {e}")
        for db_path in _find_firefox_history():
            _add_log(f"{G}[BROWSER]{RST} Found Firefox history: {db_path.parent.name}")
            found_any = True
        if not found_any:
            _add_log(f"{Y}[BROWSER]{RST} No browser history DBs found")
            _add_log(f"{Y}[BROWSER]{RST} Web visits via DNS monitor only")

    def _run(self):
        while True:
            time.sleep(self._interval)
            self._poll()

    def _poll(self):
        visits = []
        # Deduplicate by domain within a single poll: Chrome creates multiple
        # rows in `visits` for one navigation (redirect chain), and Edge may
        # sync the same URL — we only want one event per domain per poll cycle.
        seen_domains: set[str] = set()
        now_ff_ts = int(time.time() * 1_000_000)

        for browser, user_data in _ALL_CHROMIUM_PROFILES:
            for db_path in _find_chrome_like_histories(user_data):
                key = str(db_path)
                hwm = self._chrome_hwm.get(key, 0)
                rows = _read_chrome_history_visits(db_path, hwm)
                for r in rows:
                    # Always advance the high-water mark so we don't re-read
                    vt = r.get("visit_time", 0)
                    if vt > self._chrome_hwm.get(key, 0):
                        self._chrome_hwm[key] = vt
                    domain = _domain(r["url"])
                    if domain and domain not in seen_domains:
                        seen_domains.add(domain)
                        visits.append({"url": r["url"], "title": r["title"], "browser": browser})

        for db_path in _find_firefox_history():
            rows = _read_firefox_history(db_path, self._last_ff_ts)
            for r in rows:
                domain = _domain(r["url"])
                if domain and domain not in seen_domains:
                    seen_domains.add(domain)
                    visits.append({"url": r["url"], "title": r["title"], "browser": "Firefox"})

        self._last_ff_ts = now_ff_ts

        if visits:
            blocked_count = sum(1 for v in visits if _classify_url(v["url"], self._cfg)[1])
            if blocked_count:
                _add_log(f"{R}[BROWSER]{RST} {len(visits)} URL(s) — {blocked_count} BLOCKED")
            else:
                _add_log(f"{DIM}[BROWSER]{RST} {len(visits)} new URL(s) detected")
        for visit in visits:
            self._handle_visit(visit)

    def _handle_visit(self, visit: dict):
        url = visit["url"]
        cat, is_blocked, is_suspicious = _classify_url(url, self._cfg)
        risky = is_blocked or cat in ("tor", "cloud_storage", "file_sharing")

        site_name = _domain(url)
        page_title = visit.get("title", "")

        # Detect Gmail compose/send from URL fragment or page title
        is_compose = any(p in url for p in ("#compose", "/compose", "#sent", "#drafts"))
        if is_compose and cat == "webmail":
            cat = "webmail"  # keep category, but note it in page_title
            if not page_title:
                page_title = "Gmail — Compose/Send"

        payload = _base(self._cfg, "web_proxy")
        payload.update({
            "source":     "web",
            "url":        url,
            "site_name":  site_name,
            "page_title": page_title or site_name,
            "category":   cat,
            "bytes_out":  0,
            "blocked":    is_blocked,
            "risky":      risky or is_compose,
            "browser":    visit.get("browser", "unknown"),
            "is_compose": is_compose,
        })
        enqueue_event(payload)

        if is_blocked:
            _record_behaviour("blocked_site", path=_domain(url))
            _check_threat_patterns(self._cfg)
            _stats["alerts"] += 1
            uid = self._cfg.get("user_id", "")
            _screenshot_last[uid] = 0  # Force screenshot bypass — blocked site always gets a screenshot
            print(f"\n{R}{'!'*50}{RST}")
            print(f"{R}  BLOCKED SITE DETECTED: {_domain(url)}{RST}")
            print(f"{R}  Sending critical event to InsightGuard...{RST}")
            print(f"{R}{'!'*50}{RST}\n")
            _add_log(f"{R}[BLOCKED]{RST} {_domain(url)} — {cat}")
        elif is_compose:
            _add_log(f"{Y}[WEBMAIL]{RST} {site_name} — compose/send detected")
        elif cat == "webmail":
            _add_log(f"{Y}[WEBMAIL]{RST} {site_name} — {page_title or cat}")
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
            payload = _base(self._cfg, "web_proxy")
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
            payload = _base(self._cfg, "web_proxy")
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
        _warned = False
        while True:
            try:
                await self._cdp_session()
                _warned = False   # reset if we ever successfully connect
            except Exception:
                if not _warned:
                    _add_log(f"{DIM}[CDP]{RST} Upload detection disabled "
                             f"(start Chrome with --remote-debugging-port=9222 to enable)")
                    _warned = True
            await asyncio.sleep(60)

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
        payload = _base(self._cfg, "web_proxy")
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
# Outlook email monitoring (COM event hook)
# ══════════════════════════════════════════════════════════════════════════════

class OutlookMonitor:
    """
    Hooks into Microsoft Outlook via COM and fires an email event to
    InsightGuard every time the user sends an email.

    Uses company_domain from config.json to decide internal vs external:
      - recipient @same domain  → external: False  (normal)
      - recipient @other domain → external: True   (suspicious/critical)

    Fails silently if Outlook is not installed or not running.
    """

    def __init__(self, cfg: dict):
        self._cfg            = cfg
        self._company_domain = cfg.get("company_domain", "").lower().strip()
        self._thread         = threading.Thread(
            target=self._run, daemon=True, name="outlook-monitor"
        )

    def start(self):
        self._thread.start()

    def _run(self):
        if platform.system() != "Windows":
            _add_log(f"{DIM}[OUTLOOK]{RST} Not Windows — email monitoring skipped")
            return

        try:
            import pythoncom
            import win32com.client
        except ImportError:
            _add_log(f"{Y}[OUTLOOK]{RST} pywin32 not available — email monitoring disabled")
            return

        try:
            pythoncom.CoInitialize()
        except Exception:
            pass

        try:
            outlook = win32com.client.Dispatch("Outlook.Application")
            ns      = outlook.GetNamespace("MAPI")
            sent_folder = ns.GetDefaultFolder(5)   # 5 = olFolderSentMail
        except Exception as e:
            _add_log(f"{Y}[OUTLOOK]{RST} Outlook not running or not installed — {e}")
            return

        # Seed seen_ids with emails already in Sent Items so we don't
        # re-report emails sent before the agent started.
        seen_ids: set = set()
        try:
            items = sent_folder.Items
            for i in range(1, min(items.Count + 1, 201)):
                try:
                    seen_ids.add(items.Item(i).EntryID)
                except Exception:
                    pass
        except Exception:
            pass

        _add_log(
            f"{G}[OUTLOOK MONITOR]{RST} Polling Sent Items every 10 s "
            f"({len(seen_ids)} existing emails ignored)"
        )

        import time as _t
        while True:
            try:
                items = sent_folder.Items
                items.Sort("[SentOn]", True)   # newest first

                new_items = []
                for i in range(1, items.Count + 1):
                    try:
                        item = items.Item(i)
                        eid  = item.EntryID
                        if eid in seen_ids:
                            break   # sorted newest-first: once we hit a known ID, stop
                        seen_ids.add(eid)
                        new_items.append(item)
                    except Exception:
                        pass

                for item in reversed(new_items):   # process oldest-first
                    try:
                        recipient_count = item.Recipients.Count

                        attachment_mb = 0.0
                        for i in range(1, item.Attachments.Count + 1):
                            try:
                                attachment_mb += item.Attachments.Item(i).Size / 1_048_576
                            except Exception:
                                pass

                        external = False
                        company_domain = self._company_domain
                        if company_domain:
                            for i in range(1, recipient_count + 1):
                                try:
                                    recip = item.Recipients.Item(i)
                                    addr  = ""
                                    try:
                                        addr = recip.Address.lower()
                                    except Exception:
                                        pass
                                    # Exchange GAL addresses start with /o= — resolve to SMTP
                                    if not addr or addr.startswith("/o="):
                                        try:
                                            addr = (recip.AddressEntry
                                                        .GetExchangeUser()
                                                        .PrimarySmtpAddress.lower())
                                        except Exception:
                                            pass
                                    if addr and "@" in addr:
                                        if addr.split("@")[1] != company_domain:
                                            external = True
                                            break
                                except Exception:
                                    pass

                        payload = _base(self._cfg, "mail_gateway")
                        payload.update({
                            "source":          "email",
                            "direction":       "sent",
                            "recipient_count": recipient_count,
                            "attachment_mb":   round(attachment_mb, 2),
                            "external":        external,
                        })
                        enqueue_event(payload)

                        if external:
                            _add_log(f"{R}[EMAIL — EXTERNAL]{RST} "
                                     f"{recipient_count} recipient(s), "
                                     f"{attachment_mb:.1f} MB attachment")
                        else:
                            _add_log(f"{C}[EMAIL — INTERNAL]{RST} "
                                     f"{recipient_count} recipient(s), "
                                     f"{attachment_mb:.1f} MB attachment")
                    except Exception:
                        pass

            except Exception as e:
                _add_log(f"{Y}[OUTLOOK]{RST} Poll error: {e}")

            _t.sleep(10)   # poll every 10 seconds


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

    # Start archive poll monitor (catches zips created anywhere in the user profile,
    # not just in the three watchdog-monitored folders)
    archive_poll = ArchivePollMonitor(cfg)
    archive_poll.start()

    # Start USB monitor
    usb_mon = USBMonitor(cfg)
    usb_mon.start()

    # Start DNS monitor (catches ALL browser visits without touching browser files)
    dns_mon = DnsMonitor(cfg)
    dns_mon.start()

    # Start browser history monitor (Chrome/Edge/Firefox SQLite polling)
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

    # Start Outlook email monitor (COM event hook — fires on every sent email)
    outlook_mon = OutlookMonitor(cfg)
    outlook_mon.start()

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
