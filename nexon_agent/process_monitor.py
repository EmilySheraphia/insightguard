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

    if "wevtutil" in cl and re.search(r'\bcl\b|\bclear-log\b', cl):
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

        # Skip normal process launches — only report dangerous events
        if event_type == "process_launch":
            return

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
                "source":            "process",
                "activity_type":     event_type,
                "severity_override": severity,
            })

        self._enqueue(payload)

        colours = {"critical": "\033[91m", "suspicious": "\033[93m", "normal": "\033[2m"}
        c   = colours.get(severity, "")
        RST = "\033[0m"
        self._log(f"{c}[PROCESS]{RST} {event_type.upper()} — {name} (PID {pid}): {cmdline_str[:80]}")
