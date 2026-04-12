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
_started: bool = False


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
    """Seed cache, do one immediate fetch, then start background thread.
    Safe to call multiple times — only the first call starts the thread.
    """
    global _started
    if _started:
        return
    _started = True
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
