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
    "card_number":        re.compile(r'\b(?:\d[ -]?){13,19}\b'),
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
        self._lock         = threading.Lock()
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
        with self._lock:
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
        with self._lock:
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
