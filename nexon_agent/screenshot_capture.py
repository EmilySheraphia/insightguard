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

    EVIDENCE_DIR = Path(__file__).parent / "evidence"

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
                # Explicit BGRA → RGB conversion (avoids "BGRX" raw decoder
                # compatibility issues across Pillow versions)
                img = Image.frombytes("RGBA", (shot.width, shot.height), bytes(shot.bgra))
                r, g, b, a = img.split()
                img = Image.merge("RGB", (b, g, r))   # BGRA → RGB channel reorder
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
