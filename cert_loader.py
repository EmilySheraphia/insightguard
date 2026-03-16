"""
InsightGuard — CERT Dataset Loader
====================================
Reads the CERT Insider Threat Dataset r4.2 CSV files and converts
each row into the exact format the existing 6-layer pipeline expects.

Supported files:
  logon.csv      → LoginCollector
  file.csv       → FileAccessCollector
  email.csv      → EmailCollector
  device.csv     → USBCollector
  http.csv       → WebCollector
  psychometric.csv → User profiles

Usage:
  PYTHONPATH=. python cert_loader.py
"""

import os
import sys
import csv
import sqlite3
from datetime import datetime
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))

from data_acquisition.collector    import AcquisitionRouter
from data_processing.etl_pipeline  import ETLPipeline
from feature_engineering.extractor import FeatureEngineering
from ai_analytics.anomaly_model    import AnomalyDetectionModel
from storage.database              import DatabaseManager

# ── Config ────────────────────────────────────────────────────────────────────

CERT_DIR   = Path.home() / "Downloads" / "r4.2"
MAX_ROWS   = 5000   # rows per file — increase if you want more data
BATCH_SIZE = 200    # process in batches for speed

# Known risky URL categories from CERT research
RISKY_DOMAINS = {
    "wikileaks", "dropbox", "megaupload", "rapidshare", "mediafire",
    "sendspace", "4shared", "filefactory", "depositfiles", "hotfile",
    "torrent", "thepiratebay", "kickass", "isohunt", "btjunkie",
    "gmail", "yahoo", "hotmail", "protonmail",
}

# ── Helpers ───────────────────────────────────────────────────────────────────

def parse_cert_date(date_str: str) -> str:
    """Convert CERT date format '01/02/2010 06:49:00' to ISO-8601."""
    try:
        dt = datetime.strptime(date_str.strip(), "%m/%d/%Y %H:%M:%S")
        return dt.isoformat()
    except ValueError:
        return datetime.now().isoformat()


def is_risky_url(url: str) -> bool:
    url_lower = url.lower()
    return any(domain in url_lower for domain in RISKY_DOMAINS)


def get_country_for_user(user_id: str) -> str:
    """Default all CERT users to US — dataset is US-based organisation."""
    return "US"


# ── File loaders ──────────────────────────────────────────────────────────────

def load_logon(path: Path, max_rows: int) -> list[dict]:
    """
    logon.csv columns: id, date, user, pc, activity
    activity values: Logon, Logoff
    """
    rows = []
    print(f"  Reading logon.csv...")
    with open(path, newline="", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader):
            if i >= max_rows:
                break
            activity = row.get("activity", "Logon").strip()
            rows.append({
                "source":          "login",
                "user_id":         row["user"].strip(),
                "timestamp":       parse_cert_date(row["date"]),
                "event":           "login" if activity == "Logon" else "logoff",
                "country_code":    "US",
                "device_id":       row.get("pc", "").strip(),
                "failed_attempts": 0,
                "new_device":      False,
                "vpn":             False,
                "tor":             False,
                "_cert_id":        row.get("id", ""),
            })
    print(f"    Loaded {len(rows)} logon events")
    return rows


def load_file(path: Path, max_rows: int) -> list[dict]:
    """
    file.csv columns: id, date, user, pc, filename, content
    """
    rows = []
    print(f"  Reading file.csv...")
    with open(path, newline="", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader):
            if i >= max_rows:
                break
            filename = row.get("filename", "").strip()
            # Estimate file size from content length
            content  = row.get("content", "")
            data_mb  = round(len(content.encode()) / 1_048_576, 4)
            # Flag suspicious destinations
            dest = "usb" if any(x in filename.upper()
                                for x in ["USB", "REMOVABLE", "E:\\", "F:\\"]) else "local"
            rows.append({
                "source":      "file",
                "user_id":     row["user"].strip(),
                "timestamp":   parse_cert_date(row["date"]),
                "file_path":   filename,
                "operation":   "read",
                "file_count":  1,
                "data_mb":     max(data_mb, 0.001),
                "destination": dest,
                "_cert_id":    row.get("id", ""),
            })
    print(f"    Loaded {len(rows)} file events")
    return rows


def load_email(path: Path, max_rows: int) -> list[dict]:
    """
    email.csv columns: id, date, user, pc, to, cc, bcc, from, size, attachments, content
    """
    rows = []
    print(f"  Reading email.csv...")
    with open(path, newline="", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader):
            if i >= max_rows:
                break
            to_field    = row.get("to", "")
            cc_field    = row.get("cc", "")
            recipients  = [r for r in (to_field + ";" + cc_field).split(";") if r.strip()]
            # Check if any recipient is external (different domain)
            from_addr   = row.get("from", "")
            from_domain = from_addr.split("@")[-1] if "@" in from_addr else ""
            external    = any(
                from_domain and r.strip().split("@")[-1] != from_domain
                for r in recipients if "@" in r
            )
            size_bytes  = int(row.get("size", 0) or 0)
            attachments = int(row.get("attachments", 0) or 0)
            rows.append({
                "source":          "email",
                "user_id":         row["user"].strip(),
                "timestamp":       parse_cert_date(row["date"]),
                "direction":       "sent",
                "recipient_count": len(recipients),
                "attachment_count":attachments,
                "attachment_mb":   round(size_bytes / 1_048_576, 4),
                "external":        external,
                "_cert_id":        row.get("id", ""),
            })
    print(f"    Loaded {len(rows)} email events")
    return rows


def load_device(path: Path, max_rows: int) -> list[dict]:
    """
    device.csv columns: id, date, user, pc, activity
    activity values: Connect, Disconnect
    """
    rows = []
    print(f"  Reading device.csv...")
    with open(path, newline="", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader):
            if i >= max_rows:
                break
            activity = row.get("activity", "Connect").strip()
            if activity != "Connect":
                continue   # only count insertions, not removals
            rows.append({
                "source":    "usb",
                "user_id":   row["user"].strip(),
                "timestamp": parse_cert_date(row["date"]),
                "device_id": row.get("pc", "").strip(),
                "operation": "insert",
                "data_mb":   0.0,   # r4.2 doesn't include transfer volume
                "_cert_id":  row.get("id", ""),
            })
    print(f"    Loaded {len(rows)} device events")
    return rows


def load_http(path: Path, max_rows: int) -> list[dict]:
    """
    http.csv columns: id, date, user, pc, url, content
    """
    rows = []
    print(f"  Reading http.csv...")
    with open(path, newline="", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader):
            if i >= max_rows:
                break
            url      = row.get("url", "").strip()
            content  = row.get("content", "")
            risky    = is_risky_url(url)
            category = "file_sharing" if risky else "general"
            rows.append({
                "source":    "web",
                "user_id":   row["user"].strip(),
                "timestamp": parse_cert_date(row["date"]),
                "url":       url,
                "category":  category,
                "bytes_out": len(content.encode()),
                "blocked":   False,
                "_cert_id":  row.get("id", ""),
            })
    print(f"    Loaded {len(rows)} http events")
    return rows


def load_psychometric(path: Path) -> dict[str, dict]:
    """
    psychometric.csv columns: employee_name, user_id, O, C, E, A, N
    Returns dict keyed by user_id.
    """
    profiles = {}
    print(f"  Reading psychometric.csv...")
    with open(path, newline="", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        for row in reader:
            uid = row.get("user_id", "").strip()
            if uid:
                profiles[uid] = {
                    "name":       row.get("employee_name", "").strip(),
                    "user_id":    uid,
                    "openness":   int(row.get("O", 50) or 50),
                    "conscientiousness": int(row.get("C", 50) or 50),
                    "extraversion":     int(row.get("E", 50) or 50),
                    "agreeableness":    int(row.get("A", 50) or 50),
                    "neuroticism":      int(row.get("N", 50) or 50),
                }
    print(f"    Loaded {len(profiles)} user profiles")
    return profiles


# ── Main loader ───────────────────────────────────────────────────────────────

class CERTLoader:
    """
    Loads CERT r4.2 dataset through the full InsightGuard pipeline.
    """

    def __init__(self, cert_dir: Path = CERT_DIR, max_rows: int = MAX_ROWS):
        self.cert_dir  = cert_dir
        self.max_rows  = max_rows
        self.router    = AcquisitionRouter()
        self.pipeline  = ETLPipeline()
        self.fe        = FeatureEngineering()
        self.model     = AnomalyDetectionModel()
        self.db        = DatabaseManager()

    def load(self):
        print("\n" + "="*60)
        print("  InsightGuard — CERT Dataset Loader")
        print("="*60)
        print(f"\n  Dataset path : {self.cert_dir}")
        print(f"  Max rows/file: {self.max_rows}\n")

        # ── Load user profiles first ──────────────────────────────────────
        psych_path = self.cert_dir / "psychometric.csv"
        profiles   = {}
        if psych_path.exists():
            profiles = load_psychometric(psych_path)
            for uid, p in profiles.items():
                self.db.upsert_user(uid, "Unknown", p["name"])

        # ── Load all 5 event sources ──────────────────────────────────────
        all_events = []

        loaders = [
            (self.cert_dir / "logon.csv",  load_logon),
            (self.cert_dir / "file.csv",   load_file),
            (self.cert_dir / "email.csv",  load_email),
            (self.cert_dir / "device.csv", load_device),
            (self.cert_dir / "http.csv",   load_http),
        ]

        for path, loader_fn in loaders:
            if path.exists():
                events = loader_fn(path, self.max_rows)
                all_events.extend(events)
            else:
                print(f"  WARNING: {path.name} not found — skipping")

        # Sort all events by timestamp
        print(f"\n  Total raw events loaded : {len(all_events)}")
        print(f"  Sorting by timestamp...")
        all_events.sort(key=lambda e: e.get("timestamp", ""))

        # ── Process through 6-layer pipeline ─────────────────────────────
        print(f"\n  Processing through ML pipeline...")
        print(f"  (This may take a few minutes for large datasets)\n")

        stats = {
            "processed":  0,
            "errors":     0,
            "normal":     0,
            "suspicious": 0,
            "high_risk":  0,
            "critical":   0,
        }

        for i, raw in enumerate(all_events):
            try:
                # Remove internal keys before passing to router
                cert_id = raw.pop("_cert_id", "")
                user_id = raw.get("user_id", "unknown")

                # Layer 1: Acquire
                activity = self.router.route(raw)

                # Layer 2: Process
                log = self.pipeline.process(activity)
                if not log.is_valid:
                    stats["errors"] += 1
                    continue

                # Layer 3: Feature engineering
                fv = self.fe.extractFeatures(log)

                # Layer 4: AI detection
                result = self.model.detectAnomaly(log)

                # Storage
                dept = profiles.get(user_id, {}).get("name", "")
                self.db.upsert_user(user_id, dept, "")
                self.db.insert_activity_log(
                    log.log_id, user_id, log.timestamp.isoformat(),
                    log.activity_type, log.source, details=fv.to_dict()
                )
                self.db.insert_features(
                    "ft_"+log.log_id, user_id, log.log_id, fv.to_dict()
                )
                det_id = "dt_"+log.log_id
                self.db.insert_anomaly_result(det_id, user_id, log.log_id, result)

                # Store alerts for suspicious+ events
                if result["is_anomaly"]:
                    alert_id = "al_"+log.log_id[:10]
                    summary  = ("Rules: " + ", ".join(result["triggered_rules"][:3])
                                if result["triggered_rules"] else "Anomaly detected")
                    self.db.insert_alert(
                        alert_id, user_id, det_id,
                        result["severity"], log.activity_type, summary
                    )

                # Count severities
                stats["processed"] += 1
                stats[result["severity"]] = stats.get(result["severity"], 0) + 1

                # Progress update every 500 events
                if (i + 1) % 500 == 0:
                    pct = round((i + 1) / len(all_events) * 100)
                    print(f"  [{pct:>3}%] Processed {i+1:,} / {len(all_events):,} events  "
                          f"| threats: {stats['suspicious']+stats['high_risk']+stats['critical']}")

            except Exception as e:
                stats["errors"] += 1
                continue

        # ── Final report ──────────────────────────────────────────────────
        total_threats = stats["suspicious"] + stats["high_risk"] + stats["critical"]
        detection_rate = round(total_threats / max(stats["processed"], 1) * 100, 2)

        print(f"\n{'='*60}")
        print(f"  CERT Dataset Load Complete")
        print(f"{'='*60}")
        print(f"  Events processed : {stats['processed']:,}")
        print(f"  Errors skipped   : {stats['errors']:,}")
        print(f"  Normal           : {stats['normal']:,}")
        print(f"  Suspicious       : {stats['suspicious']:,}")
        print(f"  High risk        : {stats['high_risk']:,}")
        print(f"  Critical         : {stats['critical']:,}")
        print(f"  Total threats    : {total_threats:,}")
        print(f"  Detection rate   : {detection_rate}%")
        print(f"  Saved to         : storage/insightguard.db")
        print(f"{'='*60}\n")
        print(f"  Start the dashboard and connect to see real CERT detections.")
        print(f"  Run: PYTHONPATH=. python application/app.py\n")

        return stats


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Load CERT dataset into InsightGuard")
    parser.add_argument("--dir",      default=str(CERT_DIR),
                        help="Path to CERT dataset folder")
    parser.add_argument("--max-rows", type=int, default=MAX_ROWS,
                        help="Max rows per CSV file (default 5000)")
    args = parser.parse_args()

    loader = CERTLoader(
        cert_dir=Path(args.dir),
        max_rows=args.max_rows,
    )
    loader.load()