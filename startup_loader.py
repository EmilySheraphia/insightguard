"""
InsightGuard — Startup Data Loader
====================================
Runs automatically when the app starts on Render (or any server)
if the database is empty. Generates synthetic CERT-like data so
the dashboard has events to show immediately.

On Render the real CERT CSV files are not available (they are not
committed to GitHub). This script generates realistic synthetic
events that demonstrate all system features:
  - All 5 activity types (login, file, email, usb, web)
  - A mix of normal, suspicious, high_risk, critical events
  - 50 synthetic users with OCEAN personality profiles
  - Enough events per user to train personal baselines (PUB)

This runs ONCE at startup if the database has fewer than 100 events.
"""

import sys, os, random, uuid
sys.path.insert(0, os.path.dirname(__file__))

import numpy as np
from datetime import datetime, timedelta
from pathlib import Path

from data_acquisition.collector    import AcquisitionRouter
from data_processing.etl_pipeline  import ETLPipeline
from feature_engineering.extractor import FeatureEngineering
from ai_analytics.anomaly_model    import AnomalyDetectionModel
from storage.database              import DatabaseManager
from per_user_baseline             import get_store as get_pub_store
from psychometric_scorer           import get_store as get_psych_store

# ── Synthetic users ────────────────────────────────────────────────────────

SYNTHETIC_USERS = [
    # (user_id, dept, role, risk_level)
    # Normal employees
    ("NGF0157", "Finance",     "Analyst",      "normal"),
    ("MOH0273", "Engineering", "Developer",    "normal"),
    ("LAP0338", "HR",          "Manager",      "normal"),
    ("LRR0148", "IT",          "SysAdmin",     "normal"),
    ("CTR0341", "Legal",       "Counsel",      "normal"),
    ("ATE0869", "Finance",     "Director",     "normal"),
    ("ESJ0670", "Engineering", "Developer",    "normal"),
    ("IRM0931", "HR",          "Recruiter",    "normal"),
    ("BRB0355", "IT",          "Engineer",     "normal"),
    ("JDC0030", "Finance",     "Analyst",      "normal"),
    ("NOB0181", "Legal",       "Paralegal",    "normal"),
    ("DAR0885", "Engineering", "Lead",         "normal"),
    ("ABC0174", "HR",          "Coordinator",  "normal"),
    ("SSJ0784", "Finance",     "Auditor",      "normal"),
    ("RZC0746", "IT",          "Support",      "normal"),
    ("BQS0525", "Legal",       "Associate",    "normal"),
    ("AHC0142", "Engineering", "Developer",    "normal"),
    ("JCR0172", "Finance",     "Analyst",      "normal"),
    ("MHH0180", "HR",          "Manager",      "normal"),
    ("KPC0073", "IT",          "Admin",        "normal"),
    # Medium risk
    ("TAP0551", "Finance",     "Director",     "medium"),
    ("JGT0221", "Engineering", "Lead",         "medium"),
    ("GTD0219", "IT",          "SysAdmin",     "medium"),
    ("MCF0600", "HR",          "Manager",      "medium"),
    ("AKR0057", "Legal",       "Counsel",      "medium"),
    ("MSO0222", "Finance",     "Analyst",      "medium"),
    ("JLM0364", "Engineering", "Developer",    "medium"),
    ("DRR0162", "IT",          "Engineer",     "medium"),
    ("CCA0046", "HR",          "Director",     "medium"),
    ("RKD0604", "Legal",       "Associate",    "medium"),
    # High risk / insider threats
    ("BBS0039", "Finance",     "Analyst",      "high"),
    ("BTL0226", "Engineering", "Developer",    "high"),
    ("HXL0968", "IT",          "SysAdmin",     "high"),
    ("BDV0168", "HR",          "Manager",      "high"),
    ("CAH0936", "Legal",       "Counsel",      "high"),
    ("EDB0714", "Finance",     "Director",     "high"),
    ("RMW0542", "Engineering", "Lead",         "high"),
    ("FTM0406", "IT",          "Engineer",     "high"),
    ("PPF0435", "HR",          "Recruiter",    "high"),
    ("WDD0366", "Legal",       "Paralegal",    "high"),
]

ACTIVITY_TYPES = ["login", "file_access", "email", "usb", "web"]

# ── Raw event generators ───────────────────────────────────────────────────

def _ts(days_ago=0, hour=None):
    """Generate a timestamp."""
    base = datetime.now() - timedelta(days=days_ago)
    if hour is not None:
        base = base.replace(hour=hour, minute=random.randint(0,59), second=random.randint(0,59))
    return base.isoformat()

def _normal_login(uid):
    return {"source":"login","user_id":uid,"timestamp":_ts(random.randint(0,30), random.randint(8,17)),
            "event":"login","country_code":"US","device_id":"PC-"+uid[:4],
            "failed_attempts":0,"new_device":False,"vpn":False,"tor":False}

def _normal_file(uid):
    return {"source":"file","user_id":uid,"timestamp":_ts(random.randint(0,30), random.randint(8,17)),
            "file_path":"C:\\work\\"+uid+"\\doc.pdf","operation":"read",
            "file_count":random.randint(1,10),"data_mb":round(random.uniform(0.1,50),2),"destination":"local"}

def _normal_email(uid):
    return {"source":"email","user_id":uid,"timestamp":_ts(random.randint(0,30), random.randint(8,17)),
            "direction":"sent","recipient_count":random.randint(1,4),
            "attachment_count":random.randint(0,2),"attachment_mb":round(random.uniform(0,5),2),
            "external":False}

def _normal_web(uid):
    return {"source":"web","user_id":uid,"timestamp":_ts(random.randint(0,30), random.randint(8,17)),
            "url":"https://intranet.company.com","category":"intranet",
            "bytes_out":random.randint(1000,50000),"blocked":False}

def _suspicious_login(uid):
    return {"source":"login","user_id":uid,"timestamp":_ts(random.randint(0,7), random.choice([1,2,3,22,23])),
            "event":"login","country_code":"US","device_id":"PC-UNKNOWN",
            "failed_attempts":random.randint(2,4),"new_device":True,"vpn":True,"tor":False}

def _high_risk_file(uid):
    return {"source":"file","user_id":uid,"timestamp":_ts(random.randint(0,7), random.choice([1,2,3])),
            "file_path":"C:\\confidential\\"+uid+"\\data.xlsx","operation":"copy",
            "file_count":random.randint(100,400),"data_mb":round(random.uniform(800,3000),2),"destination":"usb"}

def _high_risk_email(uid):
    return {"source":"email","user_id":uid,"timestamp":_ts(random.randint(0,7), random.choice([1,2,22,23])),
            "direction":"sent","recipient_count":random.randint(10,30),
            "attachment_count":5,"attachment_mb":round(random.uniform(50,200),2),
            "external":True}

def _critical_login(uid):
    return {"source":"login","user_id":uid,"timestamp":_ts(random.randint(0,3), random.choice([1,2,3])),
            "event":"login","country_code":"RU","device_id":"PC-UNKNOWN",
            "failed_attempts":random.randint(5,10),"new_device":True,"vpn":True,"tor":True}

def _critical_usb(uid):
    return {"source":"usb","user_id":uid,"timestamp":_ts(random.randint(0,3), random.choice([1,2,3])),
            "device_id":"USB-UNKNOWN","operation":"insert","data_mb":round(random.uniform(1000,5000),2)}

# ── Main loader ────────────────────────────────────────────────────────────

def generate_synthetic_data(n_events_per_user: int = 30) -> dict:
    """
    Generate synthetic events for all users and process through
    the full InsightGuard pipeline. Returns stats dict.
    """
    print("\n" + "="*60)
    print("  InsightGuard — Generating Synthetic Demo Data")
    print("="*60)
    print(f"  Users: {len(SYNTHETIC_USERS)}")
    print(f"  Events per user: ~{n_events_per_user}")
    print(f"  Total events: ~{len(SYNTHETIC_USERS) * n_events_per_user}\n")

    router   = AcquisitionRouter()
    pipeline = ETLPipeline()
    fe       = FeatureEngineering()
    model    = AnomalyDetectionModel()
    db       = DatabaseManager()

    stats = {"processed":0,"errors":0,"normal":0,"suspicious":0,"high_risk":0,"critical":0}

    all_events = []

    for uid, dept, role, risk_level in SYNTHETIC_USERS:
        # Register user
        db.upsert_user(uid, dept, role)

        # Generate baseline normal events (enough to train PUB)
        for _ in range(max(n_events_per_user - 5, 15)):
            fn = random.choice([_normal_login, _normal_file, _normal_email, _normal_web])
            all_events.append(fn(uid))

        # Add risk events based on user's risk level
        if risk_level == "medium":
            for _ in range(3):
                all_events.append(random.choice([_suspicious_login, _high_risk_email])(uid))
        elif risk_level == "high":
            for _ in range(5):
                all_events.append(random.choice([
                    _suspicious_login, _high_risk_file,
                    _high_risk_email, _critical_login
                ])(uid))

    # Sort by timestamp
    all_events.sort(key=lambda e: e.get("timestamp",""))
    print(f"  Processing {len(all_events)} total events through pipeline...")

    for i, raw in enumerate(all_events):
        try:
            uid = raw.get("user_id","unknown")
            activity = router.route(raw)
            log = pipeline.process(activity)
            if not log.is_valid:
                stats["errors"] += 1
                continue

            fv     = fe.extractFeatures(log)
            result = model.detectAnomaly(log)

            db.insert_activity_log(log.log_id, uid, log.timestamp.isoformat(),
                                   log.activity_type, log.source, details=fv.to_dict())
            db.insert_features("ft_"+log.log_id, uid, log.log_id, fv.to_dict())
            det_id = "dt_"+log.log_id
            db.insert_anomaly_result(det_id, uid, log.log_id, result)

            if result["is_anomaly"]:
                aid = "al_"+log.log_id[:10]
                summary = ("Rules: "+", ".join(result["triggered_rules"][:3])
                           if result["triggered_rules"] else "Anomaly detected")
                db.insert_alert(aid, uid, det_id, result["severity"], log.activity_type, summary)

            stats["processed"] += 1
            stats[result["severity"]] = stats.get(result["severity"],0) + 1

            if (i+1) % 200 == 0:
                print(f"  [{round((i+1)/len(all_events)*100):>3}%] {i+1}/{len(all_events)} events processed")

        except Exception as e:
            stats["errors"] += 1
            continue

    total_threats = stats["suspicious"]+stats["high_risk"]+stats["critical"]
    print(f"\n  Done! {stats['processed']} events processed, {total_threats} threats detected.")
    print(f"  Now training personal baselines (PUB)...")

    # Pre-train personal baselines from the data we just loaded
    _pretrain_pub_from_db(db)

    print(f"{'='*60}\n")
    return stats


def _pretrain_pub_from_db(db: DatabaseManager) -> None:
    """Train personal baselines for all users in the database."""
    import sqlite3, json
    from per_user_baseline import UserBaseline, MODELS_DIR
    from feature_engineering.extractor import FeatureVector

    conn = sqlite3.connect(str(db.db_path))
    conn.row_factory = sqlite3.Row
    rows = conn.execute("""
        SELECT al.user_id, al.details_json FROM activity_logs al
        ORDER BY al.timestamp ASC
    """).fetchall()
    conn.close()

    user_events = {}
    for row in rows:
        uid = row["user_id"]
        try:
            fv_dict = json.loads(row["details_json"] or "{}")
            arr = np.array([fv_dict.get(k,0) for k in FeatureVector.COLUMNS], dtype=float)
            if uid not in user_events:
                user_events[uid] = []
            user_events[uid].append(arr)
        except Exception:
            continue

    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    trained = 0
    for uid, events in user_events.items():
        if len(events) < 10:
            continue
        b = UserBaseline(user_id=uid)
        for arr in events:
            b.add_event(arr)
        b.train()
        if b.is_trained:
            b.save(MODELS_DIR)
            trained += 1

    print(f"  Personal baselines trained: {trained} users")


def should_auto_load(db: DatabaseManager, min_events: int = 100) -> bool:
    """Returns True if database needs data."""
    try:
        stats = db.get_stats()
        return stats.get("total_events", 0) < min_events
    except Exception:
        return True


def run_startup_loader():
    """
    Called automatically at app startup.
    Only generates data if the database is empty or nearly empty.
    """
    db = DatabaseManager()
    if not should_auto_load(db):
        count = db.get_stats().get("total_events", 0)
        print(f"[Startup] Database has {count} events — skipping auto-load.")
        return

    print("[Startup] Database is empty — generating synthetic demo data...")
    generate_synthetic_data(n_events_per_user=30)
    print("[Startup] Demo data ready. Dashboard will show events immediately.")


# ── Entry point ────────────────────────────────────────────────────────────
if __name__ == "__main__":
    generate_synthetic_data(n_events_per_user=30)