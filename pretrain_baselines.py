"""
InsightGuard — Pre-Train Personal Baselines
=============================================
Run this ONCE before your demo to train all personal Isolation Forest
models for every user in the CERT dataset.

After running this script:
  - All user models saved to storage/user_baselines/
  - When you start app.py, models load automatically
  - Dashboard shows ✓ (Personal Model trained) from the very first event
  - No waiting for 10 events to accumulate during demo

Usage:
  PYTHONPATH=. python pretrain_baselines.py

Options:
  --max-rows 5000    how many CERT rows to use per file (default 5000)
  --cert-dir PATH    path to CERT r4.2 folder (default ~/Downloads/r4.2)
"""

import sys, os, argparse
sys.path.insert(0, os.path.dirname(__file__))

import sqlite3
import json
import numpy as np
from pathlib import Path
from datetime import datetime

from feature_engineering.extractor import FeatureVector
from per_user_baseline import PerUserBaselineStore, MODELS_DIR


def pretrain_from_database(db_path: Path, models_dir: Path) -> dict:
    """
    Load all existing activity logs from the database,
    group by user, and train a personal model for each user.
    """
    print("\n" + "="*60)
    print("  InsightGuard — Pre-Training Personal Baselines")
    print("="*60)
    print(f"\n  Database : {db_path}")
    print(f"  Models   : {models_dir}")

    if not db_path.exists():
        print(f"\n  ERROR: Database not found at {db_path}")
        print(f"  Run: PYTHONPATH=. python cert_loader.py  first.\n")
        return {}

    # Load all feature vectors grouped by user
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row

    print(f"\n  Loading activity logs from database...")
    rows = conn.execute("""
        SELECT al.user_id, al.details_json, al.timestamp
        FROM activity_logs al
        ORDER BY al.timestamp ASC
    """).fetchall()
    conn.close()

    print(f"  Total events in database : {len(rows):,}")

    # Group feature vectors by user
    user_events: dict[str, list] = {}
    skipped = 0
    for row in rows:
        uid = row["user_id"]
        try:
            fv_dict = json.loads(row["details_json"] or "{}")
            arr = np.array(
                [fv_dict.get(k, 0) for k in FeatureVector.COLUMNS],
                dtype=float
            )
            if uid not in user_events:
                user_events[uid] = []
            user_events[uid].append(arr)
        except Exception:
            skipped += 1

    print(f"  Unique users found       : {len(user_events):,}")
    print(f"  Skipped (bad data)       : {skipped:,}")
    print(f"\n  Training personal models...")

    # Create store and train each user
    store = PerUserBaselineStore(models_dir=models_dir)
    models_dir.mkdir(parents=True, exist_ok=True)

    trained   = 0
    skipped_u = 0
    stats     = {"trained": 0, "skipped": 0, "total_events": 0}

    for uid, events in sorted(user_events.items()):
        if len(events) < 10:
            skipped_u += 1
            continue

        # Add all events to the baseline
        from per_user_baseline import UserBaseline
        b = UserBaseline(user_id=uid)
        for arr in events:
            b.add_event(arr)

        # Train the model
        b.train()

        if b.is_trained:
            b.save(models_dir)
            trained += 1
            stats["total_events"] += len(events)

            # Progress every 50 users
            if trained % 50 == 0:
                print(f"  Trained {trained:>4} users so far...")

    stats["trained"]  = trained
    stats["skipped"]  = skipped_u

    print(f"\n{'='*60}")
    print(f"  Pre-Training Complete")
    print(f"{'='*60}")
    print(f"  Users trained     : {trained:,}")
    print(f"  Users skipped     : {skipped_u:,}  (fewer than 10 events)")
    print(f"  Total events used : {stats['total_events']:,}")
    print(f"  Models saved to   : {models_dir}")
    print(f"\n  Next steps:")
    print(f"  1. Start server:  PYTHONPATH=. python application/app.py")
    print(f"  2. Open dashboard — all users will show ✓ immediately")
    print(f"  3. Run CERT replay for demo data\n")

    return stats


def main():
    parser = argparse.ArgumentParser(
        description="Pre-train personal baselines for all CERT users"
    )
    parser.add_argument(
        "--db",
        default=str(Path(__file__).parent / "storage" / "insightguard.db"),
        help="Path to InsightGuard database"
    )
    parser.add_argument(
        "--models-dir",
        default=str(MODELS_DIR),
        help="Directory to save trained models"
    )
    args = parser.parse_args()

    pretrain_from_database(
        db_path    = Path(args.db),
        models_dir = Path(args.models_dir),
    )


if __name__ == "__main__":
    main()