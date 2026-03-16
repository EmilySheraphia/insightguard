"""
InsightGuard — Ground Truth Validator
=======================================
Validates InsightGuard detections against the CERT answers files.
Computes precision, recall, F1-score, and detection rate for
all known insider threat scenarios in r4.2.

Answer files used:
  answers/insiders.csv     — master list of all insider threat users
  answers/r4.2-1/          — individual malicious event IDs
  answers/r4.2-2/
  answers/r4.2-3/

Usage:
  PYTHONPATH=. python ground_truth_validator.py
"""

from __future__ import annotations
import csv
import os
import sqlite3
from pathlib import Path
from datetime import datetime


ANSWERS_DIR = Path.home() / "Downloads" / "answers"
DB_PATH     = Path(__file__).parent / "storage" / "insightguard.db"


# ── Load ground truth ─────────────────────────────────────────────────────────

def load_insider_users(answers_dir: Path) -> dict[str, dict]:
    """
    Load insiders.csv — master list of all known insider threat users.
    Returns dict keyed by user_id.
    """
    path     = answers_dir / "insiders.csv"
    insiders = {}

    if not path.exists():
        print(f"  WARNING: {path} not found")
        return insiders

    with open(path, newline="", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        for row in reader:
            uid = row.get("user", "").strip()
            if uid:
                insiders[uid] = {
                    "user_id":  uid,
                    "dataset":  row.get("dataset", "").strip(),
                    "scenario": row.get("scenario", "").strip(),
                    "start":    row.get("start", "").strip(),
                    "end":      row.get("end",   "").strip(),
                    "details":  row.get("details", "").strip(),
                }

    return insiders


def load_malicious_event_ids(answers_dir: Path, version: str = "r4.2") -> set[str]:
    """
    Load all malicious event IDs from r4.2 answer folders.
    Returns a set of CERT event IDs like {X1D9-S0ES98JV-5357PWMI}.
    """
    malicious_ids = set()

    # Look for r4.2 folders
    for folder_name in os.listdir(answers_dir):
        if not folder_name.startswith(version):
            continue
        folder = answers_dir / folder_name
        if not folder.is_dir():
            # It's a CSV file like r4.2-1.csv
            if folder_name.endswith(".csv"):
                _extract_ids_from_file(answers_dir / folder_name, malicious_ids)
            continue
        # It's a folder — read all CSV files inside
        for fname in os.listdir(folder):
            if fname.endswith(".csv"):
                _extract_ids_from_file(folder / fname, malicious_ids)

    return malicious_ids


def _extract_ids_from_file(path: Path, id_set: set) -> None:
    """Extract CERT event IDs from an answers CSV file."""
    try:
        with open(path, newline="", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                # ID is always the second field, format: {XXXX-XXXXXXXX-XXXXXXXX}
                parts = line.split(",")
                if len(parts) >= 2:
                    potential_id = parts[1].strip().strip('"').strip("{}")
                    if len(potential_id) > 10 and "-" in potential_id:
                        id_set.add("{" + potential_id + "}")
                        id_set.add(potential_id)
    except Exception:
        pass


# ── Load our detections ───────────────────────────────────────────────────────

def load_our_detections(db_path: Path) -> tuple[set[str], set[str]]:
    """
    Load all users and flagged users from InsightGuard's database.
    Returns (all_users, flagged_users).
    """
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row

    all_users = set(
        row[0] for row in
        conn.execute("SELECT DISTINCT user_id FROM activity_logs").fetchall()
    )

    flagged_users = set(
        row[0] for row in
        conn.execute("""
            SELECT DISTINCT user_id FROM anomaly_results
            WHERE is_anomaly = 1
        """).fetchall()
    )

    conn.close()
    return all_users, flagged_users


def load_detection_details(db_path: Path) -> list[dict]:
    """Load full detection records for detailed analysis."""
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    rows = conn.execute("""
        SELECT ar.user_id, ar.risk_score, ar.severity,
               ar.ueba_score, ar.triggered_rules,
               al.activity_type, al.timestamp
        FROM anomaly_results ar
        LEFT JOIN activity_logs al ON ar.log_id = al.log_id
        WHERE ar.is_anomaly = 1
        ORDER BY ar.risk_score DESC
    """).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ── Compute metrics ───────────────────────────────────────────────────────────

def compute_metrics(
    all_users:       set[str],
    flagged_users:   set[str],
    insider_users:   dict[str, dict],
) -> dict:
    """
    Compute precision, recall, F1, and confusion matrix.

    True Positive  = insider flagged by our system
    False Positive = non-insider flagged by our system
    False Negative = insider NOT flagged by our system
    True Negative  = non-insider NOT flagged by our system
    """
    insider_ids = set(insider_users.keys())

    # Intersect with users we actually monitored
    monitored_insiders     = insider_ids & all_users
    monitored_non_insiders = all_users - insider_ids

    TP = len(monitored_insiders     & flagged_users)
    FP = len(monitored_non_insiders & flagged_users)
    FN = len(monitored_insiders     - flagged_users)
    TN = len(monitored_non_insiders - flagged_users)

    precision = TP / (TP + FP) if (TP + FP) > 0 else 0.0
    recall    = TP / (TP + FN) if (TP + FN) > 0 else 0.0
    f1        = (2 * precision * recall / (precision + recall)
                 if (precision + recall) > 0 else 0.0)
    fpr       = FP / (FP + TN) if (FP + TN) > 0 else 0.0
    accuracy  = (TP + TN) / (TP + FP + FN + TN) if (TP+FP+FN+TN) > 0 else 0.0

    return {
        "TP":        TP,
        "FP":        FP,
        "FN":        FN,
        "TN":        TN,
        "precision": round(precision, 4),
        "recall":    round(recall,    4),
        "f1_score":  round(f1,        4),
        "fpr":       round(fpr,       4),
        "accuracy":  round(accuracy,  4),
        "monitored_insiders":     len(monitored_insiders),
        "total_insiders_in_db":   len(insider_ids),
        "detected_insiders":      [uid for uid in monitored_insiders if uid in flagged_users],
        "missed_insiders":        [uid for uid in monitored_insiders if uid not in flagged_users],
    }


# ── Main validator ────────────────────────────────────────────────────────────

def validate(answers_dir: Path = ANSWERS_DIR,
             db_path:     Path = DB_PATH) -> dict:

    print("\n" + "="*65)
    print("  InsightGuard — Ground Truth Validation")
    print("="*65)

    # ── Step 1: Load ground truth ─────────────────────────────────────
    print("\n  Loading ground truth from CERT answers...")
    insider_users = load_insider_users(answers_dir)
    print(f"    Known insider threat users : {len(insider_users)}")

    if insider_users:
        print(f"    Insider user IDs:")
        for uid, info in list(insider_users.items())[:10]:
            print(f"      {uid:12s}  scenario={info['scenario']}  "
                  f"start={info['start'][:10]}")
        if len(insider_users) > 10:
            print(f"      ... and {len(insider_users)-10} more")

    # ── Step 2: Load our detections ───────────────────────────────────
    print(f"\n  Loading InsightGuard detections from database...")
    if not db_path.exists():
        print(f"  ERROR: Database not found at {db_path}")
        print(f"  Run: PYTHONPATH=. python cert_loader.py  first.")
        return {}

    all_users, flagged_users = load_our_detections(db_path)
    print(f"    Total users monitored      : {len(all_users)}")
    print(f"    Users flagged as anomalous : {len(flagged_users)}")

    # ── Step 3: Compute metrics ───────────────────────────────────────
    print(f"\n  Computing metrics...")
    metrics = compute_metrics(all_users, flagged_users, insider_users)

    # ── Step 4: Print results ─────────────────────────────────────────
    print(f"\n{'='*65}")
    print(f"  VALIDATION RESULTS")
    print(f"{'='*65}")
    print(f"\n  Confusion Matrix:")
    print(f"    True  Positives (insiders caught)       : {metrics['TP']}")
    print(f"    False Positives (innocent users flagged): {metrics['FP']}")
    print(f"    False Negatives (insiders missed)       : {metrics['FN']}")
    print(f"    True  Negatives (innocent users clear)  : {metrics['TN']}")

    print(f"\n  Performance Metrics:")
    print(f"    Precision  : {metrics['precision']:.4f}  "
          f"({metrics['precision']*100:.1f}%)")
    print(f"    Recall     : {metrics['recall']:.4f}  "
          f"({metrics['recall']*100:.1f}%)")
    print(f"    F1 Score   : {metrics['f1_score']:.4f}")
    print(f"    Accuracy   : {metrics['accuracy']:.4f}  "
          f"({metrics['accuracy']*100:.1f}%)")
    print(f"    False +ve Rate: {metrics['fpr']:.4f}  "
          f"({metrics['fpr']*100:.1f}%)")

    print(f"\n  Insider Detection:")
    print(f"    Insiders in our dataset    : "
          f"{metrics['monitored_insiders']} / {metrics['total_insiders_in_db']}")
    print(f"    Insiders detected          : {metrics['TP']}")
    print(f"    Insiders missed            : {metrics['FN']}")

    if metrics["detected_insiders"]:
        print(f"\n  Detected insider users:")
        for uid in metrics["detected_insiders"]:
            info = insider_users.get(uid, {})
            print(f"    ✓ {uid:12s}  scenario={info.get('scenario','?')}")

    if metrics["missed_insiders"]:
        print(f"\n  Missed insider users:")
        for uid in metrics["missed_insiders"]:
            info = insider_users.get(uid, {})
            print(f"    ✗ {uid:12s}  scenario={info.get('scenario','?')}")

    print(f"\n{'='*65}")
    print(f"  Summary for your project report:")
    print(f"{'='*65}")
    print(f"""
  InsightGuard was evaluated against the CERT Insider Threat
  Dataset r4.2 ground truth answers. The system monitored
  {len(all_users)} users and processed their activity logs across
  5 data sources (logon, file, email, device, http).

  Of the {metrics['monitored_insiders']} known insider threat users present
  in our monitored dataset, the system detected {metrics['TP']}
  ({metrics['recall']*100:.1f}% recall) while generating {metrics['FP']}
  false positive alerts.

  Precision : {metrics['precision']*100:.1f}%
  Recall    : {metrics['recall']*100:.1f}%
  F1 Score  : {metrics['f1_score']:.3f}
  Accuracy  : {metrics['accuracy']*100:.1f}%
""")

    return metrics


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Validate InsightGuard against CERT ground truth"
    )
    parser.add_argument("--answers", default=str(ANSWERS_DIR),
                        help="Path to CERT answers folder")
    parser.add_argument("--db",      default=str(DB_PATH),
                        help="Path to InsightGuard database")
    args = parser.parse_args()

    validate(
        answers_dir = Path(args.answers),
        db_path     = Path(args.db),
    )