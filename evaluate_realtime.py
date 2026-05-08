"""
InsightGuard — Real-Time Performance Evaluation
================================================
Posts a controlled set of threat and normal events to the live API,
measures scores, severities, and detection latency.

Usage:
    python evaluate_realtime.py [--url http://localhost:5000]
"""

import time
import json
import statistics
import argparse
import requests
from datetime import datetime, timezone

# ─────────────────────────────────────────────────────────────────────────────
# Test suite definition
# ─────────────────────────────────────────────────────────────────────────────

# Use a fixed 10:00 AM UTC timestamp so UEBA never fires off_hours rules,
# regardless of what local time the evaluation is run.
_NOW = datetime.now(timezone.utc)
TS = _NOW.replace(hour=10, minute=0, second=0, microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")
# Fresh user ID each run so accumulated PUB history doesn't skew scores
_RUN_ID = _NOW.strftime("%H%M%S")
BASE = {
    "user_id":    f"EVAL_{_RUN_ID}",
    "timestamp":  TS,
    "department": "Finance",
    "role":       "Finance Analyst",
    "name":       "Eval User",
}

THREAT_EVENTS = [
    # ── USB ──────────────────────────────────────────────────────────────────
    {
        "label":       "USB Insert",
        "category":    "usb",
        **BASE,
        "source":      "usb",
        "device_id":   "USB_DRIVE_E:",
        "operation":   "insert",
        "data_mb":     0,
        "usb_transfer": True,
        "severity_override": "critical",
    },
    {
        "label":       "USB File Transfer (sensitive)",
        "category":    "usb",
        **BASE,
        "source":      "usb",
        "device_id":   "USB_DRIVE_E:",
        "operation":   "file_transfer",
        "data_mb":     250,
        "usb_data_mb": 250,
        "usb_transfer": True,
        "file_count":  45,
        "sensitive":   True,
        "severity_override": "critical",
    },
    # ── Archive / ZIP ─────────────────────────────────────────────────────────
    {
        "label":       "ZIP Archive Created",
        "category":    "archive",
        **BASE,
        "source":      "file",
        "file_path":   "C:\\Users\\EvalUser\\Desktop\\salary_data.zip",
        "file_name":   "salary_data.zip",
        "operation":   "compress",
        "data_mb":     12.5,
        "file_count":  1,
        "destination": "local",
        "is_archive":  True,
        "sensitive":   True,
    },
    # ── Blocked / risky web ───────────────────────────────────────────────────
    {
        "label":       "Blocked Site (thepiratebay.org)",
        "category":    "web",
        **BASE,
        "source":      "web",
        "url":         "https://thepiratebay.org",
        "category_field": "piracy",
        "blocked":     True,
        "bytes_out":   1024,
    },
    {
        "label":       "Blocked Site (mega.nz)",
        "category":    "web",
        **BASE,
        "source":      "web",
        "url":         "https://mega.nz/upload",
        "category":    "cloud_storage",
        "blocked":     True,
        "bytes_out":   5120,
    },
    {
        "label":       "TOR / Anonymous Network",
        "category":    "web",
        **BASE,
        "source":      "web",
        "url":         "https://tor2web.org",
        "category":    "tor",
        "blocked":     False,
        "bytes_out":   2048,
    },
    # ── Suspicious login ──────────────────────────────────────────────────────
    {
        "label":       "Off-Hours Login (2am)",
        "category":    "login",
        **BASE,
        "timestamp":   TS.replace("T" + TS[11:13], "T02"),
        "source":      "login",
        "event":       "login",
        "country_code":"GB",
        "vpn":         False,
        "tor":         False,
        "new_device":  False,
        "failed_attempts": 0,
    },
    {
        "label":       "Login via TOR + VPN + New Device",
        "category":    "login",
        **BASE,
        "source":      "login",
        "event":       "login",
        "country_code":"KP",
        "vpn":         True,
        "tor":         True,
        "new_device":  True,
        "failed_attempts": 3,
    },
    # ── Bulk file download ────────────────────────────────────────────────────
    {
        "label":       "Bulk File Download (salary CSVs)",
        "category":    "file",
        **BASE,
        "source":      "file",
        "file_path":   "C:\\SharedDrive\\HR\\salary_all.csv",
        "file_name":   "salary_all.csv",
        "operation":   "copy",
        "file_count":  120,
        "data_mb":     350,
        "destination": "local",
        "sensitive":   True,
    },
    # ── Suspicious email ──────────────────────────────────────────────────────
    {
        "label":       "Mass External Email + Large Attachment",
        "category":    "email",
        **BASE,
        "source":      "email",
        "direction":   "sent",
        "recipient_count": 25,
        "attachment_mb":   45,
        "external":    True,
    },
]

NORMAL_EVENTS = [
    {
        "label":       "Normal Login (9am)",
        "category":    "login",
        **BASE,
        "source":      "login",
        "event":       "login",
        "country_code":"GB",
        "vpn":         False,
        "tor":         False,
        "new_device":  False,
        "failed_attempts": 0,
    },
    {
        "label":       "Normal File Open (report)",
        "category":    "file",
        **BASE,
        "source":      "file",
        "file_path":   "C:\\Documents\\Q1_report.docx",
        "file_name":   "Q1_report.docx",
        "operation":   "read",
        "file_count":  1,
        "data_mb":     0.5,
        "destination": "local",
        "sensitive":   False,
    },
    {
        "label":       "Internal Email (to colleague)",
        "category":    "email",
        **BASE,
        "source":      "email",
        "direction":   "sent",
        "recipient_count": 1,
        "attachment_mb":   0,
        "external":    False,
    },
    {
        "label":       "Normal Web Browse (google.com)",
        "category":    "web",
        **BASE,
        "source":      "web",
        "url":         "https://google.com",
        "category":    "search",
        "blocked":     False,
        "bytes_out":   512,
    },
    {
        "label":       "Small File Copy (presentation)",
        "category":    "file",
        **BASE,
        "source":      "file",
        "file_path":   "C:\\Documents\\presentation.pptx",
        "file_name":   "presentation.pptx",
        "operation":   "copy",
        "file_count":  1,
        "data_mb":     2.1,
        "destination": "local",
        "sensitive":   False,
    },
    {
        "label":       "Normal Web Browse (stackoverflow.com)",
        "category":    "web",
        **BASE,
        "source":      "web",
        "url":         "https://stackoverflow.com",
        "category":    "technology",
        "blocked":     False,
        "bytes_out":   1024,
    },
    {
        "label":       "Small Internal Email with Attachment",
        "category":    "email",
        **BASE,
        "source":      "email",
        "direction":   "sent",
        "recipient_count": 3,
        "attachment_mb":   1.2,
        "external":    False,
    },
    {
        "label":       "File Read (memo)",
        "category":    "file",
        **BASE,
        "source":      "file",
        "file_path":   "C:\\Documents\\team_memo.txt",
        "file_name":   "team_memo.txt",
        "operation":   "read",
        "file_count":  1,
        "data_mb":     0.01,
        "destination": "local",
        "sensitive":   False,
    },
]

# ─────────────────────────────────────────────────────────────────────────────
# Runner
# ─────────────────────────────────────────────────────────────────────────────

ANOMALY_THRESHOLD = 45   # score >= 45 = detected as threat


def post_event(url: str, event: dict) -> tuple[dict, float]:
    """Post one event, return (response_json, latency_ms)."""
    payload = {k: v for k, v in event.items() if k != "label" and k != "category"}
    t0 = time.perf_counter()
    resp = requests.post(f"{url}/api/events", json=payload, timeout=10)
    latency_ms = (time.perf_counter() - t0) * 1000
    return resp.json(), latency_ms


def _make_warmup(user_id: str) -> list:
    b = {**BASE, "user_id": user_id}
    return [
        {**b, "source":"login","event":"login","country_code":"GB",
         "vpn":False,"tor":False,"new_device":False,"failed_attempts":0},
        {**b, "source":"login","event":"login","country_code":"GB",
         "vpn":False,"tor":False,"new_device":False,"failed_attempts":0},
        {**b, "source":"file","file_path":"C:\\Documents\\report.docx",
         "file_name":"report.docx","operation":"read","file_count":1,
         "data_mb":0.5,"destination":"local","sensitive":False},
        {**b, "source":"web","url":"https://google.com","category":"search",
         "blocked":False,"bytes_out":512},
        {**b, "source":"email","direction":"sent","recipient_count":2,
         "attachment_mb":0,"external":False},
    ]


def run(base_url: str):
    print("\n" + "=" * 65)
    print("  InsightGuard — Real-Time Performance Evaluation")
    print("=" * 65)

    # Separate users for threat and normal so PUB baselines don't cross-contaminate
    threat_uid = f"EVAL_T_{_RUN_ID}"
    normal_uid = f"EVAL_N_{_RUN_ID}"

    # ── Warm up both users so country/time history is established ──────────
    print("\n  Warming up user baselines (2 × 5 events)...", end=" ", flush=True)
    for ev in _make_warmup(threat_uid) + _make_warmup(normal_uid):
        try:
            requests.post(f"{base_url}/api/events", json=ev, timeout=10)
        except Exception:
            pass
    print("done")

    results_threat = []
    results_normal = []
    latencies      = []

    # ── Threat events ──────────────────────────────────────────────────────
    print("\n  THREAT SCENARIOS")
    print("  " + "-" * 60)
    for ev in THREAT_EVENTS:
        ev_out = {**ev, "user_id": threat_uid}
        try:
            r, lat = post_event(base_url, ev_out)
            score    = r.get("risk_score", 0)
            severity = r.get("severity", "?")
            detected = score >= ANOMALY_THRESHOLD
            latencies.append(lat)
            results_threat.append(detected)
            status = "✓ DETECTED" if detected else "✗ MISSED  "
            print(f"  {status}  score={score:3}  sev={severity:10s}  "
                  f"lat={lat:5.0f}ms  {ev['label']}")
        except Exception as e:
            print(f"  ERROR  {ev['label']}: {e}")
            results_threat.append(False)

    # ── Normal events ───────────────────────────────────────────────────────
    print("\n  NORMAL SCENARIOS (should NOT be flagged)")
    print("  " + "-" * 60)
    for ev in NORMAL_EVENTS:
        ev_out = {**ev, "user_id": normal_uid}
        try:
            r, lat = post_event(base_url, ev_out)
            score    = r.get("risk_score", 0)
            severity = r.get("severity", "?")
            flagged  = score >= ANOMALY_THRESHOLD
            latencies.append(lat)
            results_normal.append(flagged)
            status = "✗ FALSE POS" if flagged else "✓ CORRECT  "
            print(f"  {status}  score={score:3}  sev={severity:10s}  "
                  f"lat={lat:5.0f}ms  {ev['label']}")
        except Exception as e:
            print(f"  ERROR  {ev['label']}: {e}")
            results_normal.append(False)

    # ── Metrics ─────────────────────────────────────────────────────────────
    TP = sum(results_threat)
    FN = len(results_threat) - TP
    FP = sum(results_normal)
    TN = len(results_normal) - FP

    precision = TP / (TP + FP) if (TP + FP) > 0 else 0.0
    recall    = TP / (TP + FN) if (TP + FN) > 0 else 0.0
    f1        = (2 * precision * recall / (precision + recall)
                 if (precision + recall) > 0 else 0.0)
    accuracy  = (TP + TN) / (TP + FP + FN + TN)
    fpr       = FP / (FP + TN) if (FP + TN) > 0 else 0.0
    avg_lat   = statistics.mean(latencies) if latencies else 0
    max_lat   = max(latencies) if latencies else 0

    print(f"\n{'=' * 65}")
    print("  RESULTS SUMMARY")
    print(f"{'=' * 65}")
    print(f"""
  Confusion Matrix:
    True  Positives (threats caught)   : {TP} / {len(results_threat)}
    False Positives (normal flagged)   : {FP} / {len(results_normal)}
    False Negatives (threats missed)   : {FN}
    True  Negatives (normal cleared)   : {TN}

  Performance Metrics:
    Precision  : {precision:.4f}  ({precision*100:.1f}%)
    Recall     : {recall:.4f}  ({recall*100:.1f}%)
    F1 Score   : {f1:.4f}
    Accuracy   : {accuracy:.4f}  ({accuracy*100:.1f}%)
    FPR        : {fpr:.4f}  ({fpr*100:.1f}%)

  Detection Latency:
    Average    : {avg_lat:.0f} ms
    Maximum    : {max_lat:.0f} ms
""")
    print(f"{'=' * 65}")
    print("  FOR THESIS TABLE:")
    print(f"{'=' * 65}")
    print(f"""
  Precision: {precision*100:.1f}%, Recall: {recall*100:.1f}%,
  F1: {f1:.3f}, Accuracy: {accuracy*100:.1f}%,
  FPR: {fpr*100:.1f}%, Avg Latency: {avg_lat:.0f}ms
""")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://localhost:5000")
    args = parser.parse_args()
    run(args.url)
