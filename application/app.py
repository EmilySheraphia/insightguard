"""
InsightGuard — Layer 6: Application
Novel contributions:
  1. PERS — Psychometric-Enhanced Risk Scoring
  2. PUB  — Per-User Baseline (personal Isolation Forest per user)

Final score pipeline:
  ML_Score   = IF(global) + LOF(global) + UEBA
  PUB_Score  = IF(personal) combined with ML_Score
  PERS_Score = PUB_Score weighted with Psychometric Risk
"""

from flask import Flask, request, jsonify, Response, stream_with_context, send_file
from datetime import datetime, timezone
import json, queue, re, threading, uuid
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from data_acquisition.collector    import AcquisitionRouter
from data_processing.etl_pipeline  import ETLPipeline, enrich_raw
from feature_engineering.extractor import FeatureEngineering, FeatureVector
from ai_analytics.anomaly_model    import AnomalyDetectionModel
from ai_analytics.correlation_engine import CorrelationEngine
from explainability.lime_engine    import ExplainabilityEngine
from storage.database              import DatabaseManager
from psychometric_scorer           import init_psychometrics, get_pers_score
from psychometric_scorer           import get_store as get_psych_store
from per_user_baseline             import ingest_and_score as pub_score
from per_user_baseline             import get_store as get_pub_store
from ground_truth_validator        import validate as run_validation
from nexon_psychometrics           import load_nexon_profiles
from analytics import CounterfactualEngine, ConfidenceEngine
_cf_engine   = CounterfactualEngine()
_conf_engine = ConfidenceEngine()
from escalation import EscalationEngine
_escalation = EscalationEngine()

def _on_correlation_alert(alert: dict) -> None:
    """Store synthetic correlation alert to DB and broadcast via SSE."""
    try:
        lid = "corr_" + str(uuid.uuid4())[:10]
        db.insert_activity_log(
            lid, alert["user_id"], alert["timestamp"],
            "correlation_alert", "correlation", details=alert,
        )
        _broadcast_sse(alert)
    except Exception as _e:
        print(f"[CorrelationEngine] alert error: {_e}")

correlation_engine = CorrelationEngine(on_alert=_on_correlation_alert)
from pathlib import Path
import numpy as np
import json as _json

# ── Role-based UEBA threshold config ──────────────────────────────────────────
_ROLE_CONFIG_PATH = Path(__file__).parent.parent / "storage" / "role_config.json"
_role_config: dict = {}

EVIDENCE_DIR = Path(__file__).parent.parent / "storage" / "evidence"
EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)

def _load_role_config():
    global _role_config
    if _ROLE_CONFIG_PATH.exists():
        with open(_ROLE_CONFIG_PATH) as f:
            _role_config = _json.load(f)
        print(f"[Config] Loaded role config: {len(_role_config.get('roles',{}))} roles")
    else:
        print("[Config] role_config.json not found — using empty defaults")
        _role_config = {"roles": {"default": {}}}

def _get_role_cfg(role: str) -> dict:
    roles = _role_config.get("roles", {})
    return roles.get(role, roles.get("default", {}))

def _save_role_config():
    _ROLE_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(_ROLE_CONFIG_PATH, "w") as f:
        _json.dump(_role_config, f, indent=2)

_load_role_config()

# Rule → (fv_field, config_key, base_weight)
_RULE_ADJ = {
    "bulk_download":       ("data_mb",        "bulk_download_mb",          18),
    "massive_download":    ("data_mb",        "massive_download_mb",       32),
    "bulk_file_access":    ("file_count",     "bulk_file_count",           16),
    "extreme_file_access": ("file_count",     "extreme_file_count",        26),
    "usb_exfil":           ("usb_data_mb",    "usb_exfil_mb",              20),
    "external_email_bulk": ("recipient_count","external_email_recipients",  14),
    "large_attachment":    ("attachment_mb",  "large_attachment_mb",        12),
}

def _role_adjusted_ueba(fv_dict: dict, role: str, ueba_score: int, rules: list) -> tuple:
    """Reduce UEBA score/rules for activity that is normal for this role."""
    cfg = _get_role_cfg(role)
    if not cfg:
        return ueba_score, rules
    adjustment = 0
    filtered = []
    for rule in rules:
        if rule in _RULE_ADJ:
            fv_key, cfg_key, weight = _RULE_ADJ[rule]
            threshold = cfg.get(cfg_key)
            actual    = fv_dict.get(fv_key, 0)
            if threshold is not None and actual < threshold:
                adjustment -= weight
                continue   # rule removed for this role
        if rule == "off_hours_login":
            mult = float(cfg.get("off_hours_weight", 1.0))
            if mult < 1.0:
                adjustment -= int(12 * (1.0 - mult))
        elif rule == "vpn_suspicious":
            mult = float(cfg.get("vpn_suspicious_weight", 1.0))
            if mult < 1.0:
                adjustment -= int(6 * (1.0 - mult))
        filtered.append(rule)
    return max(0, min(100, ueba_score + adjustment)), filtered

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False

@app.after_request
def add_cors(response):
    response.headers["Access-Control-Allow-Origin"]  = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type,Authorization"
    response.headers["Access-Control-Allow-Methods"] = "GET,POST,PATCH,DELETE,OPTIONS"
    return response

@app.route("/api/<path:p>", methods=["OPTIONS"])
@app.route("/healthz",       methods=["OPTIONS"])
def options_handler(p=""):
    return "", 204

router   = AcquisitionRouter()
pipeline = ETLPipeline()
fe_eng   = FeatureEngineering()
model    = AnomalyDetectionModel()
xai      = ExplainabilityEngine()
db       = DatabaseManager()
_escalation.set_db(db)
_escalation.start()

CERT_DIR     = Path.home() / "Downloads" / "r4.2"
psych_loaded = init_psychometrics(CERT_DIR)
# Always load Nexon employee OCEAN profiles (supplements CERT data)
load_nexon_profiles()

user_profiles: dict = {}
profile_lock = threading.Lock()
sse_queues:   list  = []
sse_lock = threading.Lock()

def _full_score(fv_dict: dict, user_id: str, feature_array=None, role: str = "", raw_event: dict = None) -> dict:
    fv = FeatureVector(**{k: fv_dict.get(k,0) for k in FeatureVector.COLUMNS})
    from ai_analytics.anomaly_model import UEBAEngine
    ueba = UEBAEngine()
    _extra = raw_event if raw_event is not None else fv_dict
    raw_ueba_score, raw_rules = ueba.score(fv, extra=_extra)
    # Apply role-aware threshold adjustment
    ueba_score, rules = _role_adjusted_ueba(fv_dict, role, raw_ueba_score, raw_rules)
    arr       = fv.to_array() if feature_array is None else feature_array
    if_score  = model._if.score(arr)
    lof_score = model._lof.score(arr)
    ml_score  = min(int(if_score*100*model.IF_WEIGHT +
                        lof_score*100*model.LOF_WEIGHT +
                        ueba_score*model.UEBA_WEIGHT), 100)
    pub       = pub_score(user_id, arr, ml_score)
    pers      = get_pers_score(user_id, pub["combined_score"])
    return {
        "ml_score":            ml_score,
        "if_score":            round(if_score,4),
        "lof_score":           round(lof_score,4),
        "ueba_score":          ueba_score,
        "triggered_rules":     rules,
        "personal_if_score":   pub["personal_if_score"],
        "personal_risk_score": pub["personal_risk_score"],
        "pub_combined":        pub["combined_score"],
        "pub_is_trained":      pub["is_trained"],
        "pub_events_seen":     pub["events_seen"],
        "pub_status":          pub["status"],
        "psychometric_risk":   pers["psychometric_risk"],
        "pers_enhancement":    pers["enhancement"],
        "risk_score":          pers["pers_score"],
        "severity":            pers["severity"],
        "is_anomaly":          pers["is_anomaly"],
    }


def _process_event(raw):
    activity = router.route(raw)
    log      = pipeline.process(activity)
    if not log.is_valid: return {"error":"Unprocessable event"}
    enrich_raw(raw)
    # Debug log so you can see in server console what's being detected
    atype = log.activity_type
    print(f"[EVENT] {atype} user={raw.get('user_id','?')} source={raw.get('source','?')}", end="")
    if atype == "web":
        print(f" url={raw.get('url','?')} blocked={raw.get('blocked',False)}", end="")
    elif atype in ("file_access",):
        print(f" file={raw.get('file_name',raw.get('file_path','?'))}", end="")
    print()
    _fn_check = (raw.get("file_name","") or raw.get("file_path","")).lower()
    _archive_exts = {".zip",".rar",".7z",".tar",".gz",".bz2"}
    if any(_fn_check.endswith(ext) for ext in _archive_exts) or raw.get("is_archive"):
        print(f"[ARCHIVE SERVER] user={raw.get('user_id')} file={raw.get('file_name',raw.get('file_path','?'))} "
              f"is_archive={raw.get('is_archive')} op={raw.get('operation','?')}")
    raw["is_off_hours"] = int(log.is_off_hours)
    fv      = fe_eng.extractFeatures(log)
    uid     = log.user_id
    result  = _full_score(fv.to_dict(), uid, fv.to_array(), role=raw.get("role",""), raw_event=raw)
    db.upsert_user(uid, raw.get("department",""), raw.get("role",""), raw.get("name",""))
    # Merge raw event fields into stored details so historical queries can show
    # file names, rename/move paths, URLs, operation types, and USB file lists.
    _raw_extras = {k: raw.get(k, "") for k in
                   ("file_path", "file_name", "operation", "destination",
                    "url", "category", "site_name", "page_title")}
    stored_details = {**fv.to_dict(), **{k: v for k, v in _raw_extras.items() if v}}
    if raw.get("files"):
        stored_details["files"] = raw["files"]
    db.insert_activity_log(log.log_id, uid, log.timestamp.isoformat(),
                           log.activity_type, log.source, details=stored_details)
    db.insert_features("ft_"+log.log_id, uid, log.log_id, fv.to_dict())
    did = "dt_"+log.log_id
    # Allow agent to force a minimum severity for composite threat events
    sev_override = raw.get("severity_override","")
    _SEV_ORDER = {"normal":0,"suspicious":1,"high_risk":2,"critical":3}
    final_sev = result["severity"]
    if sev_override in _SEV_ORDER and _SEV_ORDER[sev_override] > _SEV_ORDER.get(final_sev,0):
        final_sev = sev_override
        result["severity"] = sev_override
        result["is_anomaly"] = True

    # Correlation pattern check — runs after all score adjustments, before DB write
    boosted = correlation_engine.process(uid, raw, result["risk_score"])
    if boosted > result["risk_score"]:
        result["risk_score"] = int(boosted)
        result["severity"] = (
            "critical"   if boosted >= 80 else
            "high_risk"  if boosted >= 60 else
            "suspicious" if boosted >= 45 else "normal"
        )
        result["is_anomaly"] = True
        final_sev = result["severity"]

    # Web floor — explicitly blocked sites → critical; risky category → high_risk
    if log.activity_type == "web" and log.risky_web:
        floor = 85 if raw.get("blocked") else 60
        sev   = "critical" if raw.get("blocked") else "high_risk"
        if result["risk_score"] < floor:
            result["risk_score"] = floor
            result["severity"]   = sev
            result["is_anomaly"] = True
            final_sev = sev
            if "risky_web" not in result.get("triggered_rules", []):
                result["triggered_rules"] = list(result.get("triggered_rules", [])) + ["risky_web"]

    # Archive floor — zipping/compressing files is always critical
    if raw.get("is_archive"):
        floor = 85
        if result["risk_score"] < floor:
            result["risk_score"] = floor
            result["severity"] = "critical"
            result["is_anomaly"] = True
            final_sev = "critical"
            if "archive_created" not in result.get("triggered_rules", []):
                result["triggered_rules"] = list(result.get("triggered_rules", [])) + ["archive_created"]

    # USB floor — inserting a USB device or copying files to it is always critical
    if raw.get("usb_transfer"):
        op = raw.get("operation", "")
        floor = 90 if op == "file_transfer" and raw.get("sensitive") else 82
        if result["risk_score"] < floor:
            result["risk_score"] = floor
            result["severity"] = "critical"
            result["is_anomaly"] = True
            final_sev = "critical"
            rule = "usb_exfil" if op == "file_transfer" else "usb_insert"
            if rule not in result.get("triggered_rules", []):
                result["triggered_rules"] = list(result.get("triggered_rules", [])) + [rule]

    # Store final scores (post-boost) to DB
    db.insert_anomaly_result(did, uid, log.log_id, result)
    _upd(uid, result, raw)
    aid = None
    if result["is_anomaly"]:
        aid = "al_"+log.log_id[:10]
        db.insert_alert(aid, uid, did, result["severity"], log.activity_type,
                        "Rules: "+", ".join(result["triggered_rules"][:3]) if result["triggered_rules"] else "Anomaly")

    file_name = raw.get("file_name","") or raw.get("file_path","")
    if "/" in file_name or "\\" in file_name:
        file_name = file_name.split("/")[-1].split("\\")[-1]
    op = raw.get("operation","")
    if op in ("rename","move"):
        dest_path = raw.get("destination","") or raw.get("dest_path","")
        if dest_path:
            dest_name = dest_path.split("/")[-1].split("\\")[-1]
            file_name = f"{file_name} → {dest_name}"

    # Build a clean display label for web events
    site_name = raw.get("site_name","") or raw.get("url","")
    if site_name and "://" in site_name:
        from urllib.parse import urlparse as _up
        site_name = _up(site_name).netloc or site_name
    category  = raw.get("category","")
    blocked   = bool(raw.get("blocked", False))
    pay = {
        "alert_id":aid,"user_id":uid,"department":raw.get("department",""),
        "activity_type":log.activity_type,
        "ml_score":result["ml_score"],"personal_risk_score":result["personal_risk_score"],
        "pub_combined":result["pub_combined"],"pub_is_trained":result["pub_is_trained"],
        "pub_events_seen":result["pub_events_seen"],"pub_status":result["pub_status"],
        "psychometric_risk":result["psychometric_risk"],"pers_enhancement":result["pers_enhancement"],
        "risk_score":result["risk_score"],"severity":final_sev,
        "ueba_score":result["ueba_score"],"if_score":result["if_score"],"lof_score":result["lof_score"],
        "triggered_rules":result["triggered_rules"],"timestamp":datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "data_mb":fv.data_mb,"file_count":fv.file_count,"tor":bool(fv.tor),
        "file_name":file_name,
        "site_name":site_name,
        "url":raw.get("url",""),
        "category":category,
        "blocked":blocked,
        "files":raw.get("files",[]),
        "threat_type":raw.get("threat_type",""),
        "description":raw.get("description",""),
        "log_id":log.log_id,
        "name":raw.get("name",""),
    }
    _broadcast_sse(pay)
    # Escalation
    _escalation.enqueue({**pay, "triggered_rules": result["triggered_rules"]})
    return {**pay,"is_anomaly":result["is_anomaly"],"timestamp":log.timestamp.isoformat()}


def _upd(uid, result, raw):
    with profile_lock:
        if uid not in user_profiles:
            user_profiles[uid] = {"user_id":uid,"event_count":0,"threat_count":0,
                "peak_score":0,"rolling_score":0,"risk_level":"normal","last_seen":None,
                "department":raw.get("dept",raw.get("department","")),
                "psychometric_risk":get_psych_store().get_risk(uid),
                "pub_status":"learning","pub_events_seen":0}
        p = user_profiles[uid]
        p["event_count"] += 1
        p["last_seen"]    = datetime.now().isoformat()+"Z"
        p["pub_status"]   = result.get("pub_status", p["pub_status"])
        p["pub_events_seen"] = result.get("pub_events_seen", p["pub_events_seen"])
        if result.get("is_anomaly"): p["threat_count"] += 1
        p["rolling_score"] = int(0.3*result["risk_score"]+0.7*p["rolling_score"])
        p["peak_score"]    = max(p["peak_score"], result["risk_score"])
        s = p["rolling_score"]
        p["risk_level"] = ("critical" if s>=80 else "high_risk" if s>=60
                           else "suspicious" if s>=35 else "normal")


def _broadcast_sse(payload):
    msg = f"data: {json.dumps(payload)}\n\n"
    with sse_lock:
        for q in list(sse_queues):
            try: q.put_nowait(msg)
            except queue.Full: pass   # drop event for slow client, keep them connected


@app.get("/api/config")
def get_config():
    return jsonify(_role_config), 200

@app.put("/api/config")
def update_config():
    body = request.get_json(silent=True)
    if not body: return jsonify({"error":"JSON body required"}), 400
    global _role_config
    _role_config = body
    _save_role_config()
    return jsonify({"message":"Config saved","roles":len(_role_config.get("roles",{}))}), 200

@app.get("/")
@app.get("/dashboard")
def serve_dashboard():
    import os as _os
    from flask import Response as _Resp
    base = _os.path.dirname(_os.path.abspath(__file__))
    paths = [
        _os.path.join(base, "dashboard.html"),
        _os.path.join(base, "..", "application", "dashboard.html"),
        _os.path.join(_os.getcwd(), "application", "dashboard.html"),
        _os.path.join(_os.getcwd(), "dashboard.html"),
    ]
    for p in paths:
        if _os.path.exists(p):
            with open(p, "r", encoding="utf-8") as f:
                return _Resp(f.read(), mimetype="text/html")
    return _Resp("<h1>InsightGuard API running</h1><p>Visit <a href='/healthz'>/healthz</a></p>", mimetype="text/html")

@app.get("/company")
def serve_company():
    import os as _os
    from flask import Response as _Resp
    base = _os.path.dirname(_os.path.abspath(__file__))
    paths = [
        _os.path.join(base, "company_app.html"),
        _os.path.join(_os.getcwd(), "application", "company_app.html"),
    ]
    for p in paths:
        if _os.path.exists(p):
            with open(p, "r", encoding="utf-8") as f:
                return _Resp(f.read(), mimetype="text/html")
    return _Resp("<h1>Company portal not found</h1>", mimetype="text/html")

@app.get("/api/debug/test-critical")
def debug_test_critical():
    """Fire a fake archive + blocked-site event and return their scores.
    If both show severity=critical the server has the latest fix running."""
    ts = datetime.now(timezone.utc).isoformat()
    r_archive = _process_event({
        "user_id":"debug_test","timestamp":ts,
        "department":"Test","role":"Tester","name":"Debug",
        "source":"file","file_name":"debug.zip","file_path":"/tmp/debug.zip",
        "operation":"write","file_count":1,"data_mb":10.0,"is_archive":True,
    })
    r_blocked = _process_event({
        "user_id":"debug_test","timestamp":ts,
        "department":"Test","role":"Tester","name":"Debug",
        "source":"web","url":"https://mega.nz/","site_name":"mega.nz",
        "category":"cloud_storage","bytes_out":0,"blocked":True,"risky":True,
    })
    return jsonify({
        "archive": {"risk_score": r_archive.get("risk_score"), "severity": r_archive.get("severity")},
        "blocked": {"risk_score": r_blocked.get("risk_score"), "severity": r_blocked.get("severity")},
        "fix_active": r_archive.get("severity")=="critical" and r_blocked.get("severity")=="critical",
    })

@app.get("/healthz")
def health():
    pub = get_pub_store()
    return jsonify({"status":"ok","model_ready":model._if.trained,
                    "psychometrics":psych_loaded,"psych_profiles":len(get_psych_store()),
                    "pub_users":len(pub),"pub_trained":pub.trained_count,
                    "sse_clients":len(sse_queues)})

@app.post("/api/events")
def analyse_event():
    body = request.get_json(silent=True)
    if not body: return jsonify({"error":"JSON body required"}),400
    missing = [f for f in ("user_id","timestamp","source") if f not in body]
    if missing: return jsonify({"error":f"Missing: {missing}"}),422
    r = _process_event(body)
    return jsonify(r), 200 if "error" not in r else 422

@app.post("/api/events/batch")
def analyse_batch():
    body = request.get_json(silent=True)
    if not isinstance(body,list): return jsonify({"error":"Expected JSON array"}),400
    if len(body)>500: return jsonify({"error":"Batch limit 500"}),413
    results = [_process_event(ev) for ev in body]
    return jsonify({"summary":{"processed":len(results),"threats":sum(1 for r in results if r.get("is_anomaly"))},"results":results}),200

@app.get("/api/baselines")
def get_baselines():
    pub=get_pub_store()
    return jsonify({"total_users":len(pub),"trained_users":pub.trained_count,
                    "min_events":10,"baselines":pub.get_all_status()[:50]}),200

@app.get("/api/baselines/<user_id>")
def get_user_baseline(user_id):
    s=get_pub_store().get_user_status(user_id)
    if not s: return jsonify({"error":"No baseline data"}),404
    return jsonify(s),200

@app.get("/api/psychometrics")
def get_psychometrics():
    p=get_psych_store().all_profiles()
    return jsonify({"count":len(p),"profiles":p[:50]}),200

@app.get("/api/psychometrics/<user_id>")
def get_user_psychometric(user_id):
    p=get_psych_store().get(user_id)
    if not p: return jsonify({"error":"No data"}),404
    return jsonify(p.to_dict()),200

@app.get("/api/validate")
def validate_endpoint():
    answers_dir=Path.home()/"Downloads"/"answers"
    db_path=Path(__file__).parent.parent/"storage"/"insightguard.db"
    if not answers_dir.exists(): return jsonify({"error":"Answers folder not found"}),404
    try:
        metrics=run_validation(answers_dir=answers_dir,db_path=db_path)
        return jsonify(metrics),200
    except Exception as e: return jsonify({"error":str(e)}),500

@app.get("/api/users/<user_id>/risk")
def user_risk(user_id):
    with profile_lock: p=user_profiles.get(user_id.lower())
    if not p: return jsonify({"error":"User not found"}),404
    return jsonify(p),200

@app.delete("/api/users/<user_id>/risk")
def reset_user_risk(user_id):
    with profile_lock: user_profiles.pop(user_id.lower(),None)
    return jsonify({"message":"cleared"}),200

@app.get("/api/users/<user_id>/timeline")
def user_timeline(user_id):
    with profile_lock: profile=user_profiles.get(user_id.lower(),{})
    return jsonify({"user_id":user_id,"profile":profile,
                    "timeline":db.get_user_timeline(user_id.lower(),50),
                    "alerts":db.get_alerts(user_id=user_id.lower(),limit=20)}),200

def _detect_arcs(events: list) -> list:
    """Find USB-after-file_access threat arcs within 5 minutes."""
    arcs = []
    for i, ev in enumerate(events):
        if ev["activity_type"] == "usb":
            try:
                usb_ts = datetime.fromisoformat(ev["timestamp"].replace("Z", "+00:00"))
            except Exception:
                continue
            for j in range(0, i):
                prev = events[j]
                if prev["activity_type"] == "file_access":
                    try:
                        prev_ts = datetime.fromisoformat(prev["timestamp"].replace("Z", "+00:00"))
                    except Exception:
                        continue
                    if (usb_ts - prev_ts).total_seconds() <= 300:
                        arcs.append({"from": prev["log_id"], "to": ev["log_id"],
                                     "label": "USB after file access"})
    return arcs

@app.get("/api/users/<user_id>/session")
def user_sessions(user_id):
    from datetime import timedelta as _td
    import sqlite3 as _sq
    days   = request.args.get("days", 7, type=int)
    since  = (datetime.now(timezone.utc) - _td(days=days)).strftime("%Y-%m-%dT%H:%M:%S")
    uid    = user_id.lower()

    with _sq.connect(db.db_path) as con:
        con.row_factory = _sq.Row
        rows = con.execute("""
            SELECT al.log_id, al.timestamp, al.activity_type, al.details_json,
                   ar.risk_score, ar.severity, ar.triggered_rules
            FROM activity_logs al
            LEFT JOIN anomaly_results ar ON ar.log_id = al.log_id
            WHERE LOWER(al.user_id) = ? AND al.timestamp >= ?
            ORDER BY al.timestamp ASC
        """, (uid, since)).fetchall()

    GAP_SECS = 30 * 60
    sessions = []
    current  = None

    for row in rows:
        try:
            ts = datetime.fromisoformat(row["timestamp"].replace("Z", "+00:00"))
        except Exception:
            continue

        rules = []
        try:
            rules = _json.loads(row["triggered_rules"] or "[]")
        except Exception:
            pass

        file_name  = ""
        site_name  = ""
        url        = ""
        category   = ""
        blocked    = False
        try:
            d = _json.loads(row["details_json"] or "{}")
            raw_path = d.get("file_path","") or d.get("file_name","")
            if raw_path:
                file_name = raw_path.split("/")[-1].split("\\")[-1]
            site_name = d.get("site_name","") or d.get("url","")
            url       = d.get("url","")
            category  = d.get("category","")
            blocked   = bool(d.get("blocked", False))
        except Exception:
            pass

        event = {
            "log_id":          row["log_id"],
            "timestamp":       row["timestamp"],
            "activity_type":   row["activity_type"] or "login",
            "severity":        row["severity"] or "normal",
            "risk_score":      row["risk_score"] or 0,
            "file_name":       file_name,
            "site_name":       site_name,
            "url":             url,
            "category":        category,
            "blocked":         blocked,
            "triggered_rules": rules,
        }

        if current is None or (ts - current["_last_ts"]).total_seconds() > GAP_SECS:
            if current:
                current.pop("_last_ts")
                current["threat_arcs"] = _detect_arcs(current["events"])
                sessions.append(current)
            current = {
                "session_id": f"s{len(sessions)+1}",
                "start":      row["timestamp"],
                "end":        row["timestamp"],
                "events":     [],
                "_last_ts":   ts,
            }

        current["events"].append(event)
        current["end"]      = row["timestamp"]
        current["_last_ts"] = ts

    if current:
        current.pop("_last_ts")
        current["threat_arcs"] = _detect_arcs(current["events"])
        sessions.append(current)

    return jsonify({"user_id": uid, "days": days, "sessions": sessions}), 200

@app.get("/api/users/<user_id>/trajectory")
def user_trajectory(user_id):
    from datetime import timedelta as _td
    import sqlite3 as _sq
    days  = request.args.get("days", 7, type=int)
    since = (datetime.now(timezone.utc) - _td(days=days)).strftime("%Y-%m-%dT%H:%M:%S")
    uid   = user_id.lower()

    with _sq.connect(db.db_path) as con:
        con.row_factory = _sq.Row
        rows = con.execute("""
            SELECT al.timestamp, al.activity_type,
                   ar.risk_score, ar.severity
            FROM anomaly_results ar
            JOIN activity_logs al ON ar.log_id = al.log_id
            WHERE ar.user_id = ? AND al.timestamp >= ?
            ORDER BY al.timestamp ASC
        """, (uid, since)).fetchall()

    with profile_lock:
        profile = user_profiles.get(uid, {})
    events_seen = int(profile.get("pub_events_seen", 0))

    points = []
    for row in rows:
        score = row["risk_score"] or 0
        conf  = _conf_engine.score(events_seen=events_seen, risk_score=score)
        points.append({
            "timestamp":        row["timestamp"],
            "risk_score":       score,
            "severity":         row["severity"] or "normal",
            "activity_type":    row["activity_type"] or "login",
            "confidence_lower": conf["lower"],
            "confidence_upper": conf["upper"],
        })

    return jsonify({"user_id": uid, "points": points}), 200

@app.get("/api/alerts")
def get_alerts():
    alerts=db.get_alerts(severity=request.args.get("severity",""),
                         user_id=request.args.get("user_id",""),
                         limit=min(int(request.args.get("limit",50)),200))
    return jsonify({"count":len(alerts),"alerts":alerts}),200

@app.patch("/api/alerts/<alert_id>")
def update_alert(alert_id):
    body=request.get_json(silent=True) or {}
    ok=db.update_alert_status(alert_id,body.get("status",""))
    if not ok: return jsonify({"error":"Invalid"}),400
    return jsonify({"alert_id":alert_id,"status":body.get("status","")}),200

@app.get("/api/stats")
def get_stats():
    stats=db.get_stats()
    pub=get_pub_store()
    with profile_lock:
        stats["active_users"]=len(user_profiles)
        stats["high_risk_users"]=sum(1 for p in user_profiles.values() if p["risk_level"] in("high_risk","critical"))
        stats["pub_trained_users"]=pub.trained_count
        stats["pub_total_users"]=len(pub)
        stats["user_risk_profiles"]=[
            {"user_id":p["user_id"],"department":p.get("department",""),
             "rolling_score":p["rolling_score"],"risk_level":p["risk_level"],
             "threat_count":p["threat_count"],"peak_score":p["peak_score"],
             "psychometric_risk":p.get("psychometric_risk",0),
             "pub_status":p.get("pub_status","learning"),
             "pub_events_seen":p.get("pub_events_seen",0)}
            for p in sorted(user_profiles.values(),key=lambda x:x["rolling_score"],reverse=True)]
    return jsonify(stats),200

@app.delete("/api/database/reset")
def reset_database():
    import sqlite3 as _sq
    with _sq.connect(db.db_path) as con:
        con.execute("DELETE FROM threat_alerts")
        con.execute("DELETE FROM anomaly_results")
        con.execute("DELETE FROM behaviour_features")
        con.execute("DELETE FROM activity_logs")
        con.execute("DELETE FROM users")
    with profile_lock:
        user_profiles.clear()
    correlation_engine.reset()
    return jsonify({"status": "ok", "message": "All logs cleared"}), 200


@app.post("/api/evidence/upload")
def evidence_upload():
    if "file" not in request.files:
        return jsonify({"error": "file required"}), 400
    f        = request.files["file"]
    user_id  = request.form.get("user_id", "unknown")
    trigger  = request.form.get("trigger_type", "")
    evt_type = request.form.get("event_type", "")
    log_id   = request.form.get("log_id", "")
    ts       = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%S")
    eid      = str(uuid.uuid4())
    safe_user  = re.sub(r"[^\w\-]", "_", user_id)
    safe_event = re.sub(r"[^\w\-]", "_", evt_type)
    fname    = f"{safe_user}_{ts}_{safe_event}.jpg"
    fpath    = EVIDENCE_DIR / fname
    f.save(str(fpath))
    db.insert_evidence(eid, log_id, user_id, str(fpath), trigger, evt_type, ts)
    # Notify dashboard so it can add the camera icon to the matching log row
    _broadcast_sse({
        "type":         "evidence",
        "evidence_id":  eid,
        "log_id":       log_id,
        "user_id":      user_id,
        "event_type":   evt_type,
        "trigger_type": trigger,
    })
    return jsonify({"evidence_id": eid, "status": "ok"}), 200


@app.get("/api/evidence/by-event/<log_id>")
def evidence_by_event(log_id):
    rows = db.get_evidence_by_event(log_id)
    return jsonify({"evidence": [
        {"evidence_id": r["id"], "trigger_type": r["trigger_type"],
         "event_type": r["event_type"], "timestamp": r["timestamp"]}
        for r in rows
    ]}), 200


@app.get("/api/evidence/<evidence_id>")
def evidence_serve(evidence_id):
    row = db.get_evidence_by_id(evidence_id)
    if not row:
        return jsonify({"error": "not found"}), 404
    fpath = Path(row["file_path"]).resolve()
    if not fpath.is_relative_to(EVIDENCE_DIR.resolve()):
        return jsonify({"error": "not found"}), 404
    return send_file(str(fpath), mimetype="image/jpeg")


@app.post("/api/explain/counterfactual")
def explain_counterfactual():
    body = request.get_json(silent=True) or {}
    fv_dict      = body.get("feature_dict", {})
    orig_score   = int(body.get("original_score", 0))
    if not fv_dict:
        return jsonify({"error": "feature_dict required"}), 400
    results = _cf_engine.explain(fv_dict, orig_score)
    return jsonify({"counterfactuals": results}), 200


@app.get("/api/explain/confidence")
def explain_confidence():
    user_id     = request.args.get("user_id", "")
    score       = int(request.args.get("score", 0))
    with profile_lock:
        profile = user_profiles.get(user_id.lower(), {})
    events_seen = int(profile.get("pub_events_seen", 0))
    result = _conf_engine.score(events_seen=events_seen, risk_score=score)
    return jsonify(result), 200


@app.get("/api/explain/lime/<log_id>")
def explain_lime(log_id):
    """Run LIME explanation for a stored event's feature vector."""
    import sqlite3 as _sq
    with _sq.connect(db.db_path) as con:
        con.row_factory = _sq.Row
        row = con.execute("""
            SELECT bf.features_json, ar.risk_score, ar.severity
            FROM behaviour_features bf
            JOIN anomaly_results ar ON ar.log_id = bf.log_id
            WHERE bf.log_id = ?
            LIMIT 1
        """, (log_id,)).fetchone()
    if not row:
        return jsonify({"error": "Event not found"}), 404
    try:
        fv_dict = _json.loads(row["features_json"] or "{}")
    except Exception:
        return jsonify({"error": "Invalid feature data"}), 500
    fv = FeatureVector(**{k: fv_dict.get(k, 0) for k in FeatureVector.COLUMNS})

    def _score_fn(arr: np.ndarray) -> float:
        from ai_analytics.anomaly_model import UEBAEngine
        fv2 = FeatureVector(**{k: float(v) for k, v in zip(FeatureVector.COLUMNS, arr)})
        ueba_s = UEBAEngine().score(fv2)[0]
        if_s   = model._if.score(arr)
        lof_s  = model._lof.score(arr)
        return min((if_s * 100 * model.IF_WEIGHT +
                    lof_s * 100 * model.LOF_WEIGHT +
                    ueba_s * model.UEBA_WEIGHT) / 100, 1.0)

    explanation = xai.generateExplanation(fv, _score_fn)
    return jsonify({
        "log_id":     log_id,
        "risk_score": row["risk_score"],
        "severity":   row["severity"],
        **explanation.to_dict(),
    }), 200


# ── Kill-chain sequence definitions ──────────────────────────────────────────

_KILL_CHAINS = [
    {
        "name":        "data_exfiltration_chain",
        "label":       "Data Exfiltration Kill Chain",
        "description": "File access followed by USB transfer within 30 min",
        "stage_a":     "file_access",
        "stage_b":     "usb",
        "window_mins": 30,
        "severity":    "critical",
    },
    {
        "name":        "cloud_exfil_chain",
        "label":       "Cloud Upload Exfiltration",
        "description": "File access followed by risky web/cloud activity within 20 min",
        "stage_a":     "file_access",
        "stage_b":     "web",
        "window_mins": 20,
        "severity":    "high_risk",
    },
    {
        "name":        "credential_abuse_chain",
        "label":       "Credential Abuse Sequence",
        "description": "Login event followed by bulk file access within 60 min",
        "stage_a":     "login",
        "stage_b":     "file_access",
        "window_mins": 60,
        "severity":    "high_risk",
    },
    {
        "name":        "email_exfil_chain",
        "label":       "Email Exfiltration Sequence",
        "description": "File access followed by external email within 15 min",
        "stage_a":     "file_access",
        "stage_b":     "email",
        "window_mins": 15,
        "severity":    "high_risk",
    },
    {
        "name":        "anti_forensics_chain",
        "label":       "Anti-Forensics Kill Chain",
        "description": "Process abuse / log-clear followed by file access within 10 min",
        "stage_a":     "process_launch",
        "stage_b":     "file_access",
        "window_mins": 10,
        "severity":    "critical",
    },
    {
        "name":        "logon_to_usb_chain",
        "label":       "Rapid USB Exfil After Login",
        "description": "Login followed directly by USB transfer within 10 min",
        "stage_a":     "login",
        "stage_b":     "usb",
        "window_mins": 10,
        "severity":    "critical",
    },
]


def _detect_kill_chains_from_events(events: list) -> list:
    """
    Detect kill-chain sequences in a time-ordered list of event dicts.
    Each event dict must have: log_id, timestamp, activity_type, risk_score, severity.
    Returns list of matched sequence dicts.
    """
    from datetime import timedelta as _td
    results = []
    seen = set()   # avoid duplicate matches for same pair

    for i, ev_b in enumerate(events):
        for chain in _KILL_CHAINS:
            if ev_b.get("activity_type") != chain["stage_b"]:
                continue
            try:
                ts_b = datetime.fromisoformat(ev_b["timestamp"].replace("Z", ""))
            except Exception:
                continue
            cutoff = ts_b - _td(minutes=chain["window_mins"])
            for j in range(0, i):
                ev_a = events[j]
                if ev_a.get("activity_type") != chain["stage_a"]:
                    continue
                try:
                    ts_a = datetime.fromisoformat(ev_a["timestamp"].replace("Z", ""))
                except Exception:
                    continue
                if ts_a < cutoff:
                    continue
                key = (chain["name"], ev_a["log_id"], ev_b["log_id"])
                if key in seen:
                    continue
                seen.add(key)
                delta = int((ts_b - ts_a).total_seconds() / 60)
                results.append({
                    "sequence_name":  chain["name"],
                    "label":          chain["label"],
                    "description":    chain["description"],
                    "severity":       chain["severity"],
                    "stage_a_type":   chain["stage_a"],
                    "stage_b_type":   chain["stage_b"],
                    "stage_a_log_id": ev_a["log_id"],
                    "stage_b_log_id": ev_b["log_id"],
                    "stage_a_time":   ev_a["timestamp"],
                    "stage_b_time":   ev_b["timestamp"],
                    "delta_mins":     delta,
                    "stage_a_score":  ev_a.get("risk_score", 0),
                    "stage_b_score":  ev_b.get("risk_score", 0),
                })
    return results


@app.get("/api/sequences/<user_id>")
def user_sequences(user_id):
    """Detect temporal kill-chain sequences for a user from recent DB events."""
    days  = request.args.get("days", 7, type=int)
    from datetime import timedelta as _td
    import sqlite3 as _sq
    since = (datetime.now(timezone.utc) - _td(days=days)).strftime("%Y-%m-%dT%H:%M:%S")
    uid   = user_id.lower()
    with _sq.connect(db.db_path) as con:
        con.row_factory = _sq.Row
        rows = con.execute("""
            SELECT al.log_id, al.timestamp, al.activity_type,
                   ar.risk_score, ar.severity
            FROM activity_logs al
            LEFT JOIN anomaly_results ar ON ar.log_id = al.log_id
            WHERE al.user_id = ? AND al.timestamp >= ?
            ORDER BY al.timestamp ASC
        """, (uid, since)).fetchall()
    events = [dict(r) for r in rows]
    sequences = _detect_kill_chains_from_events(events)
    return jsonify({
        "user_id":   uid,
        "days":      days,
        "sequences": sequences,
        "count":     len(sequences),
    }), 200


@app.get("/api/events/recent")
def recent_events():
    limit = min(int(request.args.get("limit", 200)), 500)
    # Default: show events from the last 24 hours so critical events from
    # earlier today are visible when the dashboard is (re)opened.
    minutes = int(request.args.get("minutes", 1440))
    from datetime import timedelta
    since = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%S")
    import sqlite3 as _sq
    with _sq.connect(db.db_path) as con:
        con.row_factory = _sq.Row
        rows = con.execute("""
            SELECT
                al.log_id, al.user_id, al.timestamp, al.activity_type, al.source,
                al.details_json,
                u.department, u.role, u.name,
                ar.risk_score, ar.severity, ar.is_anomaly,
                ar.if_score, ar.lof_score, ar.ueba_score, ar.triggered_rules
            FROM activity_logs al
            LEFT JOIN users u            ON al.user_id = u.user_id
            LEFT JOIN anomaly_results ar ON ar.log_id  = al.log_id
            WHERE al.timestamp >= ?
              AND al.user_id NOT LIKE '%.%'
            ORDER BY al.timestamp DESC
            LIMIT ?
        """, (since, limit)).fetchall()
    events = []
    for r in rows:
        rules = []
        try:
            rules = _json.loads(r["triggered_rules"] or "[]")
        except Exception:
            pass
        ml = round((r["if_score"] or 0) * 0.4 + (r["lof_score"] or 0) * 0.3 + (r["ueba_score"] or 0) * 0.3, 1)
        # Extract display fields from merged details_json
        file_name = ""
        site_name = ""
        url       = ""
        category  = ""
        blocked   = False
        data_mb   = 0.0
        file_count = 0
        usb_files = []
        try:
            details = _json.loads(r["details_json"] or "{}") if "details_json" in r.keys() else {}
            raw_path = details.get("file_path","") or details.get("file_name","")
            if raw_path:
                file_name = raw_path.split("/")[-1].split("\\")[-1]
            op = details.get("operation","")
            if op in ("rename","move"):
                dest_path = details.get("destination","") or details.get("dest_path","")
                if dest_path:
                    dest_name = dest_path.split("/")[-1].split("\\")[-1]
                    file_name = f"{file_name} → {dest_name}"
            site_name  = details.get("site_name","") or details.get("url","")
            url        = details.get("url","")
            category   = details.get("category","")
            blocked    = bool(details.get("blocked", False))
            data_mb    = float(details.get("data_mb", 0) or 0)
            file_count = int(details.get("file_count", 0) or 0)
            usb_files  = details.get("files", [])
        except Exception:
            pass
        events.append({
            "log_id":        r["log_id"],
            "user_id":       r["user_id"],
            "name":          r["name"] or "",
            "department":    r["department"] or "",
            "activity_type": r["activity_type"] or "",
            "timestamp":     r["timestamp"] or "",
            "source":        r["source"] or "",
            "risk_score":    r["risk_score"] or 0,
            "severity":      r["severity"] or "normal",
            "is_anomaly":    bool(r["is_anomaly"]),
            "ml_score":      ml,
            "pub_combined":  r["risk_score"] or 0,
            "if_score":      r["if_score"] or 0,
            "lof_score":     r["lof_score"] or 0,
            "ueba_score":    r["ueba_score"] or 0,
            "triggered_rules": rules,
            "file_name":     file_name,
            "site_name":     site_name,
            "url":           url,
            "category":      category,
            "blocked":       blocked,
            "data_mb":       data_mb,
            "file_count":    file_count,
            "files":         usb_files,
        })
    return jsonify({"count": len(events), "events": events}), 200


# ── Escalation routes ─────────────────────────────────────────────────────────

@app.get("/api/escalation/config")
def get_escalation_config():
    cfg = dict(_escalation.config)
    cfg.pop("smtp_password", None)   # never send password back to browser
    return jsonify(cfg), 200

@app.put("/api/escalation/config")
def update_escalation_config():
    body = request.get_json(silent=True) or {}
    if not body:
        return jsonify({"error": "JSON body required"}), 400
    _escalation.update_config(body)
    cfg = dict(_escalation.config)
    cfg.pop("smtp_password", None)
    return jsonify({"message": "Escalation config saved", "config": cfg}), 200

@app.post("/api/escalation/test")
def test_escalation():
    result = _escalation.send_test_email()
    code = 200 if result["status"] in ("sent", "skipped") else 500
    return jsonify(result), code

@app.post("/api/escalation/resend")
def resend_escalation():
    body = request.get_json(silent=True) or {}
    log_id = body.get("log_id", "")
    if not log_id:
        return jsonify({"error": "log_id required"}), 400
    event = db.get_event_by_log_id(log_id)
    if not event:
        return jsonify({"error": "Event not found"}), 404
    result = _escalation.send_immediate(event)
    code = 200 if result["status"] in ("sent", "skipped") else 500
    return jsonify(result), code

@app.get("/api/escalation/log")
def escalation_log():
    limit = min(request.args.get("limit", 50, type=int), 200)
    entries = db.get_escalation_log(limit=limit)
    return jsonify({"count": len(entries), "entries": entries}), 200


# ── Investigations routes ──────────────────────────────────────────────────────

@app.post("/api/investigations")
def create_investigation():
    body = request.get_json(silent=True) or {}
    user_id = body.get("user_id", "") or "unknown"
    case_id = "case_" + str(uuid.uuid4())[:8]
    db.create_investigation(
        case_id    = case_id,
        alert_id   = body.get("alert_id", ""),
        user_id    = user_id,
        department = body.get("department", ""),
        severity   = body.get("severity", ""),
    )
    return jsonify({"case_id": case_id, "status": "open"}), 201

@app.get("/api/investigations")
def list_investigations():
    status  = request.args.get("status", "")
    user_id = request.args.get("user_id", "")
    limit   = request.args.get("limit", 100, type=int)
    limit   = min(limit, 200)
    cases   = db.list_investigations(status=status, user_id=user_id, limit=limit)
    open_cases = db.list_investigations(status="open", limit=1000)
    return jsonify({"count": len(cases), "open_count": len(open_cases), "cases": cases}), 200

@app.get("/api/investigations/<case_id>")
def get_investigation(case_id):
    case = db.get_investigation(case_id)
    if not case:
        return jsonify({"error": "Case not found"}), 404
    return jsonify(case), 200

@app.patch("/api/investigations/<case_id>")
def update_investigation(case_id):
    body = request.get_json(silent=True) or {}
    status        = body.get("status", "")
    analyst_notes = body.get("analyst_notes")
    db.update_investigation(case_id, status=status, analyst_notes=analyst_notes)
    return jsonify({"case_id": case_id, "updated": True}), 200


@app.get("/api/stream")
def sse_stream():
    q=queue.Queue(maxsize=500)
    with sse_lock: sse_queues.append(q)
    @stream_with_context
    def generate():
        pub=get_pub_store()
        yield f"data: {json.dumps({'type':'init','psychometrics':psych_loaded,'psych_profiles':len(get_psych_store()),'pub_users':len(pub),'pub_trained':pub.trained_count})}\n\n"
        try:
            while True:
                try:    yield q.get(timeout=20)
                except queue.Empty: yield ": keepalive\n\n"
        except GeneratorExit: pass
        finally:
            with sse_lock:
                if q in sse_queues: sse_queues.remove(q)
    return Response(generate(),mimetype="text/event-stream",
                    headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no","Connection":"keep-alive"})

if __name__=="__main__":
    print("InsightGuard API        →  http://0.0.0.0:5000")
    print("Simulate                →  GET /api/events/simulate")
    print("CERT replay             →  GET /api/cert/replay")
    print("PERS psychometrics      →  GET /api/psychometrics")
    print("Per-User Baselines      →  GET /api/baselines")
    print("Ground truth validation →  GET /api/validate")

    # Auto-load data on startup (runs in background so server starts immediately)
    import threading as _t
    def _startup():
        try:
            from startup_loader import run_startup_loader
            run_startup_loader()
        except Exception as e:
            print(f"[Startup] Warning: {e}")
    _t.Thread(target=_startup, daemon=True).start()

    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)