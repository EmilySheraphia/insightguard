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
import json, queue, re, threading, random, time, uuid
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

_SIM_USERS = [
    {"id":"jsmith",  "dept":"Finance",     "role":"Analyst"},
    {"id":"alopez",  "dept":"Engineering", "role":"Developer"},
    {"id":"mkumar",  "dept":"HR",          "role":"Manager"},
    {"id":"twang",   "dept":"IT",          "role":"SysAdmin"},
    {"id":"rbrown",  "dept":"Legal",       "role":"Counsel"},
    {"id":"hnguyen", "dept":"Finance",     "role":"Director"},
]

def _normal_fv():
    return {"hour":random.randint(9,16),"day_of_week":random.randint(0,4),
            "is_off_hours":0,"is_weekend":0,"event_type_code":random.choice([0,2,3,5]),
            "failed_attempts":0,"vpn":0,"tor":0,"new_device":0,
            "is_risky_country":0,"is_unknown_country":0,
            "file_count":random.randint(1,15),"data_mb":round(random.uniform(0.1,30),2),
            "usb_transfer":0,"usb_data_mb":0.0,"recipient_count":random.randint(1,4),
            "attachment_mb":round(random.uniform(0,2),2),"external_email":0,"risky_web":0}

def _suspicious_fv():
    return {"hour":random.choice([7,19,20,21]),"day_of_week":random.randint(0,4),
            "is_off_hours":1,"is_weekend":0,"event_type_code":0,
            "failed_attempts":random.randint(1,2),"vpn":1,"tor":0,
            "new_device":random.randint(0,1),"is_risky_country":0,"is_unknown_country":1,
            "file_count":random.randint(5,40),"data_mb":round(random.uniform(10,200),2),
            "usb_transfer":0,"usb_data_mb":0.0,"recipient_count":random.randint(1,8),
            "attachment_mb":round(random.uniform(0,10),2),
            "external_email":random.randint(0,1),"risky_web":random.randint(0,1)}

def _high_risk_fv():
    return {"hour":random.choice([1,2,3,23]),"day_of_week":random.randint(0,4),
            "is_off_hours":1,"is_weekend":0,"event_type_code":random.choice([2,4]),
            "failed_attempts":random.randint(3,5),"vpn":1,"tor":0,"new_device":1,
            "is_risky_country":0,"is_unknown_country":1,
            "file_count":random.randint(60,200),"data_mb":round(random.uniform(600,2000),2),
            "usb_transfer":1,"usb_data_mb":round(random.uniform(200,800),2),
            "recipient_count":random.randint(10,20),"attachment_mb":round(random.uniform(30,80),2),
            "external_email":1,"risky_web":1}

def _critical_fv():
    return {"hour":random.choice([1,2,3]),"day_of_week":random.randint(0,4),
            "is_off_hours":1,"is_weekend":0,"event_type_code":0,
            "failed_attempts":random.randint(5,10),"vpn":1,"tor":1,"new_device":1,
            "is_risky_country":1,"is_unknown_country":0,
            "file_count":random.randint(300,600),"data_mb":round(random.uniform(3000,6000),2),
            "usb_transfer":1,"usb_data_mb":round(random.uniform(1000,2000),2),
            "recipient_count":random.randint(20,50),"attachment_mb":round(random.uniform(80,200),2),
            "external_email":1,"risky_web":1}

_EVENT_NAMES = {0:"login",1:"logoff",2:"file_access",3:"email",4:"usb",5:"web"}


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


def _sim(level):
    user = random.choice(_SIM_USERS)
    r    = random.random()
    fv_dict = (
        _normal_fv()     if level=="normal"     else
        _suspicious_fv() if level=="suspicious" else
        _high_risk_fv()  if level=="high"       else
        _critical_fv()   if level=="critical"   else
        _normal_fv()     if r<0.55 else
        _suspicious_fv() if r<0.75 else
        _high_risk_fv()  if r<0.90 else _critical_fv()
    )
    # Use real time for timestamp/storage; keep simulated hour in feature vector
    # so IF/LOF score against the scenario's intended time pattern
    _now = datetime.now(timezone.utc).replace(tzinfo=None)
    _wh = _role_config.get("working_hours", {"start": 8, "end": 18})
    fv_dict["is_off_hours"] = int(not (_wh.get("start", 8) <= fv_dict["hour"] < _wh.get("end", 18)))
    result = _full_score(fv_dict, user["id"])
    atype  = _EVENT_NAMES.get(fv_dict["event_type_code"],"login")
    uid    = user["id"]
    lid = str(uuid.uuid4())[:12]
    db.upsert_user(uid, user["dept"], user["role"])
    db.insert_activity_log(lid, uid, _now.isoformat()+"Z", atype, "simulator", details=fv_dict)
    db.insert_features("ft_"+lid, uid, lid, fv_dict)
    did = "dt_"+lid
    db.insert_anomaly_result(did, uid, lid, result)
    _upd(uid, result, user)
    aid = None
    if result["is_anomaly"]:
        aid = "al_"+lid[:10]
        db.insert_alert(aid, uid, did, result["severity"], atype,
                        "Rules: "+", ".join(result["triggered_rules"][:3]) if result["triggered_rules"] else "Anomaly")
    pay = {
        "alert_id":aid,"user_id":uid,"department":user["dept"],"activity_type":atype,
        "ml_score":result["ml_score"],"personal_risk_score":result["personal_risk_score"],
        "pub_combined":result["pub_combined"],"pub_is_trained":result["pub_is_trained"],
        "pub_events_seen":result["pub_events_seen"],"pub_status":result["pub_status"],
        "psychometric_risk":result["psychometric_risk"],"pers_enhancement":result["pers_enhancement"],
        "risk_score":result["risk_score"],"severity":result["severity"],
        "ueba_score":result["ueba_score"],"if_score":result["if_score"],"lof_score":result["lof_score"],
        "triggered_rules":result["triggered_rules"],"timestamp":_now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "data_mb":fv_dict["data_mb"],"file_count":fv_dict["file_count"],"tor":bool(fv_dict["tor"]),
    }
    _broadcast_sse(pay)
    return {**pay,"is_anomaly":result["is_anomaly"],"log_id":lid}


def _process_event(raw):
    activity = router.route(raw)
    log      = pipeline.process(activity)
    if not log.is_valid: return {"error":"Unprocessable event"}
    enrich_raw(raw)
    raw["is_off_hours"] = int(log.is_off_hours)
    fv      = fe_eng.extractFeatures(log)
    uid     = log.user_id
    result  = _full_score(fv.to_dict(), uid, fv.to_array(), role=raw.get("role",""), raw_event=raw)
    db.upsert_user(uid, raw.get("department",""), raw.get("role",""))
    db.insert_activity_log(log.log_id, uid, log.timestamp.isoformat(),
                           log.activity_type, log.source, details=fv.to_dict())
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
        "files":raw.get("files",[]),
        "threat_type":raw.get("threat_type",""),
        "description":raw.get("description",""),
    }
    _broadcast_sse(pay)
    # Escalation
    _escalation.enqueue({**pay, "triggered_rules": result["triggered_rules"]})
    return {**pay,"is_anomaly":result["is_anomaly"],"log_id":log.log_id,"timestamp":log.timestamp.isoformat()}


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
        dead = [q for q in sse_queues if not _try_put(q,msg)]
        for q in dead: sse_queues.remove(q)

def _try_put(q, msg):
    try: q.put_nowait(msg); return True
    except queue.Full: return False


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

# ── File download content generators ─────────────────────────────────────────

_FILE_CONTENT = {
    "Salary_Data_2025.xlsx": lambda dept: (
        "employee_id,name,department,base_salary,bonus,total_comp\n" +
        "\n".join(f"EMP{1000+i},{n},{dept},£{55000+i*2500:,},£{8000+i*500:,},£{63000+i*3000:,}"
                  for i, n in enumerate(["Alice Johnson","Bob Smith","Carol Williams","David Brown",
                                          "Emma Davis","Frank Miller","Grace Wilson","Henry Moore",
                                          "Isla Taylor","James Anderson","Karen Thomas","Liam Jackson",
                                          "Maria White","Nathan Harris","Olivia Martin","Paul Thompson",
                                          "Quinn Garcia","Rachel Martinez","Steve Robinson","Tina Clark"]))
    ),
    "admin_passwords.txt": lambda dept: (
        "# NEXON TECHNOLOGIES — IT ADMIN CREDENTIALS\n"
        "# CONFIDENTIAL — DO NOT DISTRIBUTE\n\n"
        "[Database Servers]\n"
        "prod-db-01.nexon.internal  admin  Nx!Pr0d@2025\n"
        "prod-db-02.nexon.internal  admin  Nx!Pr0d@2025\n"
        "staging-db.nexon.internal  admin  Nx!Stg@2025\n\n"
        "[Active Directory]\n"
        "ad.nexon.internal          administrator  N3x0n@AD!2025\n\n"
        "[Cloud Console]\n"
        "AWS Account ID: 123456789012\n"
        "Root: admin@nexon.com  / N3x0nCl0ud!2025\n\n"
        "[VPN Gateway]\n"
        "vpn.nexon.internal  vpnadmin  VPN!Nx2025@sec\n"
    ),
    "prod_server_list.csv": lambda dept: (
        "hostname,ip,role,os,owner,last_patch\n"
        "prod-app-01,10.0.1.10,Application Server,Ubuntu 22.04,Engineering,2025-03-15\n"
        "prod-app-02,10.0.1.11,Application Server,Ubuntu 22.04,Engineering,2025-03-15\n"
        "prod-db-01,10.0.2.10,Primary Database,RHEL 9,DBA Team,2025-02-28\n"
        "prod-db-02,10.0.2.11,Replica Database,RHEL 9,DBA Team,2025-02-28\n"
        "prod-lb-01,10.0.0.5,Load Balancer,nginx/Ubuntu,Engineering,2025-03-01\n"
        "prod-cache-01,10.0.3.10,Redis Cache,Ubuntu 22.04,Engineering,2025-03-10\n"
        "backup-01,10.0.5.10,Backup Server,Ubuntu 22.04,IT Ops,2025-01-20\n"
        "monitoring-01,10.0.6.10,Monitoring,Ubuntu 22.04,IT Ops,2025-03-01\n"
    ),
    "db_credentials.txt": lambda dept: (
        "# Application Database Credentials\n"
        "# Environment: Production\n\n"
        "DB_HOST=prod-db-01.nexon.internal\n"
        "DB_PORT=5432\n"
        "DB_NAME=nexon_production\n"
        "DB_USER=app_service\n"
        "DB_PASSWORD=AppSvc!Nx2025@prod\n\n"
        "# Read replica\n"
        "DB_REPLICA_HOST=prod-db-02.nexon.internal\n"
        "DB_REPLICA_USER=app_service_ro\n"
        "DB_REPLICA_PASSWORD=R0Service!Nx2025\n"
    ),
    "deployment_config.yaml": lambda dept: (
        "# Nexon Platform Deployment Configuration\n"
        "# DO NOT COMMIT WITH SECRETS\n\n"
        "environment: production\n"
        "region: eu-west-1\n\n"
        "database:\n"
        "  host: prod-db-01.nexon.internal\n"
        "  port: 5432\n"
        "  name: nexon_production\n"
        "  ssl: true\n\n"
        "cache:\n"
        "  host: prod-cache-01.nexon.internal\n"
        "  port: 6379\n\n"
        "services:\n"
        "  api: { replicas: 3, port: 8080 }\n"
        "  worker: { replicas: 2 }\n"
        "  scheduler: { replicas: 1 }\n"
    ),
    "All_Employees_Personal.xlsx": lambda dept: (
        "employee_id,full_name,dob,address,ni_number,bank_sort,bank_account,emergency_contact\n" +
        "\n".join(f"EMP{1000+i},{n},19{70+i%30}-{(i%12)+1:02d}-{(i%28)+1:02d},"
                  f"{i+1} High Street London,AB{100000+i}C,{20+i%80:02d}-{10+i%40:02d}-{30+i%70:02d},"
                  f"{10000000+i*13},{n.split()[0]} {n.split()[-1]} (Parent)"
                  for i, n in enumerate(["Alice Johnson","Bob Smith","Carol Williams","David Brown",
                                          "Emma Davis","Frank Miller","Grace Wilson","Henry Moore",
                                          "Isla Taylor","James Anderson","Karen Thomas","Liam Jackson",
                                          "Maria White","Nathan Harris","Olivia Martin","Paul Thompson",
                                          "Quinn Garcia","Rachel Martinez","Steve Robinson","Tina Clark",
                                          "Uma Patel","Victor Chen","Wendy Kim","Xavier Lee","Yara Singh"]))
    ),
    "firewall_rules.csv": lambda dept: (
        "rule_id,action,protocol,src_ip,dst_ip,dst_port,description\n"
        "FW001,ALLOW,TCP,0.0.0.0/0,10.0.0.5,443,HTTPS inbound to load balancer\n"
        "FW002,ALLOW,TCP,0.0.0.0/0,10.0.0.5,80,HTTP inbound redirect\n"
        "FW003,ALLOW,TCP,10.0.1.0/24,10.0.2.10,5432,App servers to primary DB\n"
        "FW004,DENY,ANY,0.0.0.0/0,10.0.2.0/24,ANY,Block direct DB access from internet\n"
        "FW005,ALLOW,TCP,10.0.0.0/8,10.0.6.10,9090,Internal monitoring access\n"
        "FW006,DENY,ANY,192.168.50.0/24,ANY,ANY,Block legacy VLAN\n"
        "FW007,ALLOW,TCP,10.0.0.0/8,ANY,22,SSH from internal only\n"
    ),
    "Active_Directory_Export.xlsx": lambda dept: (
        "username,display_name,email,department,title,manager,groups,last_logon,account_status\n" +
        "\n".join(f"usr{1000+i},{n},{n.lower().replace(' ','.')}" + "@nexon.com," +
                  f"{dept},Employee,mgr001,Domain Users;{dept}_Users,2025-04-{(i%30)+1:02d},Active"
                  for i, n in enumerate(["Alice Johnson","Bob Smith","Carol Williams","David Brown",
                                          "Emma Davis","Frank Miller","Grace Wilson","Henry Moore",
                                          "Isla Taylor","James Anderson","Karen Thomas","Liam Jackson"]))
    ),
}

def _generic_file_content(name: str, dept: str) -> str:
    """Generate plausible text content for files not in the explicit map."""
    base = name.rsplit(".", 1)[0].replace("_", " ")
    lines = [
        f"# {base}",
        f"Department: {dept}",
        f"Classification: CONFIDENTIAL",
        f"Generated: 2025-04-10",
        "",
        f"This document contains {dept} department records.",
        "Access is restricted to authorised personnel only.",
        "",
        "id,name,value,date,status",
        "001,Record A,£12450.00,2025-01-15,Active",
        "002,Record B,£8320.00,2025-02-03,Active",
        "003,Record C,£19875.00,2025-02-28,Pending",
        "004,Record D,£5100.00,2025-03-10,Active",
        "005,Record E,£33200.00,2025-03-22,Review",
    ]
    return "\n".join(lines)


@app.get("/api/files/download")
def download_file():
    from flask import make_response
    name = request.args.get("name", "file.txt")
    dept = request.args.get("dept", "General")
    gen  = _FILE_CONTENT.get(name)
    content = gen(dept) if gen else _generic_file_content(name, dept)
    resp = make_response(content.encode("utf-8"))
    resp.headers["Content-Disposition"] = f'attachment; filename="{name}"'
    resp.headers["Content-Type"] = "text/plain; charset=utf-8"
    resp.headers["Content-Length"] = len(content.encode("utf-8"))
    return resp

@app.get("/portal")
def serve_portal():
    import os as _os
    from flask import Response as _Resp
    base = _os.path.dirname(_os.path.abspath(__file__))
    paths = [
        _os.path.join(base, "employee_portal.html"),
        _os.path.join(_os.getcwd(), "application", "employee_portal.html"),
    ]
    for p in paths:
        if _os.path.exists(p):
            with open(p, "r", encoding="utf-8") as f:
                return _Resp(f.read(), mimetype="text/html")
    return _Resp("<h1>Employee Portal not found</h1>", mimetype="text/html")

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

@app.get("/api/events/simulate")
def simulate_event():
    return jsonify(_sim(request.args.get("type","random"))),200

@app.get("/api/cert/replay")
def cert_replay():
    limit = int(request.args.get("limit",200))
    speed = float(request.args.get("speed",0.3))
    def replay_worker():
        import sqlite3 as sq
        conn = sq.connect(db.db_path); conn.row_factory = sq.Row
        rows = conn.execute("""
            SELECT ar.user_id,ar.risk_score,ar.if_score,ar.lof_score,ar.ueba_score,
                   ar.triggered_rules,ar.detection_time,al.activity_type,al.timestamp,
                   al.details_json,u.department
            FROM anomaly_results ar
            LEFT JOIN activity_logs al ON ar.log_id=al.log_id
            LEFT JOIN users u ON ar.user_id=u.user_id
            ORDER BY al.timestamp ASC LIMIT ?""",(limit,)).fetchall()
        conn.close()
        print(f"[CERT Replay] {len(rows)} events with PUB+PERS...")
        for row in rows:
            try: rules=json.loads(row["triggered_rules"] or "[]")
            except: rules=[]
            uid=row["user_id"] or "unknown"
            ml=row["risk_score"] or 0
            try:
                fv_dict=json.loads(row["details_json"] or "{}")
                arr=np.array([fv_dict.get(k,0) for k in FeatureVector.COLUMNS],dtype=float)
                pub=pub_score(uid,arr,ml)
            except:
                pub={"personal_risk_score":ml,"personal_if_score":0.5,"combined_score":ml,
                     "is_trained":False,"events_seen":0,"status":"learning (0/10 events)"}
            pers=get_pers_score(uid,pub["combined_score"])
            pay={
                "user_id":uid,"department":row["department"] or "",
                "activity_type":row["activity_type"] or "login",
                "ml_score":ml,"personal_risk_score":pub["personal_risk_score"],
                "pub_combined":pub["combined_score"],"pub_is_trained":pub["is_trained"],
                "pub_events_seen":pub["events_seen"],"pub_status":pub["status"],
                "psychometric_risk":pers["psychometric_risk"],"pers_enhancement":pers["enhancement"],
                "risk_score":pers["pers_score"],"severity":pers["severity"],
                "ueba_score":row["ueba_score"] or 0,"if_score":row["if_score"] or 0.0,
                "lof_score":row["lof_score"] or 0.0,"triggered_rules":rules,
                "timestamp":row["timestamp"] or row["detection_time"],"source":"cert_dataset",
            }
            _broadcast_sse(pay)
            _upd(uid,{"risk_score":pers["pers_score"],"is_anomaly":pers["is_anomaly"],**pub},
                 {"department":row["department"] or ""})
            time.sleep(speed)
        print("[CERT Replay] Complete.")
    threading.Thread(target=replay_worker,daemon=True).start()
    return jsonify({"message":"Replaying CERT with PUB+PERS"}),200

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
                usb_ts = datetime.fromisoformat(ev["timestamp"].replace("Z",""))
            except Exception:
                continue
            for j in range(0, i):
                prev = events[j]
                if prev["activity_type"] == "file_access":
                    try:
                        prev_ts = datetime.fromisoformat(prev["timestamp"].replace("Z",""))
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
            WHERE al.user_id = ? AND al.timestamp >= ?
            ORDER BY al.timestamp ASC
        """, (uid, since)).fetchall()

    GAP_SECS = 30 * 60
    sessions = []
    current  = None

    for row in rows:
        try:
            ts = datetime.fromisoformat(row["timestamp"].replace("Z",""))
        except Exception:
            continue

        rules = []
        try:
            rules = _json.loads(row["triggered_rules"] or "[]")
        except Exception:
            pass

        file_name = ""
        try:
            d = _json.loads(row["details_json"] or "{}")
            raw = d.get("file_path","") or d.get("file_name","")
            if raw:
                file_name = raw.split("/")[-1].split("\\")[-1]
        except Exception:
            pass

        event = {
            "log_id":          row["log_id"],
            "timestamp":       row["timestamp"],
            "activity_type":   row["activity_type"] or "login",
            "severity":        row["severity"] or "normal",
            "risk_score":      row["risk_score"] or 0,
            "file_name":       file_name,
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
    if not str(fpath).startswith(str(EVIDENCE_DIR.resolve())):
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


@app.get("/api/events/recent")
def recent_events():
    limit = min(int(request.args.get("limit", 200)), 500)
    # Default: only show events from the last 60 minutes so synthetic
    # training data (timestamped hours/days ago) never pollutes the log.
    minutes = int(request.args.get("minutes", 60))
    from datetime import timedelta
    since = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%S")
    import sqlite3 as _sq
    with _sq.connect(db.db_path) as con:
        con.row_factory = _sq.Row
        rows = con.execute("""
            SELECT
                al.log_id, al.user_id, al.timestamp, al.activity_type, al.source,
                u.department, u.role,
                ar.risk_score, ar.severity, ar.is_anomaly,
                ar.if_score, ar.lof_score, ar.ueba_score, ar.triggered_rules
            FROM activity_logs al
            LEFT JOIN users u            ON al.user_id = u.user_id
            LEFT JOIN anomaly_results ar ON ar.log_id  = al.log_id
            WHERE al.timestamp >= ?
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
        # Extract file_name from details_json if stored
        file_name = ""
        try:
            details = _json.loads(r["details_json"] or "{}") if "details_json" in r.keys() else {}
            raw_path = details.get("file_path","") or details.get("file_name","")
            if raw_path:
                file_name = raw_path.split("/")[-1].split("\\")[-1]
        except Exception:
            pass
        events.append({
            "user_id":       r["user_id"],
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

@app.get("/api/escalation/log")
def escalation_log():
    limit = min(request.args.get("limit", 50, type=int), 200)
    entries = db.get_escalation_log(limit=limit)
    return jsonify({"count": len(entries), "entries": entries}), 200


# ── Investigations routes ──────────────────────────────────────────────────────

@app.post("/api/investigations")
def create_investigation():
    body = request.get_json(silent=True) or {}
    user_id = body.get("user_id", "")
    if not user_id:
        return jsonify({"error": "user_id required"}), 400
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
    ok = db.update_investigation(case_id, status=status, analyst_notes=analyst_notes)
    if not ok:
        return jsonify({"error": "Invalid update or case not found"}), 400
    return jsonify({"case_id": case_id, "updated": True}), 200


@app.get("/api/stream")
def sse_stream():
    q=queue.Queue(maxsize=100)
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