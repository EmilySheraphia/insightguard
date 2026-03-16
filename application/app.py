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

from flask import Flask, request, jsonify, Response, stream_with_context
from datetime import datetime
import json, queue, threading, random, time
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from data_acquisition.collector    import AcquisitionRouter
from data_processing.etl_pipeline  import ETLPipeline
from feature_engineering.extractor import FeatureEngineering, FeatureVector
from ai_analytics.anomaly_model    import AnomalyDetectionModel
from explainability.lime_engine    import ExplainabilityEngine
from storage.database              import DatabaseManager
from psychometric_scorer           import init_psychometrics, get_pers_score
from psychometric_scorer           import get_store as get_psych_store
from per_user_baseline             import ingest_and_score as pub_score
from per_user_baseline             import get_store as get_pub_store
from ground_truth_validator        import validate as run_validation
from pathlib import Path
import numpy as np

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

CERT_DIR     = Path.home() / "Downloads" / "r4.2"
psych_loaded = init_psychometrics(CERT_DIR)

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


def _full_score(fv_dict: dict, user_id: str, feature_array=None) -> dict:
    fv = FeatureVector(**{k: fv_dict.get(k,0) for k in FeatureVector.COLUMNS})
    from ai_analytics.anomaly_model import UEBAEngine
    ueba = UEBAEngine()
    ueba_score, rules = ueba.score(fv)
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
    result = _full_score(fv_dict, user["id"])
    atype  = _EVENT_NAMES.get(fv_dict["event_type_code"],"login")
    uid    = user["id"]
    import uuid
    lid = str(uuid.uuid4())[:12]
    db.upsert_user(uid, user["dept"], user["role"])
    db.insert_activity_log(lid, uid, datetime.now().isoformat(), atype, "simulator", details=fv_dict)
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
        "triggered_rules":result["triggered_rules"],"timestamp":datetime.now().isoformat()+"Z",
        "data_mb":fv_dict["data_mb"],"file_count":fv_dict["file_count"],"tor":bool(fv_dict["tor"]),
    }
    _broadcast_sse(pay)
    return {**pay,"is_anomaly":result["is_anomaly"],"log_id":lid}


def _process_event(raw):
    activity = router.route(raw)
    log      = pipeline.process(activity)
    if not log.is_valid: return {"error":"Unprocessable event"}
    fv      = fe_eng.extractFeatures(log)
    uid     = log.user_id
    result  = _full_score(fv.to_dict(), uid, fv.to_array())
    db.upsert_user(uid, raw.get("department",""), raw.get("role",""))
    db.insert_activity_log(log.log_id, uid, log.timestamp.isoformat(),
                           log.activity_type, log.source, details=fv.to_dict())
    db.insert_features("ft_"+log.log_id, uid, log.log_id, fv.to_dict())
    did = "dt_"+log.log_id
    db.insert_anomaly_result(did, uid, log.log_id, result)
    _upd(uid, result, raw)
    aid = None
    if result["is_anomaly"]:
        aid = "al_"+log.log_id[:10]
        db.insert_alert(aid, uid, did, result["severity"], log.activity_type,
                        "Rules: "+", ".join(result["triggered_rules"][:3]) if result["triggered_rules"] else "Anomaly")
    pay = {
        "alert_id":aid,"user_id":uid,"department":raw.get("department",""),
        "activity_type":log.activity_type,
        "ml_score":result["ml_score"],"personal_risk_score":result["personal_risk_score"],
        "pub_combined":result["pub_combined"],"pub_is_trained":result["pub_is_trained"],
        "pub_events_seen":result["pub_events_seen"],"pub_status":result["pub_status"],
        "psychometric_risk":result["psychometric_risk"],"pers_enhancement":result["pers_enhancement"],
        "risk_score":result["risk_score"],"severity":result["severity"],
        "ueba_score":result["ueba_score"],"if_score":result["if_score"],"lof_score":result["lof_score"],
        "triggered_rules":result["triggered_rules"],"timestamp":datetime.now().isoformat()+"Z",
        "data_mb":fv.data_mb,"file_count":fv.file_count,"tor":bool(fv.tor),
    }
    _broadcast_sse(pay)
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


@app.get("/")
@app.get("/dashboard")
def serve_dashboard():
    from flask import send_file
    dashboard_path = Path(__file__).parent / "dashboard.html"
    return send_file(str(dashboard_path))

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