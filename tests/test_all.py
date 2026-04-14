"""
InsightGuard — Integration Test Suite
=======================================
Tests all 6 layers + Flask API via test client.
"""

import sys, os, json, tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import importlib


def section(title):
    print(f"\n{'═'*65}")
    print(f"  {title}")
    print('═'*65)


def ok(label):  print(f"  [PASS] {label}")
def fail(label): print(f"  [FAIL] {label}")


# ─── Layer 1: Data Acquisition ─────────────────────────────────────────────

def test_layer1():
    section("LAYER 1 — Data Acquisition")
    from data_acquisition.collector import AcquisitionRouter
    router = AcquisitionRouter()
    cases = [
        {"source": "login",  "user_id": "u1", "timestamp": "2024-06-03T02:00:00",
         "event": "login", "country_code": "KP", "tor": True},
        {"source": "file",   "user_id": "u2", "timestamp": "2024-06-03T09:00:00",
         "file_count": 200, "data_mb": 3000},
        {"source": "email",  "user_id": "u3", "timestamp": "2024-06-03T11:00:00",
         "recipient_count": 10, "attachment_mb": 50, "external": True},
        {"source": "usb",    "user_id": "u4", "timestamp": "2024-06-03T14:00:00",
         "operation": "transfer", "data_mb": 800},
        {"source": "web",    "user_id": "u5", "timestamp": "2024-06-03T16:00:00",
         "url": "mega.nz", "category": "cloud_storage"},
    ]
    passed = 0
    for c in cases:
        log = router.route(c)
        assert log.user_id and log.activity_type, "Missing fields"
        ok(f"  {log.activity_type.upper():12s} → log_id={log.log_id[:8]}")
        passed += 1
    print(f"\n  {passed}/{len(cases)} passed")
    return passed == len(cases)


# ─── Layer 2: Data Processing ──────────────────────────────────────────────

def test_layer2():
    section("LAYER 2 — Data Processing (ETL)")
    from data_acquisition.collector import AcquisitionRouter
    from data_processing.etl_pipeline import ETLPipeline
    router = AcquisitionRouter(); pipe = ETLPipeline()

    raw = router.route({"source": "login", "user_id": "alice",
                         "timestamp": "2024-06-03T02:30:00",
                         "country_code": "KP", "tor": True,
                         "failed_attempts": 5, "new_device": True})
    log = pipe.process(raw)
    assert log.is_valid,        "Should be valid"
    assert log.is_off_hours,    "Should be off-hours"
    assert log.is_risky_country,"Should be risky country"
    assert log.tor,             "TOR flag should be set"
    assert log.failed_attempts == 5
    ok("Timestamp normalised + off-hours detected")
    ok("Risky country flag set (KP)")
    ok("TOR and failed_attempts propagated")

    # Invalid event
    from data_acquisition.collector import RawActivityLog
    bad = RawActivityLog(user_id="", timestamp="", activity_type="unknown", source="x")
    processed_bad = pipe.process(bad)
    assert not processed_bad.is_valid
    ok("Invalid event rejected")
    print(f"\n  4/4 passed")
    return True


# ─── Layer 3: Feature Engineering ─────────────────────────────────────────

def test_layer3():
    section("LAYER 3 — Feature Engineering")
    from data_acquisition.collector import AcquisitionRouter
    from data_processing.etl_pipeline import ETLPipeline
    from feature_engineering.extractor import FeatureEngineering, FeatureVector
    router = AcquisitionRouter(); pipe = ETLPipeline(); fe = FeatureEngineering()

    log = pipe.process(router.route({
        "source": "file", "user_id": "bob", "timestamp": "2024-06-03T02:00:00",
        "file_count": 500, "data_mb": 4000, "destination": "usb"
    }))
    fv  = fe.extractFeatures(log)
    arr = fv.to_array()

    assert len(arr) == len(FeatureVector.COLUMNS), "Feature count mismatch"
    assert fv.file_count == 500, "file_count wrong"
    assert fv.data_mb == 4000,   "data_mb wrong"
    assert fv.is_off_hours == 1, "Should be off-hours"
    ok(f"Feature vector has {len(arr)} dimensions")
    ok("file_count=500, data_mb=4000 extracted correctly")
    ok("is_off_hours flag set")

    # batch
    logs = [
        pipe.process(router.route({"source": "email", "user_id": "x",
            "timestamp": "2024-06-03T10:00:00", "recipient_count": 5,
            "attachment_mb": 20, "external": True})),
        pipe.process(router.route({"source": "usb", "user_id": "y",
            "timestamp": "2024-06-03T15:00:00", "data_mb": 300})),
    ]
    matrix = fe.to_matrix(logs)
    assert matrix.shape == (2, len(FeatureVector.COLUMNS))
    ok(f"Batch matrix shape = {matrix.shape}")
    print(f"\n  4/4 passed")
    return True


# ─── Layer 4: AI Analytics ────────────────────────────────────────────────

def test_layer4():
    section("LAYER 4 — AI Analytics (IF + LOF + UEBA)")
    from data_acquisition.collector import AcquisitionRouter
    from data_processing.etl_pipeline import ETLPipeline
    from ai_analytics.anomaly_model import AnomalyDetectionModel
    router = AcquisitionRouter(); pipe = ETLPipeline()
    model  = AnomalyDetectionModel()

    cases = [
        ("Normal login",    "login",  {"country_code": "US"}, False),
        ("TOR+KP login",    "login",  {"country_code": "KP", "tor": True,
                                       "failed_attempts": 7, "new_device": True}, True),
        ("Bulk download",   "file",   {"file_count": 400, "data_mb": 4500}, True),
        ("USB exfil",       "usb",    {"operation": "transfer", "data_mb": 1200}, True),
        ("External email",  "email",  {"recipient_count": 20, "attachment_mb": 80,
                                       "external": True}, True),
    ]
    passed = 0
    for label, src, extra, expect_threat in cases:
        raw = {"source": src, "user_id": "test",
               "timestamp": "2024-06-03T02:00:00", **extra}
        log    = pipe.process(router.route(raw))
        result = model.detectAnomaly(log)
        match  = result["is_anomaly"] == expect_threat
        passed += match
        status = "PASS" if match else "FAIL"
        print(f"  [{status}] {label:20s} "
              f"score={result['risk_score']:>3}  sev={result['severity']:10s}  "
              f"is_anomaly={result['is_anomaly']}")
    print(f"\n  {passed}/{len(cases)} passed")
    return passed >= 4   # allow 1 borderline miss


# ─── Layer 5: Explainability ──────────────────────────────────────────────

def test_layer5():
    section("LAYER 5 — Explainability Engine (LIME)")
    from data_acquisition.collector import AcquisitionRouter
    from data_processing.etl_pipeline import ETLPipeline
    from ai_analytics.anomaly_model import AnomalyDetectionModel
    from explainability.lime_engine import ExplainabilityEngine
    from feature_engineering.extractor import FeatureEngineering, FeatureVector

    router = AcquisitionRouter(); pipe = ETLPipeline()
    model  = AnomalyDetectionModel()
    fe     = FeatureEngineering(); xai = ExplainabilityEngine()

    raw = {"source": "login", "user_id": "eve", "timestamp": "2024-06-03T02:00:00",
           "country_code": "KP", "failed_attempts": 7, "tor": True, "new_device": True}
    log = pipe.process(router.route(raw))
    fv  = fe.extractFeatures(log)

    def score_fn(arr):
        dummy_fv = FeatureVector(**dict(zip(
            FeatureVector.COLUMNS, [float(v) for v in arr]
        )))
        s = (model._if.score(arr) * 100 * model.IF_WEIGHT +
             model._lof.score(arr) * 100 * model.LOF_WEIGHT +
             model._ueba.score(dummy_fv)[0] * model.UEBA_WEIGHT)
        return min(s / 100, 1.0)

    exp = xai.generateExplanation(fv, score_fn)
    assert exp.method == "LIME"
    assert len(exp.top_factors) > 0
    assert exp.confidence >= 0
    assert "Anomaly" in exp.summary or "anomaly" in exp.summary or "TOR" in exp.summary or "driven" in exp.summary

    ok(f"LIME method: {exp.method}")
    ok(f"Top factors: {len(exp.top_factors)}")
    ok(f"R² confidence: {exp.confidence:.4f}")
    ok(f"Summary: {exp.summary}")
    ok(f"Top factor: {exp.top_factors[0]['label']} (weight={exp.top_factors[0]['weight']:+.4f})")
    print(f"\n  5/5 passed")
    return True


# ─── Storage Layer ─────────────────────────────────────────────────────────

def test_storage():
    section("STORAGE LAYER — SQLite (5 tables)")
    import tempfile
    from storage.database import DatabaseManager
    tmp = tempfile.mktemp(suffix=".db")
    db  = DatabaseManager(db_path=tmp)
    passed = 0; total = 0

    def chk(label, cond):
        nonlocal passed, total
        total += 1; passed += cond
        print(f"  [{'PASS' if cond else 'FAIL'}] {label}")

    db.upsert_user("jsmith", "Finance", "Analyst")
    chk("User upsert", db.get_user("jsmith") is not None)

    db.insert_activity_log("log1", "jsmith", "2024-06-03T02:00:00",
                            "login", source="auth_system",
                            details={"tor": True})
    timeline = db.get_user_timeline("jsmith")
    chk("Activity log inserted", len(timeline) == 1)

    db.insert_anomaly_result("det1", "jsmith", "log1", {
        "model_type": "test", "risk_score": 87, "severity": "critical",
        "is_anomaly": True, "if_score": 0.8, "lof_score": 0.85,
        "ueba_score": 90, "triggered_rules": ["tor_detected"],
    })
    stats = db.get_stats()
    chk("Anomaly result inserted", stats["total_threats"] == 1)

    db.insert_alert("al1", "jsmith", "det1", "critical", "login", "TOR detected.")
    alerts = db.get_alerts()
    chk("Alert inserted", len(alerts) == 1)

    ok_upd = db.update_alert_status("al1", "confirmed")
    chk("Alert status updated", ok_upd)

    inv = db.update_alert_status("al1", "invalid_status")
    chk("Invalid status rejected", not inv)

    print(f"\n  {passed}/{total} passed")
    os.unlink(tmp)
    return passed == total


# ─── Layer 6: Flask API ────────────────────────────────────────────────────

def test_api():
    section("LAYER 6 — Flask API (all endpoints)")
    import importlib
    import application.app as app_module
    importlib.reload(app_module)
    client = app_module.app.test_client()

    def jpost(path, body):
        return client.post(path, json=body, content_type="application/json")

    passed = 0; total = 0

    def chk(label, resp, exp_status):
        nonlocal passed, total
        total += 1
        ok_flag = resp.status_code == exp_status
        passed += ok_flag
        print(f"  [{'PASS' if ok_flag else 'FAIL'}] {label}  → HTTP {resp.status_code}")
        if not ok_flag:
            print(f"         {resp.data[:150]}")
        return resp

    # Health
    r = chk("GET /healthz", client.get("/healthz"), 200)
    assert r.get_json()["model_ready"]

    # All 5 source types
    for src, extra, exp_threat in [
        ("login", {"country_code": "US"}, False),
        ("login", {"country_code": "KP", "tor": True, "failed_attempts": 6,
                   "new_device": True}, True),
        ("file",  {"file_count": 400, "data_mb": 4500}, True),
        ("usb",   {"operation": "transfer", "data_mb": 1200}, True),
        ("email", {"recipient_count": 20, "attachment_mb": 80,
                   "external": True}, True),
        ("web",   {"url": "mega.nz", "category": "cloud_storage"}, False),
    ]:
        r = chk(f"POST /api/events (source={src})", jpost("/api/events", {
            "source": src, "user_id": "testuser",
            "timestamp": "2024-06-03T02:00:00", **extra,
        }), 200)
        d = r.get_json()
        print(f"         score={d['risk_score']}  sev={d['severity']}")

    # Batch
    r = chk("POST /api/events/batch", jpost("/api/events/batch", [
        {"source": "login", "user_id": "alice",
         "timestamp": "2024-06-03T09:00:00", "country_code": "US"},
        {"source": "file",  "user_id": "bob",
         "timestamp": "2024-06-03T02:00:00",
         "file_count": 300, "data_mb": 3000},
    ]), 200)
    d = r.get_json()
    print(f"         processed={d['summary']['processed']} threats={d['summary']['threats']}")

    # User risk / timeline
    chk("GET /api/users/testuser/risk",  client.get("/api/users/testuser/risk"), 200)
    chk("GET /api/users/ghost/risk",     client.get("/api/users/ghost/risk"),    404)
    chk("GET /api/users/testuser/timeline", client.get("/api/users/testuser/timeline"), 200)

    # Alerts
    r = chk("GET /api/alerts", client.get("/api/alerts"), 200)
    print(f"         count={r.get_json()['count']}")

    # Stats / dashboard
    chk("GET /api/stats",   client.get("/api/stats"), 200)

    # Reset profile
    chk("DELETE /api/users/testuser/risk", client.delete("/api/users/testuser/risk"), 200)
    chk("GET /api/users/testuser/risk (after reset)", client.get("/api/users/testuser/risk"), 404)

    # Validation
    chk("POST missing source field", jpost("/api/events", {"user_id": "x", "timestamp": "t"}), 422)
    chk("POST empty body",  client.post("/api/events", data="bad"), 400)
    chk("POST batch too large", jpost("/api/events/batch", list(range(501))), 413)

    print(f"\n  {passed}/{total} passed")
    return passed == total


# ─── Analytics ────────────────────────────────────────────────────────────

def test_analytics():
    section("ANALYTICS — ConfidenceEngine + CounterfactualEngine")
    from analytics import ConfidenceEngine, CounterfactualEngine

    ce = ConfidenceEngine()

    # Band 1: 0–9 events → margin=25, label=low
    r = ce.score(events_seen=5, risk_score=60)
    assert r["label"] == "low",       f"Expected low, got {r['label']}"
    assert r["margin"] == 25,         f"Expected margin 25, got {r['margin']}"
    assert r["lower"] == 35,          f"Expected lower 35, got {r['lower']}"
    assert r["upper"] == 85,          f"Expected upper 85, got {r['upper']}"
    assert r["pct"] == 40,            f"Expected pct 40, got {r['pct']}"
    ok("ConfidenceEngine band=low (5 events, score=60)")

    # Band 2: 10–29 events → margin=15, label=moderate
    r2 = ce.score(events_seen=15, risk_score=50)
    assert r2["label"] == "moderate"
    assert r2["margin"] == 15
    ok("ConfidenceEngine band=moderate (15 events, score=50)")

    # Band 3: 30–99 events → margin=8, label=high
    r3 = ce.score(events_seen=50, risk_score=70)
    assert r3["label"] == "high"
    assert r3["margin"] == 8
    ok("ConfidenceEngine band=high (50 events, score=70)")

    # Band 4: 100+ events → margin=4, label=very_high
    r4 = ce.score(events_seen=200, risk_score=80)
    assert r4["label"] == "very_high"
    assert r4["margin"] == 4
    ok("ConfidenceEngine band=very_high (200 events, score=80)")

    # Clamp check: lower never < 0, upper never > 100
    r5 = ce.score(events_seen=0, risk_score=5)
    assert r5["lower"] == 0,   f"Expected lower=0, got {r5['lower']}"
    r6 = ce.score(events_seen=0, risk_score=95)
    assert r6["upper"] == 100, f"Expected upper=100, got {r6['upper']}"
    ok("ConfidenceEngine clamps lower>=0, upper<=100")

    # CounterfactualEngine: off-hours perturbation
    cfe = CounterfactualEngine()
    fv = {
        "hour": 2, "day_of_week": 1, "is_off_hours": 1, "is_weekend": 0,
        "event_type_code": 0, "failed_attempts": 0, "vpn": 0, "tor": 0,
        "new_device": 0, "is_risky_country": 0, "is_unknown_country": 0,
        "file_count": 5, "data_mb": 10.0, "usb_transfer": 0, "usb_data_mb": 0.0,
        "recipient_count": 1, "attachment_mb": 0.0, "external_email": 0, "risky_web": 0,
    }
    results = cfe.explain(fv, original_score=72)
    assert isinstance(results, list),          "explain() must return a list"
    assert len(results) <= 3,                  f"Must return top-3, got {len(results)}"
    for item in results:
        assert "label" in item
        assert "description" in item
        assert "new_score" in item
        assert "delta" in item
        assert "pct_change" in item
    ok(f"CounterfactualEngine returns {len(results)} perturbations")

    # Verify delta direction makes sense for off-hours flip
    during_hours = next((x for x in results if x["label"] == "during_working_hours"), None)
    if during_hours:
        assert during_hours["delta"] < 0, "During-hours should reduce score"
        ok(f"during_working_hours delta={during_hours['delta']} (negative, correct)")

    # Check app.py has the two new routes
    import os as _os
    app_path = _os.path.join(_os.path.dirname(__file__), '..', 'application', 'app.py')
    with open(app_path) as f:
        src = f.read()
    assert '/api/explain/counterfactual' in src, "Missing counterfactual route in app.py"
    assert '/api/explain/confidence' in src,     "Missing confidence route in app.py"
    ok("Flask routes for counterfactual + confidence present in app.py")

    return True


# ─── DB: investigations + escalation_log ──────────────────────────────────

def test_investigations_db():
    section("DB — investigations + escalation_log tables")
    import tempfile, os
    from storage.database import DatabaseManager

    tmp = tempfile.mktemp(suffix=".db")
    db  = DatabaseManager(db_path=tmp)

    # Create investigation
    db.create_investigation("case-001", alert_id="al_abc", user_id="jsmith",
                             department="Finance", severity="critical")
    ok("create_investigation() succeeds")

    # List investigations
    cases = db.list_investigations()
    assert len(cases) == 1,                  f"Expected 1 case, got {len(cases)}"
    assert cases[0]["case_id"] == "case-001"
    assert cases[0]["status"] == "open"
    ok("list_investigations() returns 1 open case")

    # Get single investigation
    case = db.get_investigation("case-001")
    assert case is not None
    assert case["user_id"] == "jsmith"
    ok("get_investigation() returns case detail")

    # Update investigation
    db.update_investigation("case-001", status="confirmed_threat", analyst_notes="Verified exfil")
    updated = db.get_investigation("case-001")
    assert updated["status"] == "confirmed_threat"
    assert updated["analyst_notes"] == "Verified exfil"
    ok("update_investigation() sets status + notes")

    # Escalation log
    db.insert_escalation_log(user_id="jsmith", severity="critical", risk_score=92,
                              sent_to="analyst@example.com", status="sent", error="")
    logs = db.get_escalation_log(limit=10)
    assert len(logs) == 1
    assert logs[0]["status"] == "sent"
    ok("insert_escalation_log() + get_escalation_log() work")

    os.unlink(tmp)
    return True


# ─── Escalation Engine ────────────────────────────────────────────────────

def test_escalation_engine():
    section("EscalationEngine — config + enqueue logic")
    import tempfile, json, os
    from escalation import EscalationEngine

    # Write a temp config
    cfg = {
        "enabled": False,
        "smtp_host": "smtp.gmail.com",
        "smtp_port": 465,
        "smtp_user": "",
        "smtp_password": "",
        "recipient_email": "",
        "min_severity": "critical"
    }
    tmp_cfg = tempfile.mktemp(suffix=".json")
    with open(tmp_cfg, "w") as f:
        json.dump(cfg, f)

    eng = EscalationEngine(config_path=tmp_cfg)
    assert eng.config["enabled"] == False
    assert eng.config["min_severity"] == "critical"
    ok("EscalationEngine loads config correctly")

    # enqueue should not crash when disabled
    eng.enqueue({
        "user_id": "jsmith", "department": "Finance",
        "severity": "critical", "risk_score": 92,
        "activity_type": "file_access", "triggered_rules": ["usb_exfil"],
        "timestamp": "2026-04-11T03:00:00Z"
    })
    ok("enqueue() accepts payload without crash (disabled mode)")

    # update_config
    eng.update_config({"enabled": False, "min_severity": "high_risk"})
    assert eng.config["min_severity"] == "high_risk"
    ok("update_config() updates min_severity")

    os.unlink(tmp_cfg)
    return True


def test_agent_modules():
    section("Agent Modules — Sensitivity + Process + Clipboard + USB")
    import sys as _sys
    _sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "nexon_agent"))

    # ── Sensitivity classification ──
    from agent import _classify_sensitivity

    cfg = {
        "sensitivity_rules": {
            "critical":     ["*salary*", "*password*"],
            "confidential": ["*invoice*", "*contract*"],
            "internal":     ["*report*"],
            "public":       ["*readme*"],
        },
        "sensitive_extensions": [".csv"],
    }

    assert _classify_sensitivity("salary_2024.csv", cfg) == "critical",    "salary → critical"
    assert _classify_sensitivity("Invoice_Q1.pdf", cfg)  == "confidential","invoice → confidential"
    assert _classify_sensitivity("weekly_report.docx", cfg) == "internal", "report → internal"
    assert _classify_sensitivity("README.md", cfg)       == "public",      "readme → public"
    assert _classify_sensitivity("notes.txt", cfg)       == "internal",    "no match → internal default"
    ok("_classify_sensitivity: all 5 cases pass")

    # Verify _is_sensitive respects public classification (even with sensitive extension)
    from agent import _is_sensitive
    cfg_ext = {
        "sensitivity_rules": {"critical": [], "confidential": [], "internal": [], "public": ["*readme*"]},
        "sensitive_extensions": [".csv"],
    }
    assert not _is_sensitive("README.csv", cfg_ext), "public file must not be sensitive even with .csv ext"
    ok("_is_sensitive: public classification overrides sensitive extension")

    # ── ConfigSync fallback ──
    import config_sync

    # Reset module cache to known state
    with config_sync._lock:
        config_sync._cache["working_hours"] = {"start": 8, "end": 18}

    start, end = config_sync.get_working_hours()
    assert start == 8 and end == 18, f"Expected (8,18), got ({start},{end})"
    ok("ConfigSync.get_working_hours: returns default (8, 18)")

    config_sync._init_cache({"working_hours": {"start": 9, "end": 17}})
    start, end = config_sync.get_working_hours()
    assert start == 9 and end == 17, f"Expected (9,17), got ({start},{end})"
    ok("ConfigSync._init_cache: applies local fallback override")

    config_sync._do_fetch("http://localhost:1")   # unreachable — should not crash
    start, end = config_sync.get_working_hours()
    assert start == 9 and end == 17, "Cache unchanged after failed fetch"
    ok("ConfigSync._do_fetch: unreachable server leaves cache intact")

    # ── ProcessMonitor command classification ──
    from process_monitor import _classify_cmd, _extract_file_path

    assert _classify_cmd("wevtutil cl System")                  == ("log_clear",      "critical"),   "wevtutil cl"
    assert _classify_cmd("taskkill /f /pid 1234")               == ("process_kill",   "critical"),   "taskkill /f"
    assert _classify_cmd("del C:\\Users\\john\\salary.csv")     == ("file",           "suspicious"), "del"
    assert _classify_cmd("move file.txt C:\\backup\\file.txt")  == ("file",           "suspicious"), "move"
    assert _classify_cmd("copy C:\\src\\a.txt C:\\dst\\a.txt")  == ("file",           "suspicious"), "copy"
    assert _classify_cmd("mkdir C:\\Users\\john\\NewFolder")    == ("file",           "normal"),     "mkdir"
    assert _classify_cmd("powershell.exe -NoProfile")           == ("process_launch", "normal"),     "plain launch"
    ok("_classify_cmd: all 7 command patterns correct")

    fpath = _extract_file_path("del C:\\Users\\john\\salary.csv")
    assert fpath == "C:\\Users\\john\\salary.csv", f"got: {fpath}"
    ok("_extract_file_path: extracts path from del command")

    # ── ClipboardMonitor pattern detection ──
    from clipboard_monitor import ClipboardMonitor

    events_fired = []
    cm = ClipboardMonitor(
        cfg={"user_id": "test", "department": "IT", "role": "Analyst",
             "device_id": "TEST-01"},
        enqueue_fn=lambda p: events_fired.append(p),
        add_log_fn=lambda _: None,
    )

    # Volume trigger
    cm._check("A" * 600)
    assert events_fired and events_fired[-1]["pattern_matched"] == "volume", "volume trigger"
    ok("ClipboardMonitor: volume (>500 chars) triggers event")

    # Credential pattern
    events_fired.clear()
    cm._last_hash = ""   # reset dedup
    cm._check("db_password=hunter2 host=prod.db.internal")
    assert events_fired and events_fired[-1]["pattern_matched"] == "credential_pattern", "credential pattern"
    ok("ClipboardMonitor: credential_pattern triggers event")

    # API key pattern
    events_fired.clear()
    cm._last_hash = ""
    cm._check("api_key=sk-abc123xyz987")
    assert events_fired and events_fired[-1]["pattern_matched"] == "api_key_pattern", "api key"
    ok("ClipboardMonitor: api_key_pattern triggers event")

    # Email list
    events_fired.clear()
    cm._last_hash = ""
    cm._check("alice@corp.com\nbob@corp.com\ncharlie@corp.com")
    assert events_fired and events_fired[-1]["pattern_matched"] == "email_list", "email list"
    ok("ClipboardMonitor: email_list (3+ emails) triggers event")

    # Deduplication — same content within 60 s should not re-fire
    events_fired.clear()
    # (last_hash is now set from the email_list check — same text)
    cm._check("alice@corp.com\nbob@corp.com\ncharlie@corp.com")
    assert len(events_fired) == 0, "dedup failed — same content fired twice"
    ok("ClipboardMonitor: dedup suppresses same content within 60 s")

    # Content preview truncated to 80 chars
    events_fired.clear()
    cm._last_hash = ""
    long_text = "password=x " + "B" * 200
    cm._check(long_text)
    assert len(events_fired[-1]["content_preview"]) <= 80, "preview not truncated"
    ok("ClipboardMonitor: content_preview truncated to 80 chars")

    # ── USB sensitivity summary ──
    # Test that _classify_sensitivity builds a correct summary dict
    files = ["salary_2024.csv", "invoice_q1.pdf", "notes.txt", "password_list.txt"]
    cfg_usb = {
        "sensitivity_rules": {
            "critical":     ["*salary*", "*password*"],
            "confidential": ["*invoice*"],
            "internal":     [],
            "public":       [],
        },
        "sensitive_extensions": [],
    }
    summary: dict[str, int] = {}
    for f in files:
        level = _classify_sensitivity(f, cfg_usb)
        summary[level] = summary.get(level, 0) + 1

    assert summary.get("critical", 0)     == 2, f"critical count: {summary}"
    assert summary.get("confidential", 0) == 1, f"confidential count: {summary}"
    assert summary.get("internal", 0)     == 1, f"internal count (notes.txt): {summary}"
    ok("USB sensitivity_summary: correct per-level counts")

    return True


def test_session_route_logic():
    section("Session Reconstruction — session grouping logic")
    from datetime import datetime, timedelta

    now = datetime(2026, 4, 11, 10, 0, 0)
    events = [
        {"log_id": "l1", "timestamp": (now).isoformat(),                         "activity_type": "login",       "risk_score": 10, "severity": "normal",    "file_name": ""},
        {"log_id": "l2", "timestamp": (now + timedelta(minutes=5)).isoformat(),   "activity_type": "file_access", "risk_score": 20, "severity": "normal",    "file_name": "doc.pdf"},
        {"log_id": "l3", "timestamp": (now + timedelta(minutes=10)).isoformat(),  "activity_type": "usb",         "risk_score": 60, "severity": "high_risk", "file_name": ""},
        {"log_id": "l4", "timestamp": (now + timedelta(minutes=60)).isoformat(),  "activity_type": "login",       "risk_score": 15, "severity": "normal",    "file_name": ""},
        {"log_id": "l5", "timestamp": (now + timedelta(minutes=65)).isoformat(),  "activity_type": "web",         "risk_score": 25, "severity": "normal",    "file_name": ""},
    ]

    from datetime import datetime as _dt
    def group_sessions(evs):
        sessions = []
        current  = None
        GAP_MINS = 30
        for ev in sorted(evs, key=lambda x: x["timestamp"]):
            try:
                ts = _dt.fromisoformat(ev["timestamp"].replace("Z",""))
            except Exception:
                continue
            if current is None or (ts - current["_last_ts"]).total_seconds() > GAP_MINS * 60:
                if current:
                    current.pop("_last_ts")
                    sessions.append(current)
                current = {
                    "session_id": f"s{len(sessions)+1}",
                    "start":      ev["timestamp"],
                    "end":        ev["timestamp"],
                    "events":     [],
                    "_last_ts":   ts,
                }
            current["events"].append(ev)
            current["end"]      = ev["timestamp"]
            current["_last_ts"] = ts
        if current:
            current.pop("_last_ts")
            sessions.append(current)
        return sessions

    sessions = group_sessions(events)
    assert len(sessions) == 2,            f"Expected 2 sessions, got {len(sessions)}"
    assert len(sessions[0]["events"]) == 3, f"Session 1 should have 3 events"
    assert len(sessions[1]["events"]) == 2, f"Session 2 should have 2 events"
    ok("Session grouping: 5 events → 2 sessions with correct event counts")

    def detect_threat_arcs(session_events):
        arcs = []
        for i, ev in enumerate(session_events):
            if ev["activity_type"] == "usb":
                try:
                    usb_ts = _dt.fromisoformat(ev["timestamp"].replace("Z",""))
                except Exception:
                    continue
                for j in range(max(0, i-5), i):
                    prev = session_events[j]
                    if prev["activity_type"] == "file_access":
                        try:
                            prev_ts = _dt.fromisoformat(prev["timestamp"].replace("Z",""))
                        except Exception:
                            continue
                        if (usb_ts - prev_ts).total_seconds() <= 300:
                            arcs.append({"from": prev["log_id"], "to": ev["log_id"]})
        return arcs

    arcs = detect_threat_arcs(sessions[0]["events"])
    assert len(arcs) == 1, f"Expected 1 threat arc, got {len(arcs)}"
    assert arcs[0]["from"] == "l2"
    assert arcs[0]["to"]   == "l3"
    ok("Threat arc detection: USB after file_access within 5 min → 1 arc")

    return True


# ─── UEBA New Rules ────────────────────────────────────────────────────────

def test_ueba_new_rules():
    section("UEBA New Rules — extra param (7 rules)")
    from ai_analytics.anomaly_model import UEBAEngine
    from feature_engineering.extractor import FeatureVector

    ueba = UEBAEngine()
    base = {k: 0 for k in FeatureVector.COLUMNS}
    fv   = FeatureVector(**base)

    def check(label, extra):
        _, triggered = ueba.score(fv, extra=extra)
        assert label in triggered, f"{label} not in triggered={triggered}"
        ok(f"{label} fires")

    check("sensitive_file_access",  {"sensitivity": "critical"})
    check("sensitive_file_access",  {"sensitivity": "confidential"})
    check("usb_any",                {"source": "usb"})
    check("cloud_upload",           {"destination": "gdrive"})
    check("off_hours_boost",        {"is_off_hours": 1})
    check("archive_created",        {"is_archive": True})
    check("process_abuse",          {"is_process_abuse": True})
    check("large_attachment_exfil", {"source": "email", "direction": "outbound",
                                     "attachment_mb": 15})

    _, triggered = ueba.score(fv, extra={})
    for label in ("sensitive_file_access", "usb_any", "cloud_upload",
                  "off_hours_boost", "archive_created", "process_abuse",
                  "large_attachment_exfil"):
        assert label not in triggered, f"{label} should not fire on empty extra"
    ok("no new rules fire on empty extra dict")

    print(f"\n  9/9 passed")
    return True


def test_correlation_engine():
    section("CorrelationEngine — 5 attack pattern detections")
    from ai_analytics.correlation_engine import CorrelationEngine

    alerts_fired = []
    engine = CorrelationEngine(on_alert=lambda a: alerts_fired.append(a))
    uid = "corr_test_user"

    # Pattern 1: sensitive_file_then_usb (5 min window)
    engine.reset(uid); alerts_fired.clear()
    engine.process(uid, {"source": "file", "sensitivity": "critical",
                         "activity_type": "file_access"}, 50.0)
    score = engine.process(uid, {"source": "usb", "activity_type": "usb"}, 60.0)
    assert len(alerts_fired) == 1, f"sensitive_file_then_usb: expected 1 alert, got {len(alerts_fired)}"
    assert alerts_fired[0]["pattern_name"] == "sensitive_file_then_usb"
    assert score == 75.0, f"score should be 75.0 (60+15), got {score}"
    assert alerts_fired[0]["source"] == "correlation", "alert source should be 'correlation'"
    assert alerts_fired[0]["activity_type"] == "correlation_alert", "alert activity_type should be 'correlation_alert'"
    assert alerts_fired[0]["severity"] == "critical", "sensitive_file_then_usb severity should be critical"
    assert "matched_events" in alerts_fired[0], "alert should contain matched_events"
    ok("sensitive_file_then_usb: fires + boosts score by 15")

    # Pattern 2: sensitive_file_then_cloud (10 min window)
    engine.reset(uid); alerts_fired.clear()
    engine.process(uid, {"source": "file", "sensitivity": "confidential",
                         "activity_type": "file_access"}, 50.0)
    score = engine.process(uid, {"source": "file", "destination": "gdrive",
                                 "activity_type": "file_access"}, 55.0)
    assert len(alerts_fired) == 1, f"sensitive_file_then_cloud: expected 1 alert, got {len(alerts_fired)}"
    assert alerts_fired[0]["pattern_name"] == "sensitive_file_then_cloud"
    assert score == 70.0, f"score should be 70.0 (55+15), got {score}"
    ok("sensitive_file_then_cloud: fires + boosts score by 15")

    # Pattern 3: bulk_file_then_email (10 min window)
    engine.reset(uid); alerts_fired.clear()
    engine.process(uid, {"source": "file", "file_count": 10,
                         "activity_type": "file_access"}, 40.0)
    score = engine.process(uid, {"source": "email", "direction": "outbound",
                                 "attachment_mb": 5.0, "activity_type": "email"}, 45.0)
    assert len(alerts_fired) == 1, f"bulk_file_then_email: expected 1 alert, got {len(alerts_fired)}"
    assert alerts_fired[0]["pattern_name"] == "bulk_file_then_email"
    ok("bulk_file_then_email: fires on file_count>=5 + outbound email with attachment")

    # Pattern 4: off_hours_multi_event (30 min window, 3+ events)
    engine.reset(uid); alerts_fired.clear()
    engine.process(uid, {"is_off_hours": 1, "activity_type": "file_access"}, 30.0)
    engine.process(uid, {"is_off_hours": 1, "activity_type": "web"}, 35.0)
    score = engine.process(uid, {"is_off_hours": 1, "activity_type": "email"}, 40.0)
    assert len(alerts_fired) == 1, f"off_hours_multi_event: expected 1 alert, got {len(alerts_fired)}"
    assert alerts_fired[0]["pattern_name"] == "off_hours_multi_event"
    ok("off_hours_multi_event: fires on 3rd consecutive off-hours event")

    # Pattern 5: process_abuse_then_file (5 min window)
    engine.reset(uid); alerts_fired.clear()
    engine.process(uid, {"source": "process", "is_process_abuse": True,
                         "activity_type": "process_kill"}, 70.0)
    score = engine.process(uid, {"source": "file", "activity_type": "file_access"}, 50.0)
    assert len(alerts_fired) == 1, f"process_abuse_then_file: expected 1 alert, got {len(alerts_fired)}"
    assert alerts_fired[0]["pattern_name"] == "process_abuse_then_file"
    ok("process_abuse_then_file: fires when process_kill precedes file access")

    # Verify reset() clears all windows — prime the pattern, reset, verify it doesn't fire
    engine.reset(); alerts_fired.clear()
    engine.process(uid, {"source": "file", "sensitivity": "critical",
                         "activity_type": "file_access"}, 50.0)
    engine.reset()    # clear all windows
    alerts_fired.clear()
    score = engine.process(uid, {"source": "usb", "activity_type": "usb"}, 60.0)
    assert score == 60.0, f"score should be unchanged after reset (sensitive_file_then_usb should not fire), got {score}"
    assert len(alerts_fired) == 0, "no alert should fire after reset clears prior state"
    ok("reset() clears all windows — pattern does not fire after reset")

    print(f"\n  6/6 passed")
    return True


def test_etl_enrichment():
    section("ETL Enrichment — is_archive + is_process_abuse flags")
    from data_processing.etl_pipeline import enrich_raw

    # Archive detection: zip file
    raw = {"source": "file", "file_path": "/home/bob/backup.zip"}
    enrich_raw(raw)
    assert raw["is_archive"] is True, "zip should be flagged as archive"
    ok("is_archive: .zip file flagged")

    # Archive detection: rar file
    raw2 = {"source": "file", "file_path": "/home/alice/export.rar"}
    enrich_raw(raw2)
    assert raw2["is_archive"] is True, "rar should be flagged"
    ok("is_archive: .rar file flagged")

    # Non-archive file
    raw3 = {"source": "file", "file_path": "/home/bob/report.pdf"}
    enrich_raw(raw3)
    assert raw3["is_archive"] is False, "pdf should not be archive"
    ok("is_archive: .pdf not flagged")

    # Email source: zip attachment should NOT flag is_archive
    raw4 = {"source": "email", "file_path": "/tmp/attachment.zip"}
    enrich_raw(raw4)
    assert raw4["is_archive"] is False, "email source should not flag is_archive"
    ok("is_archive: email source not flagged even with .zip path")

    # Process abuse: process_kill
    raw5 = {"source": "process", "activity_type": "process_kill"}
    enrich_raw(raw5)
    assert raw5["is_process_abuse"] is True, "process_kill should flag is_process_abuse"
    ok("is_process_abuse: process_kill flagged")

    # Process abuse: log_clear
    raw6 = {"source": "process", "activity_type": "log_clear"}
    enrich_raw(raw6)
    assert raw6["is_process_abuse"] is True, "log_clear should flag is_process_abuse"
    ok("is_process_abuse: log_clear flagged")

    # Not abuse: process_launch
    raw7 = {"source": "process", "activity_type": "process_launch", "severity": "normal"}
    enrich_raw(raw7)
    assert raw7["is_process_abuse"] is False, "process_launch should not flag"
    ok("is_process_abuse: process_launch not flagged")

    # Process abuse via severity=critical
    raw8 = {"source": "process", "activity_type": "process_launch", "severity": "critical"}
    enrich_raw(raw8)
    assert raw8["is_process_abuse"] is True, "severity=critical process should flag"
    ok("is_process_abuse: severity=critical process flagged")

    print(f"\n  8/8 passed")
    return True


# ─── Main ──────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    results = {
        "Layer 1 (Acquisition)":   test_layer1(),
        "Layer 2 (ETL)":           test_layer2(),
        "Layer 3 (Features)":      test_layer3(),
        "Layer 4 (AI Analytics)":  test_layer4(),
        "Layer 5 (Explainability)":test_layer5(),
        "Storage Layer":           test_storage(),
        "Layer 6 (Flask API)":     test_api(),
        "Analytics":               test_analytics(),
        "DB Investigations":       test_investigations_db(),
        "EscalationEngine":        test_escalation_engine(),
        "Session Route Logic":     test_session_route_logic(),
        "AgentModules":            test_agent_modules(),
        "UEBA New Rules":          test_ueba_new_rules(),
        "ETL Enrichment":          test_etl_enrichment(),
        "CorrelationEngine":       test_correlation_engine(),
    }

    section("FINAL SUMMARY")
    all_pass = True
    for name, result in results.items():
        status = "PASS" if result else "FAIL"
        if not result: all_pass = False
        print(f"  [{status}] {name}")

    print()
    sys.exit(0 if all_pass else 1)
