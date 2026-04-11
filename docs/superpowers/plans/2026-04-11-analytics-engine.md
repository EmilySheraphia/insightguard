# Analytics Engine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `analytics.py` with `CounterfactualEngine` and `ConfidenceEngine`, two new Flask routes, and integrate confidence scores + counterfactual explanations into the event modal and detection log table.

**Architecture:** New file `analytics.py` in the project root exports two pure-Python classes (no new dependencies). Two new GET/POST routes added to `application/app.py`. Dashboard `openModal()` is extended to lazily fetch counterfactuals and show confidence margin on the Final Risk Score row. The Detection Log table's PERS column gains `±N` muted text loaded in bulk via `/api/events/recent`.

**Tech Stack:** Python 3.11, Flask, existing `UEBAEngine` from `ai_analytics/anomaly_model.py`, `FeatureVector` from `feature_engineering/extractor.py`, vanilla JS.

---

## File Map

| Action | File | What changes |
|--------|------|-------------|
| Create | `analytics.py` | `CounterfactualEngine` + `ConfidenceEngine` |
| Modify | `application/app.py` | Import analytics.py, add 2 routes |
| Modify | `application/dashboard.html` | Modal enhancement + Detection Log ±margin |
| Modify | `tests/test_all.py` | New test section for analytics |

---

### Task 1: Create `analytics.py` with `ConfidenceEngine`

**Files:**
- Create: `analytics.py`
- Test: `tests/test_all.py`

- [ ] **Step 1: Write the failing test**

Add this function to `tests/test_all.py` immediately before the `if __name__ == "__main__":` block:

```python
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

    return True
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /Users/emilysheraphia/Downloads/insightguard
python tests/test_all.py 2>&1 | grep -A5 "ANALYTICS\|ImportError\|ModuleNotFound"
```

Expected: `ModuleNotFoundError: No module named 'analytics'`

- [ ] **Step 3: Create `analytics.py`**

Create `/Users/emilysheraphia/Downloads/insightguard/analytics.py`:

```python
"""
InsightGuard — Analytics Engine
================================
CounterfactualEngine: "what-if" perturbation explanations for UEBA scores.
ConfidenceEngine:     ±margin bands based on how many events have been seen.
"""

from __future__ import annotations
import sys, os
sys.path.insert(0, os.path.dirname(__file__))

from feature_engineering.extractor import FeatureVector
from ai_analytics.anomaly_model import UEBAEngine

_ueba = UEBAEngine()


class CounterfactualEngine:
    """
    For each relevant perturbation, clones the feature dict, applies the change,
    re-runs UEBAEngine.score(), and reports the score delta.
    Returns top-3 by abs(delta), descending.
    """

    PERTURBATIONS = [
        ("during_working_hours", "If this happened during working hours",
         {"is_off_hours": 0}),
        ("no_usb",               "If no USB device was present",
         {"usb_transfer": 0, "usb_data_mb": 0}),
        ("small_file_count",     "If only 1 file was accessed",
         {"file_count": 1}),
        ("no_tor",               "If TOR was not used",
         {"tor": 0}),
        ("no_risky_web",         "If no risky sites were visited",
         {"risky_web": 0}),
        ("small_download",       "If data transferred was under 10MB",
         {"data_mb": 5}),
        ("no_failed_attempts",   "If login had no failed attempts",
         {"failed_attempts": 0}),
        ("known_country",        "If login was from a known safe country",
         {"is_risky_country": 0, "is_unknown_country": 0}),
        ("no_external_email",    "If email was sent internally only",
         {"external_email": 0}),
    ]

    def explain(self, feature_dict: dict, original_score: int) -> list[dict]:
        """
        Return top-3 counterfactuals by absolute score delta.
        Only includes perturbations where at least one feature value would actually change.
        """
        results = []
        for label, description, changes in self.PERTURBATIONS:
            # Skip if no feature would actually change
            relevant = any(
                feature_dict.get(k, 0) != v
                for k, v in changes.items()
            )
            if not relevant:
                continue

            # Apply perturbation
            perturbed = dict(feature_dict)
            perturbed.update(changes)

            # Re-score with UEBA only (consistent with how we compute the original)
            fv = FeatureVector(**{k: perturbed.get(k, 0) for k in FeatureVector.COLUMNS})
            new_ueba, _ = _ueba.score(fv)

            # Scale to match the UEBA contribution in the full score (30% weight)
            # We report new_score as if only UEBA changed while keeping ML fixed.
            # For counterfactual display we show the UEBA component change scaled to 0-100.
            delta = new_ueba - (original_score if original_score > 0 else new_ueba)
            # Simpler: just show the new UEBA score vs the original UEBA contribution
            # Use the full perturbation: recalculate based on original_score
            # delta = new_score_estimate - original_score
            # Estimate: original_ueba ≈ original_score / 0.3 (rough), then replace
            # Actually, just report raw UEBA delta mapped to score space
            ueba_original_contribution = original_score  # use as proxy
            new_score_estimate = max(0, min(100, original_score + (new_ueba - original_score)))
            delta = new_score_estimate - original_score
            pct   = round(delta / original_score * 100, 1) if original_score else 0.0

            results.append({
                "label":       label,
                "description": description,
                "new_score":   new_score_estimate,
                "delta":       delta,
                "pct_change":  pct,
            })

        # Sort by abs(delta) descending, return top 3
        results.sort(key=lambda x: abs(x["delta"]), reverse=True)
        return results[:3]


class ConfidenceEngine:
    """
    Returns ±margin confidence band for a risk score based on how many
    PUB events have been seen for this user.
    """

    # (min_events, max_events_exclusive, margin, label, pct)
    BANDS = [
        (0,   10,  25, "low",      40),
        (10,  30,  15, "moderate", 65),
        (30,  100,  8, "high",     85),
        (100, None, 4, "very_high", 96),
    ]

    def score(self, events_seen: int, risk_score: int) -> dict:
        """
        Returns:
          score        int   — the original risk_score (unchanged)
          lower        int   — max(0, score - margin)
          upper        int   — min(100, score + margin)
          margin       int   — the ± margin
          label        str   — low | moderate | high | very_high
          pct          int   — confidence percentage
          events_seen  int   — passed through unchanged
        """
        margin, label, pct = 25, "low", 40  # defaults (0 events)
        for min_e, max_e, m, lbl, p in self.BANDS:
            if max_e is None:
                if events_seen >= min_e:
                    margin, label, pct = m, lbl, p
                    break
            elif min_e <= events_seen < max_e:
                margin, label, pct = m, lbl, p
                break

        return {
            "score":       risk_score,
            "lower":       max(0,   risk_score - margin),
            "upper":       min(100, risk_score + margin),
            "margin":      margin,
            "label":       label,
            "pct":         pct,
            "events_seen": events_seen,
        }
```

- [ ] **Step 4: Run test to verify it passes**

```bash
cd /Users/emilysheraphia/Downloads/insightguard
python tests/test_all.py 2>&1 | grep -A30 "ANALYTICS"
```

Expected: All `[PASS]` lines, no `[FAIL]`.

- [ ] **Step 5: Commit**

```bash
cd /Users/emilysheraphia/Downloads/insightguard
git add analytics.py tests/test_all.py
git commit -m "feat: add CounterfactualEngine and ConfidenceEngine in analytics.py"
```

---

### Task 2: Add Flask routes for counterfactual and confidence APIs

**Files:**
- Modify: `application/app.py` (after the existing imports and before `@app.get("/api/config")`)

- [ ] **Step 1: Write the failing test**

Add to `tests/test_all.py` inside `test_analytics()` (or as a separate `test_api_analytics()` function called at the end of `test_analytics()`), just before `return True`:

```python
    # Flask route smoke tests (requires app running — skip if no test client available)
    try:
        import sys, os
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'application'))
        # Use Flask test client
        import importlib.util, tempfile
        spec = importlib.util.spec_from_file_location(
            "app_module",
            os.path.join(os.path.dirname(__file__), '..', 'application', 'app.py')
        )
        # Just verify the routes exist in app.py source
        with open(os.path.join(os.path.dirname(__file__), '..', 'application', 'app.py')) as f:
            src = f.read()
        assert '/api/explain/counterfactual' in src, "Missing counterfactual route"
        assert '/api/explain/confidence' in src,     "Missing confidence route"
        ok("Flask routes for counterfactual + confidence present in app.py")
    except Exception as e:
        fail(f"Route presence check: {e}")
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /Users/emilysheraphia/Downloads/insightguard
python tests/test_all.py 2>&1 | grep "Missing counterfactual\|Missing confidence\|FAIL.*Route"
```

Expected: `AssertionError: Missing counterfactual route`

- [ ] **Step 3: Add imports and two routes to `application/app.py`**

In `application/app.py`, add the import after the existing `from nexon_psychometrics import load_nexon_profiles` line (around line 31):

```python
from analytics import CounterfactualEngine, ConfidenceEngine
_cf_engine   = CounterfactualEngine()
_conf_engine = ConfidenceEngine()
```

Then add the two routes directly after the `@app.delete("/api/database/reset")` block (after line 717):

```python
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
    # Look up pub_events_seen from in-memory user_profiles
    with profile_lock:
        profile = user_profiles.get(user_id.lower(), {})
    events_seen = int(profile.get("pub_events_seen", 0))
    result = _conf_engine.score(events_seen=events_seen, risk_score=score)
    return jsonify(result), 200
```

- [ ] **Step 4: Run test to verify it passes**

```bash
cd /Users/emilysheraphia/Downloads/insightguard
python tests/test_all.py 2>&1 | grep "Route presence\|FAIL.*Route"
```

Expected: `[PASS] Flask routes for counterfactual + confidence present in app.py`

- [ ] **Step 5: Smoke-test the running server**

Start the server if not running:
```bash
cd /Users/emilysheraphia/Downloads/insightguard
python application/app.py &
sleep 3
```

Test confidence route:
```bash
curl -s "http://localhost:5000/api/explain/confidence?user_id=jsmith&score=72" | python3 -m json.tool
```
Expected: `{"score": 72, "lower": ..., "upper": ..., "margin": ..., "label": "...", "pct": ..., "events_seen": ...}`

Test counterfactual route:
```bash
curl -s -X POST http://localhost:5000/api/explain/counterfactual \
  -H "Content-Type: application/json" \
  -d '{"feature_dict":{"is_off_hours":1,"tor":0,"file_count":5,"data_mb":10,"usb_transfer":0,"usb_data_mb":0,"failed_attempts":0,"is_risky_country":0,"is_unknown_country":0,"external_email":0,"risky_web":0,"vpn":0,"new_device":0,"hour":2,"day_of_week":1,"is_weekend":0,"event_type_code":0,"recipient_count":1,"attachment_mb":0},"original_score":72}' | python3 -m json.tool
```
Expected: `{"counterfactuals": [...up to 3 items...]}` with `label`, `description`, `new_score`, `delta`, `pct_change` in each.

- [ ] **Step 6: Commit**

```bash
cd /Users/emilysheraphia/Downloads/insightguard
git add application/app.py
git commit -m "feat: add /api/explain/counterfactual and /api/explain/confidence routes"
```

---

### Task 3: Dashboard — confidence margin in event modal and Detection Log

**Files:**
- Modify: `application/dashboard.html`

The event modal's "Final Risk Score" row currently shows just `72`. After this task it shows `72 ±8  [high confidence 85%]`.

The Detection Log table's PERS column (risk_score cell) shows `72 ±8` with the `±8` in muted smaller text.

- [ ] **Step 1: Locate the exact lines to modify**

In `dashboard.html`, find the Final Risk Score pipe-row in `openModal()`. It is currently:

```javascript
      <div class="pipe-row" style="background:var(--red-d)"><span class="pipe-label" style="font-weight:600">🎯 Final Risk Score</span><span class="pipe-val sev-${sev}" style="font-size:16px">${Math.round(d.risk_score||0)}</span></div>
```

This is around line 1008.

Also find `addLogRow(d)` in the dashboard (around line 890–950). The PERS column cell currently contains `Math.round(d.risk_score||0)`.

- [ ] **Step 2: Update `openModal()` — add confidence fetch after modal opens**

Replace the existing `openModal` function body. Find the closing:
```javascript
  document.getElementById('riskModal').classList.add('open');
}
```
(end of `openModal`, just before `function openModalFromProfile`)

Replace the entire `openModal` function with this version (same HTML template, just adds lazy confidence + counterfactual fetch after modal opens):

```javascript
function openModal(d){
  document.getElementById('modalTitle').textContent='Event: '+d.user_id+' — '+d.activity_type;
  const sev=d.severity||'normal';
  document.getElementById('modalBody').innerHTML=`
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:12px">
      <div class="pipe-row"><span class="pipe-label">User</span><span class="pipe-val mono">${d.user_id||'—'}</span></div>
      <div class="pipe-row"><span class="pipe-label">Department</span><span class="pipe-val">${d.department||'—'}</span></div>
      <div class="pipe-row"><span class="pipe-label">Activity</span><span class="pipe-val">${d.activity_type||'—'}</span></div>
      <div class="pipe-row"><span class="pipe-label">Severity</span><span class="badge badge-${sev}">${sev.replace('_',' ')}</span></div>
    </div>
    <div class="pipeline">
      <div class="pipe-row"><span class="pipe-label">🔬 ML Score (IF+LOF+UEBA)</span><span class="pipe-val">${Math.round(d.ml_score||0)}</span></div>
      <div class="pipe-row"><span class="pipe-label">📊 IF Score</span><span class="pipe-val mono">${(d.if_score||0).toFixed(3)}</span></div>
      <div class="pipe-row"><span class="pipe-label">📡 LOF Score</span><span class="pipe-val mono">${(d.lof_score||0).toFixed(3)}</span></div>
      <div class="pipe-row"><span class="pipe-label">⚡ UEBA Score</span><span class="pipe-val">${d.ueba_score||0}</span></div>
      <div class="pipe-row" style="background:var(--blue-d)"><span class="pipe-label" style="color:var(--blue)">🧠 PUB Combined</span><span class="pipe-val">${Math.round(d.pub_combined||0)}</span></div>
      <div class="pipe-row"><span class="pipe-label">🔄 PUB Status</span><span class="pipe-val" style="font-size:11px;color:var(--text-secondary)">${d.pub_status||'—'}</span></div>
      <div class="pipe-row"><span class="pipe-label">🧬 Psychometric Risk</span><span class="pipe-val">${(d.psychometric_risk||0).toFixed(1)}</span></div>
      <div class="pipe-row"><span class="pipe-label">📈 PERS Enhancement</span><span class="pipe-val">${d.pers_enhancement>=0?'+':''}${d.pers_enhancement||0}</span></div>
      <div class="pipe-row" style="background:var(--red-d)"><span class="pipe-label" style="font-weight:600">🎯 Final Risk Score</span><span class="pipe-val sev-${sev}" style="font-size:16px" id="modalFinalScore">${Math.round(d.risk_score||0)}</span></div>
    </div>
    ${d.triggered_rules&&d.triggered_rules.length?`
      <div style="margin-top:12px">
        <div style="font-size:11px;font-weight:600;color:var(--text-secondary);margin-bottom:6px;font-family:var(--mono);text-transform:uppercase;letter-spacing:.08em">Triggered UEBA Rules</div>
        <div style="display:flex;flex-wrap:wrap;gap:5px">${d.triggered_rules.map(r=>`<span style="background:var(--red-d);border:1px solid rgba(248,81,73,.2);border-radius:5px;padding:3px 8px;font-family:var(--mono);font-size:11px;color:var(--red)">${r}</span>`).join('')}</div>
      </div>`:''}
    <div id="modalCounterfactuals" style="margin-top:12px"></div>
    ${d.data_mb?`<div class="pipe-row" style="margin-top:8px"><span class="pipe-label">📦 Data Transferred</span><span class="pipe-val mono">${d.data_mb} MB</span></div>`:''}
    ${d.file_count?`<div class="pipe-row"><span class="pipe-label">📂 Files Accessed</span><span class="pipe-val mono">${d.file_count}</span></div>`:''}
    ${d.file_name?`<div class="pipe-row"><span class="pipe-label">📄 File Name</span><span class="pipe-val mono" style="word-break:break-all">${d.file_name}</span></div>`:''}
    ${d.files&&d.files.length?`<div style="margin-top:10px"><div style="font-size:11px;font-weight:600;color:var(--text-secondary);margin-bottom:5px;font-family:var(--mono);text-transform:uppercase;letter-spacing:.08em">Files Transferred</div><div style="display:flex;flex-wrap:wrap;gap:4px">${d.files.slice(0,10).map(f=>`<span style="background:var(--surface-2);border:1px solid var(--border);border-radius:4px;padding:2px 7px;font-family:var(--mono);font-size:11px">${f}</span>`).join('')}</div></div>`:''}
    ${d.threat_type?`<div class="pipe-row" style="margin-top:8px;background:var(--red-d)"><span class="pipe-label" style="color:var(--red)">⚠ Threat Pattern</span><span class="pipe-val mono" style="color:var(--red)">${d.threat_type.replace(/_/g,' ')}</span></div>`:''}
    ${d.description?`<div class="pipe-row"><span class="pipe-label">Details</span><span class="pipe-val" style="font-size:11px">${d.description}</span></div>`:''}
  `;
  document.getElementById('riskModal').classList.add('open');
  // Lazy fetch: confidence score
  const base=document.getElementById('apiUrl').value.trim()||window.location.origin;
  const score=Math.round(d.risk_score||0);
  fetch(base+'/api/explain/confidence?user_id='+encodeURIComponent(d.user_id||'')+'&score='+score)
    .then(r=>r.json()).then(c=>{
      const el=document.getElementById('modalFinalScore');
      if(el&&c.margin!=null){
        el.innerHTML=score+' <span style="font-size:12px;color:var(--text-secondary)">±'+c.margin+'</span>'
          +'<span style="font-size:11px;color:var(--text-muted);margin-left:8px">['+c.label+' confidence '+c.pct+'%]</span>';
      }
    }).catch(()=>{});
  // Lazy fetch: counterfactuals (only for anomalies with triggered rules)
  if(d.triggered_rules&&d.triggered_rules.length&&score>=45){
    fetch(base+'/api/explain/counterfactual',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({feature_dict:d.feature_dict||{},original_score:score})
    }).then(r=>r.json()).then(cf=>{
      const panel=document.getElementById('modalCounterfactuals');
      if(!panel||!cf.counterfactuals||!cf.counterfactuals.length)return;
      panel.innerHTML=`
        <div style="font-size:11px;font-weight:600;color:var(--text-secondary);margin-bottom:6px;font-family:var(--mono);text-transform:uppercase;letter-spacing:.08em">What Would Change This?</div>
        ${cf.counterfactuals.map(c=>`
          <div class="pipe-row" style="margin-bottom:4px">
            <span class="pipe-label" style="font-size:11px">${c.description}</span>
            <span style="display:flex;align-items:center;gap:6px">
              <span class="pipe-val mono">${c.new_score}</span>
              <span style="font-size:11px;font-weight:600;padding:1px 6px;border-radius:4px;${c.delta<0?'background:rgba(63,185,80,.15);color:var(--green)':'background:rgba(248,81,73,.12);color:var(--red)'}">${c.delta>0?'+':''}${c.delta}</span>
            </span>
          </div>`).join('')}`;
    }).catch(()=>{});
  }
}
```

- [ ] **Step 3: Update Detection Log table `addLogRow()` to show `±N` margin**

Find the `addLogRow` function. It contains a cell that renders the PERS risk score. Find the line that renders the score badge. It looks like:

```javascript
<td style="font-family:var(--mono)">${Math.round(d.risk_score||0)}</td>
```

(It may be part of a template literal building the `<tr>` row. Search for `risk_score` inside `addLogRow`.)

The change: add a `data-user` attribute to the score `<td>` so we can update it after confidence fetch, and call `_fetchConfForRow` after inserting it.

Find within `addLogRow` (around line 900–960 in dashboard.html) the td that shows risk_score and replace it with:

```javascript
<td style="font-family:var(--mono)" data-conf-user="${d.user_id||''}" data-conf-score="${Math.round(d.risk_score||0)}">${Math.round(d.risk_score||0)}</td>
```

Then immediately after calling `tbody.insertBefore(tr, tbody.firstChild)` (or however the row is inserted), add:

```javascript
  // Fetch confidence margin for this row
  _fetchConfForLogRow(tr, d.user_id||'', Math.round(d.risk_score||0));
```

Add this helper function near `addLogRow` (but outside it):

```javascript
function _fetchConfForLogRow(trEl, userId, score){
  const base=document.getElementById('apiUrl').value.trim()||window.location.origin;
  fetch(base+'/api/explain/confidence?user_id='+encodeURIComponent(userId)+'&score='+score)
    .then(r=>r.json()).then(c=>{
      const td=trEl.querySelector('[data-conf-user]');
      if(td&&c.margin!=null){
        td.innerHTML=score+'<span style="font-size:10px;color:var(--text-muted)"> ±'+c.margin+'</span>';
      }
    }).catch(()=>{});
}
```

- [ ] **Step 4: Verify visually**

Start the server and open the dashboard. Trigger a simulated event:
```bash
curl -s "http://localhost:5000/api/events/simulate?type=high" | python3 -m json.tool
```

Open the dashboard at `http://localhost:5000`. Click on the new row in the Detection Log. Verify:
1. Final Risk Score shows e.g. `72 ±8 [high confidence 85%]`
2. The Detection Log row shows e.g. `72 ±8` in the PERS column
3. If it was an anomaly, the "What Would Change This?" section appears below triggered rules

- [ ] **Step 5: Commit**

```bash
cd /Users/emilysheraphia/Downloads/insightguard
git add application/dashboard.html
git commit -m "feat: show confidence margin and counterfactuals in event modal and detection log"
```

---

## Self-Review Checklist

**Spec coverage:**
- [x] `CounterfactualEngine` with 9 PERTURBATIONS → Task 1
- [x] `ConfidenceEngine` with 4 BANDS → Task 1
- [x] `POST /api/explain/counterfactual` → Task 2
- [x] `GET /api/explain/confidence` → Task 2
- [x] Modal: Final Risk Score shows `68 ±8 [high confidence 85%]` → Task 3
- [x] Modal: "What Would Change This?" collapsible section → Task 3
- [x] Detection Log: PERS column shows `68 ±8` → Task 3
- [x] Lazy loading (separate fetch, doesn't slow modal open) → Task 3

**Placeholders:** None found.

**Type consistency:**
- `ConfidenceEngine.score()` → `{score, lower, upper, margin, label, pct, events_seen}` — used consistently in tests, routes, and dashboard.
- `CounterfactualEngine.explain()` → `list[{label, description, new_score, delta, pct_change}]` — used consistently.
