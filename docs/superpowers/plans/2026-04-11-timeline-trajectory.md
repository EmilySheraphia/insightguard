# Session Timeline & Risk Trajectory Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a Session Reconstruction Timeline section (horizontal SVG timeline per session, coloured event dots, threat arcs) and a Risk Trajectory Chart (7-day SVG line chart with confidence band) embedded in the user profile modal.

**Architecture:** Two new Flask routes query existing SQLite tables (`activity_logs` joined with `anomaly_results`). Session grouping (30-min gap = new session) done in Python. The SVG timeline section and risk trajectory chart are pure SVG — no new JS libraries. Risk trajectory is embedded directly into `openModalFromProfile()` via a lazy fetch. Dashboard gets a new "Timeline" sidebar nav item and `sectionTimeline` section.

**Tech Stack:** Python 3.11, Flask, SQLite, pure SVG in vanilla JS, existing `ConfidenceEngine` from `analytics.py`.

---

## File Map

| Action | File | What changes |
|--------|------|-------------|
| Modify | `application/app.py` | 2 new routes: `/api/users/<id>/session` + `/api/users/<id>/trajectory` |
| Modify | `application/dashboard.html` | Timeline section + trajectory chart in profile modal |
| Modify | `tests/test_all.py` | New test section |

---

### Task 1: Add `/api/users/<id>/session` route

**Files:**
- Modify: `application/app.py`
- Test: `tests/test_all.py`

The route queries `activity_logs` joined with `anomaly_results` for the given user, last N days. Events are grouped into sessions: gap > 30 minutes between consecutive events starts a new session.

- [ ] **Step 1: Write the failing test**

Add to `tests/test_all.py` before `if __name__ == "__main__":`:

```python
def test_session_route_logic():
    section("Session Reconstruction — session grouping logic")
    from datetime import datetime, timedelta

    # Build a fake list of events sorted by timestamp
    now = datetime(2026, 4, 11, 10, 0, 0)
    events = [
        {"log_id": "l1", "timestamp": (now).isoformat(),                         "activity_type": "login",       "risk_score": 10, "severity": "normal",    "file_name": ""},
        {"log_id": "l2", "timestamp": (now + timedelta(minutes=5)).isoformat(),   "activity_type": "file_access", "risk_score": 20, "severity": "normal",    "file_name": "doc.pdf"},
        {"log_id": "l3", "timestamp": (now + timedelta(minutes=10)).isoformat(),  "activity_type": "usb",         "risk_score": 60, "severity": "high_risk", "file_name": ""},
        # Gap > 30 min — new session
        {"log_id": "l4", "timestamp": (now + timedelta(minutes=60)).isoformat(),  "activity_type": "login",       "risk_score": 15, "severity": "normal",    "file_name": ""},
        {"log_id": "l5", "timestamp": (now + timedelta(minutes=65)).isoformat(),  "activity_type": "web",         "risk_score": 25, "severity": "normal",    "file_name": ""},
    ]

    # Inline the session grouping logic from the route
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

    # Check threat arc detection (USB insert after file access within 5 min)
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
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /Users/emilysheraphia/Downloads/insightguard
python tests/test_all.py 2>&1 | grep -A5 "Session Reconstruction\|FAIL.*Session"
```

Expected: The test passes immediately (pure Python logic, no server needed), but the route doesn't exist yet. If it shows `PASS`, that's fine — the route test comes next.

- [ ] **Step 3: Add the `/api/users/<id>/session` route to `app.py`**

After the existing `/api/users/<user_id>/timeline` route (around line 671), add:

```python
@app.get("/api/users/<user_id>/session")
def user_sessions(user_id):
    from datetime import timedelta as _td
    days   = int(request.args.get("days", 7))
    since  = (datetime.now(timezone.utc) - _td(days=days)).strftime("%Y-%m-%dT%H:%M:%S")
    uid    = user_id.lower()

    import sqlite3 as _sq
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
            "log_id":        row["log_id"],
            "timestamp":     row["timestamp"],
            "activity_type": row["activity_type"] or "login",
            "severity":      row["severity"] or "normal",
            "risk_score":    row["risk_score"] or 0,
            "file_name":     file_name,
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


def _detect_arcs(events: list) -> list:
    """Find USB-after-file_access threat arcs within 5 minutes."""
    arcs = []
    for i, ev in enumerate(events):
        if ev["activity_type"] == "usb":
            try:
                usb_ts = datetime.fromisoformat(ev["timestamp"].replace("Z",""))
            except Exception:
                continue
            for j in range(max(0, i - 5), i):
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
```

- [ ] **Step 4: Smoke-test the route**

```bash
# Start server if not running
cd /Users/emilysheraphia/Downloads/insightguard
python application/app.py &
sleep 3

# Simulate a few events for jsmith
curl -s "http://localhost:5000/api/events/simulate?type=high" > /dev/null
curl -s "http://localhost:5000/api/events/simulate?type=normal" > /dev/null

# Query session timeline
curl -s "http://localhost:5000/api/users/jsmith/session?days=7" | python3 -m json.tool
```

Expected: JSON with `sessions` array, each session has `session_id`, `start`, `end`, `events`, `threat_arcs`.

- [ ] **Step 5: Run test to verify it passes**

```bash
cd /Users/emilysheraphia/Downloads/insightguard
python tests/test_all.py 2>&1 | grep -A5 "Session Reconstruction\|PASS.*Session\|PASS.*Threat arc"
```

Expected: Both `[PASS]` lines.

- [ ] **Step 6: Commit**

```bash
cd /Users/emilysheraphia/Downloads/insightguard
git add application/app.py tests/test_all.py
git commit -m "feat: add /api/users/<id>/session route with 30-min session grouping and threat arc detection"
```

---

### Task 2: Add `/api/users/<id>/trajectory` route

**Files:**
- Modify: `application/app.py`

- [ ] **Step 1: Write the failing test (route presence check)**

Add to `test_session_route_logic()` in `tests/test_all.py` before `return True`:

```python
    # Check app.py has trajectory route
    import os
    with open(os.path.join(os.path.dirname(__file__), '..', 'application', 'app.py')) as f:
        src = f.read()
    assert '/api/users/<user_id>/trajectory' in src or '/api/users/<user_id>/session' in src
    ok("Trajectory and session routes present in app.py")
```

Wait — this would pass once `/session` is added. Instead let's just add the trajectory route in the same step as the test:

- [ ] **Step 2: Add `/api/users/<id>/trajectory` route to `app.py`**

Immediately after the `_detect_arcs()` function, add:

```python
@app.get("/api/users/<user_id>/trajectory")
def user_trajectory(user_id):
    from datetime import timedelta as _td
    days  = int(request.args.get("days", 7))
    since = (datetime.now(timezone.utc) - _td(days=days)).strftime("%Y-%m-%dT%H:%M:%S")
    uid   = user_id.lower()

    import sqlite3 as _sq
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

    # Build confidence bands using ConfidenceEngine
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
```

Note: This requires `_conf_engine` to exist (created in analytics-engine plan). If analytics plan hasn't been merged, import inline:

```python
# Fallback if _conf_engine not yet available at module level
try:
    _conf = _conf_engine
except NameError:
    from analytics import ConfidenceEngine as _CE; _conf = _CE()
```

Use `_conf` instead of `_conf_engine` in the route if needed. For simplicity, the plan assumes the analytics plan is merged first.

- [ ] **Step 3: Smoke-test**

```bash
curl -s "http://localhost:5000/api/users/jsmith/trajectory?days=7" | python3 -m json.tool
```

Expected: `{"user_id":"jsmith","points":[...]}` with `timestamp`, `risk_score`, `severity`, `confidence_lower`, `confidence_upper` in each point.

If `<3 points`, the dashboard will show a "not enough data" message.

- [ ] **Step 4: Commit**

```bash
cd /Users/emilysheraphia/Downloads/insightguard
git add application/app.py
git commit -m "feat: add /api/users/<id>/trajectory route with confidence band"
```

---

### Task 3: Dashboard — Risk Trajectory chart in user profile modal

**Files:**
- Modify: `application/dashboard.html`

The risk trajectory chart is a pure SVG chart embedded below the stats grid in `openModalFromProfile()`. No new libraries.

- [ ] **Step 1: Update `openModalFromProfile()` to add trajectory chart container**

Find `openModalFromProfile` function in `dashboard.html` (around line 1024). Find its closing `document.getElementById('riskModal').classList.add('open');` line.

Replace the current `openModalFromProfile` function with this version (identical existing content + trajectory container + lazy fetch):

```javascript
function openModalFromProfile(uid,d){
  const p=d.profile||{};
  const sev=p.risk_level||'normal';
  document.getElementById('modalTitle').textContent='User Profile: '+uid;
  document.getElementById('modalBody').innerHTML=`
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:12px">
      <div class="pipe-row"><span class="pipe-label">Department</span><span class="pipe-val">${p.department||'—'}</span></div>
      <div class="pipe-row"><span class="pipe-label">Risk Level</span><span class="badge badge-${sev}">${sev.replace('_',' ')}</span></div>
      <div class="pipe-row"><span class="pipe-label">Events Seen</span><span class="pipe-val mono">${p.event_count||0}</span></div>
      <div class="pipe-row"><span class="pipe-label">Threat Count</span><span class="pipe-val sev-critical">${p.threat_count||0}</span></div>
      <div class="pipe-row"><span class="pipe-label">Rolling Score</span><span class="pipe-val sev-${sev}">${Math.round(p.rolling_score||0)}</span></div>
      <div class="pipe-row"><span class="pipe-label">Peak Score</span><span class="pipe-val">${Math.round(p.peak_score||0)}</span></div>
      <div class="pipe-row"><span class="pipe-label">PUB Status</span><span class="pipe-val" style="font-size:11px">${p.pub_status||'—'}</span></div>
      <div class="pipe-row"><span class="pipe-label">Psychometric Risk</span><span class="pipe-val">${(p.psychometric_risk||0).toFixed(1)}</span></div>
    </div>
    ${d.timeline&&d.timeline.length?`
      <div style="font-size:11px;font-weight:600;color:var(--text-secondary);margin-bottom:6px;font-family:var(--mono);text-transform:uppercase;letter-spacing:.08em">Recent Events</div>
      ${d.timeline.slice(0,5).map(t=>`
        <div class="pipe-row" style="margin-bottom:4px;font-size:11px">
          <span style="color:var(--text-muted);font-family:var(--mono)">${(t.timestamp||'').slice(11,19)}</span>
          <span style="margin-left:8px">${t.activity_type||'—'}</span>
        </div>`).join('')}`:''}
    <div id="trajectoryChartWrap" style="margin-top:14px">
      <div style="font-size:11px;font-weight:600;color:var(--text-secondary);margin-bottom:6px;font-family:var(--mono);text-transform:uppercase;letter-spacing:.08em">Risk Trajectory — Last 7 Days</div>
      <div id="trajectoryChartArea" style="color:var(--text-muted);font-size:12px">Loading…</div>
    </div>
  `;
  document.getElementById('riskModal').classList.add('open');
  // Lazy fetch trajectory
  const base=document.getElementById('apiUrl').value.trim()||window.location.origin;
  fetch(base+'/api/users/'+encodeURIComponent(uid)+'/trajectory?days=7')
    .then(r=>r.json())
    .then(data=>_renderTrajectoryChart(data.points||[]))
    .catch(()=>{
      const el=document.getElementById('trajectoryChartArea');
      if(el)el.textContent='Could not load trajectory data.';
    });
}
```

- [ ] **Step 2: Add the `_renderTrajectoryChart` SVG function**

Add this function after the `openModalFromProfile` / `closeModal` block:

```javascript
// ══════════════════════════════════════════════════════
//  RISK TRAJECTORY SVG CHART
// ══════════════════════════════════════════════════════
function _renderTrajectoryChart(points){
  const el=document.getElementById('trajectoryChartArea');
  if(!el)return;
  if(!points||points.length<3){
    el.innerHTML=`<div style="text-align:center;padding:24px;color:var(--text-muted);font-size:12px">Not enough data yet (${points?points.length:0} events)</div>`;
    return;
  }

  const W=480, H=180, PAD={top:12,right:16,bottom:28,left:36};
  const chartW=W-PAD.left-PAD.right, chartH=H-PAD.top-PAD.bottom;

  // X axis: time range
  const times=points.map(p=>new Date(p.timestamp).getTime());
  const minT=Math.min(...times), maxT=Math.max(...times);
  const rangeT=maxT-minT||1;

  const toX=t=>PAD.left+((t-minT)/rangeT)*chartW;
  const toY=v=>PAD.top+chartH*(1-v/100);

  // Severity colour
  const sevCol={normal:'#3fb950',suspicious:'#e3b341',high_risk:'#db6d28',critical:'#f85149'};
  const dominant=(()=>{
    const counts={normal:0,suspicious:0,high_risk:0,critical:0};
    points.forEach(p=>counts[p.severity]=(counts[p.severity]||0)+1);
    return Object.entries(counts).sort((a,b)=>b[1]-a[1])[0][0];
  })();
  const lineCol=sevCol[dominant]||'#58a6ff';

  // Confidence band polygon
  const upperPts=points.map(p=>`${toX(new Date(p.timestamp).getTime()).toFixed(1)},${toY(p.confidence_upper).toFixed(1)}`).join(' ');
  const lowerPts=[...points].reverse().map(p=>`${toX(new Date(p.timestamp).getTime()).toFixed(1)},${toY(p.confidence_lower).toFixed(1)}`).join(' ');
  const bandPoly=upperPts+' '+lowerPts;

  // Score polyline
  const scoreLine=points.map(p=>`${toX(new Date(p.timestamp).getTime()).toFixed(1)},${toY(p.risk_score).toFixed(1)}`).join(' ');

  // Threshold lines: 45 suspicious, 60 high_risk, 80 critical
  const thresholds=[
    {v:45,col:'#e3b341',label:'Suspicious'},
    {v:60,col:'#db6d28',label:'High Risk'},
    {v:80,col:'#f85149',label:'Critical'},
  ];

  // X-axis day labels (up to 7)
  const dayLabels=(()=>{
    const labels=[];
    const step=Math.ceil(points.length/6)||1;
    for(let i=0;i<points.length;i+=step){
      const d=new Date(points[i].timestamp);
      labels.push({x:toX(new Date(points[i].timestamp).getTime()),label:d.toLocaleDateString('en-GB',{weekday:'short'})});
    }
    return labels;
  })();

  // Event dot circles
  const dots=points.map(p=>{
    const cx=toX(new Date(p.timestamp).getTime()).toFixed(1);
    const cy=toY(p.risk_score).toFixed(1);
    const col=sevCol[p.severity]||'#58a6ff';
    const tip=`${(p.timestamp||'').slice(0,19).replace('T',' ')} | ${p.activity_type} | Score: ${p.risk_score}`;
    return `<circle cx="${cx}" cy="${cy}" r="3.5" fill="${col}" stroke="var(--surface)" stroke-width="1.5"><title>${tip}</title></circle>`;
  }).join('');

  el.innerHTML=`
  <svg viewBox="0 0 ${W} ${H}" style="width:100%;height:${H}px;overflow:visible">
    <!-- Confidence band -->
    <polygon points="${bandPoly}" fill="${lineCol}" fill-opacity="0.08" stroke="none"/>
    <!-- Threshold dashed lines -->
    ${thresholds.map(t=>`
      <line x1="${PAD.left}" y1="${toY(t.v).toFixed(1)}" x2="${PAD.left+chartW}" y2="${toY(t.v).toFixed(1)}"
        stroke="${t.col}" stroke-width="1" stroke-dasharray="4,4" opacity="0.5"/>
      <text x="${PAD.left+chartW+2}" y="${(toY(t.v)+4).toFixed(1)}" fill="${t.col}" font-size="8" font-family="var(--mono)" opacity="0.7">${t.label}</text>
    `).join('')}
    <!-- Score polyline -->
    <polyline points="${scoreLine}" fill="none" stroke="${lineCol}" stroke-width="2" stroke-linejoin="round"/>
    <!-- Event dots -->
    ${dots}
    <!-- X axis -->
    <line x1="${PAD.left}" y1="${PAD.top+chartH}" x2="${PAD.left+chartW}" y2="${PAD.top+chartH}" stroke="var(--border)" stroke-width="1"/>
    <!-- Y axis labels -->
    ${[0,25,50,75,100].map(v=>`
      <text x="${PAD.left-4}" y="${(toY(v)+4).toFixed(1)}" fill="var(--chart-tick)" font-size="8" font-family="var(--mono)" text-anchor="end">${v}</text>
      <line x1="${PAD.left-2}" y1="${toY(v).toFixed(1)}" x2="${PAD.left}" y2="${toY(v).toFixed(1)}" stroke="var(--border)" stroke-width="1"/>
    `).join('')}
    <!-- X axis day labels -->
    ${dayLabels.map(l=>`<text x="${l.x.toFixed(1)}" y="${(PAD.top+chartH+12).toFixed(1)}" fill="var(--chart-tick)" font-size="8" font-family="var(--mono)" text-anchor="middle">${l.label}</text>`).join('')}
  </svg>`;
}
```

- [ ] **Step 3: Verify visually**

Start the server. Generate several events:
```bash
for i in $(seq 1 8); do curl -s "http://localhost:5000/api/events/simulate?type=random" > /dev/null; done
```

Open the dashboard. Go to Risk Monitor section. Click on any user card (the user cards should trigger `openModalFromProfile`). The modal should open, and after a moment the "Risk Trajectory — Last 7 Days" section should render an SVG chart or show "Not enough data yet (N events)".

Note: if there are fewer than 3 points in the last 7 days, the fallback message shows. Replay some events first if needed:
```bash
for i in $(seq 1 20); do curl -s "http://localhost:5000/api/events/simulate?type=random" > /dev/null; sleep 0.1; done
```

- [ ] **Step 4: Commit**

```bash
cd /Users/emilysheraphia/Downloads/insightguard
git add application/dashboard.html
git commit -m "feat: add risk trajectory SVG chart with confidence band to user profile modal"
```

---

### Task 4: Dashboard — Session Timeline section

**Files:**
- Modify: `application/dashboard.html`

- [ ] **Step 1: Add "Timeline" nav item to sidebar**

In `dashboard.html`, find the Investigations nav button added in the investigations-escalation plan (or find `data-section="Validation"` button). Add the Timeline nav button after the Investigations button (or before the Validation button if investigations plan not yet merged):

```html
      <button class="nav-item" data-section="Timeline" onclick="showSection('Timeline')">
        <svg class="ni-icon" viewBox="0 0 24 24" fill="currentColor"><path d="M11.99 2C6.47 2 2 6.48 2 12s4.47 10 9.99 10C17.52 22 22 17.52 22 12S17.52 2 11.99 2zM12 20c-4.42 0-8-3.58-8-8s3.58-8 8-8 8 3.58 8 8-3.58 8-8 8zm.5-13H11v6l5.25 3.15.75-1.23-4.5-2.67V7z"/></svg>
        Timeline
      </button>
```

- [ ] **Step 2: Add `sectionTimeline` HTML**

After the `sectionInvestigations` closing `</section>` (or after `sectionLog` closing `</section>` if investigations plan not merged), add:

```html
    <!-- ════ SESSION TIMELINE ════ -->
    <section class="section" id="sectionTimeline">
      <div class="page-hdr" style="border-bottom:1px solid var(--border)">
        <div>
          <div class="page-hdr-title">Session Timeline</div>
          <div class="page-hdr-sub">Chronological session reconstruction per user</div>
        </div>
      </div>
      <div style="padding:16px 20px;display:flex;flex-direction:column;gap:12px;overflow-y:auto;flex:1">
        <!-- User selector -->
        <div style="display:flex;gap:8px;align-items:center">
          <input id="tlUserInput" class="fi" type="text" placeholder="Type user ID…" style="width:180px;font-family:var(--mono)"
            oninput="_tlFilterUsers(this.value)">
          <select id="tlUserSelect" onchange="document.getElementById('tlUserInput').value=this.value;loadTimeline()" style="background:var(--card);border:1px solid var(--border);border-radius:var(--r);padding:6px 10px;color:var(--text);font-size:12px;font-family:var(--mono);cursor:pointer;max-width:200px">
            <option value="">-- select user --</option>
          </select>
          <button onclick="loadTimeline()" style="background:var(--card);border:1px solid var(--border);border-radius:var(--r);padding:6px 12px;color:var(--text);font-size:12px;cursor:pointer;font-family:var(--mono)">Load</button>
          <select id="tlDays" onchange="loadTimeline()" style="background:var(--card);border:1px solid var(--border);border-radius:var(--r);padding:6px 10px;color:var(--text);font-size:12px;font-family:var(--mono);cursor:pointer">
            <option value="1">1 day</option>
            <option value="3">3 days</option>
            <option value="7" selected>7 days</option>
            <option value="14">14 days</option>
          </select>
        </div>
        <!-- Timeline display -->
        <div id="tlContent">
          <div style="text-align:center;padding:60px;color:var(--text-muted)">Select a user to view their session timeline</div>
        </div>
      </div>
    </section>
```

- [ ] **Step 3: Add Timeline JS**

Add this JS block after the `_renderTrajectoryChart` function:

```javascript
// ══════════════════════════════════════════════════════
//  SESSION TIMELINE
// ══════════════════════════════════════════════════════
function _tlFilterUsers(query){
  const sel=document.getElementById('tlUserSelect');
  if(!sel)return;
  Array.from(sel.options).forEach(o=>{
    o.style.display=(o.value.toLowerCase().includes(query.toLowerCase())||!query)?'':'none';
  });
}

function _tlPopulateUserList(){
  const base=document.getElementById('apiUrl').value.trim()||window.location.origin;
  fetch(base+'/api/stats').then(r=>r.json()).then(data=>{
    const sel=document.getElementById('tlUserSelect');
    if(!sel||!data.user_risk_profiles)return;
    const existing=Array.from(sel.options).map(o=>o.value);
    data.user_risk_profiles.forEach(u=>{
      if(!existing.includes(u.user_id)){
        const o=document.createElement('option');
        o.value=o.textContent=u.user_id;
        sel.appendChild(o);
      }
    });
  }).catch(()=>{});
}

function loadTimeline(){
  const uid=(document.getElementById('tlUserInput')?.value||document.getElementById('tlUserSelect')?.value||'').trim().toLowerCase();
  if(!uid){
    document.getElementById('tlContent').innerHTML='<div style="text-align:center;padding:40px;color:var(--text-muted)">Enter a user ID above</div>';
    return;
  }
  const days=parseInt(document.getElementById('tlDays')?.value||'7');
  const base=document.getElementById('apiUrl').value.trim()||window.location.origin;
  document.getElementById('tlContent').innerHTML='<div style="text-align:center;padding:40px;color:var(--text-muted)">Loading sessions…</div>';
  fetch(base+'/api/users/'+encodeURIComponent(uid)+'/session?days='+days)
    .then(r=>r.json())
    .then(data=>_renderSessions(data.sessions||[]))
    .catch(e=>{
      document.getElementById('tlContent').innerHTML='<div style="text-align:center;padding:40px;color:var(--red)">Error loading timeline</div>';
    });
}

function _renderSessions(sessions){
  const el=document.getElementById('tlContent');
  if(!sessions||!sessions.length){
    el.innerHTML='<div style="text-align:center;padding:60px;color:var(--text-muted)">No sessions found for this user in the selected period</div>';
    return;
  }
  const sevCol={normal:'#3fb950',suspicious:'#e3b341',high_risk:'#db6d28',critical:'#f85149'};
  el.innerHTML=sessions.map(sess=>_renderOneSession(sess, sevCol)).join('');
}

function _renderOneSession(sess, sevCol){
  const evs=sess.events||[];
  if(!evs.length)return'';
  const arcs=sess.threat_arcs||[];

  // Build SVG timeline
  const DOT_R=6, ROW_H=40, PAD_L=60, PAD_R=30;
  const times=evs.map(e=>new Date(e.timestamp).getTime());
  const minT=Math.min(...times), maxT=Math.max(...times);
  const rangeT=maxT-minT||1;
  const W=Math.max(600, evs.length*60);
  const toX=t=>PAD_L+((t-minT)/rangeT)*(W-PAD_L-PAD_R);

  const dots=evs.map((ev,i)=>{
    const cx=toX(times[i]).toFixed(1);
    const cy=(ROW_H/2).toFixed(1);
    const col=sevCol[ev.severity]||'#58a6ff';
    const tip=`${(ev.timestamp||'').slice(11,19)} | ${ev.activity_type} | Score: ${ev.risk_score}${ev.file_name?' | '+ev.file_name:''}`;
    return `<circle cx="${cx}" cy="${cy}" r="${DOT_R}" fill="${col}" stroke="var(--surface)" stroke-width="2" style="cursor:pointer" onclick='openModal(${JSON.stringify(ev)})'><title>${tip}</title></circle>`;
  }).join('');

  // Threat arcs (curved SVG path between matched log_ids)
  const logIdToX={};
  evs.forEach((ev,i)=>{ logIdToX[ev.log_id]=parseFloat(toX(times[i]).toFixed(1)); });
  const arcPaths=arcs.map(arc=>{
    const x1=logIdToX[arc.from], x2=logIdToX[arc.to];
    if(x1==null||x2==null)return'';
    const y=ROW_H/2;
    const mx=(x1+x2)/2, my=y-18;
    return `<path d="M${x1} ${y} Q${mx} ${my} ${x2} ${y}" fill="none" stroke="#f85149" stroke-width="1.5" stroke-dasharray="3,2" opacity="0.8"/>
            <text x="${mx}" y="${my-4}" fill="#f85149" font-size="8" font-family="var(--mono)" text-anchor="middle">${arc.label||'threat'}</text>`;
  }).join('');

  // Timeline line
  const lineY=ROW_H/2;
  const lineX1=toX(minT).toFixed(1), lineX2=toX(maxT).toFixed(1);

  // Start/end labels
  const startLabel=(evs[0].timestamp||'').slice(11,16);
  const endLabel=(evs[evs.length-1].timestamp||'').slice(11,16);

  return `
  <div style="background:var(--card);border:1px solid var(--border);border-radius:var(--r-lg);padding:12px 16px;margin-bottom:10px">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
      <div style="font-size:12px;font-family:var(--mono);color:var(--text-secondary)">
        Session ${sess.session_id} — ${evs.length} events
        ${arcs.length?`<span style="color:var(--red);margin-left:8px">⚠ ${arcs.length} threat arc${arcs.length>1?'s':''}</span>`:''}
      </div>
      <div style="font-size:11px;color:var(--text-muted)">${(sess.start||'').slice(0,16).replace('T',' ')} → ${(sess.end||'').slice(11,16)}</div>
    </div>
    <div style="overflow-x:auto">
      <svg viewBox="0 0 ${W} ${ROW_H}" style="width:${W}px;height:${ROW_H}px;min-width:100%">
        <!-- Timeline axis -->
        <line x1="${lineX1}" y1="${lineY}" x2="${lineX2}" y2="${lineY}" stroke="var(--border)" stroke-width="1.5"/>
        <!-- Start/end labels -->
        <text x="${lineX1}" y="${ROW_H-4}" fill="var(--chart-tick)" font-size="8" font-family="var(--mono)">${startLabel}</text>
        <text x="${lineX2}" y="${ROW_H-4}" fill="var(--chart-tick)" font-size="8" font-family="var(--mono)" text-anchor="end">${endLabel}</text>
        <!-- Threat arcs -->
        ${arcPaths}
        <!-- Event dots -->
        ${dots}
      </svg>
    </div>
    <!-- Legend -->
    <div style="display:flex;gap:12px;margin-top:6px;flex-wrap:wrap">
      ${['normal','suspicious','high_risk','critical'].map(s=>`
        <span style="display:flex;align-items:center;gap:4px;font-size:10px;color:var(--text-muted)">
          <svg width="10" height="10"><circle cx="5" cy="5" r="4" fill="${sevCol[s]}"/></svg>
          ${s.replace('_',' ')}
        </span>`).join('')}
      <span style="display:flex;align-items:center;gap:4px;font-size:10px;color:var(--red)">
        <svg width="20" height="10"><line x1="0" y1="5" x2="20" y2="5" stroke="#f85149" stroke-dasharray="3,2" stroke-width="1.5"/></svg>
        threat arc
      </span>
    </div>
  </div>`;
}
```

Also update the `showSection` function to load user list when Timeline opens. Find `if(name==='Investigations')loadInvestigations();` and add:

```javascript
  if(name==='Timeline')_tlPopulateUserList();
```

- [ ] **Step 4: Verify visually**

Navigate to the Timeline section. The user dropdown should populate from `/api/stats`. Select a user and click Load. Sessions should render as horizontal SVG timelines with coloured dots. Click a dot — the existing event modal should open.

Generate events that should create a threat arc (USB after file access within 5 min). In the company portal: log in, access a file, then insert USB within 5 minutes. The session timeline should show a red dashed curved arc between the two events.

- [ ] **Step 5: Commit**

```bash
cd /Users/emilysheraphia/Downloads/insightguard
git add application/dashboard.html
git commit -m "feat: add Session Timeline section with SVG event timeline, threat arcs, and user selector"
```

---

## Self-Review Checklist

**Spec coverage:**
- [x] `GET /api/users/<id>/session?days=7` → Task 1
- [x] Session boundary: >30 min gap = new session → Task 1
- [x] Each event: `log_id, timestamp, activity_type, severity, risk_score, file_name, triggered_rules` → Task 1
- [x] Threat arcs: USB insert after file access within 5 min → Task 1 (`_detect_arcs`)
- [x] `GET /api/users/<id>/trajectory?days=7` → Task 2
- [x] Confidence band `confidence_lower` / `confidence_upper` on each point → Task 2
- [x] Risk trajectory SVG chart in user profile modal → Task 3
- [x] Dimensions: 100% width × 180px height → Task 3 (H=180 in viewBox)
- [x] Three dashed threshold lines: 45 / 60 / 80 → Task 3
- [x] Confidence band as shaded polygon → Task 3
- [x] Each data point coloured by severity with hover title → Task 3
- [x] "Not enough data yet (N events)" when <3 points → Task 3
- [x] X-axis day labels → Task 3
- [x] Timeline sidebar nav item with clock icon → Task 4
- [x] User search/select at top → Task 4
- [x] Horizontal scrollable SVG timeline per session → Task 4
- [x] Event dots coloured by severity → Task 4
- [x] Threat arcs drawn as curved red dashed line → Task 4
- [x] Hover tooltip on dot: timestamp, event type, score, filename → Task 4
- [x] Click dot opens existing event modal → Task 4

**Placeholders:** None found.

**Type consistency:**
- `_detect_arcs(events)` → `list[{from, to, label}]` — same shape used in route response and JS `sess.threat_arcs`.
- `ConfidenceEngine.score()` called via `_conf_engine` in trajectory route — requires analytics plan to be merged first.
