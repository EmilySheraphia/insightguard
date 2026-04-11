# InsightGuard Advanced Features — Design Spec
**Date:** 2026-04-11
**Status:** Approved

---

## Overview

Six advanced features added to InsightGuard on top of the existing working system.
Architecture: Option B — new dedicated sections, two new backend modules, existing
dashboard and API untouched except for additions.

**Constraint:** Must not break any currently working feature.

---

## New Files

| File | Purpose |
|------|---------|
| `analytics.py` | `CounterfactualEngine` + `ConfidenceEngine` classes |
| `escalation.py` | Background email escalation thread + queue |
| `storage/escalation_config.json` | SMTP config for alert escalation |

## Modified Files

| File | Changes |
|------|---------|
| `storage/database.py` | New `investigations` table + new `escalation_log` table + CRUD methods |
| `application/app.py` | New API routes (see below), import escalation.py + analytics.py |
| `application/dashboard.html` | New nav items (Timeline, Investigations), new sections, modal enhancements |

---

## Section 1: Session Reconstruction Timeline

### API
```
GET /api/users/<id>/session?days=7
```
Response: `{ sessions: [ { session_id, start, end, events: [...] } ] }`

Each event: `{ log_id, timestamp, activity_type, severity, risk_score, file_name, triggered_rules }`

Session boundary: gap of >30 minutes between consecutive events = new session.

### Dashboard
- New sidebar nav item: **"Timeline"** (clock icon)
- New section `sectionTimeline`
- User search/select at top (input + dropdown populated from `/api/stats` user_risk_profiles)
- Horizontal scrollable SVG timeline per session. Each session = one row.
- Event dots coloured by severity: green (normal), yellow (suspicious), orange (high_risk), red (critical)
- Threat arcs: if USB insert follows file access within 5 min, draw a curved arc connecting the two dots with a red label
- Hover tooltip on dot: timestamp, event type, score, filename
- Click dot: opens existing event modal

---

## Section 2: Analyst Case Management

### Database — new table `investigations`
```sql
CREATE TABLE IF NOT EXISTS investigations (
    case_id       TEXT PRIMARY KEY,
    alert_id      TEXT,
    user_id       TEXT NOT NULL,
    department    TEXT,
    severity      TEXT,
    status        TEXT DEFAULT 'open',
    analyst_notes TEXT DEFAULT '',
    created_at    TEXT DEFAULT (datetime('now')),
    updated_at    TEXT DEFAULT (datetime('now'))
)
```

### API
```
POST   /api/investigations              Create case (body: {alert_id, user_id, department, severity})
GET    /api/investigations              List cases (query: status, user_id, limit)
GET    /api/investigations/<case_id>   Single case detail
PATCH  /api/investigations/<case_id>   Update status + notes (body: {status, analyst_notes})
```

### Dashboard
- New sidebar nav item: **"Investigations"** with badge showing open case count
- New section `sectionInvestigations`
- Case table: case_id, user, dept, severity badge, status badge, opened time, notes preview
- Every alert row in Activity feed and Detection Log gets an **"Open Case"** button (only shown if no case exists yet for that alert)
- Clicking a case row opens a right-side panel (slide-in):
  - Original event scores (from the anomaly_result)
  - Status dropdown: open / confirmed_threat / false_positive / under_investigation / closed
  - Analyst notes textarea (auto-saves on blur via PATCH)
  - Embedded mini timeline for that user (last 2 hours)

### Status values
`open` | `confirmed_threat` | `false_positive` | `under_investigation` | `closed`

---

## Section 3: Automated Alert Escalation

### New file: `escalation.py`
```python
class EscalationEngine:
    def __init__(self, config_path)
    def start()          # starts background thread
    def enqueue(event_payload)  # called from _process_event when severity >= threshold
    def _send_email(payload)    # smtplib SMTP_SSL, Gmail app password
    def _log_escalation(payload, status)  # writes to escalation_log table
```

### Config: `storage/escalation_config.json`
```json
{
    "enabled": false,
    "smtp_host": "smtp.gmail.com",
    "smtp_port": 465,
    "smtp_user": "",
    "smtp_password": "",
    "recipient_email": "",
    "min_severity": "critical"
}
```

### Database — new table `escalation_log`
```sql
CREATE TABLE IF NOT EXISTS escalation_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     TEXT,
    severity    TEXT,
    risk_score  INTEGER,
    sent_to     TEXT,
    status      TEXT,
    error       TEXT,
    sent_at     TEXT DEFAULT (datetime('now'))
)
```

### Email content
Subject: `[InsightGuard ALERT] {severity.upper()} — {user_id} @ {department}`

Body (HTML):
- Risk score, severity badge
- User ID, department, activity type, timestamp
- Triggered UEBA rules (bulleted)
- Link: `http://<server>/` → dashboard

### Dashboard
- In Configuration section: new **"Alert Escalation"** card
- Fields: Enable toggle, SMTP user, SMTP password (masked), recipient email, min severity selector
- Save button → `PUT /api/escalation/config`
- Test button → `POST /api/escalation/test` → sends test email immediately
- Escalation log table: last 20 emails sent (time, user, score, recipient, status)

### API
```
GET  /api/escalation/config    Get current escalation config
PUT  /api/escalation/config    Update config
POST /api/escalation/test      Send test email
GET  /api/escalation/log       Get last 50 escalation log entries
```

---

## Section 4: Risk Trajectory Chart

### API
```
GET /api/users/<id>/trajectory?days=7
```
Response: `{ user_id, points: [ {timestamp, risk_score, severity, activity_type, confidence_lower, confidence_upper} ] }`

Queries `anomaly_results` JOIN `activity_logs` for the user, ordered by timestamp ASC, last 7 days.

### Chart — pure SVG, no external libraries
- Rendered inside the existing user profile modal, below the stats grid
- Dimensions: 100% width × 180px height
- X-axis: time (7 days). Y-axis: 0–100 risk score.
- Three dashed horizontal threshold lines: 45 (suspicious, yellow), 60 (high_risk, orange), 80 (critical, red)
- SVG `<polyline>` for the score line, coloured by dominant severity
- Confidence band: SVG `<polygon>` shaded area between `confidence_lower` and `confidence_upper` lines
- Each data point: `<circle>` coloured by severity, hover title = timestamp + score
- If <3 points: show "Not enough data yet (N events)" message
- X-axis tick labels: day names (Mon, Tue, etc.)

---

## Section 5: Counterfactual Explanations

### New file: `analytics.py`

```python
class CounterfactualEngine:
    PERTURBATIONS = [
        ("during_working_hours",    "If this happened during working hours",   {"is_off_hours": 0}),
        ("no_usb",                  "If no USB device was present",            {"usb_transfer": 0, "usb_data_mb": 0}),
        ("small_file_count",        "If only 1 file was accessed",             {"file_count": 1}),
        ("no_tor",                  "If TOR was not used",                     {"tor": 0}),
        ("no_risky_web",            "If no risky sites were visited",          {"risky_web": 0}),
        ("small_download",          "If data transferred was under 10MB",      {"data_mb": 5}),
        ("no_failed_attempts",      "If login had no failed attempts",         {"failed_attempts": 0}),
        ("known_country",           "If login was from a known safe country",  {"is_risky_country": 0, "is_unknown_country": 0}),
        ("no_external_email",       "If email was sent internally only",       {"external_email": 0}),
    ]

    def explain(self, feature_dict: dict, original_score: int) -> list[dict]:
        # For each perturbation that is relevant (feature value would actually change):
        #   - Clone feature_dict, apply perturbation
        #   - Re-run UEBAEngine.score()
        #   - Compute delta = new_score - original_score
        # Return top 3 by abs(delta), descending
        # Each result: {label, description, new_score, delta, pct_change}
```

### API
```
POST /api/explain/counterfactual
Body: { feature_dict: {...}, original_score: 72 }
Response: { counterfactuals: [ {label, description, new_score, delta, pct_change}, ... ] }
```

### Dashboard — event modal addition
Below "Triggered UEBA Rules", new collapsible section **"What Would Change This?"**:
- Each counterfactual row: description | new score | delta badge (green = reduction, red = increase)
- E.g.: "If this happened during working hours → 31 (−41)" with a green −41 badge
- Only shown when counterfactuals are available (not for normal-severity events with no rules)
- Loaded lazily when modal opens (separate fetch, doesn't slow modal open)

---

## Section 6: Confidence Scoring

### New class in `analytics.py`

```python
class ConfidenceEngine:
    BANDS = [
        (0,   9,   25, "low",       40),
        (10,  29,  15, "moderate",  65),
        (30,  99,   8, "high",      85),
        (100, inf,  4, "very_high", 96),
    ]

    def score(self, events_seen: int, risk_score: int) -> dict:
        # Returns: {score, lower, upper, margin, label, pct, events_seen}
        # lower = max(0, score - margin)
        # upper = min(100, score + margin)
```

### API
```
GET /api/explain/confidence?user_id=X&score=Y
Response: { score, lower, upper, margin, label, pct, events_seen }
```

### Dashboard — three integration points

1. **Event modal** — Final Risk Score row:
   - Before: `68`
   - After: `68 ± 8  [high confidence 85%]`

2. **Detection Log table** — PERS column:
   - Before: `68`
   - After: `68 ±8` (muted ±N in smaller text)
   - Confidence loaded in bulk when `loadRecentEvents()` runs (added to `/api/events/recent` response)

3. **Risk trajectory chart** — confidence band as shaded polygon (already in Section 4 design)

---

## API Summary (new routes)

```
GET  /api/users/<id>/session           Session reconstruction timeline
GET  /api/users/<id>/trajectory        Risk trajectory (7 days)
POST /api/investigations               Create investigation case
GET  /api/investigations               List cases
GET  /api/investigations/<id>          Case detail
PATCH /api/investigations/<id>         Update case
GET  /api/escalation/config            Get escalation config
PUT  /api/escalation/config            Update escalation config
POST /api/escalation/test              Send test email
GET  /api/escalation/log               Escalation log
POST /api/explain/counterfactual       Counterfactual explanation
GET  /api/explain/confidence           Confidence scoring
```

---

## Out of Scope
- Multi-analyst accounts (single analyst dashboard is sufficient for demo)
- OAuth / Gmail API (app password via SMTP is sufficient)
- Push notifications / mobile alerts
- Editing historical events
