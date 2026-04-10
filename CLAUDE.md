# InsightGuard — Project Context

## Overview
InsightGuard is a final-year university project demonstrating real-time insider threat
detection using UEBA (User and Entity Behavior Analytics). Two web applications are
served by a single Flask backend.

## Two Applications
| App | Route | Purpose |
|-----|-------|---------|
| InsightGuard Dashboard | `/` or `/dashboard` | Security analyst console |
| Nexon Technologies Portal | `/company` | Simulated employee workstation |
| Legacy Employee Portal | `/portal` | Simple portal (superseded by /company) |

## Data Flow
```
Employee action in Company Portal
  → POST /api/events (source-typed activity record with user/dept/role)
  → Flask: AcquisitionRouter → ETLPipeline → FeatureEngineering
  → AnomalyDetectionModel (IF × 0.40 + LOF × 0.30 + UEBA × 0.30)
  → _role_adjusted_ueba()  ← applies per-role threshold config
  → per_user_baseline / PUB (personal Isolation Forest per employee)
  → psychometric_scorer / PERS (OCEAN Big Five personality weighting)
  → SQLite storage
  → SSE broadcast → InsightGuard dashboard (real-time)
```

## Novel Contributions (for thesis/exam)
1. **PERS** — Psychometric-Enhanced Risk Scoring: OCEAN Big Five personality data
   combined with ML anomaly score. Formula: `PERS = ML × 0.70 + PsychRisk × 0.30`
2. **PUB** — Per-User Baseline: personal Isolation Forest per employee, trained
   incrementally (min 10 events), auto-saved to `storage/user_baselines/`

## Scoring Pipeline
```
ML_Score   = IF(global) × 0.40 + LOF(global) × 0.30 + UEBA × 0.30
PUB_Score  = ML_Score × 0.40 + Personal_IF × 0.60   (once ≥10 events)
PERS_Score = PUB_Score × 0.70 + Psychometric_Risk × 0.30
```
Severity: 0–44 normal | 45–59 suspicious | 60–79 high_risk | 80–100 critical

## Role-Based UEBA Configuration
Stored in `storage/role_config.json`. Applied in `app.py::_role_adjusted_ueba()`.
Per-role thresholds prevent false positives for roles that legitimately need high
file access (SysAdmin, CloudEngineer) or many external emails (Sales, Legal).
Editable at runtime via the InsightGuard Configuration section or `PUT /api/config`.

## Key Files
```
application/
  app.py                  Flask server, all API routes, scoring pipeline
  dashboard.html          InsightGuard security analyst dashboard
  company_app.html        Nexon Technologies employee portal
  employee_portal.html    Legacy simple portal

ai_analytics/anomaly_model.py    IF + LOF + UEBA engine
psychometric_scorer.py           PERS scoring (OCEAN Big Five)
per_user_baseline.py             PUB scoring (personal IF)
storage/database.py              SQLite ORM (5 tables)
storage/role_config.json         Per-role UEBA threshold configuration
ground_truth_validator.py        CERT dataset ground truth validation
docs/superpowers/specs/          Design specs
docs/superpowers/plans/          Implementation plans
```

## API Routes
```
GET  /                              InsightGuard dashboard
GET  /company                       Nexon company portal
GET  /healthz                       Health check
POST /api/events                    Ingest single event
POST /api/events/batch              Ingest batch (max 500)
GET  /api/events/simulate           Internal simulation (type=normal|suspicious|high|critical)
GET  /api/cert/replay               Replay CERT dataset events
GET  /api/stats                     Aggregate statistics
GET  /api/stream                    SSE real-time event stream
GET  /api/alerts                    List alerts
GET  /api/baselines                 PUB baseline status
GET  /api/psychometrics             PERS profiles
GET  /api/validate                  Ground truth validation vs CERT answers
GET  /api/users/<id>/risk           Per-user risk profile
GET  /api/users/<id>/timeline       Per-user event timeline
GET  /api/config                    Get role-based UEBA config
PUT  /api/config                    Update role-based UEBA config
GET  /api/files/download            Download generated file (name, dept query params)
```

## Event Payload Format (POST /api/events)
All events must include: `user_id`, `timestamp`, `source`, `department`, `role`

Source types and key extra fields:
- `login` / `auth_system` — event, country_code, vpn, tor, new_device, failed_attempts
- `file` / `dlp_system` — file_path, operation, file_count, data_mb, destination
- `email` / `mail_gateway` — direction, recipient_count, attachment_mb, external
- `usb` / `endpoint_agent` — device_id, operation, data_mb
- `web` / `web_proxy` — url, category, bytes_out, blocked

## Company Portal (Nexon Technologies)
- 55 employees across 8 departments (Engineering, Finance, HR, IT, Sales, Marketing, Legal, Executive, Operations)
- All employees use password: `nexon123`
- Portal tracks: logins, file access, email, web browsing, USB devices
- Everything POSTed to `/api/events` immediately

## Company Portal — Per-User Workspace State
Each employee has isolated state stored in localStorage under `nc_state_<user_id>`.
State includes: filesystem (dept-specific), emails (dept + shared), USB, browser history.
State persists across logins. First login seeds from `DEPT_FS_TEMPLATES[dept]`.
File downloads hit `GET /api/files/download?name=<n>&dept=<d>` which generates
realistic content (CSV with proper columns for salary/payroll files, credentials files, etc.).
Dept filesystem roots are `/home/` (not `/company/`).

## Dataset
- CERT Insider Threat Dataset R4.2 at `~/Downloads/r4.2/`
- `psychometric.csv` — OCEAN profiles for CERT users
- Ground truth answers at `~/Downloads/answers/`

## Deployment
- `gunicorn` for production (already in requirements.txt)
- `PORT` env variable configures listen port (default 5000)
- Single Flask app serves both UIs from the same origin
- SQLite for storage — consider PostgreSQL for production scale

## Recent Fixes (2026-04-10)
- ETL pipeline: `risky_web` now detected from `category` field (`tor`/`cloud_storage`/`file_sharing`)
- UEBA thresholds lowered: `bulk_download` 500→200 MB, `usb_exfil` 100→50 MB, `risky_web` weight 10→20
- Company portal: per-user isolated state (localStorage), dept-specific filesystems and emails
- Download button added: real file download via `/api/files/download` with generated content
- Activity log sidebar removed from company portal (logs only in InsightGuard dashboard)
