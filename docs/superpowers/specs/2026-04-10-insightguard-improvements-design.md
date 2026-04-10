# InsightGuard Improvements — Design Spec
**Date:** 2026-04-10  
**Status:** Approved

---

## Overview

Four improvement areas for the InsightGuard final-year project demo:

1. Per-user isolated workspace state in the Nexon company portal
2. Department/role-specific dummy files with real browser downloads
3. Remove activity logs from the company portal (InsightGuard-only)
4. Anomaly detection audit and fixes

---

## Section 1: Per-User Isolated State

### Goal
Each of the 55 Nexon employees has their own isolated computer state. Switching between employees feels like switching between different machines.

### State Shape (localStorage key: `nc_state_<user_id>`)
```js
{
  filesystem: {
    '/company/': [...],
    '/company/Documents/': [...],
    '/company/Personal/': [...],
    // dept-specific subdirectories
  },
  emails: [...],        // inbox seeded from dept-role template + shared announcements
  sentEmails: [],       // grows as user sends emails
  usbInserted: false,
  usbFiles: [],         // files transferred to USB
  browserHistory: [],   // { domain, url, timestamp, risk } entries
  downloadedFiles: []   // { name, mb, timestamp } entries
}
```

### Initialisation
- On first login for a user, deep-copy `DEPT_TEMPLATES[dept][role]` into their localStorage key
- `DEPT_TEMPLATES` is a JS object baked into `company_app.html`
- Every mutating action (open, copy, download, send email, USB transfer, browse) writes state back to localStorage immediately
- On subsequent logins, load existing state — state persists across sessions

### Templates
Each `DEPT_TEMPLATES[dept][role]` provides:
- A filesystem with 3–5 directories, 8–15 files with realistic names and MB sizes
- 5–8 inbox emails relevant to that department
- Shared company-wide announcements always included

---

## Section 2: Department/Role-Specific Files

### Filesystem Per Department

| Department | Sensitive Files | Normal Files |
|---|---|---|
| Finance | `Salary_Data_2025.xlsx` (12MB), `Q2_Financial_Model.xlsx` (8MB), `Audit_Trail.csv` (3MB) | `Meeting_Notes.docx`, `Expense_Policy.pdf` |
| HR | `All_Employees_Personal.xlsx` (28MB), `Salary_Bands.xlsx` (5MB), `Disciplinary_Log.xlsx` (2MB) | `Onboarding_Checklist.docx`, `Leave_Calendar.xlsx` |
| Engineering | `db_credentials.txt` (0.01MB), `prod_server_list.csv` (0.5MB), `deployment_config.yaml` (0.1MB) | `API_Spec.md`, `Sprint_Notes.docx` |
| IT/SysAdmin | `admin_passwords.txt` (0.01MB), `Active_Directory_Export.xlsx` (15MB), `firewall_rules.csv` (1MB) | `server_logs.txt`, `network_topology.csv` |
| Sales | `Client_List.xlsx` (6MB), `Pipeline_Q2.xlsx` (4MB), `Commission_Tracker.xlsx` (2MB) | `Call_Script.docx`, `Product_Catalogue.pdf` |
| Legal | `NDA_Template.docx` (0.5MB), `Litigation_Log.xlsx` (3MB), `Contracts/` dir | `Compliance_Checklist.docx`, `Policy_Updates.docx` |
| Executive | `M&A_Targets.xlsx` (8MB), `Investor_Data.xlsx` (10MB), `Strategic_Plan_2025.pdf` (5MB) | `Board_Agenda.docx`, `Travel_Schedule.xlsx` |
| Marketing | `Campaign_Data.xlsx` (4MB), `Brand_Assets/` dir | `Social_Calendar.xlsx`, `Press_Release_Draft.docx` |
| Operations | `Vendor_Contracts.xlsx` (3MB), `Asset_Register.xlsx` (7MB) | `Facilities_Schedule.xlsx`, `Maintenance_Log.txt` |

Every employee also gets a `Personal/` folder: `CV_Draft.docx` (0.2MB), `Notes.txt` (0.01MB).

### File Sensitivity Flags
Files tagged `sensitive: true` in the FS template get higher `data_mb` fed to the telemetry event, which increases UEBA score naturally.

---

## Section 3: Real File Downloads

### Flask Endpoint
```
GET /api/files/download?name=<filename>&dept=<dept>
```

Response: `Content-Disposition: attachment; filename=<name>` with generated content.

### Content Generation by Type

| Extension | Generated content |
|---|---|
| `.csv` / `.xlsx` | CSV with realistic column headers + 15–20 rows of plausible data |
| `.txt` / `.log` | Multi-line realistic text (log entries, credential-style content) |
| `.docx` / `.pdf` | Plain text delivered as `.txt` with formatted content |
| `.yaml` | Valid YAML with realistic keys/values |
| `.md` | Markdown with headings and body text |

### Download Button in Company Portal
- Appears in the file actions bar alongside Open / Copy / USB
- On click: calls `/api/files/download`, triggers browser save, AND fires a `file` telemetry event with `operation: 'download'`, correct `data_mb` and `file_count: 1`
- InsightGuard sees the download immediately via SSE

---

## Section 4: Logs Removed from Company Portal

### What stays
- Risk chip in topbar (polls `/api/users/<id>/risk` every 5s)
- Action toasts ("Files opened", "Email sent", "USB transfer")
- All telemetry firing (POST to `/api/events`)

### What is removed
- Any activity log, event history, or audit trail panel visible to the employee
- The employee has no visibility into their own risk score history or event log
- All that data is exclusively in InsightGuard's Detection Log

---

## Section 5: Anomaly Detection Audit

### Files to audit
1. `ai_analytics/anomaly_model.py` — IF + LOF initialisation, training data, weight constants
2. `_full_score()` in `application/app.py` — weight arithmetic, score clamping
3. `feature_engineering/extractor.py` — UEBA rule thresholds
4. `startup_loader.py` — baseline seeding, PUB training

### Checks
- IF and LOF models are not returning constant scores (e.g., always 0.5)
- `IF×0.40 + LOF×0.30 + UEBA×0.30` weights sum to 1.0 and produce 0–100 range
- UEBA rules fire at sensible thresholds (not too sensitive, not too loose)
- PUB trains after 10 events and contributes to the final score
- PERS weighting is applied after PUB (`PUB×0.70 + PsychRisk×0.30`)
- At least 3–4 rules trigger for a high-risk file download scenario

### Fix approach
Any arithmetic errors, untrained models, or misconfigured thresholds are fixed inline during implementation.

---

## Out of Scope
- Backend-persisted filesystem state (localStorage is sufficient for demo)
- Multi-tab synchronisation
- Real network traffic (all telemetry is simulated POST events)
- Actual `.xlsx` binary format (CSV delivered with `.xlsx` extension is acceptable)
