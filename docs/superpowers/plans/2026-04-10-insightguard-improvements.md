# InsightGuard Improvements Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add per-user isolated workspace state, department-specific files with real downloads, remove activity logs from company portal, and fix anomaly detection bugs.

**Architecture:** Per-user state stored in localStorage (key `nc_state_<user_id>`), seeded from dept-specific JS templates on first login. Flask serves a `/api/files/download` endpoint that generates realistic file content. ETL pipeline bug for risky web events is patched.

**Tech Stack:** Flask (Python), vanilla JS, localStorage, SQLite. No new dependencies.

---

## Task 1: Fix Anomaly Detection — ETL Bug + Threshold Tuning

**Files:**
- Modify: `data_processing/etl_pipeline.py:190-192`
- Modify: `ai_analytics/anomaly_model.py:48-57`

**Problem 1:** `etl_pipeline.py` line 191 reads `d.get("risky", False)` but the company portal sends `category: "tor"` / `category: "cloud_storage"` — `risky` is never in the payload, so `risky_web` is always `False`. Visiting Tor never flags.

**Problem 2:** `bulk_download` threshold is 500 MB but the largest demo file is 430 MB (`Source_Code_Archive.zip`). `usb_exfil` needs 100 MB but demo transfers are often <50 MB. Scores come out near-zero for realistic demo actions.

- [ ] **Step 1: Fix ETL risky_web detection**

In `data_processing/etl_pipeline.py`, replace lines 190–192:
```python
        elif raw.activity_type == "web":
            p.risky_web = self._safe_bool(d.get("risky", False))
            p.data_mb   = self._safe_float(d.get("bytes_out", 0)) / 1_048_576
```
with:
```python
        elif raw.activity_type == "web":
            cat = str(d.get("category", "")).lower()
            _risky_cats = {"tor", "cloud_storage", "file_sharing"}
            p.risky_web = self._safe_bool(d.get("risky", False)) or cat in _risky_cats
            p.data_mb   = self._safe_float(d.get("bytes_out", 0)) / 1_048_576
```

- [ ] **Step 2: Tune UEBA thresholds in anomaly_model.py**

In `ai_analytics/anomaly_model.py`, replace the RULES list (lines 41–57):
```python
    RULES = [
        ("off_hours_login",     12, lambda f: f.event_type_code == 0 and f.is_off_hours),
        ("high_risk_country",   25, lambda f: f.is_risky_country),
        ("unknown_country",     10, lambda f: f.is_unknown_country),
        ("tor_detected",        30, lambda f: f.tor),
        ("vpn_suspicious",       6, lambda f: f.vpn and f.is_off_hours),
        ("new_device",           8, lambda f: f.new_device),
        ("repeated_auth_fail",  12, lambda f: f.failed_attempts >= 3),
        ("bulk_download",       18, lambda f: f.data_mb >= 200),
        ("massive_download",    32, lambda f: f.data_mb >= 1500),
        ("bulk_file_access",    16, lambda f: f.file_count >= 30),
        ("extreme_file_access", 26, lambda f: f.file_count >= 100),
        ("usb_exfil",           20, lambda f: f.usb_transfer and f.usb_data_mb >= 50),
        ("external_email_bulk", 14, lambda f: f.external_email and f.recipient_count >= 5),
        ("risky_web",           20, lambda f: f.risky_web),
        ("large_attachment",    12, lambda f: f.attachment_mb >= 25),
    ]
```

- [ ] **Step 3: Update role_config.json defaults to match new thresholds**

In `storage/role_config.json`, update the `default` role:
```json
"default": {
  "bulk_download_mb": 200,
  "massive_download_mb": 1500,
  "bulk_file_count": 30,
  "extreme_file_count": 100,
  "usb_exfil_mb": 50,
  "external_email_recipients": 5,
  "large_attachment_mb": 25,
  "off_hours_weight": 1.0,
  "vpn_suspicious_weight": 1.0
}
```
Also update `SysAdmin`, `CloudEngineer`, `DevOps` entries to use proportionally higher values (e.g., `bulk_download_mb: 2000`, `usb_exfil_mb: 500`) so they don't false-positive.

- [ ] **Step 4: Verify self-test passes**

```bash
cd /Users/emilysheraphia/Downloads/insightguard
source venv/bin/activate
python ai_analytics/anomaly_model.py
```
Expected output: "Off-hours bulk file download" should show Risk >= 45 (suspicious or higher). "TOR + high-risk country" should show Risk >= 80 (critical).

- [ ] **Step 5: Commit**

```bash
git add data_processing/etl_pipeline.py ai_analytics/anomaly_model.py storage/role_config.json
git commit -m "fix: ETL risky_web detection and tune UEBA thresholds for demo"
```

---

## Task 2: Flask File Download Endpoint

**Files:**
- Modify: `application/app.py` — add route after line 355 (after `serve_company`)

- [ ] **Step 1: Add file content generators to app.py**

After the `serve_company` route (line ~355), add:
```python
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
    ext  = name.rsplit(".", 1)[-1].lower() if "." in name else "txt"
    lines = [
        f"# {base}",
        f"Department: {dept}",
        f"Classification: CONFIDENTIAL",
        f"Generated: 2025-04-10",
        "",
        f"This document contains {dept} department records.",
        "Access is restricted to authorised personnel only.",
        "",
    ]
    if ext in ("xlsx", "csv"):
        lines += ["id,name,value,date,status",
                  "001,Record A,£12450.00,2025-01-15,Active",
                  "002,Record B,£8320.00,2025-02-03,Active",
                  "003,Record C,£19875.00,2025-02-28,Pending",
                  "004,Record D,£5100.00,2025-03-10,Active",
                  "005,Record E,£33200.00,2025-03-22,Review",]
    return "\n".join(lines)


@app.get("/api/files/download")
def download_file():
    from flask import make_response
    name = request.args.get("name", "file.txt")
    dept = request.args.get("dept", "General")
    gen  = _FILE_CONTENT.get(name)
    content = gen(dept) if gen else _generic_file_content(name, dept)
    # Deliver as plain text but with original filename (xlsx/csv etc.)
    resp = make_response(content.encode("utf-8"))
    resp.headers["Content-Disposition"] = f'attachment; filename="{name}"'
    resp.headers["Content-Type"] = "text/plain; charset=utf-8"
    resp.headers["Content-Length"] = len(content.encode("utf-8"))
    return resp
```

- [ ] **Step 2: Verify endpoint works**

```bash
cd /Users/emilysheraphia/Downloads/insightguard
source venv/bin/activate
python -c "
from application.app import app
with app.test_client() as c:
    r = c.get('/api/files/download?name=Salary_Data_2025.xlsx&dept=Finance')
    print('Status:', r.status_code)
    print('Header:', r.headers.get('Content-Disposition'))
    print('Lines:', len(r.data.decode().splitlines()))
"
```
Expected: `Status: 200`, Content-Disposition contains `Salary_Data_2025.xlsx`, 22 lines.

- [ ] **Step 3: Commit**

```bash
git add application/app.py
git commit -m "feat: add /api/files/download endpoint with generated content"
```

---

## Task 3: Per-User State + Dept Filesystem Templates (company_app.html)

**Files:**
- Modify: `application/company_app.html` — replace the `FS` const and add state management functions

This is the largest task. It replaces the single global `FS` object with per-dept templates and adds localStorage-backed state isolation.

- [ ] **Step 1: Replace the `FS` const with `DEPT_FS_TEMPLATES` + state variables**

In `company_app.html`, find the `// FILE SYSTEM` section (line 519) and replace everything from `const FS = {` through the closing `};` (lines 520–593) with:

```js
// ══════════════════════════════════════════════════════
//  DEPT FILESYSTEM TEMPLATES
// ══════════════════════════════════════════════════════
const _SHARED_ROOT_FILES=[
  {name:'All Staff Policy.pdf',type:'file',icon:'📄',size:'2.1 MB',mb:2.1},
  {name:'Company Handbook 2025.docx',type:'file',icon:'📝',size:'5.4 MB',mb:5.4},
];
const DEPT_FS_TEMPLATES={
  Engineering:{
    '/home/':[
      {name:'Projects',type:'folder',icon:'📂'},
      {name:'Architecture',type:'folder',icon:'📂'},
      {name:'Personal',type:'folder',icon:'📂'},
      {name:'API_Spec_v3.pdf',type:'file',icon:'📄',size:'3.2 MB',mb:3.2},
      {name:'Dev_Setup.md',type:'file',icon:'📝',size:'0.2 MB',mb:0.2},
    ],
    '/home/Projects/':[
      {name:'Source_Code_Archive.zip',type:'file',icon:'🗜',size:'430 MB',mb:430,sensitive:true},
      {name:'db_credentials.txt',type:'file',icon:'🔑',size:'0.01 MB',mb:0.01,sensitive:true},
      {name:'prod_server_list.csv',type:'file',icon:'📊',size:'0.5 MB',mb:0.5,sensitive:true},
      {name:'deployment_config.yaml',type:'file',icon:'⚙️',size:'0.1 MB',mb:0.1},
    ],
    '/home/Architecture/':[
      {name:'System_Design_v3.pdf',type:'file',icon:'📄',size:'15.3 MB',mb:15.3},
      {name:'DB_Schema.pdf',type:'file',icon:'📄',size:'4.2 MB',mb:4.2},
      {name:'Cloud_Architecture.pptx',type:'file',icon:'📊',size:'8.8 MB',mb:8.8},
    ],
    '/home/Personal/':[
      {name:'Notes.txt',type:'file',icon:'📝',size:'0.01 MB',mb:0.01},
      {name:'CV_Draft.docx',type:'file',icon:'📝',size:'0.2 MB',mb:0.2},
    ],
  },
  Finance:{
    '/home/':[
      {name:'Finance_Reports',type:'folder',icon:'📂'},
      {name:'Payroll',type:'folder',icon:'📂'},
      {name:'Personal',type:'folder',icon:'📂'},
      {name:'Budget_Tracker_2025.xlsx',type:'file',icon:'📊',size:'6.7 MB',mb:6.7},
      {name:'Expense_Policy.pdf',type:'file',icon:'📄',size:'1.2 MB',mb:1.2},
    ],
    '/home/Finance_Reports/':[
      {name:'Q1_2025_Report.xlsx',type:'file',icon:'📊',size:'8.2 MB',mb:8.2},
      {name:'Q2_Financial_Model.xlsx',type:'file',icon:'📊',size:'9.1 MB',mb:9.1},
      {name:'Annual_Report_2024.pdf',type:'file',icon:'📄',size:'4.3 MB',mb:4.3},
      {name:'Audit_Trail.csv',type:'file',icon:'📊',size:'3.1 MB',mb:3.1,sensitive:true},
    ],
    '/home/Payroll/':[
      {name:'Salary_Data_2025.xlsx',type:'file',icon:'📊',size:'12.5 MB',mb:12.5,sensitive:true},
      {name:'Salary_Bands.xlsx',type:'file',icon:'📊',size:'5.2 MB',mb:5.2,sensitive:true},
      {name:'Bonus_Payments_Q2.xlsx',type:'file',icon:'📊',size:'3.8 MB',mb:3.8,sensitive:true},
    ],
    '/home/Personal/':[
      {name:'Notes.txt',type:'file',icon:'📝',size:'0.01 MB',mb:0.01},
      {name:'CV_Draft.docx',type:'file',icon:'📝',size:'0.2 MB',mb:0.2},
    ],
  },
  HR:{
    '/home/':[
      {name:'Employee_Records',type:'folder',icon:'📂'},
      {name:'Recruitment',type:'folder',icon:'📂'},
      {name:'Personal',type:'folder',icon:'📂'},
      {name:'Org_Chart_2025.pdf',type:'file',icon:'📄',size:'1.8 MB',mb:1.8},
      {name:'Onboarding_Checklist.docx',type:'file',icon:'📝',size:'0.9 MB',mb:0.9},
    ],
    '/home/Employee_Records/':[
      {name:'All_Employees_Personal.xlsx',type:'file',icon:'📊',size:'28.5 MB',mb:28.5,sensitive:true},
      {name:'Disciplinary_Records.xlsx',type:'file',icon:'📊',size:'5.1 MB',mb:5.1,sensitive:true},
      {name:'Performance_Reviews_Q1.xlsx',type:'file',icon:'📊',size:'14.2 MB',mb:14.2,sensitive:true},
      {name:'Contracts_2025.zip',type:'file',icon:'🗜',size:'65.3 MB',mb:65.3,sensitive:true},
    ],
    '/home/Recruitment/':[
      {name:'Job_Descriptions.docx',type:'file',icon:'📝',size:'0.8 MB',mb:0.8},
      {name:'Interview_Templates.docx',type:'file',icon:'📝',size:'0.4 MB',mb:0.4},
      {name:'Candidate_Pipeline_Q2.xlsx',type:'file',icon:'📊',size:'3.2 MB',mb:3.2},
    ],
    '/home/Personal/':[
      {name:'Notes.txt',type:'file',icon:'📝',size:'0.01 MB',mb:0.01},
      {name:'CV_Draft.docx',type:'file',icon:'📝',size:'0.2 MB',mb:0.2},
    ],
  },
  IT:{
    '/home/':[
      {name:'Admin',type:'folder',icon:'📂'},
      {name:'Network',type:'folder',icon:'📂'},
      {name:'Personal',type:'folder',icon:'📂'},
      {name:'IT_Helpdesk_Log.xlsx',type:'file',icon:'📊',size:'2.1 MB',mb:2.1},
    ],
    '/home/Admin/':[
      {name:'admin_passwords.txt',type:'file',icon:'🔑',size:'0.01 MB',mb:0.01,sensitive:true},
      {name:'Active_Directory_Export.xlsx',type:'file',icon:'📊',size:'15.2 MB',mb:15.2,sensitive:true},
      {name:'server_logs.txt',type:'file',icon:'📄',size:'8.7 MB',mb:8.7},
      {name:'Backup_Schedule.xlsx',type:'file',icon:'📊',size:'0.5 MB',mb:0.5},
    ],
    '/home/Network/':[
      {name:'firewall_rules.csv',type:'file',icon:'📄',size:'1.0 MB',mb:1.0,sensitive:true},
      {name:'network_topology.pdf',type:'file',icon:'📄',size:'3.2 MB',mb:3.2},
      {name:'VPN_Config.yaml',type:'file',icon:'⚙️',size:'0.05 MB',mb:0.05,sensitive:true},
    ],
    '/home/Personal/':[
      {name:'Notes.txt',type:'file',icon:'📝',size:'0.01 MB',mb:0.01},
      {name:'CV_Draft.docx',type:'file',icon:'📝',size:'0.2 MB',mb:0.2},
    ],
  },
  Sales:{
    '/home/':[
      {name:'CRM',type:'folder',icon:'📂'},
      {name:'Proposals',type:'folder',icon:'📂'},
      {name:'Personal',type:'folder',icon:'📂'},
      {name:'Pricing_Guide_2025.pdf',type:'file',icon:'📄',size:'2.3 MB',mb:2.3},
    ],
    '/home/CRM/':[
      {name:'Client_List_Q2.xlsx',type:'file',icon:'📊',size:'16.8 MB',mb:16.8,sensitive:true},
      {name:'Lead_Database.xlsx',type:'file',icon:'📊',size:'31.2 MB',mb:31.2,sensitive:true},
      {name:'Pipeline_Q2.xlsx',type:'file',icon:'📊',size:'8.4 MB',mb:8.4},
      {name:'Commission_Tracker.xlsx',type:'file',icon:'📊',size:'2.1 MB',mb:2.1,sensitive:true},
    ],
    '/home/Proposals/':[
      {name:'BigCorp_Proposal_v3.docx',type:'file',icon:'📝',size:'4.5 MB',mb:4.5},
      {name:'Enterprise_Template.docx',type:'file',icon:'📝',size:'1.2 MB',mb:1.2},
      {name:'Q2_Contracts.zip',type:'file',icon:'🗜',size:'22.3 MB',mb:22.3},
    ],
    '/home/Personal/':[
      {name:'Notes.txt',type:'file',icon:'📝',size:'0.01 MB',mb:0.01},
      {name:'CV_Draft.docx',type:'file',icon:'📝',size:'0.2 MB',mb:0.2},
    ],
  },
  Legal:{
    '/home/':[
      {name:'Contracts',type:'folder',icon:'📂'},
      {name:'NDAs',type:'folder',icon:'📂'},
      {name:'Personal',type:'folder',icon:'📂'},
      {name:'Regulatory_Filings_2025.pdf',type:'file',icon:'📄',size:'22.4 MB',mb:22.4},
    ],
    '/home/Contracts/':[
      {name:'Contracts_Archive_2025.zip',type:'file',icon:'🗜',size:'65.1 MB',mb:65.1,sensitive:true},
      {name:'Litigation_Log.xlsx',type:'file',icon:'📊',size:'3.2 MB',mb:3.2,sensitive:true},
      {name:'IP_Portfolio.pdf',type:'file',icon:'📄',size:'8.7 MB',mb:8.7},
    ],
    '/home/NDAs/':[
      {name:'NDA_Template.docx',type:'file',icon:'📝',size:'0.5 MB',mb:0.5},
      {name:'Signed_NDAs_2025.zip',type:'file',icon:'🗜',size:'18.2 MB',mb:18.2,sensitive:true},
      {name:'Compliance_Checklist.docx',type:'file',icon:'📝',size:'0.8 MB',mb:0.8},
    ],
    '/home/Personal/':[
      {name:'Notes.txt',type:'file',icon:'📝',size:'0.01 MB',mb:0.01},
      {name:'CV_Draft.docx',type:'file',icon:'📝',size:'0.2 MB',mb:0.2},
    ],
  },
  Executive:{
    '/home/':[
      {name:'Strategy',type:'folder',icon:'📂'},
      {name:'Board',type:'folder',icon:'📂'},
      {name:'Personal',type:'folder',icon:'📂'},
      {name:'Travel_Schedule_Q2.xlsx',type:'file',icon:'📊',size:'0.8 MB',mb:0.8},
    ],
    '/home/Strategy/':[
      {name:'Strategic_Plan_2025.pdf',type:'file',icon:'📄',size:'5.1 MB',mb:5.1,sensitive:true},
      {name:'M&A_Targets.xlsx',type:'file',icon:'📊',size:'8.3 MB',mb:8.3,sensitive:true},
      {name:'Investor_Data.xlsx',type:'file',icon:'📊',size:'10.2 MB',mb:10.2,sensitive:true},
    ],
    '/home/Board/':[
      {name:'Board_Minutes_Q1.docx',type:'file',icon:'📝',size:'2.1 MB',mb:2.1,sensitive:true},
      {name:'Board_Agenda_Q2.docx',type:'file',icon:'📝',size:'0.9 MB',mb:0.9},
      {name:'Executive_Compensation.xlsx',type:'file',icon:'📊',size:'4.5 MB',mb:4.5,sensitive:true},
    ],
    '/home/Personal/':[
      {name:'Notes.txt',type:'file',icon:'📝',size:'0.01 MB',mb:0.01},
      {name:'CV_Draft.docx',type:'file',icon:'📝',size:'0.2 MB',mb:0.2},
    ],
  },
  Marketing:{
    '/home/':[
      {name:'Campaigns',type:'folder',icon:'📂'},
      {name:'Brand_Assets',type:'folder',icon:'📂'},
      {name:'Personal',type:'folder',icon:'📂'},
      {name:'Social_Media_Calendar.xlsx',type:'file',icon:'📊',size:'1.8 MB',mb:1.8},
    ],
    '/home/Campaigns/':[
      {name:'Campaign_Results_Q1.xlsx',type:'file',icon:'📊',size:'5.6 MB',mb:5.6},
      {name:'Q2_Campaign_Brief.docx',type:'file',icon:'📝',size:'2.1 MB',mb:2.1},
      {name:'Customer_Segments.xlsx',type:'file',icon:'📊',size:'12.4 MB',mb:12.4,sensitive:true},
    ],
    '/home/Brand_Assets/':[
      {name:'Brand_Assets_2025.zip',type:'file',icon:'🗜',size:'180 MB',mb:180},
      {name:'Logo_Pack.zip',type:'file',icon:'🗜',size:'45 MB',mb:45},
      {name:'Brand_Guidelines.pdf',type:'file',icon:'📄',size:'8.2 MB',mb:8.2},
    ],
    '/home/Personal/':[
      {name:'Notes.txt',type:'file',icon:'📝',size:'0.01 MB',mb:0.01},
      {name:'CV_Draft.docx',type:'file',icon:'📝',size:'0.2 MB',mb:0.2},
    ],
  },
  Operations:{
    '/home/':[
      {name:'Vendors',type:'folder',icon:'📂'},
      {name:'Projects',type:'folder',icon:'📂'},
      {name:'Personal',type:'folder',icon:'📂'},
      {name:'Facilities_Schedule.xlsx',type:'file',icon:'📊',size:'1.4 MB',mb:1.4},
    ],
    '/home/Vendors/':[
      {name:'Vendor_Contracts.zip',type:'file',icon:'🗜',size:'42.1 MB',mb:42.1,sensitive:true},
      {name:'Asset_Register.xlsx',type:'file',icon:'📊',size:'7.2 MB',mb:7.2},
      {name:'Supplier_List.xlsx',type:'file',icon:'📊',size:'3.8 MB',mb:3.8},
    ],
    '/home/Projects/':[
      {name:'Project_Plans_2025.xlsx',type:'file',icon:'📊',size:'9.4 MB',mb:9.4},
      {name:'Resource_Allocation.xlsx',type:'file',icon:'📊',size:'4.1 MB',mb:4.1},
      {name:'Risk_Register.xlsx',type:'file',icon:'📊',size:'2.3 MB',mb:2.3},
    ],
    '/home/Personal/':[
      {name:'Notes.txt',type:'file',icon:'📝',size:'0.01 MB',mb:0.01},
      {name:'CV_Draft.docx',type:'file',icon:'📝',size:'0.2 MB',mb:0.2},
    ],
  },
};
// Fallback for unknown depts
DEPT_FS_TEMPLATES.General=DEPT_FS_TEMPLATES.Operations;

// Per-user state (loaded from localStorage on login)
let currentFS={}, currentEmails=[], currentUSBInserted=false, currentUSBFiles=[], currentBrowserHistory=[];
```

- [ ] **Step 2: Add dept email templates just before the `STATE` section (before line 644)**

Find the line `// ══ STATE` comment (line ~644) and insert before it:

```js
// ══════════════════════════════════════════════════════
//  DEPT EMAIL TEMPLATES
// ══════════════════════════════════════════════════════
const SHARED_EMAILS=[
  {from:'hr@nexon.com',     subject:'Q2 Performance Reviews — Action Required',  preview:'Please complete your team performance reviews by Friday…', body:'Hi Team,\n\nQ2 performance reviews are due this Friday. Please log into the HR portal.\n\nRegards, HR Team', external:false, attachMB:0.3},
  {from:'it@nexon.com',     subject:'System Maintenance — 22:00 Tonight',        preview:'Planned maintenance window tonight at 22:00…', body:'Dear All,\n\nScheduled maintenance tonight from 22:00-01:00.\n\nIT Operations', external:false, attachMB:0},
  {from:'ceo@nexon.com',    subject:'Company All-Hands — Thursday 3pm',          preview:'Please join us for our quarterly all-hands…', body:'Team,\n\nPlease join me for our Q2 all-hands this Thursday at 3pm.\n\nRobert Anderson, CEO', external:false, attachMB:0.1},
  {from:'security@nexon.com',subject:'Security Awareness Training — Mandatory',  preview:'All staff must complete training by May 15…', body:'Important: All staff must complete 2025 Security Awareness Training by 15 May.\n\nIT Security', external:false, attachMB:0},
];
const DEPT_EMAIL_TEMPLATES={
  Finance:[
    {from:'audit@kpmg.com', subject:'External Audit — Document Request', preview:'Please provide the following financial documents for our Q2 audit…', body:'Dear Finance Team,\n\nAs part of our Q2 audit engagement, we require:\n- Full general ledger export\n- Bank reconciliation statements (Jan-Mar)\n- Payroll records for all staff\n\nPlease send to audit@kpmg.com by Friday.\n\nKPMG Audit Services', external:true, attachMB:0.2},
    {from:'cfo@nexon.com',  subject:'URGENT: Budget Variance Q1 — Action Required', preview:'Q1 actuals show a 12% variance against budget. Please review…', body:'Team,\n\nQ1 actuals show a 12% variance. I need full analysis by Monday.\n\nJennifer Williams, CFO', external:false, attachMB:1.5},
    {from:'vendor@payrollpro.com', subject:'Payroll Processing — April Run Complete', preview:'April payroll has been processed. Total: £2,847,320…', body:'Dear Nexon Payroll Team,\n\nApril payroll run complete.\nTotal employees: 55\nGross payroll: £2,847,320\nNet transfers initiated: £2,209,450\n\nPayroll Pro Services', external:true, attachMB:0.8},
  ],
  HR:[
    {from:'legal@nexon.com', subject:'Employee Termination — Confidential', preview:'Please prepare the necessary documentation for termination of employment…', body:'Dear HR,\n\nPlease prepare termination documentation for EMP-2847.\nEffective date: 30 April 2025.\nReason: Gross misconduct.\n\nThis is strictly confidential.\n\nLegal Team', external:false, attachMB:0.5},
    {from:'recruiter@linkedin.com', subject:'New Applicants — Senior Developer Role', preview:'17 new applicants have applied to the Senior Developer position…', body:'Hi,\n\n17 candidates have applied to your Senior Developer role.\n\nTop matches:\n- Sarah Park (95% match)\n- James Liu (92% match)\n- Maria Costa (88% match)\n\nLinkedIn Recruiter', external:true, attachMB:0.2},
    {from:'pension@provider.com', subject:'Q1 Pension Contributions — Confirmation', preview:'Confirming Q1 pension contributions for all enrolled employees…', body:'Dear HR Team,\n\nQ1 pension contributions processed:\nEmployees enrolled: 48\nTotal employee contributions: £89,450\nTotal employer contributions: £178,900\n\nNexon Pension Provider', external:true, attachMB:1.2},
  ],
  Engineering:[
    {from:'devops@nexon.com', subject:'Production Deploy FAILED — nexon/platform-core', preview:'Build #847 failed at deployment stage. Rollback initiated…', body:'ALERT: Production deployment failed.\n\nRepository: nexon/platform-core\nBranch: main\nBuild: #847\nStage: Post-deploy health check\nError: 3/10 instances unhealthy\n\nRollback initiated. Investigation required.\n\nDevOps Automation', external:false, attachMB:0.3},
    {from:'security@nexon.com', subject:'CRITICAL: Dependency Vulnerability — CVE-2025-1234', preview:'A critical vulnerability has been found in a production dependency…', body:'Security Alert,\n\nCritical vulnerability detected:\nCVE-2025-1234 (CVSS 9.8)\nAffected: log4j-core 2.14.1\nComponent: nexon/analytics-service\n\nPatch required within 24 hours.\n\nIT Security', external:false, attachMB:0.1},
    {from:'client@bigcorp.com', subject:'API Integration Issue — Production', preview:'We are experiencing failures in your API since this morning…', body:'Hi Engineering Team,\n\nSince 09:30 this morning we are seeing 503 errors from your API.\nAffected endpoint: POST /api/v2/transactions\nError rate: 34%\n\nThis is business critical for us.\n\nBigCorp Integration Team', external:true, attachMB:0.5},
  ],
  IT:[
    {from:'soc@nexon.com', subject:'ALERT: Multiple Failed Login Attempts — admin account', preview:'InsightGuard has detected 8 failed logins to the admin account from IP 185.220.x.x…', body:'Security Alert,\n\nMultiple failed logins detected:\nAccount: administrator@nexon.com\nFailed attempts: 8\nSource IP: 185.220.101.47 (Tor exit node)\nTime: 03:22-03:45 UTC\n\nAccount temporarily locked. Review required.\n\nSOC Team', external:false, attachMB:0},
    {from:'vendor@server.com', subject:'Hardware Warranty Expiry — 12 Servers', preview:'The following servers will have warranty expiry in the next 30 days…', body:'Dear IT Team,\n\nWarranty expiring in 30 days:\n- prod-app-01 through prod-app-04\n- prod-db-01, prod-db-02\n- 6 additional servers\n\nRenewal quote attached.\n\nServer Solutions Ltd', external:true, attachMB:0.4},
  ],
  Sales:[
    {from:'crm@salesforce.com', subject:'Pipeline Alert: 3 Deals Closing This Week', preview:'You have 3 deals in final negotiation expected to close by Friday…', body:'Sales Alert,\n\nDeals closing this week:\n1. BigCorp — £340,000 (90% probability)\n2. TechStart Ltd — £85,000 (75% probability)\n3. Global Retail Co — £210,000 (85% probability)\n\nTotal pipeline value at risk: £635,000\n\nSalesforce CRM', external:true, attachMB:0.1},
    {from:'legal@nexon.com', subject:'Contract Review Required — GlobalCorp MSA', preview:'The GlobalCorp Master Service Agreement requires your sign-off before…', body:'Hi Sales Team,\n\nThe GlobalCorp MSA is ready for your review.\nContract value: £1.2M over 3 years\nKey clauses flagged: data processing addendum, liability caps.\n\nNeeds your sign-off by Thursday.\n\nLegal Team', external:false, attachMB:2.1},
  ],
  Legal:[
    {from:'court@hmcts.gov.uk', subject:'Case Ref: HC-2025-04821 — Response Required', preview:'The High Court requires your response to the claimant's particulars by…', body:'Dear Nexon Technologies Legal,\n\nCase Reference: HC-2025-04821\nClaimant: DataBreach Victims Group\n\nYou are required to file your defence by 30 April 2025.\n\nHM Courts & Tribunals Service', external:true, attachMB:1.8},
    {from:'ico@information-commissioner.org.uk', subject:'Data Protection Inquiry — Reference ICO-2025-0482', preview:'The ICO has opened an inquiry into a reported data incident…', body:'Dear Nexon Technologies,\n\nFollowing a complaint received on 3 April 2025, we have opened an inquiry.\n\nPlease provide your Data Protection Impact Assessment for your UEBA system within 14 days.\n\nICO', external:true, attachMB:0.5},
  ],
  Executive:[
    {from:'investor@vccapital.com', subject:'Board Update Request — Q1 Financials', preview:'As per our investor agreement, we request the Q1 financial summary…', body:'Dear Board,\n\nPer our shareholder agreement, please provide Q1 financials including:\n- Revenue and EBITDA\n- Headcount and burn\n- Key KPIs vs targets\n\nVC Capital Partners', external:true, attachMB:0},
    {from:'manda@advisory.com', subject:'CONFIDENTIAL: Acquisition Target — Preliminary Analysis', preview:'Following our brief discussion, please find attached the preliminary analysis…', body:'Dear Robert,\n\nPreliminary analysis of the identified target attached. Key highlights:\n- Revenue: £8.2M ARR\n- Team: 47 FTE\n- Valuation range: £45-65M\n\nRecommend proceeding to NDA stage.\n\nM&A Advisory', external:true, attachMB:3.2},
  ],
  Marketing:[
    {from:'google@ads.google.com', subject:'Campaign Performance — April Week 2', preview:'Your Google Ads campaigns delivered 2.4M impressions this week…', body:'Campaign Summary — Week of 7 April 2025\n\nImpressions: 2,400,000\nClicks: 18,450\nConversions: 312\nCost: £8,920\nCPA: £28.59\n\nGoogle Ads', external:true, attachMB:0.2},
    {from:'pr@prfirm.com', subject:'Press Coverage — Nexon Named in Top 50 Tech Firms', preview:'We have secured coverage in TechCrunch, Forbes and The Guardian…', body:'Great news!\n\nNexon Technologies has been featured in:\n- TechCrunch: Top 50 UK Tech Firms 2025\n- Forbes: Companies to Watch\n- The Guardian: Tech Supplement\n\nYour PR Team', external:true, attachMB:1.5},
  ],
  Operations:[
    {from:'vendor@facilities.com', subject:'Office Lease Renewal — Action Required', preview:'Your current lease expires 30 June 2025. Please confirm renewal intention…', body:'Dear Operations Team,\n\nYour office lease at 100 Tech Street expires 30 June 2025.\nRenewal terms: 3-year term, £180,000 p.a. (+8% on current).\n\nConfirmation required by 30 April.\n\nFacilities Management', external:true, attachMB:0.8},
    {from:'pm@nexon.com', subject:'Project Status — Q2 Infrastructure Upgrade', preview:'Phase 2 of the infrastructure upgrade is 3 days behind schedule…', body:'Team,\n\nQ2 Infrastructure Upgrade Status:\nPhase 1: Complete ✅\nPhase 2: 3 days behind schedule ⚠️\nPhase 3: On track ✅\n\nMitigations in place for Phase 2 delay.\n\nProject Management', external:false, attachMB:0.3},
  ],
};
DEPT_EMAIL_TEMPLATES.General=[];
```

- [ ] **Step 3: Commit checkpoint**

```bash
git add application/company_app.html
git commit -m "feat: add per-dept filesystem and email templates"
```

---

## Task 4: Per-User State Management Functions (company_app.html)

**Files:**
- Modify: `application/company_app.html` — add state functions, replace STATE section

- [ ] **Step 1: Replace the global STATE variables**

Find the `// ══ STATE` section (line ~644):
```js
let emp=null, currentPath='/company/', selectedFiles=new Set();
let usbInserted=false, usbFiles=[], browserHistory=[];
let emails=[...INBOX_TEMPLATES.map((e,i)=>({...e,id:i,unread:i<4,folder:'inbox',date:new Date(Date.now()-i*3600000*2).toLocaleTimeString('en-GB',{hour:'2-digit',minute:'2-digit'})}))];
let sentEmails=[], currentFolder='inbox';
let pollInt=null;
```

Replace with:
```js
let emp=null, currentPath='/home/', selectedFiles=new Set();
let currentFolder='inbox';
let pollInt=null;
```

- [ ] **Step 2: Add state management functions — insert after the EMPLOYEES array (after line ~515)**

Insert the following block right after the `];` that closes `EMPLOYEES`:

```js
// ══════════════════════════════════════════════════════
//  PER-USER STATE MANAGEMENT
// ══════════════════════════════════════════════════════
function _stateKey(uid){return 'nc_state_'+uid;}

function buildInitialState(e){
  const deptFS=DEPT_FS_TEMPLATES[e.dept]||DEPT_FS_TEMPLATES.General;
  const filesystem={};
  Object.keys(deptFS).forEach(path=>{
    filesystem[path]=deptFS[path].map(f=>({...f}));
  });
  const deptMails=DEPT_EMAIL_TEMPLATES[e.dept]||[];
  const allTemplates=[...SHARED_EMAILS,...deptMails];
  const emails=allTemplates.map((m,i)=>({
    ...m,id:i,unread:i<(deptMails.length+2),folder:'inbox',
    date:new Date(Date.now()-i*3600000*2).toLocaleTimeString('en-GB',{hour:'2-digit',minute:'2-digit'})
  }));
  return {filesystem,emails,usbInserted:false,usbFiles:[],browserHistory:[],downloadedFiles:[]};
}

function loadUserState(e){
  try{
    const raw=localStorage.getItem(_stateKey(e.id));
    if(raw){
      const s=JSON.parse(raw);
      currentFS=s.filesystem||{};
      currentEmails=s.emails||[];
      currentUSBInserted=s.usbInserted||false;
      currentUSBFiles=s.usbFiles||[];
      currentBrowserHistory=s.browserHistory||[];
      return;
    }
  }catch(err){}
  // First login — seed from template
  const s=buildInitialState(e);
  currentFS=s.filesystem;
  currentEmails=s.emails;
  currentUSBInserted=s.usbInserted;
  currentUSBFiles=s.usbFiles;
  currentBrowserHistory=s.browserHistory;
  saveUserState();
}

function saveUserState(){
  if(!emp)return;
  try{
    localStorage.setItem(_stateKey(emp.id),JSON.stringify({
      filesystem:currentFS,
      emails:currentEmails,
      usbInserted:currentUSBInserted,
      usbFiles:currentUSBFiles,
      browserHistory:currentBrowserHistory,
      downloadedFiles:[]
    }));
  }catch(err){}
}
```

- [ ] **Step 3: Update `showApp()` to load user state**

Find `showApp()` function. Find the line `renderFiles(); renderEmailList(); browserHome();` and add `loadUserState(emp);` before it:
```js
  loadUserState(emp);
  renderFiles(); renderEmailList(); browserHome();
```

Also update the login event's initial path. Find:
```js
  if(pollInt)clearInterval(pollInt);
  pollInt=setInterval(()=>pollRisk(emp.id),5000);
  pollRisk(emp.id);
```
After that block, ensure `currentPath='/home/';` is set:
```js
  currentPath='/home/';
  if(pollInt)clearInterval(pollInt);
  pollInt=setInterval(()=>pollRisk(emp.id),5000);
  pollRisk(emp.id);
```

- [ ] **Step 4: Update `doLogout()` to save and clear state**

Find `doLogout()`:
```js
function doLogout(){
  sessionStorage.removeItem('nc_user');emp=null;
  if(pollInt){clearInterval(pollInt);pollInt=null;}
  document.getElementById('app').style.display='none';
  document.getElementById('loginPage').style.display='flex';
}
```
Replace with:
```js
function doLogout(){
  saveUserState();
  sessionStorage.removeItem('nc_user');emp=null;
  currentFS={};currentEmails=[];currentUSBInserted=false;currentUSBFiles=[];currentBrowserHistory=[];
  currentPath='/home/';currentFolder='inbox';
  if(pollInt){clearInterval(pollInt);pollInt=null;}
  document.getElementById('app').style.display='none';
  document.getElementById('loginPage').style.display='flex';
}
```

- [ ] **Step 5: Commit**

```bash
git add application/company_app.html
git commit -m "feat: per-user state management with localStorage isolation"
```

---

## Task 5: Wire State Into All Mutating Functions (company_app.html)

**Files:**
- Modify: `application/company_app.html` — update functions to use `currentFS`, `currentEmails`, etc.

- [ ] **Step 1: Update file manager to use `currentFS`**

Replace every occurrence of `FS[` with `currentFS[` (4 occurrences: in `renderFiles`, `fileNav`, `buildUSBFileSelect`, `updateUSBSize`, `doUSBTransfer`).

Specifically:
- `renderFiles()` line: `const entries=FS[currentPath]||[]` → `const entries=currentFS[currentPath]||[]`
- `fileNav()` line: after navigating, at end of function add `saveUserState();`
- `buildUSBFileSelect()` line: `const allFiles=Object.values(FS).flat()` → `const allFiles=Object.values(currentFS).flat()`
- `updateUSBSize()` line: `const allFiles=Object.values(FS).flat()` → `const allFiles=Object.values(currentFS).flat()`
- `doUSBTransfer()` line: `const allFiles=Object.values(FS).flat()` → `const allFiles=Object.values(currentFS).flat()`

- [ ] **Step 2: Update email functions to use `currentEmails` and save state**

Replace every `emails=` assignment and `emails.` reference with `currentEmails`:

In `renderEmailList()`:
- `const toShow=emails.filter(...)` → `const toShow=currentEmails.filter(...)`

In `readEmail()`:
- `emails=emails.map(em=>em.id===e.id?{...em,unread:false}:em);` → `currentEmails=currentEmails.map(em=>em.id===e.id?{...em,unread:false}:em); saveUserState();`

In `sendEmail()`:
- `emails.unshift({id:Date.now(),...})` → `currentEmails.unshift({id:Date.now(),...}); saveUserState();`

In `showApp()`:
- `const unread=emails.filter(...)` → `const unread=currentEmails.filter(...)`

- [ ] **Step 3: Update USB functions to use `currentUSBInserted`**

In `insertUSB()`:
- `usbInserted=true;` → `currentUSBInserted=true; saveUserState();`

In `ejectUSB()`:
- `usbInserted=false;` → `currentUSBInserted=false; saveUserState();`

In `saveToUSB()` (in file manager):
- `if(!usbInserted)` → `if(!currentUSBInserted)`

In `doUSBTransfer()`: after `toast(...)` add `saveUserState();`

- [ ] **Step 4: Update browser history to use `currentBrowserHistory` and save**

In `visitSite()`:
- `browserHistory.push(bm.domain);` → `currentBrowserHistory.push(bm.domain); saveUserState();`

In `navigateTo()`:
- `browserHistory.push(url);` → `currentBrowserHistory.push(url); saveUserState();`

In `browserBack()`:
- `if(browserHistory.length>1)` → `if(currentBrowserHistory.length>1)`
- `browserHistory.pop()` → `currentBrowserHistory.pop()`
- `const prev=browserHistory[browserHistory.length-1]` → `const prev=currentBrowserHistory[currentBrowserHistory.length-1]`

- [ ] **Step 5: Commit**

```bash
git add application/company_app.html
git commit -m "feat: wire per-user state into all mutating functions"
```

---

## Task 6: Download Button + `downloadFiles()` Function (company_app.html)

**Files:**
- Modify: `application/company_app.html` — add download button to HTML and JS function

- [ ] **Step 1: Add Download button to file actions bar in HTML**

Find the file actions bar HTML (contains `id="fileActions"`):
```html
<div id="fileActions" style="display:none;...">
```
Inside it, after the existing buttons (Open, Copy, USB), add:
```html
<button class="btn btn-ghost" onclick="downloadFiles()">⬇️ Download</button>
```

- [ ] **Step 2: Add `downloadFiles()` JS function**

After the `deleteFiles()` function, add:
```js
function downloadFiles(){
  const files=[...selectedFiles];
  if(!files.length)return;
  files.forEach(f=>{
    if(f.type==='folder')return;
    const url=apiBase()+'/api/files/download?name='+encodeURIComponent(f.name)+'&dept='+encodeURIComponent(emp.dept);
    const a=document.createElement('a');
    a.href=url;
    a.download=f.name;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    // Fire telemetry
    fireEvent({source:'file',file_path:currentPath+f.name,operation:'download',file_count:1,data_mb:f.mb||0,destination:'external'},'Downloaded: '+f.name);
  });
  toast('Download started',files.length+' file(s) downloading','success');
  selectedFiles.clear();renderFiles();
}
```

- [ ] **Step 3: Commit**

```bash
git add application/company_app.html
git commit -m "feat: add file download button with real Flask-generated content"
```

---

## Task 7: Remove Activity Log Sidebar (company_app.html)

**Files:**
- Modify: `application/company_app.html` — remove sidebar HTML, CSS, and `addActivity()` call

- [ ] **Step 1: Remove the activity sidebar HTML**

Find and delete the activity sidebar div (lines ~416–424):
```html
    <!-- Activity sidebar -->
    <div class="activity-sidebar">
      <div class="as-hdr">Activity Log</div>
      <div class="as-list" id="asList">
        <div style="padding:14px;text-align:center;color:var(--text-muted);font-size:11px;line-height:1.6">
          Your activity is<br>recorded here
        </div>
      </div>
    </div>
```

- [ ] **Step 2: Remove `addActivity()` call from `fireEvent()`**

Find in `fireEvent()`:
```js
  addActivity(label, extra.source||'event');
```
Delete that line.

- [ ] **Step 3: Remove `.activity-sidebar` CSS**

Find and delete the CSS block for `.activity-sidebar`, `.as-hdr`, `.as-list`, `.as-item`, `.as-ev`, `.as-dot`, `.as-time` from the `<style>` section.

- [ ] **Step 4: Remove `addActivity()` function**

Find and delete the entire `addActivity` function (lines ~1077–1086):
```js
function addActivity(label,type){
  const list=document.getElementById('asList');
  ...
}
```

- [ ] **Step 5: Commit**

```bash
git add application/company_app.html
git commit -m "feat: remove activity log sidebar from company portal (InsightGuard-only)"
```

---

## Task 8: Update CLAUDE.md

**Files:**
- Modify: `CLAUDE.md`

- [ ] **Step 1: Update the Key Files section and Data Flow**

Add to `## Key Files`:
```
storage/role_config.json         Per-role UEBA threshold configuration
docs/superpowers/specs/          Design specs
docs/superpowers/plans/          Implementation plans
```

Update `## Novel Contributions` to note the ETL fix:
```
Note: Web events set risky_web from category field (tor/cloud_storage/file_sharing).
```

Add a new section:
```markdown
## Company Portal — Per-User State
Each employee has isolated state stored in localStorage under `nc_state_<user_id>`.
State includes: filesystem (dept-specific), emails (dept + shared), USB, browser history.
State persists across logins. First login seeds from `DEPT_FS_TEMPLATES[dept]`.
File downloads hit `GET /api/files/download?name=<n>&dept=<d>` which generates
realistic content (CSV with proper columns for salary/payroll files, etc.).
```

- [ ] **Step 2: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: update CLAUDE.md with per-user state and download endpoint"
```

---

## Self-Review Checklist

- [x] **ETL bug fixed:** `risky_web` now reads from `category` field — Tor/cloud/file_sharing visits will flag
- [x] **Threshold tuning:** `bulk_download` 500→200 MB, `usb_exfil` 100→50 MB, `risky_web` 10→20 weight
- [x] **Download endpoint:** `/api/files/download` generates realistic content, `Content-Disposition` header set
- [x] **Per-dept filesystems:** 9 departments, each with sensitive + normal files, personal folder
- [x] **Per-dept emails:** 2–3 role-specific emails + shared company announcements per user
- [x] **State isolation:** `loadUserState`/`saveUserState` backed by localStorage, cleared on logout
- [x] **All FS references updated:** `FS[` → `currentFS[` in 5 places
- [x] **All email references updated:** `emails` → `currentEmails` in 4 functions
- [x] **USB/browser state updated:** `usbInserted` → `currentUSBInserted`, `browserHistory` → `currentBrowserHistory`
- [x] **Download button:** HTML button + `downloadFiles()` function triggers both real download and telemetry
- [x] **Activity sidebar removed:** HTML div, CSS, `addActivity()` call, and function all deleted
- [x] **CLAUDE.md updated**
- [x] **No TBD or placeholders** — all code blocks are complete
- [x] **Type consistency** — `currentFS`, `currentEmails`, `currentUSBInserted`, `currentUSBFiles`, `currentBrowserHistory` used consistently across all tasks
