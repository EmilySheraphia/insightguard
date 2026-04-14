# Sub-project 3: Browser Intelligence — Design Spec

**Date:** 2026-04-14  
**Status:** Approved  
**Scope:** Windows agent enhancements — incognito detection, file upload detection (with filename), web email tracking, three new UEBA rules

---

## Overview

This sub-project adds real browser intelligence to the Nexon endpoint agent. A new `BrowserIntelligenceMonitor` class runs in its own thread, using two mechanisms:

1. **psutil** — detects incognito/private browser sessions by scanning process command-line args
2. **Chrome DevTools Protocol (CDP)** — connects to `localhost:9222` to capture file upload filenames and webmail page titles

All signals are emitted as standard events via the existing `_post_event()` function, flowing through the existing InsightGuard scoring pipeline unchanged. Three new `EXTRA_RULES` entries in `UEBAEngine` score these signals.

---

## Section 1 — Architecture

```
BrowserIntelligenceMonitor (new thread in nexon_agent/agent.py)
  ├── psutil poller (5s interval)
  │     └── scans Chrome/Edge/Firefox cmdline for incognito flags
  │           → fires "incognito_detected" event + sets _incognito_active flag
  │
  ├── CDP connection (localhost:9222)
  │     ├── Network.enable → requestWillBeSent → parse multipart filename
  │     │     → fires "file_upload" event with file_name + destination domain
  │     └── Target poller (5s) → title scan on webmail domains
  │           → fires "webmail_activity" event with provider + email subject
  │
  └── All events tagged with incognito: True/False via _incognito_active flag
```

**CDP prerequisite:** Chrome/Edge must be launched with `--remote-debugging-port=9222`. If the port is unavailable, the CDP components retry every 10s silently — psutil incognito detection continues to work regardless.

**New file:** None. `BrowserIntelligenceMonitor` is added to `nexon_agent/agent.py`.  
**New dependency:** `websockets` added to `nexon_agent/requirements.txt`.

---

## Section 2 — Incognito Detection

Every 5 seconds, the psutil poller scans all running processes:

| Browser | Process name | Flag |
|---------|-------------|------|
| Chrome | `chrome.exe` | `--incognito` |
| Edge | `msedge.exe` | `--inprivate` |
| Firefox | `firefox.exe` | `-private` or `--private-window` |

**On first detection:** fires `"incognito_detected"` event and sets `_incognito_active = True`.  
**On session end:** when flag is no longer present, sets `_incognito_active = False`.  
All events emitted by `BrowserIntelligenceMonitor` include `"incognito": <bool>` from this flag.

Event payload:
```python
{
    "source": "browser_intel",
    "activity_type": "incognito_detected",
    "browser": "chrome",          # chrome | edge | firefox
    "incognito": True,
    "user_id": ..., "timestamp": ..., "department": ..., "role": ...
}
```

---

## Section 3 — CDP File Upload Detection

**Connection:** HTTP GET `http://localhost:9222/json` → pick first target with `type == "page"` → open WebSocket. Send `{"id":1,"method":"Network.enable"}`. Reconnect on disconnect with 10s retry.

**Detection logic** on `Network.requestWillBeSent`:
1. Check `request.headers` for `Content-Type: multipart/form-data`
2. If present, scan `request.postData` for `Content-Disposition: form-data; name=...; filename="<name>"` using regex
3. Extract destination domain from request URL
4. Emit event

**Limitation:** Chrome truncates `postData` for large files. When truncated, `file_name` is `null` but the event still fires — `file_upload_cloud` UEBA rule triggers on destination domain.

Event payload:
```python
{
    "source": "browser_intel",
    "activity_type": "file_upload",
    "file_name": "Q1_salary_data.csv",   # null if postData truncated
    "destination": "drive.google.com",
    "incognito": True,
    "user_id": ..., "timestamp": ..., "department": ..., "role": ...
}
```

---

## Section 4 — Web Email Tracking

Every 5 seconds, poll `http://localhost:9222/json` for all open page targets. For each target with a matching webmail URL, extract and parse the page title.

**Supported providers:**

| Provider | Domain match | Title pattern | Subject extraction |
|----------|-------------|---------------|--------------------|
| Gmail | `mail.google.com` | `"Subject - user@gmail.com - Gmail"` | `split(" - ")[0]` |
| Outlook.com | `outlook.live.com`, `outlook.office.com` | `"Subject - Outlook"` | `split(" - ")[0]` |
| Yahoo Mail | `mail.yahoo.com` | `"Subject - Yahoo Mail"` | `split(" - ")[0]` |
| ProtonMail | `mail.proton.me` | `"Subject \| ProtonMail"` | `split(" | ")[0]` |

**Compose/send detection** via URL path:
- Gmail: `#compose` or `#sent`
- Outlook: `/mail/compose` or `/mail/sentitems`
- Others: `/compose`

**Deduplication:** event only fires when page title changes from last poll — prevents flooding when user sits on inbox.

Event payload:
```python
{
    "source": "browser_intel",
    "activity_type": "webmail_activity",
    "email_provider": "gmail",
    "page_title": "Q1 Financials - alice@nexon.com - Gmail",
    "email_subject": "Q1 Financials",
    "compose_detected": True,
    "incognito": False,
    "user_id": ..., "timestamp": ..., "department": ..., "role": ...
}
```

---

## Section 5 — UEBA Rules

Three new entries appended to `UEBAEngine.EXTRA_RULES` in `ai_analytics/anomaly_model.py`:

| Label | Weight | Trigger |
|-------|--------|---------|
| `incognito_session` | 20 | `extra.get("incognito") is True` |
| `file_upload_cloud` | 25 | `extra.get("activity_type") == "file_upload"` AND `extra.get("destination")` in `{"drive.google.com", "onedrive.live.com", "dropbox.com", "wetransfer.com", "mega.nz", "s3.amazonaws.com"}` |
| `webmail_outbound` | 15 | `extra.get("activity_type") == "webmail_activity"` AND `extra.get("compose_detected") is True` |

**Scoring example:** file upload to Google Drive, incognito, off-hours:
- `file_upload_cloud` (25) + `incognito_session` (20) + `off_hours_boost` (15) = 60 UEBA points → `high_risk` before IF/LOF contribute.

---

## Section 6 — Files & Integration

### Files Changed

| File | Change |
|------|--------|
| `nexon_agent/agent.py` | Add `BrowserIntelligenceMonitor` class; instantiate and `start()` in `main()` |
| `nexon_agent/requirements.txt` | Add `websockets` |
| `ai_analytics/anomaly_model.py` | Append 3 entries to `EXTRA_RULES` |
| `tests/test_all.py` | Add `test_browser_intelligence()` section (9 assertions) |

### Data Flow (No Server Changes)

```
Windows agent (nexon_agent/agent.py)
  BrowserIntelligenceMonitor
    → POST /api/events  {"source": "browser_intel", ...}
      → existing ETL pipeline (enrich_raw sets is_archive etc.)
      → FeatureEngineering.extractFeatures()
      → UEBAEngine.score(fv, extra=raw)
          └── new EXTRA_RULES: incognito_session, file_upload_cloud, webmail_outbound
      → PUB → PERS → CorrelationEngine → DB → SSE broadcast
```

### Tests (tests/test_all.py)

**`test_browser_intelligence()`** — 9 assertions:
- `incognito_session` rule fires when `extra["incognito"] is True`
- `incognito_session` rule does NOT fire when `extra["incognito"] is False`
- `file_upload_cloud` fires for `drive.google.com` destination
- `file_upload_cloud` fires for `dropbox.com` destination
- `file_upload_cloud` does NOT fire for `internal-sharepoint.nexon.com`
- `webmail_outbound` fires when `compose_detected is True`
- `webmail_outbound` does NOT fire when `compose_detected is False`
- `webmail_outbound` does NOT fire when `activity_type != "webmail_activity"`
- Combined: incognito + file_upload_cloud + off_hours_boost all trigger together

---

## Acceptance Criteria

- [ ] `BrowserIntelligenceMonitor` starts cleanly when Chrome debug port unavailable (no crash)
- [ ] Incognito detection fires on Chrome `--incognito`, Edge `--inprivate`, Firefox `-private`
- [ ] `_incognito_active` clears when no incognito process detected
- [ ] File upload events include `file_name` for small files, `null` for large
- [ ] Webmail events deduplicated — only fires on title change
- [ ] All 3 new UEBA rules produce non-zero contribution when triggered
- [ ] All 9 test assertions pass
- [ ] No regressions in existing test sections

---

## Out of Scope

- Modifying existing `BrowserMonitor` URL polling (unchanged)
- Server-side changes (no new routes, no DB schema changes)
- Firefox CDP support (Firefox uses a different remote debugging protocol)
- Capturing full email body or recipient list via CDP
- Persistence of incognito state across agent restarts
