# Nexon Endpoint Agent — Setup Guide

Real Windows endpoint monitoring agent that sends live activity to InsightGuard.

---

## What It Does

| Monitor | What Is Tracked |
|---------|-----------------|
| **Login** | Fires a login event the moment the agent starts |
| **File System** | Every file created, modified, moved, or deleted in Documents / Desktop / Downloads — with filename and size |
| **USB Devices** | Insertion and removal of USB drives; every file copied to USB (filenames + total MB) |
| **Browser History** | Every URL visited in Chrome, Edge, or Firefox; blocked/suspicious sites are flagged immediately |

All events appear instantly in the InsightGuard dashboard via the real-time SSE stream.

---

## Requirements

- **Python 3.10 or later** on the Windows laptop  
  Download: https://www.python.org/downloads/  
  During install, **tick "Add Python to PATH"**

- **Network access** — both machines must be on the same Wi-Fi / LAN  
  (InsightGuard machine and employee laptop)

---

## Step 1 — Find the InsightGuard Server IP

On the **InsightGuard machine**, open a terminal and run:

```
ipconfig
```

Look for the IPv4 address under your active network adapter — something like `192.168.1.42`.

InsightGuard already listens on `0.0.0.0:5000` so it accepts connections from any machine on the LAN.

Verify it is reachable from the employee laptop by opening a browser and going to:

```
http://192.168.1.42:5000/healthz
```

You should see `{"status": "ok"}`.

---

## Step 2 — Copy the Agent to the Employee Laptop

Copy the entire `nexon_agent/` folder to the Windows laptop. USB drive or shared folder both work.

Suggested location:

```
C:\NexonAgent\
```

---

## Step 3 — Run Setup

Open **Command Prompt** (Win + R → `cmd` → Enter) and navigate to the agent folder:

```cmd
cd C:\NexonAgent
setup.bat
```

This will:
1. Create a Python virtual environment
2. Install all dependencies (`requests`, `watchdog`, `psutil`, `pywin32`)

---

## Step 4 — Configure the Agent

Open `config.json` in Notepad and fill in the details for this employee:

```json
{
    "server_url": "http://192.168.1.42:5000",
    "user_id": "EMP042",
    "name": "Sarah Connor",
    "department": "Finance",
    "role": "Financial Analyst",
    "device_id": "NEXON-LAPTOP-FIN-01",
    ...
}
```

**Key fields to change:**

| Field | What to put |
|-------|-------------|
| `server_url` | IP address of the InsightGuard machine (Step 1) |
| `user_id` | Employee ID — must match an ID in the InsightGuard employee list |
| `name` | Employee's full name |
| `department` | One of: Engineering, Finance, HR, IT, Sales, Marketing, Legal, Executive, Operations |
| `role` | Job title (e.g. Financial Analyst, SysAdmin, Software Engineer) |
| `device_id` | Any unique identifier for this laptop |

**Blocked sites** are listed in the `blocked_sites` array. Add or remove domains as needed. When an employee visits one of these, the agent sends a `blocked: true` web event and the dashboard flags it immediately.

---

## Step 5 — Start the Agent

```cmd
start_agent.bat
```

Or double-click `start_agent.bat` in Explorer.

You will see a live terminal with colour-coded output:

```
  User ID:    EMP042
  Name:       Sarah Connor
  Department: Finance
  Server:     http://192.168.1.42:5000

[LOGIN]          Login event queued for EMP042
[FILE MONITOR]   Watching C:\Users\sarah\Documents
[FILE MONITOR]   Watching C:\Users\sarah\Desktop
[FILE MONITOR]   Watching C:\Users\sarah\Downloads
[USB MONITOR]    Started (polling every 5s)
[BROWSER MONITOR] Started (polling every 10s)
[READY]          All monitors active. Events streaming to http://192.168.1.42:5000

[08:42:01] [SENT] auth_system → score 12.4
[08:42:15] [WEB] outlook.com — webmail
[08:43:02] [FILE] WRITE Salary_Data_2025.xlsx (4.20 MB)
[08:43:45] [BLOCKED] mega.nz — cloud_storage
[08:44:10] [USB] Inserted: E:
[08:44:30] [USB TRANSFER] 3 file(s) → E: (12.40 MB)
```

Press **Ctrl+C** to stop the agent.

---

## Monitored Paths

By default the agent watches:

- `%USERPROFILE%\Documents`
- `%USERPROFILE%\Desktop`
- `%USERPROFILE%\Downloads`

To add more paths, edit `monitor_paths` in `config.json`.

---

## Browser Support

| Browser | History Location |
|---------|-----------------|
| Chrome | `%LOCALAPPDATA%\Google\Chrome\User Data\Default\History` |
| Microsoft Edge | `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\History` |
| Firefox | `%APPDATA%\Mozilla\Firefox\Profiles\*.default\places.sqlite` |

The agent copies the history database to read it (browsers lock the file while running).

---

## Troubleshooting

**"Cannot reach InsightGuard"**  
→ Check firewall on the InsightGuard machine: allow inbound TCP port 5000  
→ On Windows: `netsh advfirewall firewall add rule name="InsightGuard" dir=in action=allow protocol=TCP localport=5000`

**"Python not found"**  
→ Reinstall Python from python.org, tick "Add to PATH"  
→ Then restart Command Prompt and re-run setup.bat

**Browser history not appearing**  
→ Make sure at least one supported browser is installed (Chrome, Edge, or Firefox)  
→ The agent polls every 10 seconds — wait a moment after browsing

**File events not appearing**  
→ Check the `monitor_paths` in config.json exist on this machine  
→ `%USERPROFILE%\Documents` expands to something like `C:\Users\YourName\Documents`

**USB not detected**  
→ `pywin32` must be installed correctly — re-run `setup.bat`  
→ The agent polls USB drives every 5 seconds

---

## Auto-Start on Windows Login (Optional)

To make the agent start automatically when the employee logs in:

1. Press **Win + R**, type `shell:startup`, press Enter
2. Create a shortcut to `start_agent.bat` in that folder
3. The agent will now start silently every time Windows starts

To run it minimised (background):  
Create the shortcut, right-click → Properties → Run: **Minimised**
