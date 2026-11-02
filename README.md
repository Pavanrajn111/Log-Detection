# Sysmon Sentinel • Local Endpoint Monitoring Dashboard

**Sysmon Sentinel** is a lightweight, real-time local endpoint security monitoring dashboard built with **Python 3.11 + Flask + HTML5 + CSS3 + Vanilla JavaScript**.

It monitors and visualizes Windows telemetry directly from:
`Applications and Services Logs → Microsoft → Windows → Sysmon → Operational`

---

## Key Features

- **Automated Collector Noise Filtering:** Silently drops internal polling loops (`wevtutil.exe`, `conhost.exe`, `sc.exe`, and collector scripts) to prevent metric and feed flooding.
- **Full Sysmon Event Ingestion:**
  - **Event ID 1:** Process Creation (clean binary extraction, PID, full command line, parent process hierarchy, integrity level)
  - **Event ID 3:** Network Connections (inbound/outbound destination IP, port, hostname, protocol)
  - **Event ID 7:** Image Loaded (DLLs, drivers, digital signature verification)
  - **Event ID 11:** File Creations (target file extraction, disk write activity, path resolution)
  - **Event ID 12 / 13 / 14:** Registry Key & Value Activity (SetValue, DeleteValue, persistence detection)
  - **Event ID 22:** DNS Queries (queried hostnames, resolution IP results, status codes)
- **Real-Time Interactive UI:**
  - Temporal event activity timeline (pure SVG, zero external chart dependencies)
  - Category breakdown stacked progress distribution
  - Instant client-side search across processes, paths, IPs, domains, and command lines
  - Severity and Event ID pill filters
  - Detailed Event Inspector Modal with Process & Parent Hierarchy trees, parsed cryptographic hashes (`SHA256`, `MD5`, `IMPHASH`) with 1-click copy buttons, structured event attributes, and formatted raw XML.
- **Graceful Permission Handling & Fallback:**
  - Displays troubleshooting instructions when run in a standard shell.
  - Automatically loads labeled `[DEMO FALLBACK]` data if elevated access is restricted, ensuring uninterrupted presentations.

---

## Quickstart

### 1. Requirements
- Windows 10 / 11 / Windows Server
- [Microsoft Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) installed and running
- Python 3.11+
- Flask

```powershell
pip install Flask
```

### 2. Run Application

For real live Sysmon events, start your terminal as Administrator:
1. Open PowerShell or Command Prompt with **"Run as administrator"**.
2. Run:

```powershell
python app.py
```

3. Open your browser:
```text
http://127.0.0.1:5000
```

---

## Project Structure

```text
SysmonDashboard/
├── app.py                  # Flask backend, XML parser, noise suppression & JSON API
├── templates/
│   └── index.html          # Dark security UI, SVG timeline, filter engine & modal inspector
├── .gitignore              # Standard git exclusion rules
└── README.md               # Documentation and setup guide
```
