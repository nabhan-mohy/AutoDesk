# AutoDesk IT Health Monitor

AutoDesk IT Health Monitor is a lightweight, read-only Windows-focused workstation health dashboard for dealership, showroom, billing, and service-advisor environments. It checks the PC, network, and printers in one place, surfaces clear recommendations, and exports evidence in CSV, JSON, and HTML formats for support tickets or escalation.

The app is designed to answer a simple operational question:

"Is this workstation ready for daily business use?"

It does this without performing destructive remediation. It never clears queues, restarts services, or prints test pages automatically. It reports what it observed, what it expected, and what the technician should do next.

Version: 1.0.0

---

## Why this project is useful

In dealership environments, downtime is expensive and often hidden until it affects a customer-facing workflow. A workstation can look fine on the surface while still failing in one of these ways:

- CPU or memory is under pressure but not critical enough to be obvious
- The PC has no active IPv4 address, an APIPA address, or a broken default gateway
- Internal business services (DMS, SQL, app server, file server) are unreachable even though internet access works
- Printers are installed but offline, misconfigured, or queued with stuck jobs
- DNS is slow or broken even though the workstation appears online
- A technician needs evidence for a support ticket before escalating to IT or networking

AutoDesk is built to reduce that ambiguity. It helps a technician confirm:

- whether the workstation is healthy
- which layer is failing: system, network, or printer
- whether the issue is confirmed, warning-level, or inconclusive
- which recommendation to apply next
- what evidence was gathered for the record

---

## What it checks

### System checks

- Computer hostname and current username
- Windows version and architecture
- CPU utilization percentage
- RAM utilization percentage
- Total, used, and free disk space for each available drive
- System uptime
- Timestamp of the latest health check
- PASS / WARNING / FAIL classification using thresholds from config

### Network checks

- Active network interfaces and assigned IPv4 addresses
- Default gateway detection and gateway reachability
- DNS server configuration
- DNS resolution of configured test hostnames
- Internet reachability to configurable external endpoints
- TCP connectivity checks to configured internal business services and ports
- Ping-based host checks for optional target hosts
- Safe timeout handling so one network failure does not crash the entire scan

### Printer checks

- Installed printers via Windows interfaces
- Default printer detection
- Printer status and status messages
- Windows Print Spooler service state
- Available queues and pending jobs where permissions allow
- Optional reachability tests for configured network printers
- Status reporting that distinguishes between a driver/service signal and actual physical print evidence

### Automated assessment

- Run full health check from one button
- Run system-only, network-only, or printer-only checks
- Progress updates while checks run
- Summary cards for PASS, WARNING, FAIL, INFO
- Filterable and searchable detailed results
- Recommendations for each issue
- Refresh or rerun controls

### Reporting and evidence

- CSV report
- JSON report
- HTML report
- Local reports folder generation under the project
- Includes check name, category, status, observed value, expected condition, timestamp, and recommendation
- Includes hostname and app version
- Avoids storing passwords, tokens, or unrelated personal information

### Configuration and customization

- Configurable thresholds for CPU, RAM, and disk
- DNS test hostnames
- Gateway and service connectivity checks
- Business application hostnames and port numbers
- Network printer hosts and ports
- Timeout values
- Safe defaults for all options

### User experience

- Dark glassmorphism Streamlit dashboard
- Professional clean enterprise visuals
- Modern sidebar controls
- Searchable, filterable diagnostic tables
- Download buttons for reports
- Clear readiness summary and next actions

---

## Project architecture

```text
AutoDesk/
├── app.py                     # Streamlit dashboard UI
├── config.json                # Default configuration and thresholds
├── requirements.txt           # Python dependencies
├── README.md                  # Project documentation
├── pytest.ini                 # Test configuration
├── src/
│   ├── __init__.py
│   ├── check_model.py         # Result model, status helpers, safe conversion
│   ├── config_loader.py       # Config loading/validation/defaults
│   ├── system_checks.py       # CPU, memory, disks, uptime, identity
│   ├── network_checks.py      # Gateways, DNS, HTTP/TCP checks, ping
│   ├── printer_checks.py      # Printer enumeration and spooler checks
│   ├── health_engine.py       # Orchestrates check runners and readiness summary
│   └── reporting.py           # CSV/JSON/HTML export generation
├── reports/                   # Local generated reports (created as needed)
├── tests/
│   ├── test_health_engine.py
│   ├── test_network_checks.py
│   ├── test_reporting.py
│   └── test_config_loader.py
└── .gitignore
```

---

## How it works

The app loads configuration from `config.json`, validates it, and runs a set of checks grouped into categories:

- System
- Network
- Printer

Each check returns a structured result object built from the shared model in `src/check_model.py`. Each result includes:

- name
- category
- status
- observed value
- expected condition
- recommendation
- timestamp
- optional details

The health engine catches exceptions so that a single failing or unsupported diagnostic does not crash the entire scan. It aggregates results into a readiness verdict:

- PASS = ready
- WARNING = ready with issues
- FAIL = not ready

This keeps the user experience safe and stable even when one environment or device is partially unavailable.

---

## Safety and reliability principles

This project is intentionally conservative and read-only.

- No arbitrary commands are executed from UI input
- All subprocess calls use argument lists and timeouts
- Internet reachability does not automatically imply internal business services are reachable
- Printer service state is never treated as proof that physical printing works
- Unsupported or restricted system APIs are handled gracefully
- One failed check does not halt the full health scan
- Reports remain local on the device

---

## Installation

### Prerequisites

- Python 3.10+ recommended
- Windows 11 is the primary target environment
- No administrator privileges are required for normal checks
- If using a Linux/macOS environment, printer checks may gracefully report unsupported behavior

### Create a virtual environment

PowerShell:

```powershell
cd AutoDesk
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Command Prompt:

```cmd
cd AutoDesk
python -m venv .venv
.venv\Scripts\activate.bat
```

### Install dependencies

```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

---

## How to run the app

From the project root:

```powershell
streamlit run app.py
```

Or:

```powershell
python -m streamlit run app.py
```

Then open the local URL shown by Streamlit, usually:

```text
http://localhost:8501
```

---

## How to use it

### Standard workflow

1. Launch the app.
2. Review the dashboard header and configuration warnings.
3. Click "Run Full Health Check".
4. Watch live progress.
5. Review summary cards and recommended next actions.
6. Use the search/filter controls to inspect detailed results.
7. Download CSV, JSON, or HTML evidence reports.

### Individual checks

From the sidebar, you can run:

- Full health check
- System checks only
- Network checks only
- Printer checks only
- Refresh / rerun last scan scope

### Report generation

Reports are saved to the local `reports/` folder when a scan runs. The app also exposes in-browser download buttons.

---

## Configuration guide

The configuration is in `config.json`.

### Example structure

```json
{
  "app_name": "AutoDesk IT Health Monitor",
  "version": "1.0.0",
  "thresholds": {
    "cpu_warning_percent": 75.0,
    "cpu_fail_percent": 95.0,
    "memory_warning_percent": 80.0,
    "memory_fail_percent": 95.0,
    "disk_warning_percent": 85.0,
    "disk_fail_percent": 95.0,
    "disk_min_free_gb_warning": 10.0,
    "uptime_minimum_hours": 0.0
  },
  "timeouts": {
    "tcp_connect_seconds": 3.0,
    "ping_seconds": 2.0,
    "dns_resolve_seconds": 4.0,
    "subprocess_seconds": 10.0,
    "http_check_seconds": 6.0
  },
  "network": {
    "internet_test_urls": [
      "https://www.google.com",
      "https://www.microsoft.com"
    ],
    "dns_test_hostnames": [
      "www.google.com",
      "microsoft.com"
    ],
    "ping_hosts": [],
    "business_services": []
  },
  "printers": {
    "network_printers": [],
    "max_jobs_listed_per_queue": 20
  }
}
```

### What to customize

- Increase or decrease warning/fail thresholds for CPU, memory, and disk
- Add internal service hostnames and ports to confirm business app connectivity
- Add DNS test hosts relevant to your environment
- Add printer IPs/hostnames for network printer reachability checks
- Tune timeouts if your environment is slower or more constrained

### Important notes

- The tool avoids hardcoding dealership-specific internal infrastructure
- The configuration is intentionally safe and template-friendly
- Invalid config values fall back to safe defaults and report a visible warning

---

## Running tests

Run unit tests with:

```powershell
python -m pytest -q
```

This project includes tests for:

- health engine summary logic
- network gateway classification logic
- report generation
- config validation and defaulting
- crash safety behavior

---

## Commands summary

### Setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

### Run app

```powershell
streamlit run app.py
```

### Run tests

```powershell
python -m pytest -q
```

### Clear reports folder

```powershell
Remove-Item -Recurse -Force .\reports\*
```

---

## Example of a typical issue result

A DNS resolution failure might show:

- Status: FAIL or WARNING depending on evidence strength
- Observed: “Resolution failed after 0.08s: Name or service not known”
- Expected: “hostname resolves within timeout”
- Recommendation: “Try ipconfig /flushdns, verify DNS servers, and check whether the issue is only internal name resolution.”

A printer issue may show:

- Status: WARNING
- Observed: “'Printer A' is marked OFFLINE by Windows”
- Expected: “Idle / Printing (device reachable and ready)”
- Recommendation: “Verify power and network, then send a Windows test page only after confirming the device status.”

---

## What makes this project different

Unlike a basic availability script, AutoDesk is designed as a technician-facing decision-support tool that:

- explains why something is warning or failing
- distinguishes confirmed failure from inconclusive evidence
- keeps actions read-only and safe
- provides exportable evidence for IT or support teams
- is easy to configure without writing code

---

## Roadmap and future extension ideas

This repo is a strong foundation for additional capabilities such as:

- DHCP and IP configuration analysis
- Windows Event Log review
- performance bottleneck analysis
- historical scan storage and comparison
- incident summary and ticket-ready output
- PDF report generation
- asset inventory tracking
- rule-based root-cause analysis
- offline local AI explanation assistant
- centralized multi-workstation dashboard

These enhancements can build on the current architecture without changing the core read-only diagnostic model.

---

## License

This project is distributed as a local internal diagnostic tool intended for authorized IT and support use. It is not a substitute for formal enterprise monitoring or vendor-specific support tooling.

---

## Final note

AutoDesk IT Health Monitor is most useful when run directly on a workstation that needs to be assessed quickly and confidently. It is designed to reduce guesswork, avoid destructive actions, and provide actionable evidence for support operations in a dealership environment.

Use it as a local health and troubleshooting companion for:

- showroom PCs
- billing workstations
- service advisor systems
- office computers
- network-connected printer checks
- connection validation for internal business services

If you are operating in a dealership or retail IT environment, this dashboard gives you a fast, repeatable way to verify workstation readiness without needing to write scripts or manually gather evidence from multiple system tools.
