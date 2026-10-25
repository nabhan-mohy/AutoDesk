# AutoDesk IT Health Monitor

**Version 1.0.0** — An automated PC, network, and printer readiness checker for automotive dealership IT environments.

---

## 1. Project Overview & Dealership Use Case

Showroom PCs, billing workstations, and service-advisor systems must be ready *before* customers and staff depend on them. When something breaks — a printer offline, the DMS server unreachable, DNS failing after a DHCP renewal — the IT Support Executive needs fast, evidence-based answers instead of guesswork.

**AutoDesk IT Health Monitor** runs every diagnostic with one button and produces:

- A clear **READY / READY WITH ISSUES / NOT READY** workstation verdict,
- PASS / WARNING / FAIL results with the observed value, expected condition, and a plain-language **recommendation** for each issue,
- Timestamped **CSV, JSON, and HTML reports** saved locally for ticketing and escalation.

The tool is **read-only**: it never clears print queues, restarts services, prints test pages, or performs any remediation. It also never claims a printer can physically print based only on service status or network reachability.

### Typical workflow

1. Technician opens the dashboard on the affected PC (`streamlit run app.py`).
2. Clicks **Run Full Health Check** (~5–20 seconds).
3. Reviews summary cards and the filterable results table.
4. Exports the CSV/HTML report and attaches it to the support ticket.

---

## 2. Features & Technology Stack

### Features

| Area | What is checked |
|---|---|
| **System** | Hostname, username, OS version/build, architecture, CPU %, RAM %, per-drive disk space, uptime, check timestamp |
| **Network** | Active interfaces + IPv4 addresses, default gateway discovery & reachability (ping + TCP fallback probes), DNS servers, DNS resolution of configured hostnames, internet endpoints (HTTP HEAD), TCP tests to configured internal business services (DMS, SQL, document servers), optional ping hosts |
| **Printer** | Installed printers via Windows APIs (WMI/PowerShell `Get-PrintQueue`), default printer, queue status & status messages, pending job counts, Print Spooler service state, optional reachability tests for configured network printers (TCP:9100 raw port + ICMP) |
| **Assessment** | Single-button full run with live progress and elapsed time, individual category runs, refresh/rerun, searchable + filterable results tables, per-issue recommendations |
| **Reporting** | Timestamped CSV + JSON + HTML in `reports/`, plus in-browser download buttons; hostname and app version embedded in every row |
| **Configuration** | All thresholds, endpoints, ports, printer addresses, and timeouts live in `config.json` — nothing dealership-specific is hardcoded |

### Technology stack

- **Python 3.12+**
- **Streamlit** — local web dashboard
- **psutil** — CPU/RAM/disk/uptime/interfaces/routes
- **Standard library** — `socket`, `subprocess`, `urllib`, `dns` (optional dnspython), `csv`, `json`, `ipaddress`
- **Windows-native commands** used where appropriate: `ping`, `route print`, `ipconfig /all`, PowerShell `Get-Printer` / `Get-PrintQueue` / `Get-Service`
- **pytest** — unit tests with all hardware/network dependencies mocked

No Docker, no cloud, no paid APIs, no database. Everything runs and stays on the local machine.

---

## 3. Architecture & Project Structure

```
autodesk-it-health-monitor/
├── app.py                    # Streamlit UI: buttons, progress, tables, downloads
├── config.json               # Thresholds, endpoints, printers, timeouts
├── requirements.txt
├── pytest.ini
├── .gitignore                # excludes reports/, __pycache__, venv, etc.
├── README.md
├── src/
│   ├── __init__.py
│   ├── check_model.py        # CheckResult dataclass, PASS/WARNING/FAIL/INFO, classify_percent()
│   ├── config_loader.py      # load + validate + merge-with-defaults for config.json
│   ├── system_checks.py      # identity, CPU, RAM, disks, uptime
│   ├── network_checks.py     # interfaces, gateway, DNS, internet, TCP services, ping
│   ├── printer_checks.py     # WMI/PowerShell enumeration, spooler, queues, network printers
│   ├── health_engine.py      # orchestrates categories, catches crashes, builds report dict
│   └── reporting.py          # CSV / JSON / HTML writers + byte exporters for downloads
├── reports/                  # generated evidence files (gitignored contents)
│   └── .gitkeep
└── tests/
    ├── test_health_engine.py   # summarization, thresholds, crash isolation, progress cb
    ├── test_network_checks.py  # gateway classification rules (all probes mocked)
    ├── test_reporting.py       # CSV/JSON/HTML structure and content
    └── test_config_loader.py   # defaults merging, validation, bad-config handling
```

**Design principles**

- Every check returns a list of `CheckResult`; an exception inside any check is converted into a FAIL result (`error_result`) so **one broken diagnostic can never crash the run**.
- The health engine runs categories independently and records total duration.
- Status semantics are deliberately conservative (see §8 Gateway classification).
- Subprocesses always use argument lists (no shell strings), timeouts, and captured output — nothing from the UI is ever executed as a command.

---

## 4. Installation & Launch

### Prerequisites

- Windows 11 (primary target) — Linux/macOS also run, with printer checks gracefully reporting "not applicable".
- Python 3.12+ with `pip`. **No administrator privileges required.**

### Setup (PowerShell)

```powershell
cd autodesk-it-health-monitor
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

### Launch the dashboard

```powershell
python -m streamlit run app.py
```

Open the URL printed in the terminal — normally **http://localhost:8501**.

### Run the tests

```powershell
python -m pytest -q
```

Expected output: `58 passed` (the authoritative current count — rerun the suite to confirm after any change).

---

## 5. Configuration (`config.json`)

Edit `config.json` in any text editor, save, then click **Reload config** in the sidebar (or restart Streamlit). Invalid values fall back to safe defaults with a visible warning.

### Resource thresholds (percent)

```json
"thresholds": {
  "cpu_warning_percent": 75.0,      "cpu_fail_percent": 95.0,
  "memory_warning_percent": 80.0,   "memory_fail_percent": 95.0,
  "disk_warning_percent": 85.0,     "disk_fail_percent": 95.0,
  "disk_min_free_gb_warning": 10.0
}
```

### Timeouts (seconds) — keep checks from hanging

```json
"timeouts": {
  "tcp_connect_seconds": 3.0, "ping_seconds": 2.0,
  "dns_resolve_seconds": 4.0, "subprocess_seconds": 10.0,
  "http_check_seconds": 6.0
}
```

### Network endpoints

```json
"network": {
  "internet_test_urls": ["https://www.google.com", "https://www.microsoft.com"],
  "dns_test_hostnames": ["www.google.com", "microsoft.com", "update.microsoft.com"],
  "ping_hosts": [],
  "business_services": [
    { "name": "DMS SQL Server", "host": "dms-sql.yourdomain.local",
      "port": 1433, "enabled": true }
  ]
}
```

- Add one entry per **internal** line-of-business service you need tested (DMS app server, SQL instance, document server, license server…). Internet reachability does **not** imply internal services are reachable — that is exactly why these TCP tests exist.
- `ping_hosts`: e.g. file server or domain controller hostnames/IPs. Failed pings produce WARNING (many servers block ICMP), not FAIL.
- **Do not commit your dealership's real internal IPs to a shared repository** — `config.json` is included here as a template with placeholders disabled by default.

### Network printers

```json
"printers": {
  "network_printers": [
    { "name": "Showroom HP LaserJet", "host": "192.168.10.50",
      "enabled": true, "raw_port": 9100 }
  ],
  "max_jobs_listed_per_queue": 20
}
```

Set `enabled: true` and fill `host` (IP or hostname) to activate reachability tests (TCP 9100 raw printing port + ICMP). Results are labelled *reachable/unreachable*, never "can print".

### Configuration validation rules and acceptable bounds

`src/config_loader.py::validate_config()` checks every user-tunable surface on load; each problem is shown as an explicit warning in the sidebar (malformed entries are never silently ignored), and out-of-range values are additionally clamped at use time so a bad config cannot produce nonsense PASS/FAIL classifications.

| Setting | Rule / accepted range |
|---|---|
| `cpu/memory/disk_warning_percent` | number, **1–99** |
| `cpu/memory/disk_fail_percent` | number, **1–100** |
| warning vs fail thresholds | per resource, `warning <= fail` (inverted pairs rejected) |
| `disk_min_free_gb_warning` | number, **0–1,000,000** GB |
| `uptime_minimum_hours` | number, **0–87,600** (one year) |
| `timeouts.*` | every key must be a number, **0.001–120 s**; booleans/strings rejected explicitly |
| `internet_test_urls[i]` | non-empty, must start with `http://` or `https://` |
| `dns_test_hostnames[i]` / `ping_hosts[i]` | valid hostname or IPv4 literal |
| `business_services[i]` | object with valid host (required when enabled) and numeric port **1–65535**; invalid entries reported by name/index |
| `network_printers[i]` | **every entry validated, enabled or not**: valid host/IP required when enabled, invalid host always flagged, `raw_port` validated whenever present (**1–65535**, defaults to 9100 at probe time); non-object entries reported as malformed |
| `max_jobs_listed_per_queue` | integer **1–10,000** |
| Section types | `thresholds`, `network`, `printers` etc. must be objects; lists must be lists |
| Corrupt `config.json` | falls back to full defaults with a visible error instead of crashing |

---

## 6. Running Diagnostics & Exporting Reports

- **Run Full Health Check** — executes System → Network → Printer with a live progress bar and elapsed-time readout.
- **Individual sections** — tick only System / Network / Printer to run a subset.
- **Refresh / Rerun** — the sidebar reruns the last selection; results update in place.
- **Results tables** — searchable by check name and filterable by status/category; every WARNING/FAIL row shows its recommendation under **Recommended next actions**.
- **Reports** — each run auto-writes to `reports/health_<hostname>_<YYYYMMDD_HHMMSS>.{csv,json,html}`. Download buttons for all three formats appear below the results.
  - **CSV** — columns: check_name, category, status, observed_value, expected_condition, recommendation, timestamp, hostname, app_version (Excel-ready).
  - **JSON** — full structured report including per-check `details` dicts.
  - **HTML** — self-contained styled page suitable for emailing the IT team.

Reports contain only diagnostic data (hostnames, IP addresses of configured devices, utilization numbers). **No passwords, tokens, or personal documents are collected.**

---

## 7. Troubleshooting Common Errors

| Symptom | Cause / Fix |
|---|---|
| `streamlit` not recognized | Use `python -m streamlit run app.py`; ensure the venv is activated and `pip install -r requirements.txt` succeeded. |
| Port 8501 already in use | Another Streamlit instance is running. Close it or run `python -m streamlit run app.py --server.port 8502`. |
| Dashboard loads but printer section says "WMI requires Windows" | Expected on non-Windows hosts. On Windows 11, verify the **Print Spooler** service is running (`services.msc`). |
| "Printer enumeration denied / access error" | Some locked-down GPOs restrict WMI for standard users. Run as the logged-in user (admin not normally needed); if it persists, note the message in the ticket — the tool intentionally does not retry with elevation. |
| Many network FAILs at once | Physical layer first: Ethernet cable / Wi-Fi, then `ipconfig` for a valid IPv4 address, then compare against the gateway result. |
| Gateway shows WARNING "inconclusive" | Router is likely blocking ICMP and no corroborating failure exists. This is *not* an outage — confirm with `tracert <gateway>` if suspicious. |
| Checks hang near timeout settings | Lower `timeouts.*` values in `config.json`; each probe is individually capped so a dead host cannot stall the whole run. |
| Config edit has no effect | Click **Reload config** in the sidebar; a JSON syntax error will be shown with the parser message and defaults restored. |
| Tests fail with import errors | Ensure you run `python -m pytest` from the project root (where `pytest.ini` lives). |

---

## 8. Security, Privacy & Status-Semantics Notes

- **Read-only diagnostics.** No remediation: queues are never cleared, services never restarted, test pages never printed.
- **Safe subprocess usage.** All external commands are fixed argument lists (`["ping","-n","2",host]`, PowerShell `Get-PrintQueue`, …) with timeouts; **arbitrary input from the UI is never executed**.
- **No admin rights required** for normal operation; permission-denied paths degrade gracefully to INFO/WARNING with explanations.
- **Local-only.** No telemetry, no uploads; all reports stay in `reports/` on the machine.
- **No credential collection**, no browsing history, no file contents.
- **No scanning beyond configured targets.** Only the gateway, explicitly listed hosts/services/printers are probed — no subnet sweeps, no arbitrary public IP ranges.
- **Gateway classification policy** (deliberate anti-false-positive design):
  - **PASS** — ping succeeds, or a TCP probe reaches the gateway despite blocked ICMP.
  - **WARNING** — gateway discovered heuristically, probes inconclusive, or other outbound TCP traffic succeeds (proving routing works while ICMP is filtered).
  - **FAIL** — reserved for sufficient evidence: authoritative default route **and** failed ICMP **and** failed direct TCP probes **and** no successful outbound TCP check anywhere in the same run.
  - A failed ping alone is **never** reported as a confirmed outage.

---

## 9. Unit Tests — How to Run & Actual Results

```powershell
python -m pytest -q            # quick summary
python -m pytest -v            # per-test detail
```

Tests mock psutil, sockets, ping/subprocess, WMI, and filesystem-dependent calls, so they require **no printer, no admin rights, and no internet connection**. Coverage includes: status classification and threshold boundaries, config validation/default merging, report generation (CSV/JSON/HTML structure), crash isolation (a raising check becomes FAIL without killing the run), progress-callback completion, missing printers, DNS failures, timeouts, permission errors, and all eight gateway classification rules.

**Actual result in the development environment (Python 3.12, Linux container):**

```
..........................................................               [100%]
58 passed in 0.35s
```

| Suite | Tests | Focus |
|---|---|---|
| `test_health_engine.py` | 8 | summarize/verdict, thresholds, crash isolation, progress |
| `test_network_checks.py` | 18 | gateway PASS/WARNING/FAIL evidence rules, internet endpoint false-outage rules, ping loss-parsing, invalid service port handling, crash isolation in the runner loop (mocked) |
| `test_printer_checks.py` | 11 | offline status => WARNING never FAIL, probe-only failure inconclusive, FAIL requires corroborated local outage, non-Windows graceful degradation |
| `test_config_loader.py` | 16 | defaults merging, threshold bounds (warn<=fail, explicit min/max per threshold), every printer host/port validated even when disabled, malformed entries, timeout bounds, corrupt-file handling |
| `test_reporting.py` | 5 | CSV rows, JSON schema, HTML content, filename safety, no credentials in output |

### Smoke test (GitHub Actions)

`.github/workflows/smoke.yml` runs on push/PR to `main`, weekly, and manually
(`workflow_dispatch`). It executes the **real** end-to-end pipeline headlessly —
`src.health_engine.run_full_check()` followed by
`src.reporting.write_reports(report, out_dir="reports/smoke")` (the actual
exported API; there is no `generate_reports` function) — and **fails the build
if any of the CSV/JSON/HTML report files is missing or empty**. It additionally
asserts the CSV header contains `check_name`/`recommendation` and that the JSON
payload carries hostname/version. A second step launches Streamlit headless and
requires an HTTP 200 from `http://localhost:8501/` before the job passes.
Generated reports are uploaded as workflow artifacts (`smoke-reports`) for
evidence.

The same pipeline was run locally in this environment and passed:

```
csv : reports/smoke/health_<host>_<timestamp>.csv  (~3.9 KB)
json: reports/smoke/health_<host>_<timestamp>.json (~8.0 KB)
html: reports/smoke/health_<host>_<timestamp>.html (~6.6 KB)
SMOKE OK: {'counts': {...}, 'overall': 'READY WITH ISSUES', 'total': 18}
```

An end-to-end smoke run of `run_full_check()` was also executed on this environment: the dashboard launched (HTTP 200 on :8501), all categories completed in ~1.3 s, and CSV/JSON/HTML reports were written successfully. Windows-printer code paths (WMI/PowerShell) are exercised only on Windows 11 hosts; elsewhere they return clear "not applicable" INFO results rather than crashing.

### Manual Windows 11 checklist (required before showroom rollout)

GitHub-hosted CI cannot validate live devices. On a representative Windows 11
workstation, run from PowerShell in the project directory:

```powershell
python -m pip install -r requirements.txt
python -m pytest -q          # expect: 58 passed
python -m streamlit run app.py
```

Then verify each item:

1. Dashboard loads at http://localhost:8501 with title, version and readiness banner.
2. **Run Full Health Check** completes with live progress and elapsed time.
3. System cards show real hostname, user, Windows build, CPU/RAM/disk/uptime.
4. Network section shows the actual adapter IPv4, discovered gateway, DNS servers, and per-endpoint results (individual endpoint failures appear as WARNING, not FAIL).
5. Printer section lists installed printers, the default printer, spooler state and queue jobs via PowerShell/CIM (`Get-PrintQueue`, `root\standardcimv2`).
6. Deliberately break one check (e.g., unplug network cable mid-scan) — the run must finish and explain the failure, not crash.
7. All three download buttons produce non-empty CSV/JSON/HTML files, and copies land in `reports/`.
8. Open the HTML report in Edge and confirm it renders.
9. Re-run after editing `config.json` and click **Reload config**; invalid values must surface as visible warnings.

---

## 10. Screenshots

Add real captures to `docs/screenshots/` and reference them here once deployed on a Windows 11 workstation:

1. `01_dashboard_top.png` — title, overall READY banner, system resource cards, last scan timestamp.
2. `02_run_progress.png` — progress bar during **Run Full Health Check** with elapsed time.
3. `03_network_results.png` — network table showing gateway/DNS/internet/TCP-service rows.
4. `04_printer_results.png` — installed printers, default printer, spooler state, queue jobs.
5. `05_reports_downloads.png` — CSV/JSON/HTML download buttons and `reports/` folder contents.
6. `06_html_report.png` — the exported HTML report opened in a browser.

*(Capture with Win+Shift+S after launching the app; keep screenshots free of real internal hostnames if publishing publicly.)*

---

## 11. Known Limitations & Future Improvements

**Limitations (by design)**
- Printer "status" reflects Windows spooler/queue metadata and network reachability — physical print capability cannot be verified without printing a page, which this tool refuses to do automatically.
- Some WMI/queue details require the current user's permissions; restricted environments yield partial INFO/WARNING results.
- Gateway and ICMP results are inherently heuristic on networks that filter ICMP (mitigated by the classification policy above).
- Single-workstation scope: no central server, fleet dashboard, or scheduled background runs yet.

**Future improvements**
- Scheduled automatic scans + desktop notification when a scan turns NOT READY.
- Historical trend charts (CPU/RAM/disk over time) persisted locally as SQLite/Parquet.
- Signed PDF report option and one-click copy-to-clipboard ticket summary.
- Optional agent/server mode for showroom-wide visibility.
- Additional adapters: antivirus service state, Windows Update pending-reboot detection, mapped-drive verification, badge-reader/TPM checks.

---

## License / Support

Internal tool for dealership IT support. Modify freely; keep reports on local machines per your data-handling policy.

## Continuous integration (GitHub Actions)

`.github/workflows/ci.yml` runs the full unit-test suite automatically on every
push/PR to `main`, across a matrix of **ubuntu-latest and windows-latest** runners
with Python **3.12 and 3.13**. All hardware, printer and network dependencies are
mocked in tests, so CI never needs real devices or internet access. The workflow
also verifies that `app.py` parses cleanly.

> Note: GitHub-hosted `windows-latest` runners provide PowerShell and the CIM
> cmdlets, so printer-enumeration code paths can be smoke-checked there via the
> mocked suites; the manual Windows 11 checklist below still applies for live
> device validation before rolling out to showroom PCs.

## Status classification rules (how FAIL/WARNING are decided)

The tool is deliberately conservative about claiming outages:

### Internet endpoints vs. the overall connectivity verdict

Each configured `internet_test_urls` entry is probed independently, and the two
levels of result mean different things:

- **Individual endpoint rows are never FAIL.** An endpoint that does not answer
  is recorded as **WARNING** with a recommendation explaining the likely benign
  causes (site down, HEAD request blocked, proxy/captive-portal filtering). A
  single dead website must never make a workstation NOT READY.
- **The authoritative verdict lives in one summary row** ("Internet
  connectivity"), computed from corroborated evidence across *all* endpoints
  plus other outbound checks:
  - At least one endpoint succeeds → summary PASS; failed endpoints stay WARNING.
  - All endpoints fail but gateway/TCP probes elsewhere succeeded → summary
    **WARNING** (HTTP egress filtering or captive portal — not a proven outage).
  - All endpoints fail **and** no other outbound traffic succeeded **and** the
    default gateway itself was confirmed dead → summary **FAIL** (confirmed
    internet outage). This is the only way an internet FAIL can be produced.

### Gateway evidence

| Situation | Status | Why |
|---|---|---|
| Gateway ping succeeds (or TCP probe reaches it) | PASS | Direct proof of reachability |
| Gateway discovered heuristically, probes inconclusive, or ICMP blocked while other traffic works | WARNING | A failed ping alone is never treated as an outage; a gateway found via config/route table is not necessarily reachable |
| Authoritative default route + all gateway probes fail + every other outbound TCP check also fails | FAIL | Corroborated evidence of a real connectivity failure |

### Printer evidence layers

Four separate evidence layers are kept distinct, and no single layer is ever
used to claim the device cannot physically print:

1. **Device-reported status** (Windows CIM/`Get-PrintQueue` printer status and
   status messages) — ambiguous and often stale, so capped at **WARNING**;
   "Offline"/"Not Available"/"Unknown" never produces FAIL on its own.
2. **Spooler service state** (Windows Print Spooler) — a locally verifiable
   fact; stopped spooler is a definitive **FAIL**.
3. **Queue/job state** (queued/error/paused jobs per queue) — reported as
   INFO/WARNING; job counts prove nothing about hardware health.
4. **Network reachability** (ICMP + TCP raw port for configured printers) —
   probes alone are **inconclusive**: a printer answering neither ping nor TCP
   is most often asleep or filtering probes, so it stays **WARNING** unless the
   workstation's own interface/gateway checks are simultaneously failing
   (corroborated wider outage), which is the only case escalated to **FAIL**.

| Situation | Status | Why |
|---|---|---|
| One internet endpoint down while another succeeds | WARNING (endpoint) + WARNING (summary) | Single site may be down/block HEAD/proxy-filtered; internet works |
| All endpoints fail but other outbound TCP succeeded earlier | WARNING | HTTP egress filtering or captive portal, not proven outage |
| All endpoints fail and nothing else got outbound | FAIL | Confirmed internet outage |
| Windows reports printer Offline/Not Available/Unknown | WARNING | Device-reported status is ambiguous/stale; never asserts hardware failure |
| Configured network printer answers neither ping nor TCP, PC network otherwise healthy | WARNING | Printer may be asleep or filtering probes - inconclusive |
| Network printer unreachable AND workstation interface/gateway checks also failing | FAIL | Part of a wider corroborated outage |
| Print Spooler service stopped | FAIL | Definitive, locally verifiable service failure |

No evidence layer alone is used to claim the device cannot physically print, and
the tool never clears queues, restarts services, or prints test pages.

