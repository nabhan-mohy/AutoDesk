"""Printer diagnostics for Windows (with graceful non-Windows fallback).

Strategy:
1. Preferred: WMI via PowerShell `Get-PrintQueue` / `Get-CimInstance`
   (Win32_Printer) - works on Windows 10/11 without extra Python packages.
2. Fallback: `wmic printer get ...` on older systems.
3. If neither is available (non-Windows or missing utilities), return an INFO
   result explaining the limitation - never crash.

Safety: read-only. This module NEVER clears queues, restarts services, or
prints test pages. Service state of the Print Spooler and network reachability
are reported as *indirect* evidence only; we never claim a printer can
physically print from those signals alone.
"""
from __future__ import annotations

import json
import os
import subprocess

from .check_model import (
    CheckResult,
    FAIL,
    INFO,
    PASS,
    WARNING,
    error_result,
    make_result,
    safe_float,
)
from .network_checks import tcp_probe, ping_host

CATEGORY = "Printer"

# Win32_Printer PrinterStatus codes (MS documentation)
STATUS_MAP = {
    1: "Other", 2: "Unknown", 3: "Idle", 4: "Printing", 5: "Warmup",
    6: "Stopped Printing", 7: "Offline", 8: "Not Available",
}

# Per-key defaults mirror config_loader.DEFAULT_CONFIG["timeouts"].
# Bounds (0.001 .. 120 s) mirror the range validation in
# config_loader.validate_config so a hand-edited config can never
# produce a nonsensical timeout (0, negative, or huge).
_TIMEOUT_DEFAULTS: dict[str, float] = {
    "tcp_connect_seconds": 3.0,
    "ping_seconds": 2.0,
    "dns_resolve_seconds": 4.0,
    "subprocess_seconds": 10.0,
    "http_check_seconds": 6.0,
}

def cfg_timeout(cfg: dict, key: str) -> float:
    """Return a validated timeout from ``cfg['timeouts'][key]``.

    Falls back to the built-in default for that key, then clamps to the
    same sane bounds used by ``config_loader.validate_config``. Never
    raises - a malformed value degrades to the default rather than
    crashing the check that requested it.
    """
    default = _TIMEOUT_DEFAULTS.get(key, 3.0)
    raw = (cfg.get("timeouts", {}) or {}).get(key, default)
    return safe_float(raw, default, 0.001, 120.0)


def _is_windows() -> bool:
    return os.name == "nt"


def _run(cmd: list[str], timeout: float) -> tuple[int, str, str]:
    res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return res.returncode, res.stdout or "", res.stderr or ""


_PS_GET_PRINTERS = r'''
$ErrorActionPreference='SilentlyContinue'
$r = Get-CimInstance -ClassName Win32_Printer | Select-Object Name, Default, PrinterStatus, StatusInfo, WorkOffline, Shared, PortName, ServerName, DriverName | ConvertTo-Json -Compress
Write-Output $r
'''

_PS_SPOOLER = r'''
$ErrorActionPreference='SilentlyContinue'
$s = Get-Service -Name Spooler | Select-Object Name, Status, StartType | ConvertTo-Json -Compress
Write-Output $s
'''

_PS_QUEUE_JOBS = r'''
$ErrorActionPreference='SilentlyContinue'
$q = Get-PrintQueue | Select-Object Name, JobCount, PrinterStatus, QueuePrintProcessor | ConvertTo-Json -Compress
Write-Output $q
'''


def _normalize_records(data) -> list[dict]:
    """ConvertTo-Json returns a single object when there's one item."""
    if data is None:
        return []
    if isinstance(data, dict):
        return [data]
    if isinstance(data, list):
        return [d for d in data if isinstance(d, dict)]
    return []


def _query_printers(timeout: float) -> tuple[list[dict], str]:
    """Return (printer_records, method_used). Raises OSError if nothing works."""
    if not _is_windows():
        raise OSError("Printer enumeration via WMI requires Windows")
    last_err = ""
    # 1) PowerShell + CIM
    try:
        rc, out, err = _run(["powershell", "-NoProfile", "-NonInteractive",
                             "-Command", _PS_GET_PRINTERS], timeout)
        out = out.strip()
        if rc == 0 and out:
            try:
                return _normalize_records(json.loads(out)), "PowerShell Get-CimInstance Win32_Printer"
            except json.JSONDecodeError:
                last_err = "PowerShell returned unparsable output"
        else:
            last_err = (err or out or f"exit code {rc}").strip()[:200]
    except FileNotFoundError:
        last_err = "PowerShell not found"
    except subprocess.SubprocessError as exc:
        last_err = f"PowerShell timed out/failed: {exc}"
    # 2) wmic fallback
    try:
        rc, out, err = _run(["wmic", "printer", "get",
                             "Name,Default,PrinterStatus,WorkOffline,PortName,ServerName",
                             "/format:csv"], timeout)
        if rc == 0 and out.strip():
            printers = []
            lines = [ln for ln in out.strip().splitlines() if ln.strip()]
            if len(lines) > 1:
                header = lines[0].split(",")[1:]  # skip Node column
                for ln in lines[1:]:
                    parts = ln.split(",")[1:]
                    rec = dict(zip(header, parts))
                    printers.append({
                        "Name": rec.get("Name", ""),
                        "Default": (rec.get("Default", "").lower() == "true"),
                        "PrinterStatus": int(rec.get("PrinterStatus", 2) or 2),
                        "WorkOffline": rec.get("WorkOffline", ""),
                        "PortName": rec.get("PortName", ""),
                        "ServerName": rec.get("ServerName", ""),
                    })
            return printers, "wmic printer"
        last_err += f"; wmic failed: {(err or out).strip()[:120]}"
    except (FileNotFoundError, subprocess.SubprocessError) as exc:
        last_err += f"; wmic unavailable: {exc}"
    raise OSError(last_err or "No supported printer query interface available")


def check_installed_printers(cfg: dict) -> list[CheckResult]:
    results: list[CheckResult] = []
    # Bound the job-listing threshold defensively (issue #2): invalid values
    # fall back to the default and are clamped to a sane range.
    max_jobs = int(safe_float(cfg["printers"].get("max_jobs_listed_per_queue", 20), 20, 1, 10000))
    try:
        printers, method = _query_printers(cfg_timeout(cfg, "subprocess_seconds"))
    except OSError as exc:
        return [make_result(
            name="Installed printers", category=CATEGORY, status=INFO,
            observed=f"Cannot enumerate printers here: {exc}",
            expected="Windows with PowerShell or wmic available",
            recommendation=("Printer diagnostics require Windows. On Windows, ensure "
                            "PowerShell (CIM) or wmic.exe is available and the Spooler service runs."),
        )]
    except Exception as exc:
        return [error_result("Installed printers", CATEGORY, exc)]

    if not printers:
        return [make_result(
            name="Installed printers", category=CATEGORY, status=WARNING,
            observed="No printers are installed on this workstation",
            expected="At least one printer configured for billing/showroom use",
            recommendation="Install the required printer via Settings > Bluetooth & devices > Printers & scanners.",
        )]

    names = [p.get("Name", "?") for p in printers]
    results.append(make_result(
        name="Installed printers", category=CATEGORY, status=INFO,
        observed=f"{len(printers)} printer(s): " + ", ".join(names[:10]),
        expected="Informational", details={"method": method},
    ))

    defaults = [p for p in printers if p.get("Default")]
    if defaults:
        results.append(make_result(
            name="Default printer", category=CATEGORY, status=PASS,
            observed=", ".join(p.get("Name", "?") for p in defaults),
            expected="Exactly one default printer",
        ))
    else:
        results.append(make_result(
            name="Default printer", category=CATEGORY, status=WARNING,
            observed="No default printer set",
            expected="A default printer should be configured",
            recommendation="Set the correct default in Settings > Printers & scanners (billing PCs must default to the invoice printer).",
        ))

    for p in printers:
        name = p.get("Name", "?")
        code = p.get("PrinterStatus", 2)
        try:
            code = int(code)
        except (TypeError, ValueError):
            code = 2
        status_name = STATUS_MAP.get(code, f"Code {code}")
        offline_flag = str(p.get("WorkOffline", "")).lower() in ("true", "1")
        # IMPORTANT: Win32_Printer status codes are device-reported hints that
        # Windows updates lazily; 'Offline' can also mean the OS simply has no
        # recent conversation with the device (sleeping MFD, USB re-plug,
        # pending driver handshake). We therefore NEVER assert a confirmed
        # hardware outage from these codes alone - worst case is WARNING with
        # verification steps. A FAIL would require corroborated evidence such
        # as a failed network probe, which is reported separately.
        if offline_flag or code == 7:
            st, rec = WARNING, (f"'{name}' is marked OFFLINE/not available by Windows. This is "
                                "device-reported and can be stale - verify power, cable/Wi-Fi and "
                                "the printer's own network page, then send one test document from "
                                "Windows to confirm before treating it as down.")
        elif code in (6,):
            st, rec = WARNING, (f"'{name}' is 'Stopped Printing'. Look for errors on the device panel "
                                "(paper jam, low toner, open cover) and check the queue below.")
        elif code in (2,):
            st, rec = WARNING, (f"'{name}' status is Unknown. Open its queue in Windows to verify it accepts jobs.")
        else:
            st, rec = PASS, ""
        results.append(make_result(
            name=f"Printer status: {name}", category=CATEGORY, status=st,
            observed=f"Win32_Printer status: {status_name}" + (" (WorkOffline=true)" if offline_flag else ""),
            expected="Idle / Printing (device reachable and ready)",
            recommendation=rec,
            details={"status_code": code, "port": p.get("PortName", ""),
                     "server": p.get("ServerName", ""),
                     "note": ("Device-reported OS status only - ambiguous by nature. Physical "
                              "printing was NOT tested and an 'offline' flag does not prove a "
                              "hardware failure.")},
        ))

    # Queues & pending jobs (best-effort, separate failure domain)
    try:
        queues = _query_queues(cfg_timeout(cfg, "subprocess_seconds"))
        for q in queues:
            qname = q.get("Name", "?")
            jobs = q.get("JobCount")
            if jobs is None:
                continue
            jobs = int(jobs)
            if jobs > max_jobs:
                st, rec = WARNING, (f"{jobs} pending jobs on '{qname}'. Check the first job's error "
                                    "state; ask users to cancel stale documents. (This tool will not "
                                    "clear the queue automatically.)")
            elif jobs > 0:
                st, rec = INFO, "Jobs are queued; verify they complete within a few minutes."
            else:
                st, rec = PASS, ""
            results.append(make_result(
                name=f"Queue: {qname}", category=CATEGORY, status=st,
                observed=f"{jobs} pending job(s)", expected="Queue normally empty",
                recommendation=rec, details={"job_count": jobs},
            ))
    except Exception as exc:
        results.append(make_result(
            name="Printer queues", category=CATEGORY, status=INFO,
            observed=f"Queue/job counts unavailable: {exc}",
            expected="Get-PrintQueue accessible",
            recommendation="Queues can still be inspected manually in Windows Print Management.",
        ))
    return results


def _query_queues(timeout: float) -> list[dict]:
    if not _is_windows():
        raise OSError("requires Windows")
    rc, out, err = _run(["powershell", "-NoProfile", "-NonInteractive",
                         "-Command", _PS_QUEUE_JOBS], timeout)
    out = out.strip()
    if rc != 0 or not out:
        raise OSError((err or f"exit {rc}").strip()[:160] or "no output")
    try:
        return _normalize_records(json.loads(out))
    except json.JSONDecodeError as exc:
        raise OSError(f"unparsable queue output ({exc})")


def check_spooler_service(cfg: dict) -> list[CheckResult]:
    if not _is_windows():
        return [make_result(
            name="Print Spooler service", category=CATEGORY, status=INFO,
            observed="Not applicable outside Windows",
            expected="Windows host", recommendation="Run this tool on the dealership's Windows PCs.")]
    try:
        rc, out, err = _run(["powershell", "-NoProfile", "-NonInteractive",
                             "-Command", _PS_SPOOLER], cfg_timeout(cfg, "subprocess_seconds"))
        out = out.strip()
        if rc != 0 or not out:
            # fallback: sc query (read-only)
            rc2, out2, _ = _run(["sc", "query", "Spooler"], cfg_timeout(cfg, "subprocess_seconds"))
            if "RUNNING" in (out2 or "").upper():
                return [make_result(name="Print Spooler service", category=CATEGORY, status=PASS,
                                    observed="Running (via 'sc query')", expected="Spooler running")]
            return [make_result(
                name="Print Spooler service", category=CATEGORY, status=WARNING,
                observed=f"Could not determine spooler state: {(err or out2 or '').strip()[:150]}",
                expected="Spooler service Running",
                recommendation="Open services.msc and check 'Print Spooler'. (This tool does not restart services automatically.)")]
        try:
            data = json.loads(out)
        except json.JSONDecodeError as exc:
            return [make_result(
                name="Print Spooler service", category=CATEGORY, status=WARNING,
                observed=f"Spooler query returned unparsable output: {exc}; raw: {out[:120]!r}",
                expected="PowerShell Get-Service returns JSON",
                recommendation="Open services.msc and check 'Print Spooler' manually. "
                               "(This tool does not restart services automatically.)")]
        if isinstance(data, list):  # defensive: unexpected multi-object output
            data = data[0] if data and isinstance(data[0], dict) else {}
        if not isinstance(data, dict):
            data = {}
        status = str(data.get("Status", "")).lower()
        # PowerShell renders ControlSet services as 'Running'; accept numeric
        # CIM state codes (1 = Stopped ... 4 = Running) too so a running
        # spooler is never misread as stopped.
        if status in ("running", "4"):
            return [make_result(name="Print Spooler service", category=CATEGORY, status=PASS,
                                observed=f"Status={data.get('Status')}, StartType={data.get('StartType')}",
                                expected="Spooler Running (Automatic)")]
        return [make_result(
            name="Print Spooler service", category=CATEGORY, status=FAIL,
            observed=f"Spooler status: {data.get('Status')}",
            expected="Spooler Running",
            recommendation=("The Print Spooler is not running, so no printing can occur. A technician "
                            "can start it via services.msc (Spooler > Start) once policy allows. This "
                            "tool intentionally does not restart services."),
        )]
    except Exception as exc:
        return [error_result("Print Spooler service", CATEGORY, exc)]


def check_network_printers(cfg: dict, prior_results: list[CheckResult] | None = None
                           ) -> list[CheckResult]:
    """Optional reachability tests for configured network printers.

    Evidence layers kept distinct:
      - device-reported status  -> 'Printer status:' results (WARNING max)
      - spooler service state   -> 'Print Spooler service' result
      - queue state             -> 'Queue:' results
      - network reachability    -> this function
    A printer that answers neither ping nor TCP is most often sleeping or
    filtering ICMP/raw ports, so we report WARNING unless the whole local
    network is also failing (corroborated evidence), in which case FAIL.
    """
    results: list[CheckResult] = []
    printers = [p for p in cfg["printers"].get("network_printers", [])
                if isinstance(p, dict) and p.get("enabled") and str(p.get("host", "")).strip()]
    if not printers:
        return [make_result(
            name="Network printer reachability", category=CATEGORY, status=INFO,
            observed="No network printers configured",
            expected="Configure printer IPs under printers.network_printers to enable tests",
            recommendation="Add showroom/service-advisor printer IPs in config.json for reachability checks.",
        )]
    tcp_to = cfg_timeout(cfg, "tcp_connect_seconds")
    ping_to = cfg_timeout(cfg, "ping_seconds")
    # Corroboration: if the workstation's own network path is broken (no active
    # interface, or every gateway probe failed), unreachable printers are part
    # of a wider confirmed failure rather than individual device issues.
    local_net_broken = any(
        r.status == FAIL and (r.name == "Network interfaces"
                              or r.name.startswith("Gateway reachability"))
        for r in (prior_results or []))
    for prn in printers:
        host = str(prn["host"]).strip()
        name = str(prn.get("name") or host)
        try:
            # Defensive parse (issue #2): invalid ports fall back to 9100.
            port = int(safe_float(prn.get("raw_port", 9100), 9100, 1, 65535))
        except (TypeError, ValueError):
            port = 9100
        ok_tcp, tcp_info, _lat = tcp_probe(host, port, tcp_to)
        ok_ping, avg, ping_info = ping_host(host, ping_to)
        if ok_tcp:
            st = PASS
            obs = f"TCP:{port} open ({tcp_info}); ping {'OK' if ok_ping else 'blocked/unreachable'}"
            rec = ""
        elif ok_ping:
            st = WARNING
            obs = f"Ping OK (avg {avg} ms) but TCP:{port} failed ({tcp_info})"
            rec = (f"'{name}' responds to ping but the raw printing port {port} is closed. Verify the "
                   "printer uses port 9100/JetDirect or configure the correct port; the device may also "
                   "need a reboot by authorized staff.")
        elif local_net_broken:
            st = FAIL
            obs = f"Unreachable: ping failed ({ping_info}); TCP:{port} failed ({tcp_info})"
            rec = (f"'{name}' at {host} is unreachable AND the workstation's own network checks are "
                   "failing, so this is likely part of a wider connectivity outage. Fix the PC's "
                   "network connection first, then re-test the printer.")
        else:
            # No corroboration: many printers sleep deeply or block ICMP and
            # non-standard raw ports. Do NOT assert an outage from probes alone.
            st = WARNING
            obs = f"Not confirmed reachable: ping failed ({ping_info}); TCP:{port} failed ({tcp_info})"
            rec = (f"'{name}' at {host} answered neither ping nor TCP:{port}. This is inconclusive: "
                   "the device may be asleep, filter ICMP, or use a different print port. Check its "
                   "control-panel network page and print a configuration page before treating it as down. "
                   "Note: even when reachable, this does not prove the device can physically print.")
        results.append(make_result(
            name=f"Network printer: {name} ({host})", category=CATEGORY, status=st,
            observed=obs, expected="Printer IP reachable (ping and/or raw port 9100)",
            recommendation=rec,
            details={"host": host, "port": port, "ping_ok": ok_ping, "tcp_ok": ok_tcp,
                     "avg_ms": avg, "evidence": "probes only; no physical print test performed"},
        ))
    return results


def run_printer_checks(cfg: dict) -> list[CheckResult]:
    results: list[CheckResult] = []
    for fn in (check_installed_printers, check_spooler_service, check_network_printers):
        try:
            if fn is check_network_printers:
                results.extend(fn(cfg, prior_results=results))
            else:
                results.extend(fn(cfg))
        except Exception as exc:
            results.append(error_result(fn.__name__, CATEGORY, exc))
    return results
