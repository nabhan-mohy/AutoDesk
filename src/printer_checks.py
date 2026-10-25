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
)
from .network_checks import tcp_probe, ping_host

CATEGORY = "Printer"

# Win32_Printer PrinterStatus codes (MS documentation)
STATUS_MAP = {
    1: "Other", 2: "Unknown", 3: "Idle", 4: "Printing", 5: "Warmup",
    6: "Stopped Printing", 7: "Offline", 8: "Not Available",
}


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
    max_jobs = int(cfg["printers"].get("max_jobs_listed_per_queue", 20))
    try:
        printers, method = _query_printers(cfg["timeouts"]["subprocess_seconds"])
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
        if offline_flag or code == 7:
            st, rec = FAIL, (f"'{name}' reports OFFLINE/not available. Check power, cable/Wi-Fi, "
                             "and the printer's own network settings; reprint a document after it returns online.")
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
                     "server": p.get("ServerName", ""), "note": "Device readiness inferred from OS-reported status only; physical printing was NOT tested."},
        ))

    # Queues & pending jobs (best-effort, separate failure domain)
    try:
        queues = _query_queues(cfg["timeouts"]["subprocess_seconds"])
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
                             "-Command", _PS_SPOOLER], cfg["timeouts"]["subprocess_seconds"])
        out = out.strip()
        if rc != 0 or not out:
            # fallback: sc query (read-only)
            rc2, out2, _ = _run(["sc", "query", "Spooler"], cfg["timeouts"]["subprocess_seconds"])
            if "RUNNING" in (out2 or "").upper():
                return [make_result(name="Print Spooler service", category=CATEGORY, status=PASS,
                                    observed="Running (via 'sc query')", expected="Spooler running")]
            return [make_result(
                name="Print Spooler service", category=CATEGORY, status=WARNING,
                observed=f"Could not determine spooler state: {(err or out2 or '').strip()[:150]}",
                expected="Spooler service Running",
                recommendation="Open services.msc and check 'Print Spooler'. (This tool does not restart services automatically.)")]
        data = json.loads(out)
        status = str(data.get("Status", "")).lower()
        if status in ("running", "1"):
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


def check_network_printers(cfg: dict) -> list[CheckResult]:
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
    tcp_to = cfg["timeouts"]["tcp_connect_seconds"]
    ping_to = cfg["timeouts"]["ping_seconds"]
    for prn in printers:
        host = str(prn["host"]).strip()
        name = str(prn.get("name") or host)
        port = int(prn.get("raw_port", 9100))
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
        else:
            st = FAIL
            obs = f"Unreachable: ping failed ({ping_info}); TCP:{port} failed ({tcp_info})"
            rec = (f"'{name}' at {host} is unreachable. Check printer power/network cable/Wi-Fi, then "
                   "ask the network team whether the printer VLAN/ACL changed. Note: even when reachable, "
                   "this does not prove the device can physically print.")
        results.append(make_result(
            name=f"Network printer: {name} ({host})", category=CATEGORY, status=st,
            observed=obs, expected="Printer IP reachable (ping and/or raw port 9100)",
            recommendation=rec,
            details={"host": host, "port": port, "ping_ok": ok_ping, "tcp_ok": ok_tcp, "avg_ms": avg},
        ))
    return results


def run_printer_checks(cfg: dict) -> list[CheckResult]:
    results: list[CheckResult] = []
    for fn in (check_installed_printers, check_spooler_service, check_network_printers):
        try:
            results.extend(fn(cfg))
        except Exception as exc:
            results.append(error_result(fn.__name__, CATEGORY, exc))
    return results
