"""Windows workstation analysis: Event Log, services, processes, DHCP/IP
configuration, routes, proxy, VPN, mapped drives and asset inventory.

All queries are READ-ONLY through PowerShell CIM / native commands with
argument lists + timeouts. Nothing here requires administrator rights for the
System/Application event logs of a normal workstation; where an API is
unavailable (non-Windows host, locked-down policy) the check returns INFO /
WARNING 'unsupported' evidence instead of pretending or crashing.

No unnecessary personal data: event collection is bounded by a configurable
time window and level filter, and only Level/Source/EventID/Time/message
summary are kept (messages truncated).
"""
from __future__ import annotations

import json
import os
import platform
import re
import socket
import subprocess
import time

import psutil

from .check_model import (
    CheckResult, CONFIRMED, FAIL, INFO, INCONCLUSIVE, OBSERVATION, PASS,
    UNSUPPORTED, WARNING_LEVEL, WARNING, error_result, make_result, safe_float,
)

CATEGORY = "Windows Analysis"
ASSET_CATEGORY = "Asset"

# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _is_windows() -> bool:
    return os.name == "nt"


def _run_ps(script: str, timeout: float) -> tuple[int, str, str]:
    """Run a fixed PowerShell script (never user-supplied) and capture output."""
    return _run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                timeout)


def _run(cmd: list[str], timeout: float) -> tuple[int, str, str]:
    res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return res.returncode, res.stdout or "", res.stderr or ""


def _json_records(out: str) -> list[dict]:
    out = (out or "").strip()
    if not out:
        return []
    try:
        data = json.loads(out)
    except json.JSONDecodeError as exc:
        raise ValueError(f"unparsable PowerShell JSON ({exc}): {out[:120]!r}") from exc
    if isinstance(data, dict):
        return [data]
    if isinstance(data, list):
        return [d for d in data if isinstance(d, dict)]
    return []


def _subproc_timeout(cfg: dict) -> float:
    return safe_float(cfg.get("timeouts", {}).get("subprocess_seconds", 10), 10, 1, 120)


# Plain-language interpretations for the most common dealership-PC events.
_EVENT_HINTS = {
    6008: ("Unexpected shutdown", "The PC lost power or crashed without a clean shutdown. Ask the user what happened; check UPS/power strip."),
    41:   ("Unexpected restart (Kernel-Power)", "System rebooted without cleanly shutting down first - typical of hard resets or power loss."),
    1001: ("Bugcheck / Blue screen record", "Windows recorded a crash dump. Note the bugcheck code for driver/firmware escalation."),
    7000: ("Service failed to start", "A service could not start. Identify the service name in the message; verify its binary and dependencies."),
    7001: ("Service dependency failure", "A service's dependency failed, so it did not start either."),
    7031: ("Service terminated unexpectedly", "The service crashed. Note which service and whether it recurs."),
    7034: ("Service ended unexpectedly", "Last known good state was Running; the service process died. Correlate with application updates."),
    1000: ("Application crash (Application Error)", "An application crashed (note faulting module - often a bad DLL/driver)."),
    1002: ("Application hang", "An application stopped responding (hang). Correlate with high CPU/RAM rows."),
    1074: ("Planned restart/shutdown", "Normal initiated shutdown/restart - usually benign unless during business hours."),
    6013: ("System uptime info", "Informational uptime event."),
}


def interpret_event(source: str, event_id: int, message: str) -> str:
    """Plain-language interpretation for a Windows event (no raw XML dumping)."""
    hint = _EVENT_HINTS.get(event_id)
    if hint:
        return f"{hint[0]}: {hint[1]}"
    low = (message or "").lower()
    if "timeout" in low:
        return "A component timed out - often slow disk, network or an overloaded service."
    if "crash" in low or "fault" in low:
        return "Crash-related event; identify the faulting module in the full message via Event Viewer."
    if "failed" in low or "error" in low:
        return "Reported failure; open the event in Event Viewer for details and correlate with this scan."
    return "Review the event detail in Event Viewer (eventvwr.msc) and correlate with symptoms."


# --------------------------------------------------------------------------- #
# Event log analyzer
# --------------------------------------------------------------------------- #
_PS_EVENTS = r'''
$ErrorActionPreference='SilentlyContinue'
$since=(Get-Date).AddHours(-{hours})
$lv=@({levels})
$ev=Get-WinEvent -FilterHashtable=@{{LogName='{log}';StartTime=$since;Level=$lv}} -MaxEvents {max} |
  Select-Object LogName,ProviderName,Id,LevelDisplayName,TimeCreated,@{{n='Message';e={{($_.Message -replace '\s+',' ').Substring(0,[Math]::Min(220,$_.Message.Length))}}}} |
  ConvertTo-Json -Compress
Write-Output $ev
'''


def check_event_log(cfg: dict) -> list[CheckResult]:
    results: list[CheckResult] = []
    if not _is_windows():
        return [make_result(
            name="Windows Event Log analysis", category=CATEGORY, status=INFO,
            observed="Event log analysis requires Windows",
            expected="Windows host", evidence=UNSUPPORTED,
            recommendation="Run this tool on the dealership's Windows workstations.")]
    win = cfg.get("windows_analysis", {}) or {}
    hours = safe_float(win.get("eventlog_hours", 24), 24, 1, 720)
    max_events = int(safe_float(win.get("eventlog_max_events", 50), 50, 1, 200))
    levels_sql = ", ".join(str(int(x)) for x in (1, 2, 3))  # Critical, Error, Warning
    for logname in ("System", "Application"):
        script = _PS_EVENTS.format(hours=float(hours), levels=levels_sql,
                                   log=logname, max=max_events)
        try:
            rc, out, err = _run_ps(script, _subproc_timeout(cfg) + 5)
            records = _json_records(out) if rc == 0 or out.strip() else []
        except FileNotFoundError:
            results.append(make_result(
                name=f"Event Log ({logname})", category=CATEGORY, status=INFO,
                observed="PowerShell not available - cannot read event log",
                expected="Windows PowerShell present", evidence=UNSUPPORTED,
                recommendation="Open eventvwr.msc manually for this workstation."))
            continue
        except (ValueError, subprocess.SubprocessError, OSError) as exc:
            results.append(make_result(
                name=f"Event Log ({logname})", category=CATEGORY, status=WARNING,
                observed=f"Could not read event log: {str(exc)[:160]}",
                expected="Get-WinEvent accessible", evidence=INCONCLUSIVE,
                recommendation="Event log access may be restricted by policy; review eventvwr.msc manually."))
            continue
        criticals = [e for e in records if str(e.get("LevelDisplayName", "")).lower() == "critical"]
        errors = [e for e in records if str(e.get("LevelDisplayName", "")).lower() == "error"]
        warns = [e for e in records if str(e.get("LevelDisplayName", "")).lower() == "warning"]
        top = (criticals + errors)[:8]
        lines = []
        for e in top:
            eid = e.get("Id")
            src = e.get("ProviderName", "?")
            ts = str(e.get("TimeCreated", ""))[:19]
            msg = e.get("Message", "")
            lines.append(f"[{ts}] {src} ID {eid}: {msg}")
        summary_lines = "\n".join(lines) if lines else ""
        interp = []
        for e in top:
            h = interpret_event(e.get("ProviderName", ""), int(e.get("Id", 0) or 0),
                                e.get("Message", ""))
            interp.append(f"ID {e.get('Id')} ({e.get('ProviderName')}): {h}")
        st, ev_cls, rec = PASS, OBSERVATION, ""
        if criticals or errors:
            st = WARNING  # recent errors deserve attention but are not proof of today's outage
            ev_cls = WARNING_LEVEL
            rec = ("Recent Critical/Error events found. Open each in Event Viewer "
                   "(eventvwr.msc > Windows Logs) using the source and Event ID shown, "
                   "correlate timestamps with user-reported symptoms. This tool shows a "
                   "short interpretation but does not replace full event details.")
        elif warns:
            st, ev_cls = INFO, OBSERVATION
        results.append(make_result(
            name=f"Event Log ({logname}) last {hours:g}h", category=CATEGORY, status=st,
            observed=(f"{len(criticals)} critical / {len(errors)} error / {len(warns)} warning events. "
                      + (summary_lines.replace('\n', ' | ') if summary_lines else "No critical/error events.")),
            expected=f"No Critical/Error events in the last {hours:g} hours",
            recommendation=rec,
            evidence=ev_cls,
            details={"events": top[:20], "interpretations": interp,
                     "counts": {"critical": len(criticals), "error": len(errors),
                                "warning": len(warns)},
                     "window_hours": hours},
        ))
    return results


# --------------------------------------------------------------------------- #
# Services & processes
# --------------------------------------------------------------------------- #
# Business-relevant services checked WITHOUT admin rights (read-only query).
_KEY_SERVICES = {
    "Spooler": "Print Spooler - required for all local printing",
    "Dnscache": "DNS Client - local name resolution cache",
    "LanmanWorkstation": "Workstation - file share / network drive access",
    "Winmgmt": "Windows Management Instrumentation - monitoring & DMS agents",
    "wuauserv": "Windows Update",
    "BITS": "Background Intelligent Transfer (updates/DMS patches)",
}

_PS_SERVICES = r'''
$ErrorActionPreference='SilentlyContinue'
$s=Get-Service -Name {names} | Select-Object Name,Status,StartType | ConvertTo-Json -Compress
Write-Output $s
'''


def check_services(cfg: dict) -> list[CheckResult]:
    results: list[CheckResult] = []
    if not _is_windows():
        return [make_result(
            name="Windows services inspection", category=CATEGORY, status=INFO,
            observed="Service inspection via PowerShell requires Windows",
            expected="Windows host", evidence=UNSUPPORTED,
            recommendation="Run on the dealership workstation; use 'systemctl' equivalents manually elsewhere.")]
    names = ", ".join(f"'{n}'" for n in _KEY_SERVICES)
    try:
        rc, out, err = _run_ps(_PS_SERVICES.format(names=names), _subproc_timeout(cfg))
        if rc != 0 and not out.strip():
            raise OSError((err or f"exit {rc}").strip()[:150])
        records = _json_records(out)
    except (FileNotFoundError, ValueError, OSError, subprocess.SubprocessError) as exc:
        return [make_result(
            name="Windows services inspection", category=CATEGORY, status=WARNING,
            observed=f"Could not query services: {str(exc)[:160]}",
            expected="Get-Service accessible", evidence=INCONCLUSIVE,
            recommendation="Open services.msc manually to verify key services.")]
    seen = {str(r.get("Name", "")).lower(): r for r in records}
    for svc, why in _KEY_SERVICES.items():
        rec = seen.get(svc.lower())
        if rec is None:
            results.append(make_result(
                name=f"Service: {svc}", category=CATEGORY, status=INFO,
                observed="Service not present on this host", expected=why,
                evidence=OBSERVATION))
            continue
        status = str(rec.get("Status", "")).lower()
        if status in ("running", "4"):
            results.append(make_result(
                name=f"Service: {svc}", category=CATEGORY, status=PASS,
                observed=f"Running (start type {rec.get('StartType', '?')})",
                expected=why))
        elif status in ("stopped", "1"):
            sev = FAIL if svc in ("Spooler", "Dnscache", "LanmanWorkstation") else WARNING
            results.append(make_result(
                name=f"Service: {svc}", category=CATEGORY, status=sev,
                observed=f"STOPPED (start type {rec.get('StartType', '?')})",
                expected=why,
                evidence=CONFIRMED if sev == FAIL else WARNING_LEVEL,
                recommendation=(f"'{svc}' is stopped but should run ({why}). An authorized "
                                "technician can start it via services.msc. This tool never starts "
                                "or stops services automatically.")))
        else:
            results.append(make_result(
                name=f"Service: {svc}", category=CATEGORY, status=WARNING,
                observed=f"State: {rec.get('Status')}", expected=why,
                evidence=INCONCLUSIVE,
                recommendation=f"Verify '{svc}' state in services.msc ({why})."))
    return results


def check_top_processes(cfg: dict) -> list[CheckResult]:
    """Cross-platform resource-hog listing (psutil). Never terminates anything."""
    try:
        procs = []
        for p in psutil.process_iter(["pid", "name", "cpu_percent", "memory_info"]):
            try:
                mi = p.info.get("memory_info")
                procs.append({"pid": p.info["pid"], "name": p.info.get("name") or "?",
                              "cpu": p.info.get("cpu_percent") or 0.0,
                              "mem_mb": round((mi.rss if mi else 0) / 1e6, 1)})
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        if not procs:
            return [make_result(name="Top processes", category=CATEGORY, status=INFO,
                                observed="Process list unavailable", expected="psutil access",
                                evidence=INCONCLUSIVE)]
        # Prime cpu_percent then sample again (first call returns 0).
        time.sleep(0.4)
        mem_top = sorted(procs, key=lambda d: d["mem_mb"], reverse=True)[:5]
        cpu_top = sorted(procs, key=lambda d: d["cpu"], reverse=True)[:5]
        fmt = lambda lst, unit: "; ".join(f"{d['name']}({d['pid']}) {d[unit]}{'MB' if unit=='mem_mb' else '%'}"
                                          for d in lst)
        return [make_result(
            name="Top resource-consuming processes", category=CATEGORY, status=INFO,
            observed=f"By RAM: {fmt(mem_top,'mem_mb')} | By CPU: {fmt(cpu_top,'cpu')}",
            expected="Informational - identify runaway applications before closing them manually",
            evidence=OBSERVATION,
            details={"top_mem": mem_top, "top_cpu": cpu_top},
        )]
    except Exception as exc:
        return [error_result("Top resource-consuming processes", CATEGORY, exc)]


# --------------------------------------------------------------------------- #
# IP configuration / DHCP lease / DNS server comparison / proxy / VPN / routes
# --------------------------------------------------------------------------- #
_PS_IPCONFIG = r'''
$ErrorActionPreference='SilentlyContinue'
$c=Get-NetIPConfiguration | ForEach-Object {
  [PSCustomObject]@{
    Interface=$_.InterfaceAlias
    IPv4=($_.IPv4Address.IPAddress -join ',')
    Prefix=($_.IPv4Address.PrefixLength -join ',')
    Gateway=($_.IPv4DefaultGateway.NextHop -join ',')
    Dns=($_.DNSServer.ServerAddresses -join ',')
  }} | ConvertTo-Json -Compress
Write-Output $c
'''

_PS_LEASE = r'''
$ErrorActionPreference='SilentlyContinue'
$l=Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" |
  Select-Object Description,DHCPEnabled,IPAddress,SubnetDefaultGateway,DnsServerSearchOrder,LeaseConsumed,LeaseExpires |
  ConvertTo-Json -Compress
Write-Output $l
'''

_PS_PROXY = r'''
$ErrorActionPreference='SilentlyContinue'
$k='HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
$p=[PSCustomObject]@{ProxyEnable=(Get-ItemProperty $k -Name ProxyEnable -EA SilentlyContinue).ProxyEnable;
ProxyServer=(Get-ItemProperty $k -Name ProxyServer -EA SilentlyContinue).ProxyServer;
AutoConfigURL=(Get-ItemProperty $k -Name AutoConfigURL -EA SilentlyContinue).AutoConfigURL}
$envp=[PSCustomObject]@{HTTP=$env:HTTP_PROXY;HTTPS=$env:HTTPS_PROXY;NO=$env:NO_PROXY}
[PSCustomObject]@{ie=$p;env=$envp}|ConvertTo-Json -Compress
'''


def _vpn_interfaces() -> list[str]:
    vpns = []
    try:
        for nic, st in psutil.net_if_stats().items():
            low = nic.lower()
            if any(t in low for t in ("vpn", "wireguard", "tunnel", "ppp", "wg", "tap", "utun")) \
                    and st.isup:
                vpns.append(nic)
    except Exception:
        pass
    return vpns


def check_ip_configuration(cfg: dict) -> list[CheckResult]:
    results: list[CheckResult] = []
    # Cross-platform base view via psutil (works everywhere)
    try:
        nics = {}
        stats = psutil.net_if_stats()
        for nic, addrs in psutil.net_if_addrs().items():
            st = stats.get(nic)
            if not st or not st.isup:
                continue
            for a in addrs:
                if a.family == socket.AF_INET and a.address and not a.address.startswith("127."):
                    nics.setdefault(nic, []).append((a.address, a.netmask or ""))
        apiPA = [ip for ips in nics.values() for ip, _ in ips if ip.startswith("169.254.")]
        dhcp_state = None
        expires = None
        if _is_windows():
            try:
                rc, out, _ = _run_ps(_PS_LEASE, _subproc_timeout(cfg))
                leases = _json_records(out) if out.strip() else []
                for l in leases:
                    enabled = str(l.get("DHCPEnabled", "")).lower() in ("true", "1")
                    if enabled:
                        dhcp_state = True
                    exp = l.get("LeaseExpires")
                    if exp:
                        expires = str(exp)
            except (ValueError, OSError, subprocess.SubprocessError, FileNotFoundError):
                dhcp_state = None
        rows = []
        for nic, ips in nics.items():
            rows.append(f"{nic}: " + ", ".join(f"{ip}/{m}" for ip, m in ips))
        if not rows:
            return results  # interface check already reports the no-NIC case
        st = WARNING if apiPA else PASS
        results.append(make_result(
            name="IP configuration (IPv4)", category=CATEGORY, status=st,
            observed="; ".join(rows),
            expected="Private/business IPv4 address on the active adapter",
            evidence=(WARNING_LEVEL if apiPA else OBSERVATION),
            recommendation=("Adapter holds an APIPA 169.254.x.x address - DHCP did not answer. "
                            "Run 'ipconfig /release' + 'ipconfig /renew'; if it persists check the "
                            "DHCP scope/VLAN with the network team.") if apiPA else "",
            details={"adapters": nics, "apipa": apiPA}))
        if dhcp_state is not None:
            results.append(make_result(
                name="DHCP lease", category=CATEGORY,
                status=PASS if dhcp_state else INFO,
                observed=("DHCP-enabled adapter detected" + (f"; lease expires {expires}" if expires else ""))
                if dhcp_state else "Static IP configuration (DHCP disabled on active adapters)",
                expected="Business PCs normally use DHCP from the dealership scope",
                evidence=OBSERVATION,
                details={"dhcp_enabled": dhcp_state, "lease_expires": expires}))
        vpns = _vpn_interfaces()
        results.append(make_result(
            name="VPN / tunnel interfaces", category=CATEGORY, status=INFO,
            observed=", ".join(vpns) if vpns else "No VPN/tunnel adapter detected as up",
            expected="Informational", evidence=OBSERVATION,
            details={"vpn_interfaces": vpns},
            recommendation=("A VPN adapter is active. If internal DMS/services are unreachable, "
                            "verify split-tunnel routing - VPNs can hijack internal subnets.") if vpns else ""))
        return results
    except Exception as exc:
        return [error_result("IP configuration (IPv4)", CATEGORY, exc)]


def check_proxy(cfg: dict) -> list[CheckResult]:
    if not _is_windows():
        env = {k: v for k, v in os.environ.items() if k.lower() in
               ("http_proxy", "https_proxy", "no_proxy")}
        return [make_result(
            name="Web proxy configuration", category=CATEGORY, status=INFO,
            observed=("Environment proxies: " + json.dumps(env)) if env else
            "No proxy environment variables set (IE/proxy registry requires Windows)",
            expected="Informational", evidence=OBSERVATION, details={"env": env})]
    try:
        rc, out, _ = _run_ps(_PS_PROXY, _subproc_timeout(cfg))
        data = _json_records(out)[0] if out.strip() else {}
        ie = data.get("ie", {}) or {}
        env = data.get("env", {}) or {}
        enabled = str(ie.get("ProxyEnable")) in ("1", "True", "true")
        server = ie.get("ProxyServer") or ""
        pac = ie.get("AutoConfigURL") or ""
        obs = []
        if enabled and server:
            obs.append(f"Manual proxy: {server}")
        if pac:
            obs.append(f"Auto-config (PAC): {pac}")
        if env:
            obs.append("Env: " + ", ".join(f"{k}={v}" for k, v in env.items()))
        return [make_result(
            name="Web proxy configuration", category=CATEGORY, status=INFO,
            observed="; ".join(obs) if obs else "No proxy configured (direct internet)",
            expected="Informational - explains blocked/slow HTTP endpoints",
            evidence=OBSERVATION,
            details={"proxy_enabled": enabled, "server": server, "pac": pac, "env": env},
            recommendation=("A proxy is configured. If internet endpoint checks fail while TCP works, "
                            "the proxy is likely filtering - test through the browser and confirm proxy "
                            "policy with the network team.") if (enabled or pac) else "")]
    except (ValueError, OSError, subprocess.SubprocessError, FileNotFoundError, IndexError) as exc:
        return [make_result(
            name="Web proxy configuration", category=CATEGORY, status=INFO,
            observed=f"Could not read proxy settings: {str(exc)[:120]}",
            expected="Registry readable", evidence=UNSUPPORTED)]


def check_routes_dns_compare(cfg: dict) -> list[CheckResult]:
    """Route table summary + DNS server comparison (adapter vs resolver)."""
    results: list[CheckResult] = []
    try:
        from .network_checks import get_dns_servers, discover_gateways
        gws, method = discover_gateways()
        servers = get_dns_servers()
        private = []
        for s in servers:
            try:
                import ipaddress
                ip = ipaddress.ip_address(s)
                private.append((s, ip.is_private))
            except ValueError:
                continue
        pub = [s for s, priv in private if not priv]
        privs = [s for s, priv in private if priv]
        # Heuristic: a dealership AD domain controller usually serves internal DNS;
        # public DNS alone can break internal name resolution (DMS by hostname).
        st, rec = INFO, ""
        if servers and pub and not privs:
            st = WARNING
            rec = ("Only public DNS servers are configured. Internal dealership names "
                   "(DMS server, domain controllers, \\share paths) will NOT resolve. Add the "
                   "internal DNS server (usually the domain controller) as primary in the "
                   "adapter's IPv4 settings or DHCP scope option 006.")
        results.append(make_result(
            name="DNS server configuration", category=CATEGORY, status=st,
            observed=f"Servers: {', '.join(servers) or 'unknown'} (private: {', '.join(privs) or '-'}; "
                     f"public: {', '.join(pub) or '-'})",
            expected="Internal DNS first on domain-joined business PCs",
            recommendation=rec, evidence=(WARNING_LEVEL if st == WARNING else OBSERVATION),
            details={"servers": servers, "private": privs, "public": pub}))
        if len(set(servers)) > 1:
            results.append(make_result(
                name="DNS server comparison", category=CATEGORY, status=INFO,
                observed=f"{len(set(servers))} DNS servers configured; compare their answers with "
                         "'nslookup <internal-host> <server>' if resolution is inconsistent",
                expected="Consistent answers between configured servers",
                evidence=OBSERVATION, details={"servers": servers}))
        if gws:
            results.append(make_result(
                name="Default route summary", category=CATEGORY, status=INFO,
                observed=f"Default gateway(s) {', '.join(gws)} via {method}",
                expected="Informational", evidence=OBSERVATION,
                details={"gateways": gws, "method": method}))
        return results
    except Exception as exc:
        return [error_result("Route/DNS configuration", CATEGORY, exc)]


# --------------------------------------------------------------------------- #
# Mapped drives & business application connectivity (optional)
# --------------------------------------------------------------------------- #
def check_mapped_drives(cfg: dict) -> list[CheckResult]:
    results: list[CheckResult] = []
    drives = cfg.get("business", {}).get("mapped_drives", []) or []
    if not drives:
        return [make_result(
            name="Mapped business drives", category=CATEGORY, status=INFO,
            observed="No mapped drives configured (business.mapped_drives)",
            expected="Optionally configure \\server\\share drive letters used by billing/DMS",
            evidence=OBSERVATION,
            recommendation="Add entries like {\"letter\":\"S\",\"path\":\"\\\\fileserver\\software\"} "
                           "to config.json to verify share availability at login."])]
    for d in drives:
        letter = str(d.get("letter", "")).strip().rstrip(":\\").upper()
        path = str(d.get("path", "")).strip()
        if not letter or not path:
            results.append(make_result(
                name=f"Mapped drive {letter or '?'}", category=CATEGORY, status=WARNING,
                observed=f"Incomplete config entry {d}", expected="{letter, path} both set",
                evidence=INCONCLUSIVE, recommendation="Fix the entry in config.json."))
            continue
        probe = f"{letter}:\\" if _is_windows() else None
        ok, obs = False, ""
        if probe:
            try:
                usage = psutil.disk_usage(probe)
                ok = usage.total >= 0  # exists & readable
                obs = f"{probe} accessible ({round(usage.free/1e9,1)} GB free)"
            except (OSError, PermissionError) as exc:
                obs = f"{probe} not accessible: {exc}"
        else:
            # non-Windows: just test the UNC host reachability via SMB-ish TCP 445
            host = re.sub(r"^\\\\", "", path).split("\\")[0]
            from .network_checks import tcp_probe
            tok, tinfo, _ = tcp_probe(host, 445, safe_float(
                cfg.get("timeouts", {}).get("tcp_connect_seconds", 3), 3, 0.1, 60))
            ok, obs = tok, f"SMB port 445 on {host}: {tinfo}"
        results.append(make_result(
            name=f"Mapped drive {letter}: ({path})", category=CATEGORY,
            status=PASS if ok else WARNING, observed=obs,
            expected="Drive present and readable at the workstation",
            evidence=(OBSERVATION if ok else INCONCLUSIVE),
            recommendation="" if ok else ("Reconnect via 'net use " + (f"{letter}: {path}" if _is_windows() else path) +
                                          "' or check credentials/session; if the share itself is down, "
                                          "escalate to the file-server owner.")))
    return results


def check_business_app_urls(cfg: dict) -> list[CheckResult]:
    """Optional HTTP(S) readiness probes for business web apps (DMS portal etc.)."""
    urls = cfg.get("business", {}).get("app_urls", []) or []
    if not urls:
        return [make_result(
            name="Business application URLs", category=CATEGORY, status=INFO,
            observed="No business app URLs configured (business.app_urls)",
            expected="Optionally add internal app URLs to verify HTTP-level availability",
            evidence=OBSERVATION,
            recommendation="Add e.g. https://dms.dealership.local/portal under \"business\" in config.json.")]
    from .network_checks import _http_probe
    timeout = safe_float(cfg.get("timeouts", {}).get("http_check_seconds", 6), 6, 0.1, 60)
    results = []
    for u in urls:
        u = str(u).strip()
        if not u:
            continue
        ok, info = _http_probe(u, timeout)
        results.append(make_result(
            name=f"Business app HTTP: {u}", category=CATEGORY,
            status=PASS if ok else WARNING,
            observed=info, expected=f"HTTP response within {timeout}s",
            evidence=(OBSERVATION if ok else INCONCLUSIVE),
            recommendation="" if ok else (f"{u} did not respond. A TCP port test passing while HTTP "
                                          "fails points to the application layer (service running but "
                                          "not serving) - escalate to the app/DMS vendor team.")))
    return results


# --------------------------------------------------------------------------- #
# Asset inventory
# --------------------------------------------------------------------------- #
_PS_COMPUTER = r'''
$ErrorActionPreference='SilentlyContinue'
$cs=Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer,Model,TotalPhysicalMemory,HostName,Domain | ConvertTo-Json -Compress
Write-Output $cs
'''
_PS_BIOS = r'''
$ErrorActionPreference='SilentlyContinue'
$b=Get-CimInstance Win32_BIOS | Select-Object SerialNumber | ConvertTo-Json -Compress
Write-Output $b
'''
_PS_APPS = r'''
$ErrorActionPreference='SilentlyContinue'
$a=@()
foreach($root in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'){
  $a+=Get-ChildItem $root -EA SilentlyContinue | ForEach-Object { $_.GetValue('DisplayName') } | Where-Object {$_}}
($a | Sort-Object -Unique) | ConvertTo-Json -Compress
'''


def collect_asset(cfg: dict) -> dict:
    """Gather hardware/software inventory (best-effort, cross-platform)."""
    asset: dict = {
        "hostname": socket.gethostname(),
        "os_caption": f"{platform.system()} {platform.release()}",
        "os_build": platform.version(),
        "architecture": platform.machine(),
        "cpu_name": platform.processor() or "",
        "cpu_cores": psutil.cpu_count(logical=True),
        "ram_gb": round(psutil.virtual_memory().total / 1e9, 1),
        "disk_total_gb": round(sum(
            psutil.disk_usage(p.mountpoint).total for p in psutil.disk_partitions(all=False)
            if _safe_usage(p.mountpoint)) / 1e9, 1),
        "installed_apps": [],
        "manufacturer": "", "model": "", "serial": "",
        "details": {},
    }
    if _is_windows():
        try:
            rc, out, _ = _run_ps(_PS_COMPUTER, _subproc_timeout(cfg))
            cs = (_json_records(out) or [{}])[0]
            asset["manufacturer"] = str(cs.get("Manufacturer", ""))
            asset["model"] = str(cs.get("Model", ""))
            asset["domain"] = str(cs.get("Domain", ""))
        except Exception:
            pass
        try:
            rc, out, _ = _run_ps(_PS_BIOS, _subproc_timeout(cfg))
            b = (_json_records(out) or [{}])[0]
            asset["serial"] = str(b.get("SerialNumber", ""))
        except Exception:
            pass
        try:
            rc, out, _ = _run_ps(_PS_APPS, _subproc_timeout(cfg) + 5)
            apps = _json_records(out)
            flat = []
            for a in apps:
                if isinstance(a, str):
                    flat.append(a)
                elif isinstance(a, dict):
                    flat.append(str(a.get("value") or a.get("Name") or ""))
            asset["installed_apps"] = [x for x in flat if x][:200]
        except Exception:
            pass
    return asset


def _safe_usage(mount: str) -> bool:
    try:
        psutil.disk_usage(mount)
        return True
    except (OSError, PermissionError):
        return False


def check_asset(cfg: dict) -> list[CheckResult]:
    try:
        asset = collect_asset(cfg)
        from . import history_db
        prev = history_db.latest_asset(asset["hostname"])
        changes = []
        if prev:
            for field in ("ram_gb", "cpu_cores", "disk_total_gb", "model", "asset_tag"):
                old, new = prev.get(field), asset.get(field)
                if new not in (None, "", 0) and old not in (None, "") and old != new:
                    changes.append(f"{field}: {old} -> {new}")
        aid = history_db.save_asset(asset)
        obs = (f"{asset['manufacturer']} {asset['model']} | {asset['os_caption']} build "
               f"{asset['os_build']} | {asset['cpu_cores']} cores | {asset['ram_gb']} GB RAM | "
               f"{asset['disk_total_gb']} GB disk | {len(asset['installed_apps'])} installed apps")
        st = WARNING if changes else INFO
        return [make_result(
            name="Asset inventory snapshot", category=ASSET_CATEGORY, status=st,
            observed=obs,
            expected="Recorded for change tracking over time",
            evidence=(WARNING_LEVEL if changes else OBSERVATION),
            recommendation=("Hardware/inventory attributes CHANGED since the previous record: "
                            + "; ".join(changes) + ". Confirm this was an approved change (RAM upgrade, "
                            "device swap) and update documentation/asset tag.") if changes else "",
            details={"asset_id": aid, "changes": changes, "asset_tag": (prev or {}).get("asset_tag", ""),
                     "apps_sample": asset["installed_apps"][:15]})]
    except Exception as exc:
        return [error_result("Asset inventory snapshot", ASSET_CATEGORY, exc)]


# --------------------------------------------------------------------------- #
# Runner
# --------------------------------------------------------------------------- #
def run_windows_checks(cfg: dict) -> list[CheckResult]:
    results: list[CheckResult] = []
    runners = [check_event_log, check_services, check_top_processes,
               check_ip_configuration, check_routes_dns_compare, check_proxy,
               check_mapped_drives, check_business_app_urls]
    for fn in runners:
        try:
            results.extend(fn(cfg))
        except Exception as exc:  # one broken analysis must never kill the run
            results.append(error_result(getattr(fn, "__name__", "windows check"),
                                        CATEGORY, exc))
    return results
