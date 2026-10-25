"""Network diagnostics: interfaces, gateway, DNS, internet, TCP services, ping.

Design notes for the technician:
- Internet reachability does NOT imply dealership internal services are up;
  each business service is tested separately by host+TCP port.
- Every check has a timeout and is wrapped so one failure cannot crash the run.
- No admin rights required (ping uses the system `ping` utility when present,
  otherwise falls back to a TCP/ICMP-free heuristic).
"""
from __future__ import annotations

import ipaddress
import os
import re
import socket
import subprocess
import urllib.request
import urllib.error

import psutil

from .check_model import (
    CheckResult,
    FAIL,
    INFO,
    PASS,
    WARNING,
    error_result,
    make_result,
)

CATEGORY = "Network"


# --------------------------------------------------------------------------- #
# Interfaces
# --------------------------------------------------------------------------- #
def get_interfaces() -> dict[str, list[str]]:
    """Return {nic_name: [ipv4,...]} for operational, non-loopback NICs."""
    out: dict[str, list[str]] = {}
    stats = psutil.net_if_stats()
    addrs = psutil.net_if_addrs()
    for nic, addr_list in addrs.items():
        st = stats.get(nic)
        if st is not None and not st.isup:
            continue
        ips = []
        for a in addr_list:
            if a.family == socket.AF_INET and a.address and not a.address.startswith("127."):
                ips.append(a.address)
        if ips:
            out[nic] = ips
    return out


def check_interfaces() -> list[CheckResult]:
    try:
        nics = get_interfaces()
        if not nics:
            return [make_result(
                name="Network interfaces", category=CATEGORY, status=FAIL,
                observed="No active IPv4 interface found (excluding loopback)",
                expected="At least one NIC with an IPv4 address",
                recommendation=("Check the Ethernet cable / Wi-Fi connection. Run 'ipconfig' - "
                                "if the adapter shows 169.254.x.x, DHCP failed; release/renew "
                                "with 'ipconfig /release' then 'ipconfig /renew'."),
            )]
        apiPA = any(ip.startswith("169.254.") for ips in nics.values() for ip in ips)
        detail = "; ".join(f"{nic}: {', '.join(ips)}" for nic, ips in nics.items())
        status = WARNING if apiPA else PASS
        rec = ""
        if apiPA:
            rec = ("An interface has an APIPA address (169.254.x.x) - DHCP did not hand out "
                   "an address. Renew IP, then check the DHCP scope on the server if it persists.")
        return [make_result(
            name="Network interfaces", category=CATEGORY, status=status,
            observed=detail, expected="Active NIC with valid IPv4 (not 169.254.x.x)",
            recommendation=rec, details={"interfaces": nics},
        )]
    except PermissionError as exc:
        return [make_result(
            name="Network interfaces", category=CATEGORY, status=WARNING,
            observed=f"Interface details are restricted: {exc}",
            expected="Readable interface list",
            recommendation="Some containers/locked-down systems restrict psutil network APIs.")]
    except Exception as exc:
        return [error_result("Network interfaces", CATEGORY, exc)]


# --------------------------------------------------------------------------- #
# Default gateway
# --------------------------------------------------------------------------- #
def discover_gateways() -> list[str]:
    gateways: set[str] = set()
    # Preferred cross-platform source: /proc/net/route (Linux)
    try:
        with open("/proc/net/route") as fh:
            for line in fh.readlines()[1:]:
                f = line.split()
                if len(f) >= 3 and f[1] == "00000000":
                    gw_hex = f[2]
                    gw = ".".join(str(int(gw_hex[i:i + 2], 16)) for i in (6, 4, 2, 0))
                    if gw != "0.0.0.0":
                        gateways.add(gw)
    except OSError:
        pass
    try:
        for route in psutil.net_routes():
            dest = route.destination or ""
            gw = route.gateway or ""
            if not gw:
                continue
            try:
                if ipaddress.ip_address(dest) in (ipaddress.ip_address("0.0.0.0"),):
                    gateways.add(gw)
            except ValueError:
                # default route may be shown as 'default'
                if dest.lower() in ("default", "0.0.0.0/0"):
                    gateways.add(gw)
    except Exception:
        pass
    if not gateways and _is_windows():
        # Windows fallback via route print
        try:
            res = subprocess.run(["route", "print", "0.0.0.0"], capture_output=True,
                                 text=True, timeout=8)
            for line in (res.stdout or "").splitlines():
                m = re.search(r"0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)", line)
                if m:
                    gateways.add(m.group(1))
        except (OSError, subprocess.SubprocessError):
            pass
    if not gateways and not _is_windows():
        try:
            res = subprocess.run(["ip", "-4", "route", "show", "default"],
                                 capture_output=True, text=True, timeout=5)
            m = re.search(r"default\s+via\s+(\d+\.\d+\.\d+\.\d+)", res.stdout or "")
            if m:
                gateways.add(m.group(1))
        except (OSError, subprocess.SubprocessError):
            pass
    return sorted(gateways)


def ping_host(host: str, timeout_s: float) -> tuple[bool, float | None, str]:
    """Ping using the OS utility. Returns (ok, avg_ms, raw_output_or_error)."""
    if _is_windows():
        cmd = ["ping", "-n", "2", "-w", str(int(timeout_s * 1000)), host]
    else:
        cmd = ["ping", "-c", "2", "-W", str(int(timeout_s)), host]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True,
                             timeout=timeout_s * 2 + 4)
        output = (res.stdout or "") + (res.stderr or "")
        times = [float(t) for t in re.findall(r"time[=<]\s*(\d+(?:\.\d+)?)\s*ms", output, re.I)]
        lost = None
        m = re.search(r"(\d+)%", output)
        if "unreachable" in output.lower() or "could not find" in output.lower() or "100% loss" in output.lower().replace(" ", ""):
            ok = False
        else:
            ok = res.returncode == 0 and bool(times)
        if m and "loss" in output.lower():
            lost = int(m.group(1))
        avg = round(sum(times) / len(times), 1) if times else None
        return ok, avg, f"loss={lost}% avg={avg}ms" if lost is not None else output.strip()[:120]
    except FileNotFoundError:
        return False, None, "ping utility not available on this system"
    except (subprocess.SubprocessError, OSError) as exc:
        return False, None, f"ping failed: {exc}"


def _is_windows() -> bool:
    return os.name == "nt"


def check_gateway(cfg: dict) -> list[CheckResult]:
    try:
        gws = discover_gateways()
        if not gws:
            return [make_result(
                name="Default gateway", category=CATEGORY, status=WARNING,
                observed="Could not determine default gateway",
                expected="A default route exists",
                recommendation=("Verify IP configuration (ipconfig). On some VLAN setups the "
                                "gateway may not appear without admin rights."),
            )]
        results = []
        timeout = cfg["timeouts"]["ping_seconds"]
        for gw in gws[:2]:
            ok, avg, info = ping_host(gw, timeout)
            if ok:
                status, rec = PASS, ""
            else:
                status = FAIL
                rec = ("Gateway does not respond to ping. Check the switch/cable first, then "
                       "ask the network administrator whether the router/firewall blocks ICMP "
                       "(a blocked ping is possible even when routing works).")
            results.append(make_result(
                name=f"Gateway reachability {gw}", category=CATEGORY,
                status=status,
                observed=f"{'reachable' if ok else 'NOT reachable'} ({info})",
                expected="Gateway responds to ping",
                recommendation=rec,
                details={"gateway": gw, "avg_ms": avg, "raw": info},
            ))
        return results
    except Exception as exc:
        return [error_result("Default gateway", CATEGORY, exc)]


# --------------------------------------------------------------------------- #
# DNS
# --------------------------------------------------------------------------- #
def get_dns_servers() -> list[str]:
    servers: list[str] = []
    try:
        import dns.resolver  # type: ignore  # optional dnspython
        servers = [str(s) for s in dns.resolver.nameservers]
    except Exception:
        pass
    if not servers:
        # Parse ipconfig /all (Windows) or /etc/resolv.conf (others)
        try:
            if _is_windows():
                out = subprocess.run(["ipconfig", "/all"], capture_output=True, text=True,
                                     timeout=cfg_timeout_default()).stdout or ""
                servers = re.findall(r"DNS Servers?[\.\s]*[:\s]\s*([0-9a-fA-F.:]+)", out)
                servers = [s.strip() for s in servers if s.strip()]
            else:
                with open("/etc/resolv.conf") as fh:
                    servers = [ln.split()[1] for ln in fh if ln.startswith("nameserver")]
        except Exception:
            servers = []
    # de-dup preserving order
    seen, uniq = set(), []
    for s in servers:
        if s not in seen:
            seen.add(s)
            uniq.append(s)
    return uniq


def cfg_timeout_default() -> int:
    return 8


def check_dns(cfg: dict) -> list[CheckResult]:
    results: list[CheckResult] = []
    try:
        servers = get_dns_servers()
        results.append(make_result(
            name="DNS servers configured", category=CATEGORY,
            status=INFO if servers else WARNING,
            observed=", ".join(servers) if servers else "Could not read DNS server list",
            expected="At least one DNS server",
            recommendation="" if servers else "Run 'ipconfig /all' to confirm DNS settings.",
            details={"servers": servers},
        ))
    except Exception as exc:
        results.append(error_result("DNS servers configured", CATEGORY, exc))

    timeout = cfg["timeouts"]["dns_resolve_seconds"]
    old = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        for host in cfg["network"].get("dns_test_hostnames", []):
            host = str(host).strip()
            if not host:
                continue
            try:
                infos = socket.getaddrinfo(host, None, socket.AF_INET)
                ips = sorted({i[4][0] for i in infos})
                results.append(make_result(
                    name=f"DNS resolution: {host}", category=CATEGORY, status=PASS,
                    observed=f"Resolved to {', '.join(ips)}",
                    expected=f"'{host}' resolves within {timeout}s",
                    details={"ips": ips},
                ))
            except socket.gaierror as exc:
                results.append(make_result(
                    name=f"DNS resolution: {host}", category=CATEGORY, status=FAIL,
                    observed=f"Resolution failed: {exc}",
                    expected=f"'{host}' resolves within {timeout}s",
                    recommendation=("DNS failure. Try 'ipconfig /flushdns', verify the DNS server "
                                    "in ipconfig, and test another hostname. If only internal "
                                    "names fail, the problem is the dealership DNS/domain controller."),
                    details={"error": str(exc)},
                ))
            except OSError as exc:
                results.append(make_result(
                    name=f"DNS resolution: {host}", category=CATEGORY, status=FAIL,
                    observed=f"Network error during resolution: {exc}",
                    expected=f"'{host}' resolves within {timeout}s",
                    recommendation="Check local connectivity before blaming DNS.",
                    details={"error": str(exc)},
                ))
    finally:
        socket.setdefaulttimeout(old)
    return results


# --------------------------------------------------------------------------- #
# Internet connectivity
# --------------------------------------------------------------------------- #
def check_internet(cfg: dict) -> list[CheckResult]:
    results: list[CheckResult] = []
    timeout = cfg["timeouts"]["http_check_seconds"]
    successes = 0
    total = 0
    for url in cfg["network"].get("internet_test_urls", []):
        url = str(url).strip()
        if not url:
            continue
        total += 1
        try:
            req = urllib.request.Request(url, method="HEAD",
                                         headers={"User-Agent": "AutoDesk-HealthMonitor/1.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                code = resp.status
            successes += 1
            results.append(make_result(
                name=f"Internet endpoint: {url}", category=CATEGORY, status=PASS,
                observed=f"HTTP {code}", expected=f"HTTP response within {timeout}s",
            ))
        except urllib.error.HTTPError as exc:
            # A HTTP error still proves the endpoint was reached
            successes += 1
            results.append(make_result(
                name=f"Internet endpoint: {url}", category=CATEGORY, status=PASS,
                observed=f"Reached endpoint, HTTP {exc.code}",
                expected=f"HTTP response within {timeout}s",
            ))
        except Exception as exc:
            results.append(make_result(
                name=f"Internet endpoint: {url}", category=CATEGORY, status=FAIL,
                observed=f"No response: {exc}",
                expected=f"HTTP response within {timeout}s",
                recommendation=("External connectivity problem. Check the local link, gateway, "
                                "and DNS first; then confirm the firewall/proxy is not blocking "
                                "this site. Note: internet working does NOT mean internal DMS/"
                                "business apps are reachable."),
                details={"error": str(exc)},
            ))
    if total and successes == 0:
        results.append(make_result(
            name="Internet connectivity summary", category=CATEGORY, status=FAIL,
            observed=f"0/{total} external endpoints reachable",
            expected="At least one endpoint reachable",
            recommendation="No internet access from this workstation. Follow the per-endpoint failures above.",
        ))
    elif total and successes < total:
        results.append(make_result(
            name="Internet connectivity summary", category=CATEGORY, status=WARNING,
            observed=f"{successes}/{total} external endpoints reachable",
            expected="All configured endpoints reachable",
            recommendation="Partial internet access - one endpoint may be down or filtered; verify proxy/firewall rules.",
        ))
    return results


# --------------------------------------------------------------------------- #
# Internal business services (TCP)
# --------------------------------------------------------------------------- #
def tcp_probe(host: str, port: int, timeout: float) -> tuple[bool, str]:
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True, "TCP connection established"
    except socket.timeout:
        return False, f"Timed out after {timeout}s (host may be down, firewalled, or overloaded)"
    except ConnectionRefusedError:
        return False, "Connection refused (host reachable but service/listener down)"
    except socket.gaierror as exc:
        return False, f"Hostname could not be resolved: {exc}"
    except OSError as exc:
        return False, f"Network error: {exc}"


def check_business_services(cfg: dict) -> list[CheckResult]:
    results: list[CheckResult] = []
    timeout = cfg["timeouts"]["tcp_connect_seconds"]
    services = [s for s in cfg["network"].get("business_services", [])
                if isinstance(s, dict) and s.get("enabled") and str(s.get("host", "")).strip()]
    if not services:
        results.append(make_result(
            name="Internal business services", category=CATEGORY, status=INFO,
            observed="No internal services configured in config.json",
            expected="Configure DMS/line-of-business hosts and ports to test them",
            recommendation=("Add your dealership's actual internal service hostnames/IPs and TCP "
                            "ports under network.business_services in config.json (do not rely on "
                            "internet tests for internal apps)."),
        ))
    for svc in services:
        host = str(svc["host"]).strip()
        port = int(svc.get("port", 0))
        name = str(svc.get("name") or f"{host}:{port}")
        ok, info = tcp_probe(host, port, timeout)
        rec = "" if ok else (
            f"Cannot reach {name} at {host}:{port}. Verify the service is running on the server, "
            "check Windows Firewall / switch VLAN ACLs, and confirm the hostname/port in config.json. "
            "Escalate to the server/DMS team if the PC itself is healthy.")
        results.append(make_result(
            name=f"Service TCP: {name} ({host}:{port})", category=CATEGORY,
            status=PASS if ok else FAIL,
            observed=info,
            expected=f"TCP connect to {host}:{port} succeeds within {timeout}s",
            recommendation=rec,
            details={"host": host, "port": port},
        ))
    return results


# --------------------------------------------------------------------------- #
# Optional extra ping hosts (e.g. file server, DMS server)
# --------------------------------------------------------------------------- #
def check_ping_hosts(cfg: dict) -> list[CheckResult]:
    results: list[CheckResult] = []
    timeout = cfg["timeouts"]["ping_seconds"]
    for host in cfg["network"].get("ping_hosts", []):
        host = str(host).strip()
        if not host:
            continue
        ok, avg, info = ping_host(host, timeout)
        results.append(make_result(
            name=f"Ping: {host}", category=CATEGORY, status=PASS if ok else WARNING,
            observed=info, expected=f"{host} responds to ping",
            recommendation="" if ok else (f"{host} unreachable by ping. Some servers block ICMP; "
                                          "confirm with a targeted TCP service test before treating it as down."),
            details={"avg_ms": avg},
        ))
    return results


def run_network_checks(cfg: dict) -> list[CheckResult]:
    runners = [check_interfaces, check_gateway, check_dns, check_internet,
               check_business_services, check_ping_hosts]
    results: list[CheckResult] = []
    for fn in runners:
        try:
            results.extend(fn(cfg))
        except Exception as exc:
            results.append(error_result(fn.__name__, CATEGORY, exc))
    return results
