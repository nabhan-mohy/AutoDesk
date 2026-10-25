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
import time
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


def check_interfaces(cfg: dict) -> list[CheckResult]:
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
def discover_gateways() -> tuple[list[str], str]:
    """Return (gateway_ips, method).

    method describes how reliable the discovery was:
      - "routing table" : authoritative default route (psutil / /proc/net/route)
      - "heuristic"     : parsed from an OS utility; uncertain
      - "none"          : no gateway could be determined
    """
    gateways: set[str] = set()
    method = "none"
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
                        method = "routing table"
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
                    method = "routing table"
            except ValueError:
                # default route may be shown as 'default'
                if dest.lower() in ("default", "0.0.0.0/0"):
                    gateways.add(gw)
                    method = "routing table"
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
                    method = "heuristic"
        except (OSError, subprocess.SubprocessError):
            pass
    if not gateways and not _is_windows():
        try:
            res = subprocess.run(["ip", "-4", "route", "show", "default"],
                                 capture_output=True, text=True, timeout=5)
            m = re.search(r"default\s+via\s+(\d+\.\d+\.\d+\.\d+)", res.stdout or "")
            if m:
                gateways.add(m.group(1))
                method = "heuristic"
        except (OSError, subprocess.SubprocessError):
            pass
    return sorted(gateways), method


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
        # Match ONLY the loss percentage ("N% packet loss" / "loss: N%"), never
        # any bare 'N%' - an earlier greedy r"(\d+)% could grab TTL/other fields.
        m = re.search(r"(\d{1,3})\s*%\s*(?:packet\s+)?loss|(?:loss|lost)\D{0,20}?(\d{1,3})\s*%",
                      output, re.I)
        if m:
            lost = int(next(g for g in m.groups() if g is not None))
        low = output.lower().replace(" ", "")
        if ("unreachable" in low or "couldnotfind" in low or "100%loss" in low):
            ok = False
        else:
            ok = res.returncode == 0 and bool(times)
        avg = round(sum(times) / len(times), 1) if times else None
        return ok, avg, f"loss={lost}% avg={avg}ms" if lost is not None else output.strip()[:120]
    except FileNotFoundError:
        return False, None, "ping utility not available on this system"
    except (subprocess.SubprocessError, OSError) as exc:
        return False, None, f"ping failed: {exc}"


def _is_windows() -> bool:
    return os.name == "nt"


def check_gateway(cfg: dict, prior_results: list[CheckResult] | None = None
                  ) -> list[CheckResult]:
    try:
        gws, method = discover_gateways()
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
        tcp_timeout = cfg["timeouts"]["tcp_connect_seconds"]
        # Corroborating evidence: did any *other* TCP probe already succeed in
        # this run? If yes, routing works and an unresponsive gateway is most
        # likely just blocking ICMP - never report an outage in that case.
        other_tcp_ok = any(
            r.status == PASS and ("TCP" in r.name or "Internet endpoint" in r.name)
            for r in (prior_results or []))
        for gw in gws[:2]:
            ok, avg, info = ping_host(gw, timeout)
            evidence = f"icmp: {info}"
            if ok:
                # Ping succeeded -> authoritative proof of reachability.
                status = PASS
                rec = ""
                observed = f"reachable ({info})"
            else:
                # A failed ping alone is NOT sufficient evidence of an outage:
                # many routers/firewalls block ICMP. Try TCP fallback probes to
                # common gateway ports before classifying.
                tcp_ok = False
                for port in (53, 80, 443):
                    p_ok, _, _ = tcp_probe(gw, port, tcp_timeout)
                    if p_ok:
                        tcp_ok = True
                        evidence += f"; tcp:{port} open"
                        break
                if tcp_ok:
                    status = PASS
                    rec = ""
                    observed = f"reachable via TCP despite no ICMP reply ({evidence})"
                elif method != "routing table" or other_tcp_ok:
                    # Gateway discovered heuristically, or other traffic proves
                    # routing works -> inconclusive, WARNING only.
                    status = WARNING
                    rec = ("Gateway did not answer ping or TCP probes, but this is "
                           "inconclusive: discovery was heuristic and/or other network "
                           "traffic succeeds, so the router probably just blocks ICMP. "
                           "Verify with 'tracert <gateway>' before treating this as an outage.")
                    observed = f"NOT confirmed reachable ({evidence})"
                else:
                    # Authoritative default route AND every probe (ICMP + TCP here
                    # + other TCP checks in this run) failed. That combination is
                    # sufficient evidence of an actual connectivity failure.
                    status = FAIL
                    rec = ("No route through the gateway appears to work: ping, direct TCP "
                           "probes, and all other outbound TCP tests failed together. Check "
                           "the physical link/cable and IP configuration (ipconfig), then "
                           "escalate to the network team with these results.")
                    observed = f"NOT responding to any probe, corroborated by failed TCP checks ({evidence})"
            results.append(make_result(
                name=f"Gateway reachability {gw}", category=CATEGORY,
                status=status,
                observed=observed,
                expected="Gateway responds to ping or a TCP probe",
                recommendation=rec,
                details={"gateway": gw, "avg_ms": avg, "discovery_method": method,
                         "raw": info, "evidence": evidence},
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
    # NOTE: socket.setdefaulttimeout() does NOT reliably bound getaddrinfo's
    # internal resolver on all platforms (Windows can block in the system
    # resolver regardless). We still set it as a best-effort guard, but also
    # classify slow/failed lookups conservatively so a hang is reported as an
    # inconclusive WARNING rather than silently stalling or over-claiming.
    old = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        for host in cfg["network"].get("dns_test_hostnames", []):
            host = str(host).strip()
            if not host:
                continue
            t0 = time.perf_counter()
            try:
                infos = socket.getaddrinfo(host, None, socket.AF_INET)
                ips = sorted({i[4][0] for i in infos})
                elapsed = round(time.perf_counter() - t0, 2)
                rec = ""
                st = PASS
                if elapsed > timeout:
                    # Succeeded but slower than configured: suspicious but not
                    # proof of failure -> WARNING with explanation.
                    st = WARNING
                    rec = (f"Resolution of '{host}' took {elapsed}s, longer than the configured "
                           f"{timeout}s budget (the OS resolver may ignore the timeout). Check DNS "
                           "server responsiveness; intermittent slowness often precedes outages.")
                results.append(make_result(
                    name=f"DNS resolution: {host}", category=CATEGORY, status=st,
                    observed=f"Resolved to {', '.join(ips)} in {elapsed}s",
                    expected=f"'{host}' resolves within {timeout}s",
                    recommendation=rec,
                    details={"ips": ips, "seconds": elapsed},
                ))
            except socket.gaierror as exc:
                elapsed = round(time.perf_counter() - t0, 2)
                # A fast NODATA/NXDOMAIN answer is a definite negative; a slow
                # failure usually means the resolver itself timed out, which is
                # indistinguishable from egress filtering - report WARNING then.
                definitive = elapsed < timeout
                results.append(make_result(
                    name=f"DNS resolution: {host}", category=CATEGORY,
                    status=FAIL if definitive else WARNING,
                    observed=f"Resolution failed after {elapsed}s: {exc}",
                    expected=f"'{host}' resolves within {timeout}s",
                    recommendation=(("DNS failure. Try 'ipconfig /flushdns', verify the DNS server "
                                      "in ipconfig, and test another hostname. If only internal "
                                      "names fail, the problem is the dealership DNS/domain controller.")
                                     if definitive else
                                     ("Lookup did not complete quickly enough; this is inconclusive - "
                                      "the DNS server may be slow/unreachable or the query filtered. "
                                      "Retry and compare against the gateway/interface rows.")),
                    details={"error": str(exc), "seconds": elapsed},
                ))
            except OSError as exc:
                results.append(make_result(
                    name=f"DNS resolution: {host}", category=CATEGORY, status=WARNING,
                    observed=f"Network error during resolution: {exc}",
                    expected=f"'{host}' resolves within {timeout}s",
                    recommendation="Transient network error during lookup; re-run before concluding. "
                                   "Check local connectivity before blaming DNS.",
                    details={"error": str(exc)},
                ))
            except Exception as exc:  # never let one hostname kill the batch
                results.append(error_result(f"DNS resolution: {host}", CATEGORY, exc))
    finally:
        socket.setdefaulttimeout(old)
    return results


# --------------------------------------------------------------------------- #
# Internet connectivity
# --------------------------------------------------------------------------- #
def _http_probe(url: str, timeout: float) -> tuple[bool, str]:
    """Try one internet endpoint. Returns (reachable, observed_text)."""
    try:
        req = urllib.request.Request(url, method="HEAD",
                                     headers={"User-Agent": "AutoDesk-HealthMonitor/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return True, f"HTTP {resp.status}"
    except urllib.error.HTTPError as exc:
        # Any HTTP status proves the endpoint was actually reached.
        return True, f"Reached endpoint, HTTP {exc.code}"
    except Exception as exc:
        return False, f"No response: {exc}"


def check_internet(cfg: dict, prior_results: list[CheckResult] | None = None
                   ) -> list[CheckResult]:
    """Internet connectivity via multiple configurable endpoints.

    Classification rules (issue #1 fix - no false outages from one site):
    - A *single* endpoint failure NEVER decides overall readiness on its own.
    - Individual endpoint failures are always WARNING when any other endpoint
      succeeds OR any other outbound traffic succeeded earlier in this run.
    - When EVERY endpoint fails, the authoritative verdict is carried by one
      summary result:
        * FAIL   - only with corroborated evidence of a real outage: zero HTTP
                   successes AND no successful gateway/ping/TCP-outbound check
                   anywhere in this run (and, when available, a gateway that
                   itself was classified FAIL).
        * WARNING - everything else (other outbound traffic works, discovery
                   was inconclusive, or ICMP/HTTP egress may simply be blocked
                   by the dealership proxy/firewall).
    - No individual endpoint row is ever marked FAIL; the summary row owns the
      outage verdict. This guarantees one down website, a HEAD-request block,
      or a proxy filter cannot by itself push the workstation to NOT READY.
    """
    results: list[CheckResult] = []
    timeout = cfg["timeouts"]["http_check_seconds"]
    urls = [str(u).strip() for u in cfg["network"].get("internet_test_urls", [])
            if str(u).strip()]
    outcomes: list[tuple[str, bool, str]] = []
    for url in urls:
        ok, info = _http_probe(url, timeout)
        outcomes.append((url, ok, info))

    successes = sum(1 for _, ok, _ in outcomes if ok)
    total = len(outcomes)

    # ---- corroboration sources from earlier checks in this same run -------- #
    prior = prior_results or []
    # Successful outbound traffic elsewhere (gateway reply, ping host, or any
    # TCP probe) proves routing works even if every HTTP endpoint fails.
    other_tcp_ok = any(
        r.status == PASS and ("TCP" in r.name or "Gateway reachability" in r.name
                              or r.name.startswith("Ping:"))
        for r in prior)
    # A gateway already classified FAIL is positive evidence of a local-path
    # breakage (authoritative route + failed ICMP + failed TCP probes there),
    # which strengthens an all-endpoints-failed verdict into a confirmed outage.
    gateway_fail = any(r.name.startswith("Gateway reachability") and r.status == FAIL
                       for r in prior)

    all_failed = total > 0 and successes == 0
    confirmed_outage = all_failed and not other_tcp_ok

    for url, ok, info in outcomes:
        if ok:
            results.append(make_result(
                name=f"Internet endpoint: {url}", category=CATEGORY, status=PASS,
                observed=info, expected=f"HTTP response within {timeout}s",
            ))
        else:
            # Per issue #1: individual endpoint failures are ALWAYS WARNING.
            # Whether this is a genuine outage is decided by the summary row,
            # using corroborated evidence across all endpoints and checks.
            if successes > 0:
                rec = (f"'{url}' did not respond, but at least one other endpoint succeeded, "
                       "so internet access works. This endpoint is most likely down, blocking "
                       "HEAD requests, or filtered by the dealership proxy/firewall.")
            elif other_tcp_ok:
                rec = (f"'{url}' did not respond and no endpoint succeeded, but other outbound "
                       "traffic (gateway/ping/TCP) works - HTTP(S) egress may be filtered. Not "
                       "proof of an internet outage.")
            elif confirmed_outage:
                rec = ("Every configured endpoint failed and no other outbound traffic "
                       "succeeded anywhere in this run. See the 'Internet connectivity "
                       "summary' result for the authoritative verdict.")
            else:
                rec = (f"'{url}' did not respond. Inconclusive on its own - see the "
                       "'Internet connectivity summary' result.")
            results.append(make_result(
                name=f"Internet endpoint: {url}", category=CATEGORY, status=WARNING,
                observed=info, expected=f"HTTP response within {timeout}s",
                recommendation=rec, details={"error": info},
            ))

    # ---- authoritative summary row ----------------------------------------- #
    if total and successes == 0 and other_tcp_ok:
        # Outbound TCP works but no HTTP endpoint answered: inconclusive.
        results.append(make_result(
            name="Internet connectivity summary", category=CATEGORY, status=WARNING,
            observed=f"0/{total} HTTP endpoints reachable, but other outbound TCP traffic succeeds",
            expected="At least one endpoint reachable",
            recommendation=("General connectivity appears OK; HTTP(S) egress may be filtered by "
                            "proxy/firewall, or all test sites happened to be unreachable. Verify "
                            "proxy settings before treating this as an outage."),
        ))
    elif total and successes == 0 and gateway_fail:
        # Every endpoint failed AND the gateway itself was confirmed dead by
        # independent, corroborated evidence -> sufficient for a real outage.
        results.append(make_result(
            name="Internet connectivity summary", category=CATEGORY, status=FAIL,
            observed=(f"0/{total} external endpoints reachable AND the default gateway was "
                      "confirmed unreachable by ICMP+TCP probes"),
            expected="At least one endpoint reachable",
            recommendation=("Corroborated connectivity failure: no endpoint responded and the "
                            "gateway check independently failed. Fix the local link/IP "
                            "configuration first (see gateway/interface rows), then re-run."),
        ))
    elif total and successes == 0:
        # All endpoints failed but there is no corroborated outage evidence
        # (gateway status unknown/inconclusive): never assert an outage.
        results.append(make_result(
            name="Internet connectivity summary", category=CATEGORY, status=WARNING,
            observed=f"0/{total} external endpoints reachable, but no corroborated outage evidence",
            expected="At least one endpoint reachable",
            recommendation=("No configured endpoint answered, however the rest of this run does "
                            "not confirm a wider failure (gateway probes were inconclusive or "
                            "blocked). Test in a browser before treating this as an outage; add "
                            "more reliable endpoints to network.internet_test_urls if this "
                            "persists."),
        ))
    elif total and successes < total:
        results.append(make_result(
            name="Internet connectivity summary", category=CATEGORY, status=WARNING,
            observed=f"{successes}/{total} external endpoints reachable",
            expected="All configured endpoints reachable",
            recommendation="Internet works overall - one endpoint may be down or filtered; verify proxy/firewall rules.",
        ))
    return results


# --------------------------------------------------------------------------- #
# Internal business services (TCP)
# --------------------------------------------------------------------------- #
def tcp_probe(host: str, port: int,
              timeout: float) -> tuple[bool, str, float | None]:
    """Return (ok, message, latency_ms)."""
    t0 = time.perf_counter()
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            ms = round((time.perf_counter() - t0) * 1000, 1)
            return True, f"TCP connection established ({ms} ms)", ms
    except socket.timeout:
        return False, f"Timed out after {timeout}s (host may be down, firewalled, or overloaded)", None
    except ConnectionRefusedError:
        return False, "Connection refused (host reachable but service/listener down)", None
    except socket.gaierror as exc:
        return False, f"Hostname could not be resolved: {exc}", None
    except OSError as exc:
        return False, f"Network error: {exc}", None


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
        # Defensive parse (mirrors printer raw_port handling): a malformed
        # port becomes an explicit WARNING row instead of crashing the batch.
        raw_port = svc.get("port", 0)
        try:
            port = int(raw_port)
            if not 1 <= port <= 65535:
                raise ValueError(raw_port)
        except (TypeError, ValueError):
            results.append(make_result(
                name=f"Service TCP: {svc.get('name') or host} (invalid port)",
                category=CATEGORY, status=WARNING,
                observed=f"Configured port {raw_port!r} is not a valid TCP port (1-65535); skipped",
                expected="An integer port between 1 and 65535",
                recommendation="Fix the 'port' value for this service in config.json.",
                details={"host": host, "port": raw_port},
            ))
            continue
        name = str(svc.get("name") or f"{host}:{port}")
        ok, info, _lat = tcp_probe(host, port, timeout)
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
    # Order matters: interfaces and business-service TCP probes run first so
    # the gateway check can use them as corroborating evidence (a failed ping
    # alone must never produce FAIL). The internet check likewise receives the
    # accumulated results so a single unreachable endpoint cannot by itself
    # claim a confirmed outage.
    runners = [check_interfaces, check_business_services, check_ping_hosts,
               check_gateway, check_dns, check_internet]
    # Functions that need corroborating evidence from earlier results of this
    # same run. Keep this set in sync with the signatures above - a missing
    # entry here previously raised TypeError inside the loop.
    evidence_consumers = {check_gateway, check_internet}
    results: list[CheckResult] = []
    for fn in runners:
        try:
            if fn in evidence_consumers:
                rs = fn(cfg, prior_results=results)
            else:
                rs = fn(cfg)
        except Exception as exc:  # one broken check must never kill the run
            rs = [error_result(getattr(fn, "__name__", "network check"), CATEGORY, exc)]
        results.extend(rs)
    return results
