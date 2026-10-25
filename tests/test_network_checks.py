"""Unit tests for network checks, especially gateway status classification.

All ping/TCP/subprocess dependencies are mocked - no real network needed.
Rules under test:
  PASS    -> gateway connectivity succeeds (ping or TCP probe)
  WARNING -> discovery heuristic / probe inconclusive / ICMP possibly blocked
  FAIL    -> only with sufficient evidence of an actual connectivity failure
             (authoritative route + all probes + corroborating failed TCP checks)
"""
import sys
import time
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.check_model import CheckResult, PASS, WARNING, FAIL
from src import network_checks as nc

CFG = {
    "timeouts": {"ping_seconds": 1, "tcp_connect_seconds": 1,
                 "dns_resolve_seconds": 1, "http_check_seconds": 1},
    "network": {},
}


def _gw_result(results):
    gw = [r for r in results if r.name.startswith("Gateway reachability")]
    assert gw, f"no gateway result in {[r.name for r in results]}"
    return gw[0]


def test_gateway_ping_success_is_pass():
    with patch.object(nc, "discover_gateways", return_value=(["10.0.0.1"], "routing table")), \
         patch.object(nc, "ping_host", return_value=(True, 2.5, "loss=0% avg=2.5ms")):
        res = nc.check_gateway(CFG)
    assert _gw_result(res).status == PASS


def test_gateway_ping_fail_tcp_success_is_pass():
    """ICMP blocked but TCP probe reaches the gateway -> reachable."""
    with patch.object(nc, "discover_gateways", return_value=(["10.0.0.1"], "routing table")), \
         patch.object(nc, "ping_host", return_value=(False, None, "100% loss")), \
         patch.object(nc, "tcp_probe", return_value=(True, "TCP connection established", 1.0)):
        res = nc.check_gateway(CFG)
    assert _gw_result(res).status == PASS


def test_gateway_failed_ping_heuristic_discovery_is_warning_not_fail():
    """Heuristic discovery + failed probes must never claim a confirmed outage."""
    with patch.object(nc, "discover_gateways", return_value=(["10.0.0.1"], "heuristic")), \
         patch.object(nc, "ping_host", return_value=(False, None, "100% loss")), \
         patch.object(nc, "tcp_probe", return_value=(False, "Timed out", None)):
        res = nc.check_gateway(CFG)
    r = _gw_result(res)
    assert r.status == WARNING
    assert "inconclusive" in r.recommendation.lower()


def test_gateway_blocked_icmp_with_working_tcp_elsewhere_is_warning():
    """A failed ping alone must not produce FAIL when other TCP checks pass."""
    prior = [CheckResult(name="Service TCP: DMS (10.1.1.5:1433)", category="Network",
                         status=PASS)]
    with patch.object(nc, "discover_gateways", return_value=(["10.0.0.1"], "routing table")), \
         patch.object(nc, "ping_host", return_value=(False, None, "100% loss")), \
         patch.object(nc, "tcp_probe", return_value=(False, "Timed out", None)):
        res = nc.check_gateway(CFG, prior_results=prior)
    assert _gw_result(res).status == WARNING


def test_gateway_confirmed_outage_all_evidence_fails_is_fail():
    """FAIL only when authoritative route + every probe + all other TCP checks fail."""
    prior = [CheckResult(name="Service TCP: DMS (10.1.1.5:1433)", category="Network",
                         status=FAIL)]
    with patch.object(nc, "discover_gateways", return_value=(["10.0.0.1"], "routing table")), \
         patch.object(nc, "ping_host", return_value=(False, None, "unreachable")), \
         patch.object(nc, "tcp_probe", return_value=(False, "Network error", None)):
        res = nc.check_gateway(CFG, prior_results=prior)
    assert _gw_result(res).status == FAIL


def test_gateway_no_discovery_is_warning():
    with patch.object(nc, "discover_gateways", return_value=([], "none")):
        res = nc.check_gateway(CFG)
    assert res[0].name == "Default gateway"
    assert res[0].status == WARNING


def test_gateway_internal_error_does_not_crash():
    with patch.object(nc, "discover_gateways", side_effect=RuntimeError("boom")):
        res = nc.check_gateway(CFG)
    assert res[0].status == FAIL
    assert "boom" in res[0].observed


def test_tcp_probe_returns_latency_tuple():
    ok, msg, ms = nc.tcp_probe("127.0.0.1", 1, 0.5)  # port 1 refused instantly
    assert ok is False
    assert isinstance(msg, str)
    assert ms is None


# --------------------------------------------------------------------------- #
# Internet endpoint classification (issue #1: no false outages from one site)
# --------------------------------------------------------------------------- #
CFG_NET = {
    "timeouts": {"http_check_seconds": 1, "tcp_connect_seconds": 1,
                 "ping_seconds": 1, "dns_resolve_seconds": 1},
    "network": {"internet_test_urls": ["https://a.test", "https://b.test"]},
}


def _endpoint(results, url):
    m = [r for r in results if r.name == f"Internet endpoint: {url}"]
    assert m, [r.name for r in results]
    return m[0]


def test_internet_one_endpoint_down_other_up_is_warning():
    """A single failing endpoint must be WARNING when another succeeds."""
    probes = {"https://a.test": (True, "HTTP 200"), "https://b.test": (False, "No response: timeout")}
    with patch.object(nc, "_http_probe", side_effect=lambda u, t: probes[u]):
        res = nc.check_internet(CFG_NET)
    assert _endpoint(res, "https://a.test").status == PASS
    assert _endpoint(res, "https://b.test").status == WARNING
    summary = [r for r in res if r.name == "Internet connectivity summary"][0]
    assert summary.status == WARNING  # never FAIL when partial success


def test_internet_all_fail_but_tcp_works_elsewhere_is_warning():
    """Zero HTTP successes but corroborated outbound TCP -> inconclusive, WARNING."""
    prior = [CheckResult(name="Gateway reachability 10.0.0.1", category="Network", status=PASS)]
    with patch.object(nc, "_http_probe", return_value=(False, "No response: blocked")):
        res = nc.check_internet(CFG_NET, prior_results=prior)
    assert all(_endpoint(res, u).status == WARNING for u in ("https://a.test", "https://b.test"))
    summary = [r for r in res if r.name == "Internet connectivity summary"][0]
    assert summary.status == WARNING


def test_internet_endpoint_rows_never_fail():
    """Issue #1: individual endpoint rows are always WARNING, never FAIL -
    a single endpoint must not decide overall readiness on its own."""
    prior = [CheckResult(name="Service TCP: DMS (10.1.1.5:1433)", category="Network", status=FAIL)]
    with patch.object(nc, "_http_probe", return_value=(False, "No response: unreachable")):
        res = nc.check_internet(CFG_NET, prior_results=prior)
    assert all(_endpoint(res, u).status == WARNING for u in ("https://a.test", "https://b.test"))


def test_internet_confirmed_outage_requires_gateway_failure_evidence():
    """Summary FAIL only when every endpoint fails AND the gateway check was
    independently confirmed dead (corroborated evidence)."""
    prior = [
        CheckResult(name="Service TCP: DMS (10.1.1.5:1433)", category="Network", status=FAIL),
        CheckResult(name="Gateway reachability 192.168.1.1", category="Network", status=FAIL),
    ]
    with patch.object(nc, "_http_probe", return_value=(False, "No response: unreachable")):
        res = nc.check_internet(CFG_NET, prior_results=prior)
    summary = [r for r in res if r.name == "Internet connectivity summary"][0]
    assert summary.status == FAIL


def test_internet_all_fail_without_corroboration_is_warning_not_fail():
    """All endpoints down but no corroborated outage evidence (gateway status
    unknown/inconclusive) -> WARNING; never report an outage from probes alone."""
    prior = [CheckResult(name="Network interfaces", category="Network", status=PASS)]
    with patch.object(nc, "_http_probe", return_value=(False, "No response: blocked")):
        res = nc.check_internet(CFG_NET, prior_results=prior)
    summary = [r for r in res if r.name == "Internet connectivity summary"][0]
    assert summary.status == WARNING


def test_internet_all_success_is_pass_no_summary_issue():
    with patch.object(nc, "_http_probe", return_value=(True, "HTTP 200")):
        res = nc.check_internet(CFG_NET)
    assert all(r.status == PASS for r in res)


# --------------------------------------------------------------------------- #
# Regression tests for hardening fixes (issue: "fix all problems on the code")
# --------------------------------------------------------------------------- #
def test_ping_loss_regex_ignores_non_loss_percentages():
    """A stray '64%' (e.g. TTL) must not be read as packet loss."""
    fake = type("R", (), {"returncode": 0, "stdout":
                          "64 bytes from 10.0.0.1: ttl=64% time=1ms\n"
                          "2 packets transmitted, 2 received, 0% packet loss",
                          "stderr": ""})()
    with patch.object(nc.subprocess, "run", return_value=fake):
        ok, avg, info = nc.ping_host("10.0.0.1", 1)
    assert ok is True
    assert "loss=0%" in info


CFG_SVC = {
    "timeouts": {"tcp_connect_seconds": 1, "ping_seconds": 1},
    "network": {"business_services": [
        {"name": "Broken DMS", "host": "dms.local", "port": "abc", "enabled": True},
        {"name": "Good DMS", "host": "dms2.local", "port": 1433, "enabled": True},
    ]},
}


def test_business_service_invalid_port_becomes_warning_not_crash():
    """A malformed port used to raise ValueError and kill the whole network run."""
    with patch.object(nc, "tcp_probe", return_value=(True, "TCP ok", 1.0)):
        res = nc.check_business_services(CFG_SVC)
    bad = [r for r in res if "invalid port" in r.name]
    good = [r for r in res if r.name.startswith("Service TCP: Good DMS")]
    assert bad and bad[0].status == WARNING
    assert good and good[0].status == PASS


def test_run_network_checks_survives_raising_check():
    """If any single check function raises, the run continues with an error row."""
    def boom(cfg, prior_results=None):
        raise RuntimeError("gateway exploded")
    with patch.object(nc, "check_interfaces", return_value=[]), \
         patch.object(nc, "check_business_services", return_value=[]), \
         patch.object(nc, "check_ping_hosts", return_value=[]), \
         patch.object(nc, "check_gateway", side_effect=boom), \
         patch.object(nc, "check_dns", return_value=[]), \
         patch.object(nc, "check_internet", return_value=[]):
        res = nc.run_network_checks(CFG)
    assert any(r.status == FAIL and "gateway exploded" in r.observed for r in res)


def test_dns_fast_gaierror_is_fail_slow_is_warning():
    cfg = {"timeouts": {"dns_resolve_seconds": 4.0},
           "network": {"dns_test_hostnames": ["x.test"]}}
    import socket as _s

    def fast_raise(host, *a, **k):
        raise _s.gaierror(-2, "Name or service not known")
    with patch.object(nc.socket, "getaddrinfo", side_effect=fast_raise):
        res = nc.check_dns(cfg)
    dns_rows = [r for r in res if r.name.startswith("DNS resolution")]
    assert dns_rows and dns_rows[0].status == nc.FAIL  # instant NXDOMAIN = definite negative

    def slow_raise(host, *a, **k):
        time.sleep(0.05)
        raise _s.gaierror(-3, "Temporary failure in name resolution")
    cfg2 = {"timeouts": {"dns_resolve_seconds": 0.001},
           "network": {"dns_test_hostnames": ["x.test"]}}
    with patch.object(nc.socket, "getaddrinfo", side_effect=slow_raise):
        res2 = nc.check_dns(cfg2)
    dns_rows2 = [r for r in res2 if r.name.startswith("DNS resolution")]
    assert dns_rows2 and dns_rows2[0].status == nc.WARNING  # timeout-ish -> inconclusive
