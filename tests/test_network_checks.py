"""Unit tests for network checks, especially gateway status classification.

All ping/TCP/subprocess dependencies are mocked - no real network needed.
Rules under test:
  PASS    -> gateway connectivity succeeds (ping or TCP probe)
  WARNING -> discovery heuristic / probe inconclusive / ICMP possibly blocked
  FAIL    -> only with sufficient evidence of an actual connectivity failure
             (authoritative route + all probes + corroborating failed TCP checks)
"""
import sys
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
