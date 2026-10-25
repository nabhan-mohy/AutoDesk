"""Unit tests for printer interpretation rules (issue #3).

Everything is mocked: no Windows, no printers, no network required.
Rules under test:
  - Device-reported 'Offline' status alone => WARNING, never FAIL.
  - Network probes that both fail with no corroborating local-network failure
    => WARNING (inconclusive), not a claimed outage.
  - FAIL for an unreachable network printer only when the workstation's own
    interface/gateway checks also failed.
"""
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.check_model import CheckResult, PASS, WARNING, FAIL, INFO
from src import printer_checks as pc

CFG = {
    "timeouts": {"subprocess_seconds": 2, "tcp_connect_seconds": 1, "ping_seconds": 1},
    "printers": {
        "network_printers": [
            {"name": "Showroom", "host": "10.20.30.40", "enabled": True, "raw_port": 9100},
        ],
        "max_jobs_listed_per_queue": 20,
    },
}


def _find(results, prefix):
    m = [r for r in results if r.name.startswith(prefix)]
    assert m, [r.name for r in results]
    return m[0]


def test_offline_device_status_is_warning_not_fail():
    """Win32_Printer offline flag alone must never assert a hardware outage."""
    printers = [{"Name": "Invoice MFP", "Default": True, "PrinterStatus": 7,
                 "WorkOffline": True, "PortName": "10.20.30.40", "ServerName": ""}]
    with patch.object(pc, "_is_windows", return_value=True), \
         patch.object(pc, "_query_printers", return_value=(printers, "mock")), \
         patch.object(pc, "_query_queues", return_value=[]):
        res = pc.check_installed_printers(CFG)
    r = _find(res, "Printer status: Invoice MFP")
    assert r.status == WARNING
    assert "offline" in r.observed.lower()
    assert "not prove" in r.details["note"].lower() or "NOT tested" in r.details["note"]


def test_idle_device_status_pass():
    printers = [{"Name": "OK", "Default": True, "PrinterStatus": 3,
                 "WorkOffline": False, "PortName": "WSD", "ServerName": ""}]
    with patch.object(pc, "_is_windows", return_value=True), \
         patch.object(pc, "_query_printers", return_value=(printers, "mock")), \
         patch.object(pc, "_query_queues", return_value=[]):
        res = pc.check_installed_printers(CFG)
    assert _find(res, "Printer status: OK").status == PASS


def test_network_printer_probes_only_failure_is_warning():
    """Ping+TCP both failing without other evidence => inconclusive WARNING."""
    with patch.object(pc, "tcp_probe", return_value=(False, "Timed out", None)), \
         patch.object(pc, "ping_host", return_value=(False, None, "100% loss")):
        res = pc.check_network_printers(CFG)
    r = _find(res, "Network printer: Showroom")
    assert r.status == WARNING
    assert "inconclusive" in r.recommendation.lower()


def test_network_printer_fail_requires_corroborated_local_failure():
    prior = [CheckResult(name="Gateway reachability 10.0.0.1", category="Network", status=FAIL)]
    with patch.object(pc, "tcp_probe", return_value=(False, "No route", None)), \
         patch.object(pc, "ping_host", return_value=(False, None, "unreachable")):
        res = pc.check_network_printers(CFG, prior_results=prior)
    assert _find(res, "Network printer: Showroom").status == FAIL


def test_network_printer_tcp_open_is_pass():
    with patch.object(pc, "tcp_probe", return_value=(True, "TCP connection established", 4.0)), \
         patch.object(pc, "ping_host", return_value=(False, None, "ICMP blocked")):
        res = pc.check_network_printers(CFG)
    assert _find(res, "Network printer: Showroom").status == PASS


def test_no_printers_configured_is_info():
    cfg = dict(CFG)
    cfg["printers"] = {"network_printers": [], "max_jobs_listed_per_queue": 20}
    res = pc.check_network_printers(cfg)
    assert res[0].status == INFO


def test_non_windows_enumeration_degrades_gracefully():
    with patch.object(pc, "_is_windows", return_value=False):
        res = pc.check_installed_printers(CFG)
    assert res[0].status == INFO
    assert "Windows" in res[0].recommendation or "Windows" in res[0].observed


def test_bad_raw_port_does_not_crash():
    cfg = {**CFG, "printers": {"network_printers": [
        {"name": "Weird", "host": "h", "enabled": True, "raw_port": "xyz"}],
        "max_jobs_listed_per_queue": 20}}
    with patch.object(pc, "tcp_probe", return_value=(False, "x", None)), \
         patch.object(pc, "ping_host", return_value=(False, None, "x")):
        res = pc.check_network_printers(cfg)
    assert _find(res, "Network printer: Weird").status == WARNING


def test_spooler_running_is_pass_not_a_print_claim():
    """Spooler PASS is service state only; result must not claim printing works."""
    import json
    payload = json.dumps({"Name": "Spooler", "Status": "Running", "StartType": "Automatic"})
    with patch.object(pc, "_is_windows", return_value=True), \
         patch.object(pc, "_run", return_value=(0, payload, "")):
        res = pc.check_spooler_service(CFG)
    assert res[0].status == PASS


def test_spooler_stopped_is_fail_with_manual_only_remediation():
    """Stopped spooler is a confirmed service failure, but the recommendation
    must never auto-restart anything."""
    import json
    payload = json.dumps({"Name": "Spooler", "Status": "Stopped", "StartType": "Automatic"})
    with patch.object(pc, "_is_windows", return_value=True), \
         patch.object(pc, "_run", side_effect=[(0, payload, ""), (0, "", "")]):
        res = pc.check_spooler_service(CFG)
    r = res[0]
    assert r.status == FAIL
    rec = r.recommendation.lower()
    assert "does not restart" in rec or "technician" in rec


def test_evidence_layers_are_distinct_results():
    """Device status, queue state and network reachability are separate rows:
    an offline device flag (WARNING) does not change the probe verdict."""
    printers = [{"Name": "MFP", "Default": True, "PrinterStatus": 7,
                 "WorkOffline": True, "PortName": "10.20.30.40", "ServerName": ""}]
    queues = [{"Name": "MFP", "JobCount": 3}]
    with patch.object(pc, "_is_windows", return_value=True), \
         patch.object(pc, "_query_printers", return_value=(printers, "mock")), \
         patch.object(pc, "_query_queues", return_value=queues):
        dev = pc.check_installed_printers(CFG)
    device_row = _find(dev, "Printer status: MFP")
    queue_row = _find(dev, "Queue: MFP")
    assert device_row.status == WARNING          # device-reported: uncertain
    assert queue_row.status == INFO              # queued jobs: informational
    # Network layer evaluated independently: probes succeed -> PASS regardless
    with patch.object(pc, "tcp_probe", return_value=(True, "open", 2.0)), \
         patch.object(pc, "ping_host", return_value=(True, 1.0, "ok")):
        net = pc.check_network_printers(CFG)
    assert _find(net, "Network printer: Showroom").status == PASS
