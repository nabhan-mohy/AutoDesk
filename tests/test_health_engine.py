"""Unit tests for the health engine (all hardware/network mocked)."""
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.check_model import CheckResult, PASS, WARNING, FAIL, INFO, classify_percent
from src.health_engine import summarize, run_full_check


def _r(status, name="x", category="System"):
    return CheckResult(name=name, category=category, status=status)


def test_summarize_ready():
    s = summarize([_r(PASS), _r(INFO), _r(PASS)])
    assert s["overall"] == "READY"
    assert s["counts"][PASS] == 2


def test_summarize_warning():
    s = summarize([_r(PASS), _r(WARNING)])
    assert s["overall"] == "READY WITH ISSUES"


def test_summarize_fail_overrides_warning():
    s = summarize([_r(WARNING), _r(FAIL)])
    assert s["overall"] == "NOT READY"


def test_classify_percent_thresholds():
    assert classify_percent(50, 75, 95) == PASS
    assert classify_percent(75, 75, 95) == WARNING
    assert classify_percent(80, 75, 95) == WARNING
    assert classify_percent(95, 75, 95) == FAIL
    assert classify_percent(99, 75, 95) == FAIL


def test_classify_lower_is_worse():
    # free-space style: value 4% used is fine; 96% used fails
    assert classify_percent(4, 75, 95) == PASS
    assert classify_percent(96, 75, 95) == FAIL


CFG = {
    "app_name": "Test", "version": "0.0-test",
    "thresholds": {"cpu_warning_percent": 75, "cpu_fail_percent": 95,
                   "memory_warning_percent": 80, "memory_fail_percent": 95,
                   "disk_warning_percent": 85, "disk_fail_percent": 95,
                   "disk_min_free_gb_warning": 10, "uptime_minimum_hours": 0},
    "timeouts": {"tcp_connect_seconds": 1, "ping_seconds": 1,
                 "dns_resolve_seconds": 1, "subprocess_seconds": 1, "http_check_seconds": 1},
    "network": {"internet_test_urls": [], "dns_test_hostnames": [],
                "ping_hosts": [], "business_services": []},
    "printers": {"network_printers": [], "max_jobs_listed_per_queue": 20},
}


def test_run_full_check_with_mocked_checks():
    fake_sys = [_r(PASS, "CPU utilization")]
    fake_net = [_r(WARNING, "Gateway reachability 10.0.0.1", "Network")]
    fake_prn = [_r(FAIL, "Printer status: HP", "Printer")]
    with patch("src.health_engine.run_system_checks", return_value=fake_sys), \
         patch("src.health_engine.run_network_checks", return_value=fake_net), \
         patch("src.health_engine.run_printer_checks", return_value=fake_prn):
        report = run_full_check(CFG, ["System", "Network", "Printer"])
    assert report["summary"]["overall"] == "NOT READY"
    assert report["duration_seconds"] >= 0
    assert len(report["results"]) == 3
    assert report["version"] == "0.0-test"


def test_run_full_check_crash_in_one_category_does_not_kill_run():
    def boom(cfg):
        raise RuntimeError("simulated crash")
    with patch("src.health_engine.run_system_checks", side_effect=boom), \
         patch("src.health_engine.run_network_checks", return_value=[_r(PASS, "n", "Network")]), \
         patch("src.health_engine.run_printer_checks", return_value=[]):
        report = run_full_check(CFG, ["System", "Network", "Printer"])
    # A crashing check function must be converted into a FAIL result, not propagate.
    crashed = [r for r in report["results"] if r.name == "run_system_checks"]
    assert crashed and crashed[0].status == FAIL
    assert "simulated crash" in crashed[0].observed
    assert any(r.name == "n" for r in report["results"])  # other categories still ran
    assert report["summary"]["overall"] == "NOT READY"


def test_progress_callback_invoked():
    calls = []
    with patch("src.health_engine.run_system_checks", return_value=[]), \
         patch("src.health_engine.run_network_checks", return_value=[]), \
         patch("src.health_engine.run_printer_checks", return_value=[]):
        run_full_check(CFG, ["System"], progress_cb=lambda s, f: calls.append((s, f)))
    assert calls and calls[-1][1] == 1.0
