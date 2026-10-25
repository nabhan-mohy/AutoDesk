"""Unit tests for configuration loading and validation."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.config_loader import load_config, validate_config, DEFAULT_CONFIG, _deep_merge


def test_load_real_project_config():
    cfg = load_config()  # repo config.json
    assert cfg["app_name"] == "AutoDesk IT Health Monitor"
    assert cfg["_load_error"] is None
    assert isinstance(cfg["thresholds"]["cpu_warning_percent"], float)
    # shipped defaults must pass validation
    assert cfg["_validation_problems"] == []


def test_missing_file_falls_back_to_defaults(tmp_path):
    cfg = load_config(str(tmp_path / "nope.json"))
    assert cfg["thresholds"] == DEFAULT_CONFIG["thresholds"]
    assert cfg["_load_error"] is None  # missing file is not an error, just defaults


def test_malformed_json_uses_defaults(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{ this is not json", encoding="utf-8")
    cfg = load_config(str(p))
    assert cfg["_load_error"] is not None
    assert cfg["timeouts"] == DEFAULT_CONFIG["timeouts"]


def test_partial_config_merged_over_defaults(tmp_path):
    p = tmp_path / "part.json"
    p.write_text(json.dumps({"thresholds": {"cpu_warning_percent": 60}}), encoding="utf-8")
    cfg = load_config(str(p))
    assert cfg["thresholds"]["cpu_warning_percent"] == 60
    # untouched keys keep defaults
    assert cfg["thresholds"]["memory_warning_percent"] == \
        DEFAULT_CONFIG["thresholds"]["memory_warning_percent"]


def test_validate_flags_inverted_thresholds():
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))
    cfg["thresholds"]["cpu_warning_percent"] = 99
    cfg["thresholds"]["cpu_fail_percent"] = 50
    problems = validate_config(cfg)
    assert any("cpu_warning_percent" in p for p in problems)


def test_validate_flags_enabled_service_without_host():
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))
    cfg["network"]["business_services"] = [{"name": "DMS", "host": "", "port": 1433, "enabled": True}]
    problems = validate_config(cfg)
    assert any("DMS" in p and "no host" in p for p in problems)


def test_validate_flags_bad_port_and_timeout():
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))
    cfg["network"]["business_services"] = [{"name": "App", "host": "srv", "port": 70000, "enabled": True}]
    cfg["timeouts"]["tcp_connect_seconds"] = -5
    problems = validate_config(cfg)
    assert any("invalid port" in p for p in problems)
    assert any("timeout" in p for p in problems)


def test_deep_merge_nested():
    merged = _deep_merge({"a": {"b": 1, "c": 2}}, {"a": {"c": 3}})
    assert merged == {"a": {"b": 1, "c": 3}}


# --------------------------------------------------------------------------- #
# Extended validation coverage (issue #2)
# --------------------------------------------------------------------------- #
def _base_cfg():
    from src.config_loader import DEFAULT_CONFIG
    import copy
    return copy.deepcopy(DEFAULT_CONFIG)


def test_default_config_is_valid():
    assert validate_config(_base_cfg()) == []


def test_rejects_fail_below_warning():
    cfg = _base_cfg()
    cfg["thresholds"]["cpu_fail_percent"] = 50.0  # below warning 75
    problems = " ".join(validate_config(cfg))
    assert "cpu_warning_percent" in problems and "cpu_fail_percent" in problems


def test_rejects_out_of_range_threshold_bounds():
    cfg = _base_cfg()
    cfg["thresholds"]["memory_fail_percent"] = 150.0
    cfg["thresholds"]["disk_min_free_gb_warning"] = -5
    cfg["thresholds"]["uptime_minimum_hours"] = -1
    problems = " ".join(validate_config(cfg))
    assert "memory_fail_percent" in problems
    assert "disk_min_free_gb_warning" in problems
    assert "uptime_minimum_hours" in problems


def test_rejects_non_numeric_threshold():
    cfg = _base_cfg()
    cfg["thresholds"]["cpu_warning_percent"] = "high"
    assert any("cpu" in p for p in validate_config(cfg))


def test_validates_printer_port_and_host_even_when_disabled():
    cfg = _base_cfg()
    cfg["printers"]["network_printers"] = [
        {"name": "Shop", "host": "bad host name", "enabled": False, "raw_port": 99999},
        {"name": "Front", "host": "10.0.0.5", "enabled": True, "raw_port": "abc"},
    ]
    problems = " ".join(validate_config(cfg))
    assert "Shop" in problems and "invalid port" in problems
    assert "Front" in problems and "non-numeric port" in problems


def test_enabled_printer_without_host_flagged():
    cfg = _base_cfg()
    cfg["printers"]["network_printers"] = [{"name": "Ghost", "host": "", "enabled": True}]
    assert any("Ghost" in p and "no host" in p for p in validate_config(cfg))


def test_malformed_list_entries_reported():
    cfg = _base_cfg()
    cfg["printers"]["network_printers"] = ["not-an-object"]
    cfg["network"]["business_services"] = [42]
    cfg["network"]["internet_test_urls"] = ["ftp://nope", "  "]
    cfg["network"]["ping_hosts"] = ["has space"]
    problems = " ".join(validate_config(cfg))
    assert "must be an object" in problems
    assert "http://" in problems or "https://" in problems
    assert "ping_hosts[0]" in problems


def test_bad_timeout_values_reported_per_key():
    cfg = _base_cfg()
    cfg["timeouts"]["ping_seconds"] = 0
    cfg["timeouts"]["dns_resolve_seconds"] = "fast"
    problems = " ".join(validate_config(cfg))
    assert "ping_seconds" in problems and "dns_resolve_seconds" in problems
