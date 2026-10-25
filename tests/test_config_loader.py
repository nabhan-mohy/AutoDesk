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
