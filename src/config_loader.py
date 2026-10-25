"""Configuration loading and validation for AutoDesk IT Health Monitor.

Loads config.json, merges it over built-in safe defaults so that a missing or
partially-written file never crashes the application.
"""
from __future__ import annotations

import copy
import json
import os
from typing import Any

DEFAULT_CONFIG: dict[str, Any] = {
    "app_name": "AutoDesk IT Health Monitor",
    "version": "1.0.0",
    "thresholds": {
        "cpu_warning_percent": 75.0,
        "cpu_fail_percent": 95.0,
        "memory_warning_percent": 80.0,
        "memory_fail_percent": 95.0,
        "disk_warning_percent": 85.0,
        "disk_fail_percent": 95.0,
        "disk_min_free_gb_warning": 10.0,
        "uptime_minimum_hours": 0.0,
    },
    "timeouts": {
        "tcp_connect_seconds": 3.0,
        "ping_seconds": 2.0,
        "dns_resolve_seconds": 4.0,
        "subprocess_seconds": 10.0,
        "http_check_seconds": 6.0,
    },
    "network": {
        "internet_test_urls": ["https://www.google.com", "https://www.microsoft.com"],
        "dns_test_hostnames": ["www.google.com", "microsoft.com"],
        "ping_hosts": [],
        "business_services": [],
    },
    "printers": {
        "network_printers": [],
        "max_jobs_listed_per_queue": 20,
    },
}

CONFIG_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config.json"
)


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge *override* into a copy of *base*."""
    merged = copy.deepcopy(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def validate_config(cfg: dict) -> list[str]:
    """Return a list of human-readable problems found in *cfg*. Empty = valid."""
    problems: list[str] = []
    th = cfg.get("thresholds", {})
    try:
        if float(th.get("cpu_warning_percent", 0)) > float(th.get("cpu_fail_percent", 100)):
            problems.append("cpu_warning_percent is greater than cpu_fail_percent")
        if float(th.get("memory_warning_percent", 0)) > float(th.get("memory_fail_percent", 100)):
            problems.append("memory_warning_percent is greater than memory_fail_percent")
        if float(th.get("disk_warning_percent", 0)) > float(th.get("disk_fail_percent", 100)):
            problems.append("disk_warning_percent is greater than disk_fail_percent")
        for name in ("cpu", "memory", "disk"):
            w = float(th.get(f"{name}_warning_percent", 50))
            if not (0 < w <= 100):
                problems.append(f"{name}_warning_percent must be between 0 and 100")
    except (TypeError, ValueError):
        problems.append("Threshold values must be numbers")

    to = cfg.get("timeouts", {})
    try:
        for key, val in to.items():
            v = float(val)
            if v <= 0 or v > 120:
                problems.append(f"timeout '{key}' should be between 0 and 120 seconds (got {val})")
    except (TypeError, ValueError):
        problems.append("Timeout values must be numbers")

    for svc in cfg.get("network", {}).get("business_services", []):
        if svc.get("enabled"):
            if not svc.get("host"):
                problems.append(f"Business service '{svc.get('name', '?')}' is enabled but has no host")
            try:
                port = int(svc.get("port", 0))
                if not 1 <= port <= 65535:
                    problems.append(f"Business service '{svc.get('name', '?')}' has invalid port")
            except (TypeError, ValueError):
                problems.append(f"Business service '{svc.get('name', '?')}' has non-numeric port")
    return problems


def load_config(path: str | None = None) -> dict:
    """Load configuration from JSON, merging over defaults. Never raises on
    a malformed file - falls back to defaults and records the issue."""
    path = path or CONFIG_PATH
    user_cfg: dict = {}
    load_error = None
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                loaded = json.load(fh)
            if isinstance(loaded, dict):
                user_cfg = loaded
            else:
                load_error = "config.json root is not an object; using defaults"
        except (json.JSONDecodeError, OSError) as exc:
            load_error = f"Could not read config.json ({exc}); using defaults"
    cfg = _deep_merge(DEFAULT_CONFIG, user_cfg)
    cfg["_config_path"] = path
    cfg["_load_error"] = load_error
    cfg["_validation_problems"] = validate_config(cfg)
    return cfg
