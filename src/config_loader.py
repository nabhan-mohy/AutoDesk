"""Configuration loading and validation for AutoDesk IT Health Monitor.

Loads config.json, merges it over built-in safe defaults so that a missing or
partially-written file never crashes the application.
"""
from __future__ import annotations

import copy
import ipaddress
import json
import os
import re
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


def _valid_host(value: Any) -> bool:
    """Accept non-empty hostname or literal IPv4/IPv6 without scheme/spaces.

    Literal IPs are validated with the ``ipaddress`` module so typos like
    '10.0.0.999' are rejected explicitly instead of failing later at probe time.
    """
    host = str(value or "").strip()
    if not host or any(c.isspace() for c in host) or "://" in host:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    # Not an IP literal - treat as a DNS hostname (RFC-1123 style check).
    return bool(re.fullmatch(r"[A-Za-z0-9]([A-Za-z0-9\-\.]*[A-Za-z0-9])?", host)) \
        and len(host) <= 253


def _printer_port(raw: Any, label: str, problems: list[str]) -> None:
    """Validate one printer raw-port entry, appending explicit problems."""
    if raw is None:  # absent -> caller default (9100) applies
        return
    if isinstance(raw, bool):
        problems.append(f"{label} has boolean port {raw!r}; expected 1-65535")
        return
    try:
        port = int(raw)
    except (TypeError, ValueError):
        problems.append(f"{label} has non-numeric port '{raw}'")
        return
    if not 1 <= port <= 65535:
        problems.append(f"{label} has invalid port {raw} (must be 1-65535)")


def _num_in_range(value: Any, lo: float, hi: float) -> float | None:
    """Return value as float if it parses and lies within [lo, hi], else None."""
    try:
        v = float(value)
    except (TypeError, ValueError):
        return None
    return v if lo <= v <= hi else None


def validate_config(cfg: dict) -> list[str]:
    """Return a list of human-readable problems found in *cfg*. Empty = valid.

    Covers every user-tunable surface: resource thresholds (warning < fail and
    both within sane bounds), timeouts, business services, ping hosts, DNS
    hostnames, internet URLs, and network-printer addresses/ports. Malformed
    entries are reported explicitly instead of being silently ignored.
    """
    problems: list[str] = []

    # ------------------------------------------------------------------ #
    # Resource thresholds. Every value must be numeric AND inside its own
    # explicit [lower, upper] bound; warning must not exceed fail. Anything
    # out of range is reported explicitly (issue #2) - the check runners
    # additionally clamp values at use time so an invalid config can never
    # produce nonsense PASS/FAIL classifications.
    # ------------------------------------------------------------------ #
    th = cfg.get("thresholds", {})
    if not isinstance(th, dict):
        problems.append("'thresholds' section must be an object")
        th = {}

    def _check_threshold(key: str, lo: float, hi: float, required: bool = True) -> float | None:
        """Validate one threshold against explicit lower/upper bounds."""
        if key not in th or th[key] is None:
            if required:
                problems.append(f"{key} is missing; using default")
            return None
        raw = th[key]
        if isinstance(raw, bool):
            problems.append(f"{key} must be a number, got boolean {raw!r}")
            return None
        v = _num_in_range(raw, lo, hi)
        if v is None:
            try:
                float(raw)  # parses but out of range?
                problems.append(f"{key} must be between {lo:g} and {hi:g} (got {raw})")
            except (TypeError, ValueError):
                problems.append(f"{key} must be a number (got {raw!r})")
            return None
        return v

    percent_bounds = (("cpu_warning_percent", 1.0, 99.0),
                      ("cpu_fail_percent", 1.0, 100.0),
                      ("memory_warning_percent", 1.0, 99.0),
                      ("memory_fail_percent", 1.0, 100.0),
                      ("disk_warning_percent", 1.0, 99.0),
                      ("disk_fail_percent", 1.0, 100.0))
    parsed: dict[str, float | None] = {}
    for key, lo, hi in percent_bounds:
        parsed[key] = _check_threshold(key, lo, hi)

    for label, wkey, fkey in (("cpu", "cpu_warning_percent", "cpu_fail_percent"),
                              ("memory", "memory_warning_percent", "memory_fail_percent"),
                              ("disk", "disk_warning_percent", "disk_fail_percent")):
        w, f = parsed.get(wkey), parsed.get(fkey)
        if w is not None and f is not None and w > f:
            problems.append(f"{wkey} ({w:g}) is greater than {fkey} ({f:g})")

    # Optional thresholds: absent is fine (defaults apply); only explicitly
    # configured values are validated against their bounds.
    parsed["disk_min_free_gb_warning"] = _check_threshold(
        "disk_min_free_gb_warning", 0.0, 1_000_000.0, required=False)
    parsed["uptime_minimum_hours"] = _check_threshold(
        "uptime_minimum_hours", 0.0, 87_600.0, required=False)

    # ------------------------------------------------------------------ #
    # Timeouts: every key must be a positive number <= 120 seconds.
    # ------------------------------------------------------------------ #
    to = cfg.get("timeouts", {})
    if not isinstance(to, dict):
        problems.append("'timeouts' section must be an object")
        to = {}
    for key, val in to.items():
        if isinstance(val, bool) or not isinstance(val, (int, float, str)):
            problems.append(f"timeout '{key}' must be a number (got {val!r})")
            continue
        v = _num_in_range(val, 0.001, 120.0)
        if v is None:
            problems.append(f"timeout '{key}' must be between 0.001 and 120 seconds (got {val!r})")

    # ------------------------------------------------------------------ #
    # Network section
    # ------------------------------------------------------------------ #
    net = cfg.get("network", {})
    if not isinstance(net, dict):
        problems.append("'network' section must be an object")
        net = {}

    for i, url in enumerate(net.get("internet_test_urls", []) or []):
        u = str(url).strip()
        if not u:
            problems.append(f"internet_test_urls[{i}] is empty")
        elif not u.lower().startswith(("http://", "https://")):
            problems.append(f"internet_test_urls[{i}] '{url}' must start with http:// or https://")

    for i, host in enumerate(net.get("dns_test_hostnames", []) or []):
        if not _valid_host(host):
            problems.append(f"dns_test_hostnames[{i}] '{host}' is not a valid hostname")

    for i, host in enumerate(net.get("ping_hosts", []) or []):
        if not _valid_host(host):
            problems.append(f"ping_hosts[{i}] '{host}' is not a valid hostname/IP")

    svcs = net.get("business_services", [])
    if not isinstance(svcs, list):
        problems.append("network.business_services must be a list")
        svcs = []
    for i, svc in enumerate(svcs):
        if not isinstance(svc, dict):
            problems.append(f"business_services[{i}] must be an object, got {type(svc).__name__}")
            continue
        enabled = bool(svc.get("enabled"))
        name = svc.get("name", f"entry #{i + 1}")
        has_host = bool(svc.get("host")) and str(svc["host"]).strip() != ""
        if not has_host:
            if enabled:
                problems.append(f"Business service '{name}' is enabled but has no host")
        elif not _valid_host(svc["host"]):
            problems.append(f"Business service '{name}' has invalid host '{svc['host']}'")
        # Validate the port whenever it is present, enabled or not - a typo in
        # a disabled entry must be surfaced explicitly (issue #2), matching
        # how network-printer ports are treated.
        raw_port = svc.get("port")
        if raw_port is None or (isinstance(raw_port, str) and raw_port.strip() == ""):
            if enabled:
                problems.append(f"Business service '{name}' has no port (must be 1-65535)")
        else:
            _printer_port(raw_port, f"business service {name}", problems)

    # ------------------------------------------------------------------ #
    # Printers section: validate EVERY configured printer address and port,
    # whether enabled or not (a typo should be surfaced, not hidden).
    # ------------------------------------------------------------------ #
    prn = cfg.get("printers", {})
    if not isinstance(prn, dict):
        problems.append("'printers' section must be an object")
        prn = {}
    plist = prn.get("network_printers", [])
    if not isinstance(plist, list):
        problems.append("printers.network_printers must be a list")
        plist = []
    for i, p in enumerate(plist):
        if not isinstance(p, dict):
            problems.append(f"network_printers[{i}] must be an object, got {type(p).__name__}")
            continue
        name = p.get("name", f"entry #{i + 1}")
        host = str(p.get("host", "")).strip()
        enabled = bool(p.get("enabled"))
        # Validate the address for EVERY entry (even disabled ones) so typos
        # are surfaced explicitly instead of being silently skipped.
        if not host:
            if enabled:
                problems.append(f"Network printer '{name}' is enabled but has no host/IP")
        elif not _valid_host(host):
            problems.append(f"Network printer '{name}' has invalid host '{p.get('host')}'")
        # Validate the port whenever it is present, enabled or not.
        _printer_port(p.get("raw_port"), f"Network printer '{name}'", problems)

    try:
        mj = int(prn.get("max_jobs_listed_per_queue", 20))
        if not 1 <= mj <= 10000:
            problems.append(f"max_jobs_listed_per_queue must be between 1 and 10000 (got {prn.get('max_jobs_listed_per_queue')})")
    except (TypeError, ValueError):
        problems.append("max_jobs_listed_per_queue must be a number")

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
