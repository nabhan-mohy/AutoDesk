"""Health engine: orchestrates all checks, computes overall readiness."""
from __future__ import annotations

import time
from datetime import datetime, timezone

from .check_model import CheckResult, FAIL, INFO, PASS, WARNING
from .config_loader import load_config
from .system_checks import run_system_checks
from .network_checks import run_network_checks
from .printer_checks import run_printer_checks


def summarize(results: list[CheckResult]) -> dict:
    counts = {PASS: 0, WARNING: 0, FAIL: 0, INFO: 0}
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1
    if counts[FAIL]:
        overall = "NOT READY"
    elif counts[WARNING]:
        overall = "READY WITH ISSUES"
    else:
        overall = "READY"
    return {"counts": counts, "overall": overall, "total": len(results)}


def _safe(fn, cfg, category, fn_name=None) -> list[CheckResult]:
    try:
        return fn(cfg)
    except Exception as exc:  # pragma: no cover - runners already guard
        from .check_model import error_result
        name = fn_name or getattr(fn, "__name__", None) or str(fn)
        return [error_result(name, category, exc)]


def run_full_check(cfg: dict | None = None, categories: list[str] | None = None,
                   progress_cb=None) -> dict:
    """Run the requested check categories and return a report dictionary.

    progress_cb: optional callable(str stage, float fraction 0..1).
    """
    cfg = cfg or load_config()
    categories = categories or ["System", "Network", "Printer"]
    stages = [("System", "run_system_checks", run_system_checks),
              ("Network", "run_network_checks", run_network_checks),
              ("Printer", "run_printer_checks", run_printer_checks)]
    all_results: list[CheckResult] = []
    start = time.time()
    for i, (cat, fn_name, fn) in enumerate(stages):
        if cat not in categories:
            continue
        if progress_cb:
            progress_cb(f"Running {cat.lower()} checks...", i / len(stages))
        all_results.extend(_safe(fn, cfg, cat, fn_name))
    if progress_cb:
        progress_cb("Done", 1.0)
    duration = round(time.time() - start, 2)
    summary = summarize(all_results)
    return {
        "app_name": cfg.get("app_name", "AutoDesk IT Health Monitor"),
        "version": cfg.get("version", "1.0.0"),
        "hostname": next((r.details.get("hostname") for r in all_results
                           if r.name == "Computer identity"), "") or __import__("socket").gethostname(),
        "started_local": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
        "duration_seconds": duration,
        "summary": summary,
        "results": all_results,
        "config_problems": cfg.get("_validation_problems", []),
        "config_load_error": cfg.get("_load_error"),
    }
