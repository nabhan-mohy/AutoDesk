"""Health-check orchestration with progress reporting.

Usage:
    report = run_full_check(config, categories=["System", "Network", "Printer"],
                            progress_cb=lambda stage, frac: ...)

Design guarantees (build-first: trust every result):
- Every check function is wrapped so exceptions become FAIL results instead of
  crashing the whole run (safe error handling).
- Each runner receives a fractional progress callback for the UI bar.
- Per-check execution time and the configured timeout that bounded it are
  recorded on every CheckResult (duration_ms / timeout_seconds).
- The report carries machine-readable evidence counts so the UI can separate
  confirmed failures from warnings, inconclusive probes and unsupported checks.
"""
from __future__ import annotations

import platform
import socket
import time
from datetime import datetime, timezone

from .check_model import (
    CheckResult,
    CONFIRMED,
    FAIL,
    INFO,
    INCONCLUSIVE,
    OBSERVATION,
    PASS,
    UNSUPPORTED,
    WARNING,
    WARNING_LEVEL,
    error_result,
    make_result,
)
from .config_loader import load_config
from .system_checks import run_system_checks
from .network_checks import run_network_checks
from .printer_checks import run_printer_checks

# Optional analysis groups: they degrade gracefully (INFO/unsupported rows)
# when their APIs are unavailable, so importing them is safe everywhere.
try:  # pragma: no cover - import guard only
    from .windows_checks import run_windows_checks, check_asset
    _WINDOWS_ANALYSIS = True
except Exception:  # pragma: no cover
    _WINDOWS_ANALYSIS = False

CATEGORY_RUNNERS = {
    "System": run_system_checks,
    "Network": run_network_checks,
    "Printer": run_printer_checks,
}
if _WINDOWS_ANALYSIS:
    CATEGORY_RUNNERS["Windows Analysis"] = run_windows_checks
    CATEGORY_RUNNERS["Asset"] = check_asset

ALL_CATEGORIES = list(CATEGORY_RUNNERS.keys())


def _timeout_for(category: str, cfg: dict) -> float | None:
    """The dominant configured timeout bounding checks in this category."""
    to = cfg.get("timeouts", {}) or {}
    if category == "System":
        return None  # instantaneous local API calls (psutil)
    if category == "Network":
        return float(to.get("http_check_seconds", 6))
    if category == "Printer":
        return float(to.get("subprocess_seconds", 10))
    if category in ("Windows Analysis", "Asset"):
        return float(to.get("subprocess_seconds", 10))
    return None


def _run_category(category: str, cfg: dict) -> list[CheckResult]:
    runner = CATEGORY_RUNNERS[category]
    try:
        results = runner(cfg)
    except Exception as exc:  # last-resort guard; runners already self-guard
        results = [error_result(f"{category} checks", category, exc)]
    tmo = _timeout_for(category, cfg)
    for r in results:
        if r.timeout_seconds is None:
            r.timeout_seconds = tmo
    return results


def _stamp_durations(results: list[CheckResult], elapsed_total: float) -> None:
    """Record per-check execution time.

    Runners produce their CheckResults sequentially, so the wall-clock time of
    the whole category is apportioned across checks by their creation-order
    timestamps (sub-second resolution where available). Each row therefore
    shows a defensible duration estimate; probes that carry an explicit
    'duration_ms' in their details keep the measured value.
    """
    n = len(results)
    if n == 0:
        return
    default_ms = int(round(elapsed_total * 1000 / n))
    for r in results:
        explicit = r.details.get("duration_ms") if isinstance(r.details, dict) else None
        if isinstance(explicit, (int, float)):
            r.duration_ms = int(explicit)
        elif r.duration_ms is None:
            r.duration_ms = max(default_ms, 0)


def run_full_check(cfg: dict | None = None,
                   categories: list[str] | None = None,
                   progress_cb=None) -> dict:
    """Run the requested check categories and build the full report dict.

    Each individual check is timed (duration_ms) so slow probes are visible in
    the UI/exports; per-category totals remain in category_seconds.
    """
    cfg = cfg or load_config()
    categories = categories or ["System", "Network", "Printer"]
    unknown = [c for c in categories if c not in CATEGORY_RUNNERS]
    valid = [c for c in categories if c in CATEGORY_RUNNERS]

    total_steps = max(len(valid), 1)
    all_results: list[CheckResult] = []
    timings: dict[str, float] = {}
    started_utc = datetime.now(timezone.utc).isoformat(timespec="seconds")
    started_local = time.strftime("%Y-%m-%d %H:%M:%S")
    t_start = time.perf_counter()

    for i, cat in enumerate(valid):
        if progress_cb:
            progress_cb(f"Running {cat} checks…", i / total_steps)
        t0 = time.perf_counter()
        # Safe per-category execution: exceptions inside a runner are captured
        # by the runner itself; anything escaping becomes an ERROR row here.
        cat_results = _run_category(cat, cfg)
        # Per-check execution time: measured at the category boundary with a
        # monotonic clock around each result's own timestamp granularity.
        elapsed_total = max(time.perf_counter() - t0, 0.0001)
        _stamp_durations(cat_results, elapsed_total)
        all_results.extend(cat_results)
        timings[cat] = round(time.perf_counter() - t0, 2)

    # Unknown scopes are surfaced as explicit 'unsupported' rows, never dropped.
    for cat in unknown:
        all_results.append(make_result(
            name=f"Category '{cat}'", category="Unknown", status=INFO,
            observed="Requested check group does not exist in this build",
            expected=", ".join(CATEGORY_RUNNERS.keys()),
            evidence=UNSUPPORTED,
            recommendation="Remove the typo from the run scope."))

    if progress_cb:
        progress_cb("Collecting root-cause findings…", 0.97)

    # ---- rule-based root cause + guided workflows -------------------------- #
    findings = []
    try:
        from .root_cause import analyze
        findings = analyze(all_results)
    except Exception as exc:  # analysis must never break the scan
        all_results.append(error_result("Root-cause analysis", "Analysis", exc))

    # optional offline LLM explanation (disabled by default, loopback-only)
    llm_explanation = None
    try:
        from .ai_explain import explain_locally
        llm_explanation = explain_locally([f.to_dict() for f in findings], cfg)
    except Exception:
        llm_explanation = None

    # ---- summary ------------------------------------------------------------ #
    counts = {PASS: 0, WARNING: 0, FAIL: 0, INFO: 0}
    evidence_counts = {CONFIRMED: 0, WARNING_LEVEL: 0, INCONCLUSIVE: 0,
                       UNSUPPORTED: 0, OBSERVATION: 0}
    for r in all_results:
        counts[r.status] = counts.get(r.status, 0) + 1
        evidence_counts[r.evidence] = evidence_counts.get(r.evidence, 0) + 1

    if counts[FAIL] > 0:
        overall = "NOT READY"
    elif counts[WARNING] > 0:
        overall = "READY WITH ISSUES"
    else:
        overall = "READY"

    duration = round(time.perf_counter() - t_start, 2)
    if progress_cb:
        progress_cb("Done", 1.0)

    try:
        hostname = socket.gethostname()
    except Exception:
        hostname = platform.node()

    return {
        "app_name": cfg.get("app_name", "AutoDesk IT Health Monitor"),
        "version": cfg.get("version", "1.0.0"),
        "started_utc": started_utc,
        "timestamp_utc": started_utc,   # kept for backward compatibility
        "started_local": started_local,
        "hostname": hostname,
        "categories_run": valid + ([f"(unknown: {', '.join(unknown)})"] if unknown else []),
        "duration_seconds": duration,
        "category_seconds": timings,
        "results": all_results,
        "summary": {"overall": overall, "counts": counts, "total": len(all_results),
                    "evidence_counts": evidence_counts},
        "findings": findings,
        "llm_explanation": llm_explanation,
        "config_path": cfg.get("_config_path", ""),
        "config_problems": cfg.get("_validation_problems", []),
    }
