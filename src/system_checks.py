"""System health checks (hostname, OS, CPU, RAM, disks, uptime).

All checks use psutil and platform - no admin rights required.  Every public
check function returns a list of CheckResult and never raises: unexpected
errors are converted into FAIL results so one bad check cannot crash the run.
"""
from __future__ import annotations

import getpass
import os
import platform
import socket
import time

import psutil

from .check_model import (
    CheckResult,
    FAIL,
    INFO,
    PASS,
    WARNING,
    classify_percent,
    error_result,
    make_result,
    safe_float,
)

CATEGORY = "System"


def _fmt_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024 or unit == "TB":
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def _fmt_duration(seconds: float) -> str:
    m, s = divmod(int(seconds), 60)
    h, m = divmod(m, 60)
    d, h = divmod(h, 24)
    parts = []
    if d:
        parts.append(f"{d}d")
    if h:
        parts.append(f"{h}h")
    if m:
        parts.append(f"{m}m")
    parts.append(f"{s}s")
    return " ".join(parts)


def _thresholds(cfg: dict) -> dict:
    """Return resource thresholds with explicit bounds enforced (issue #2).

    Validation in config_loader already flags out-of-range values; this is the
    second line of defence so classification always uses sane numbers even if a
    hand-edited config slips through. Defaults mirror DEFAULT_CONFIG.
    """
    th = cfg.get("thresholds", {}) or {}
    d = {
        "cpu_warning_percent": safe_float(th.get("cpu_warning_percent"), 75.0, 1.0, 99.0),
        "cpu_fail_percent": safe_float(th.get("cpu_fail_percent"), 95.0, 1.0, 100.0),
        "memory_warning_percent": safe_float(th.get("memory_warning_percent"), 80.0, 1.0, 99.0),
        "memory_fail_percent": safe_float(th.get("memory_fail_percent"), 95.0, 1.0, 100.0),
        "disk_warning_percent": safe_float(th.get("disk_warning_percent"), 85.0, 1.0, 99.0),
        "disk_fail_percent": safe_float(th.get("disk_fail_percent"), 95.0, 1.0, 100.0),
        "disk_min_free_gb_warning": safe_float(th.get("disk_min_free_gb_warning"), 10.0, 0.0, 1_000_000.0),
        "uptime_minimum_hours": safe_float(th.get("uptime_minimum_hours"), 0.0, 0.0, 87_600.0),
    }
    # warning must never exceed fail after clamping
    for pre in ("cpu", "memory", "disk"):
        w, k = f"{pre}_warning_percent", f"{pre}_fail_percent"
        if d[w] > d[k]:
            d[w] = d[k]
    return d


# --------------------------------------------------------------------------- #
# Individual checks
# --------------------------------------------------------------------------- #
def check_identity() -> list[CheckResult]:
    try:
        host = socket.gethostname()
        try:
            user = getpass.getuser()
        except Exception:
            user = os.environ.get("USERNAME") or os.environ.get("USER") or "unknown"
        info = {
            "hostname": host,
            "username": user,
            "os": f"{platform.system()} {platform.release()}",
            "os_version": platform.version(),
            "architecture": platform.machine(),
            "python": platform.python_version(),
        }
        return [make_result(
            name="Computer identity",
            category=CATEGORY,
            status=INFO,
            observed=f"Host '{host}', user '{user}', {info['os']} ({info['architecture']})",
            expected="Informational",
            details=info,
        )]
    except Exception as exc:  # pragma: no cover - defensive
        return [error_result("Computer identity", CATEGORY, exc)]


def check_cpu(cfg: dict) -> list[CheckResult]:
    try:
        th = _thresholds(cfg)
        pct = psutil.cpu_percent(interval=1)
        cores = psutil.cpu_count(logical=True)
        status = classify_percent(pct, th["cpu_warning_percent"], th["cpu_fail_percent"])
        rec = ""
        if status == WARNING:
            rec = ("CPU load is elevated. Close unused applications and check Task Manager "
                   "for runaway processes; on showroom PCs verify antivirus scans are not "
                   "scheduled during business hours.")
        elif status == FAIL:
            rec = ("CPU is saturated. Open Task Manager, identify the top process, restart "
                   "the affected application. If persistent, reboot the PC and escalate to "
                   "the IT lead.")
        return [make_result(
            name="CPU utilization",
            category=CATEGORY,
            status=status,
            observed=f"{pct}% across {cores} logical cores",
            expected=f"< {th['cpu_warning_percent']}% (warning at {th['cpu_warning_percent']}%, fail at {th['cpu_fail_percent']}%)",
            recommendation=rec,
            details={"percent": pct, "logical_cores": cores},
        )]
    except Exception as exc:
        return [error_result("CPU utilization", CATEGORY, exc)]


def check_memory(cfg: dict) -> list[CheckResult]:
    try:
        th = _thresholds(cfg)
        vm = psutil.virtual_memory()
        status = classify_percent(vm.percent, th["memory_warning_percent"], th["memory_fail_percent"])
        rec = ""
        if status == WARNING:
            rec = ("RAM usage is high. Close browser tabs / unused applications. If a "
                   "billing workstation consistently runs above this level, consider "
                   "increasing physical RAM.")
        elif status == FAIL:
            rec = ("RAM is nearly exhausted - expect freezes and slow DMS response. Save "
                   "work, close heavy applications, and reboot if needed. Escalate if it "
                   "recurs after reboot.")
        return [make_result(
            name="Memory utilization",
            category=CATEGORY,
            status=status,
            observed=f"{vm.percent}% used ({_fmt_bytes(vm.used)} of {_fmt_bytes(vm.total)})",
            expected=f"< {th['memory_warning_percent']}% (fail at {th['memory_fail_percent']}%)",
            recommendation=rec,
            details={"percent": vm.percent, "total_gb": round(vm.total / 1e9, 2),
                     "available_gb": round(vm.available / 1e9, 2)},
        )]
    except Exception as exc:
        return [error_result("Memory utilization", CATEGORY, exc)]


def check_disks(cfg: dict) -> list[CheckResult]:
    results: list[CheckResult] = []
    try:
        th = _thresholds(cfg)
        partitions = psutil.disk_partitions(all=False)
        if not partitions:
            return [make_result(
                name="Disk space", category=CATEGORY, status=WARNING,
                observed="No mounted disk partitions found",
                expected="At least one readable data partition",
                recommendation="Verify drives are visible in Disk Management.",
            )]
        for part in partitions:
            mount = part.mountpoint
            # Skip read-only media that cannot be queried (e.g. empty CD drive)
            try:
                usage = psutil.disk_usage(mount)
            except (PermissionError, OSError):
                continue
            if usage.total == 0:
                continue
            used_pct = usage.percent
            free_gb = usage.free / (1024 ** 3)
            status = classify_percent(used_pct, th["disk_warning_percent"], th["disk_fail_percent"])
            if status == PASS and free_gb < th["disk_min_free_gb_warning"]:
                status = WARNING
            rec = ""
            reason = []
            if status != PASS:
                reason.append(f"{used_pct}% used")
                if free_gb < th["disk_min_free_gb_warning"]:
                    reason.append(f"only {free_gb:.1f} GB free")
                rec = (f"Free space on {mount}: delete temp files (Disk Cleanup / Storage Sense), "
                       "empty Recycle Bin, move large files to the server. Windows updates need "
                       "at least several GB of headroom.")
            results.append(make_result(
                name=f"Disk space {mount}",
                category=CATEGORY,
                status=status,
                observed=f"Total {_fmt_bytes(usage.total)}, Used {_fmt_bytes(usage.used)}, Free {_fmt_bytes(usage.free)} ({used_pct}% used)",
                expected=f"< {th['disk_warning_percent']}% used and >= {th['disk_min_free_gb_warning']} GB free",
                recommendation=rec,
                details={"mount": mount, "percent": used_pct, "free_gb": round(free_gb, 2),
                         "total_gb": round(usage.total / 1e9, 2), "reason": "; ".join(reason)},
            ))
        if not results:
            results.append(make_result(
                name="Disk space", category=CATEGORY, status=INFO,
                observed="No queryable partitions (all access-denied or empty)",
                expected="At least one partition", recommendation="Run the tool with a normal user session."))
        return results
    except Exception as exc:
        return [error_result("Disk space", CATEGORY, exc)]


def check_uptime(cfg: dict) -> list[CheckResult]:
    try:
        boot = psutil.boot_time()
        uptime_s = time.time() - boot
        min_hours = _thresholds(cfg)["uptime_minimum_hours"]
        status = PASS
        rec = ""
        if min_hours and uptime_s / 3600 < min_hours:
            status = WARNING
            rec = (f"Machine rebooted less than {min_hours:g} hours ago. Verify Windows "
                   "did not unexpectedly restart during business hours (check Event Viewer).")
        return [make_result(
            name="System uptime",
            category=CATEGORY,
            status=status,
            observed=_fmt_duration(uptime_s),
            expected=">= configured minimum" if min_hours else "Informational",
            recommendation=rec,
            details={"uptime_seconds": int(uptime_s)},
        )]
    except Exception as exc:
        return [error_result("System uptime", CATEGORY, exc)]


def run_system_checks(cfg: dict) -> list[CheckResult]:
    """Run all system checks and append a summary timestamp result."""
    results: list[CheckResult] = []
    for fn in (lambda c: check_identity(), check_cpu, check_memory, check_disks, check_uptime):
        try:
            results.extend(fn(cfg))
        except Exception as exc:  # pragma: no cover - functions already guard
            results.append(error_result(fn.__name__, CATEGORY, exc))
    results.append(make_result(
        name="Health check timestamp",
        category=CATEGORY,
        status=INFO,
        observed=time.strftime("%Y-%m-%d %H:%M:%S"),
        expected="Informational",
    ))
    return results
