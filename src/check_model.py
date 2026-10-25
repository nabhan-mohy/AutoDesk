"""Core check-result data model and status classification helpers.

Shared by system / network / printer checks and the health engine.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any

PASS = "PASS"
WARNING = "WARNING"
FAIL = "FAIL"
INFO = "INFO"  # informational only - never affects overall readiness

VALID_STATUSES = {PASS, WARNING, FAIL, INFO}


@dataclass
class CheckResult:
    """One diagnostic result."""
    name: str
    category: str            # System | Network | Printer
    status: str              # PASS | WARNING | FAIL | INFO
    observed: str = ""       # what was actually seen
    expected: str = ""       # the expected condition / threshold
    recommendation: str = "" # troubleshooting advice when not PASS
    details: dict = field(default_factory=dict)
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
    )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def classify_percent(value: float, warning_at: float, fail_at: float,
                     higher_is_worse: bool = True) -> str:
    """Classify a percentage-style metric against warning/fail thresholds.

    Threshold inputs are clamped defensively (issue #2): if config validation
    ever let an out-of-range value through, classification still behaves
    sanely instead of producing nonsense statuses.
    """
    try:
        w = min(max(float(warning_at), 0.0), 100.0)
        f = min(max(float(fail_at), 0.0), 100.0)
    except (TypeError, ValueError):
        w, f = 80.0, 95.0  # last-resort safe defaults
    if higher_is_worse:
        if value >= f:
            return FAIL
        if value >= w:
            return WARNING
        return PASS
    # lower is worse (e.g. free space percent)
    if value <= (100 - f):
        return FAIL
    if value <= (100 - w):
        return WARNING
    return PASS


def safe_float(value: Any, default: float, lo: float | None = None,
               hi: float | None = None) -> float:
    """Parse *value* to float; on any failure use *default*; clamp to [lo, hi]."""
    try:
        v = float(value)
    except (TypeError, ValueError):
        v = float(default)
    if lo is not None:
        v = max(v, lo)
    if hi is not None:
        v = min(v, hi)
    return v


def make_result(name: str, category: str, status: str, observed: Any = "",
                expected: str = "", recommendation: str = "",
                details: dict | None = None) -> CheckResult:
    return CheckResult(
        name=name,
        category=category,
        status=status if status in VALID_STATUSES else FAIL,
        observed=str(observed),
        expected=expected,
        recommendation=recommendation,
        details=details or {},
    )


def error_result(name: str, category: str, exc: Exception | str,
                 recommendation: str = "") -> CheckResult:
    """Wrap an unexpected exception into a FAIL result so one broken check
    can never crash the whole run."""
    msg = str(exc) if exc else repr(exc)
    return make_result(
        name=name,
        category=category,
        status=FAIL,
        observed=f"Check raised an error: {msg}",
        expected="Check completes without an internal error",
        recommendation=recommendation
        or "Note this error, retry the check; if it persists review the traceback in the console.",
        details={"error": msg},
    )
