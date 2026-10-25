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


# Evidence classes (build-first goal: "trust every result").
# Every non-PASS row carries exactly one of these so a technician can tell at a
# glance whether something is a confirmed failure, a soft warning, an
# inconclusive probe, or simply unsupported on this host.
CONFIRMED = "confirmed"          # sufficient corroborated evidence of a real fault
WARNING_LEVEL = "warning"        # degraded but working / threshold exceeded
INCONCLUSIVE = "inconclusive"    # probe failed but cannot prove a fault (ICMP blocked, stale hints)
UNSUPPORTED = "unsupported"      # API/OS/tool unavailable here - NOT a device problem
OBSERVATION = "observation"      # informational only, never affects readiness

VALID_EVIDENCE = {CONFIRMED, WARNING_LEVEL, INCONCLUSIVE, UNSUPPORTED, OBSERVATION}


def infer_evidence(status: str, details: dict | None = None) -> str:
    """Best-effort evidence class for a result based on its status/details."""
    d = details or {}
    if d.get("evidence_class"):
        return str(d["evidence_class"])
    if d.get("error"):
        return CONFIRMED  # internal error rows are treated as definite problems
    if status == PASS:
        return OBSERVATION
    if status == INFO:
        return OBSERVATION
    if status == FAIL:
        return CONFIRMED
    # WARNING: distinguish 'could not determine / not supported' from a real
    # degraded signal using common wording in the observed text.
    obs = str(d.get("observed", "")).lower()
    if any(k in obs for k in ("could not", "cannot", "not available", "not applicable",
                              "unparsable", "restricted")):
        return INCONCLUSIVE
    return WARNING_LEVEL


@dataclass
class CheckResult:
    """One diagnostic result."""
    name: str
    category: str            # System | Network | Printer | Windows Analysis | ...
    status: str              # PASS | WARNING | FAIL | INFO
    observed: str = ""       # what was actually seen
    expected: str = ""       # the expected condition / threshold
    recommendation: str = "" # troubleshooting advice when not PASS
    details: dict = field(default_factory=dict)
    duration_ms: int | None = None   # per-check execution time (measured by engine)
    timeout_seconds: float | None = None  # configured timeout that bounded this check
    evidence: str = ""               # confirmed | warning | inconclusive | unsupported | observation
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
    )

    def __post_init__(self):
        if self.evidence not in VALID_EVIDENCE:
            self.evidence = infer_evidence(self.status, {"observed": self.observed, **self.details})

    @property
    def verdict(self) -> str:
        """Human-readable interpretation combining status + evidence class."""
        if self.status == PASS:
            return "Confirmed working"
        if self.status == INFO:
            return "Observation (no impact)"
        if self.status == FAIL:
            if self.evidence == CONFIRMED:
                return "Confirmed failure"
            return "Failure (see evidence)"
        # WARNING
        return {
            WARNING_LEVEL: "Warning - degraded",
            INCONCLUSIVE: "Inconclusive - needs manual verification",
            UNSUPPORTED: "Unsupported on this host",
            CONFIRMED: "Warning - confirmed signal",
            OBSERVATION: "Observation",
        }.get(self.evidence, "Warning")

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
                details: dict | None = None, evidence: str = "",
                timeout_seconds: float | None = None) -> CheckResult:
    d = details or {}
    ev = evidence or d.pop("evidence_class", "") or ""
    if not ev and status == INFO and any(
            k in str(observed).lower() for k in ("cannot", "not applicable", "requires windows")):
        ev = UNSUPPORTED
    return CheckResult(
        name=name,
        category=category,
        status=status if status in VALID_STATUSES else FAIL,
        observed=str(observed),
        expected=expected,
        recommendation=recommendation,
        details=d,
        evidence=ev,
        timeout_seconds=timeout_seconds,
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
