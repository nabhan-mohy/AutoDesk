
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

PASS = "PASS"
WARNING = "WARNING"
FAIL = "FAIL"
INFO = "INFO"

VALID_STATUSES = {PASS, WARNING, FAIL, INFO}

# Evidence classifications
CONFIRMED = "confirmed"
WARNING_LEVEL = "warning"
INCONCLUSIVE = "inconclusive"
UNSUPPORTED = "unsupported"
OBSERVATION = "observation"

VALID_EVIDENCE = {
    CONFIRMED,
    WARNING_LEVEL,
    INCONCLUSIVE,
    UNSUPPORTED,
    OBSERVATION,
}


def infer_evidence(status: str, details: dict | None = None) -> str:
    """Infer an evidence class from a result's status and details."""
    d = details or {}

    explicit = d.get("evidence_class")
    if explicit in VALID_EVIDENCE:
        return explicit

    if d.get("error"):
        return CONFIRMED

    if status in {PASS, INFO}:
        return OBSERVATION

    if status == FAIL:
        return CONFIRMED

    observed = str(d.get("observed", "")).lower()

    if any(
        phrase in observed
        for phrase in (
            "could not",
            "cannot",
            "not available",
            "not applicable",
            "unparsable",
            "restricted",
            "requires windows",
        )
    ):
        return INCONCLUSIVE

    return WARNING_LEVEL


@dataclass
class CheckResult:
    """One diagnostic result."""

    name: str
    category: str
    status: str
    observed: str = ""
    expected: str = ""
    recommendation: str = ""
    details: dict = field(default_factory=dict)

    # Retain both names for compatibility with existing callers.
    duration_ms: int | None = None
    execution_ms: float | None = None

    timeout_seconds: float | None = None
    evidence: str = ""
    confidence: str = "medium"

    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc)
        .astimezone()
        .isoformat(timespec="seconds")
    )

    def __post_init__(self) -> None:
        # Ensure the status is always valid.
        if self.status not in VALID_STATUSES:
            self.status = FAIL

        # Normalize evidence rather than allowing unsupported values.
        if self.evidence not in VALID_EVIDENCE:
            self.evidence = infer_evidence(
                self.status,
                {
                    "observed": self.observed,
                    **self.details,
                },
            )

        # Prevent invalid confidence values from propagating.
        if self.confidence not in {"low", "medium", "high"}:
            self.confidence = "medium"

    @property
    def verdict(self) -> str:
        """Return a technician-friendly interpretation of the result."""
        if self.status == PASS:
            return "Confirmed working"

        if self.status == INFO:
            if self.evidence == UNSUPPORTED:
                return "Unsupported on this host"
            return "Observation (no impact)"

        if self.status == FAIL:
            if self.evidence == CONFIRMED:
                return "Confirmed failure"
            if self.evidence == UNSUPPORTED:
                return "Unsupported on this host"
            return "Failure (see evidence)"

        return {
            WARNING_LEVEL: "Warning - degraded",
            INCONCLUSIVE: "Inconclusive - needs manual verification",
            UNSUPPORTED: "Unsupported on this host",
            CONFIRMED: "Warning - confirmed signal",
            OBSERVATION: "Observation",
        }.get(self.evidence, "Warning")

    def to_dict(self) -> dict[str, Any]:
        """Return a serializable dictionary representation."""
        return asdict(self)


def classify_percent(
    value: float,
    warning_at: float,
    fail_at: float,
    higher_is_worse: bool = True,
) -> str:
    """Classify a percentage metric against warning and failure thresholds."""
    try:
        value = float(value)
        warning = min(max(float(warning_at), 0.0), 100.0)
        failure = min(max(float(fail_at), 0.0), 100.0)
    except (TypeError, ValueError, OverflowError):
        return FAIL

    if higher_is_worse:
        if failure <= warning:
            return FAIL
        if value >= failure:
            return FAIL
        if value >= warning:
            return WARNING
        return PASS

    if failure <= warning:
        return FAIL
    if value <= 100.0 - failure:
        return FAIL
    if value <= 100.0 - warning:
        return WARNING
    return PASS


def safe_float(
    value: Any,
    default: float,
    lo: float | None = None,
    hi: float | None = None,
) -> float:
    """Convert a value to float, use a fallback, and optionally clamp it."""
    try:
        result = float(value)
        if not __import__("math").isfinite(result):
            result = float(default)
    except (TypeError, ValueError, OverflowError):
        result = float(default)

    if lo is not None:
        result = max(result, lo)

    if hi is not None:
        result = min(result, hi)

    return result


def make_result(
    name: str,
    category: str,
    status: str,
    observed: Any = "",
    expected: str = "",
    recommendation: str = "",
    details: dict | None = None,
    execution_ms: float | None = None,
    timeout_seconds: float | None = None,
    evidence: str = "",
    confidence: str = "medium",
    duration_ms: int | None = None,
) -> CheckResult:
    """Create a normalized diagnostic result."""
    result_details = dict(details or {})

    # Extract any evidence classification stored in details.
    details_evidence = result_details.pop("evidence_class", "")
    resolved_evidence = evidence or details_evidence or ""

    # Preserve unsupported classification for common INFO results.
    if (
        not resolved_evidence
        and status == INFO
        and any(
            phrase in str(observed).lower()
            for phrase in (
                "cannot",
                "not applicable",
                "requires windows",
                "unsupported",
            )
        )
    ):
        resolved_evidence = UNSUPPORTED

    # Keep both timing fields populated when only one is supplied.
    if execution_ms is None and duration_ms is not None:
        execution_ms = float(duration_ms)

    if duration_ms is None and execution_ms is not None:
        duration_ms = max(0, int(execution_ms))

    return CheckResult(
        name=name,
        category=category,
        status=status if status in VALID_STATUSES else FAIL,
        observed=str(observed),
        expected=expected,
        recommendation=recommendation,
        details=result_details,
        duration_ms=duration_ms,
        execution_ms=execution_ms,
        timeout_seconds=timeout_seconds,
        evidence=resolved_evidence,
        confidence=confidence,
    )


def error_result(
    name: str,
    category: str,
    exc: Exception | str,
    recommendation: str = "",
    execution_ms: float | None = None,
    timeout_seconds: float | None = None,
) -> CheckResult:
    """Convert an unexpected diagnostic exception into a FAIL result."""
    message = str(exc) if exc else repr(exc)

    return make_result(
        name=name,
        category=category,
        status=FAIL,
        observed=f"Check raised an error: {message}",
        expected="Check completes without an internal error",
        recommendation=(
            recommendation
            or "Record this error and retry the check. "
            "If it persists, review the application logs."
        ),
        details={"error": message},
        execution_ms=execution_ms,
        timeout_seconds=timeout_seconds,
        evidence=CONFIRMED,
        confidence="low",
    )
