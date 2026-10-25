"""Unit tests for report generation (no hardware/network needed)."""
import csv
import io
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.check_model import CheckResult, PASS, WARNING, FAIL
from src.health_engine import summarize
from src.reporting import to_csv_bytes, to_json_bytes, to_html_bytes, write_reports


def _report():
    results = [
        CheckResult(name="CPU utilization", category="System", status=PASS,
                    observed="12%", expected="< 75%"),
        CheckResult(name="Gateway reachability 10.0.0.1", category="Network", status=WARNING,
                    observed="loss=50%", expected="0% loss", recommendation="Check cable."),
        CheckResult(name='Printer "HP <Laser>"', category="Printer", status=FAIL,
                    observed="Offline", expected="Idle",
                    recommendation="Check power & network. HTML chars: <script>alert(1)</script>"),
    ]
    return {
        "app_name": "AutoDesk IT Health Monitor", "version": "1.0.0",
        "hostname": "SHOWROOM-PC01", "started_local": "2026-01-01T09:00:00+05:30",
        "duration_seconds": 4.2, "summary": summarize(results), "results": results,
        "config_problems": [],
    }


def test_csv_columns_and_rows():
    data = to_csv_bytes(_report())
    rows = list(csv.DictReader(io.StringIO(data.decode("utf-8-sig"))))
    assert len(rows) == 3
    required = {"check_name", "category", "status", "observed_value",
                "expected_condition", "recommendation", "timestamp", "hostname", "app_version"}
    assert required.issubset(set(rows[0].keys()))
    assert rows[2]["status"] == "FAIL"
    assert rows[2]["hostname"] == "SHOWROOM-PC01"
    assert "Check cable." in rows[1]["recommendation"]


def test_json_structure():
    payload = json.loads(to_json_bytes(_report()).decode("utf-8"))
    assert payload["hostname"] == "SHOWROOM-PC01"
    assert payload["version"] == "1.0.0"
    assert payload["summary"]["overall"] == "NOT READY"
    assert len(payload["results"]) == 3
    r = payload["results"][0]
    for key in ("name", "category", "status", "observed", "expected", "timestamp"):
        assert key in r


def test_html_escapes_and_includes_summary():
    htmltext = to_html_bytes(_report()).decode("utf-8")
    assert "SHOWROOM-PC01" in htmltext
    assert "NOT READY" in htmltext
    # XSS-style content must be escaped, not emitted raw
    assert "<script>alert(1)</script>" not in htmltext
    assert "&lt;script&gt;" in htmltext


def test_write_reports_creates_three_files(tmp_path):
    paths = write_reports(_report(), out_dir=str(tmp_path))
    assert set(paths) == {"csv", "json", "html"}
    for p in paths.values():
        assert Path(p).exists() and Path(p).stat().st_size > 0
    # hostname sanitized into file name
    assert "SHOWROOM-PC01" in Path(paths["csv"]).name


def test_no_credentials_in_output():
    blob = to_json_bytes(_report()) + to_csv_bytes(_report()) + to_html_bytes(_report())
    lowered = blob.decode("utf-8", errors="ignore").lower()
    for forbidden in ("password", "token", "secret", "credential"):
        assert forbidden not in lowered
