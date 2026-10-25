"""Report generation: CSV, JSON and optional HTML into ./reports/ plus in-memory
byte buffers for Streamlit download buttons.

Reports contain only diagnostic data (host name, check names, values). No
passwords, tokens or unnecessary personal data are stored.
"""
from __future__ import annotations

import csv
import html
import io
import json
import os
import re
from datetime import datetime

REPORTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "reports")

CSV_COLUMNS = [
    "check_name", "category", "status", "observed_value", "expected_condition",
    "recommendation", "timestamp", "hostname", "app_version",
]


def _stamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def results_rows(report: dict) -> list[dict]:
    host = report.get("hostname", "")
    ver = report.get("version", "")
    rows = []
    for r in report["results"]:
        rows.append({
            "check_name": r.name,
            "category": r.category,
            "status": r.status,
            "observed_value": r.observed,
            "expected_condition": r.expected,
            "recommendation": r.recommendation,
            "timestamp": r.timestamp,
            "hostname": host,
            "app_version": ver,
        })
    return rows


def to_csv_bytes(report: dict) -> bytes:
    buf = io.StringIO(newline="")
    writer = csv.DictWriter(buf, fieldnames=CSV_COLUMNS)
    writer.writeheader()
    for row in results_rows(report):
        writer.writerow(row)
    return buf.getvalue().encode("utf-8-sig")  # BOM helps Excel


def to_json_bytes(report: dict) -> bytes:
    payload = {
        "app_name": report.get("app_name"),
        "version": report.get("version"),
        "hostname": report.get("hostname"),
        "started_local": report.get("started_local"),
        "duration_seconds": report.get("duration_seconds"),
        "summary": report.get("summary"),
        "config_problems": report.get("config_problems", []),
        "results": [r.to_dict() for r in report["results"]],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False).encode("utf-8")


_STATUS_COLORS = {"PASS": "#1a7f37", "WARNING": "#b58900", "FAIL": "#c62828", "INFO": "#455a64"}


def to_html_bytes(report: dict) -> bytes:
    esc = html.escape
    s = report.get("summary", {})
    counts = s.get("counts", {})
    rows_html = []
    for r in report["results"]:
        color = _STATUS_COLORS.get(r.status, "#333")
        rows_html.append(
            "<tr>"
            f"<td>{esc(r.timestamp)}</td><td>{esc(r.category)}</td>"
            f"<td><span style='color:{color};font-weight:600'>{esc(r.status)}</span></td>"
            f"<td>{esc(r.name)}</td><td>{esc(r.observed)}</td><td>{esc(r.expected)}</td>"
            f"<td>{esc(r.recommendation)}</td></tr>")
    doc = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>IT Health Report - {esc(str(report.get('hostname','')))}</title>
<style>
body{{font-family:'Segoe UI',Arial,sans-serif;margin:24px;color:#222}}
h1{{font-size:20px}} .meta{{color:#555;font-size:13px}}
.summary span{{display:inline-block;padding:4px 10px;border-radius:4px;margin-right:8px;
background:#eee;font-size:13px}}
table{{border-collapse:collapse;width:100%;margin-top:16px;font-size:12px}}
th,td{{border:1px solid #ddd;padding:6px;text-align:left;vertical-align:top}}
th{{background:#f5f5f5}} tr:nth-child(even){{background:#fafafa}}
.overall{{font-size:16px;font-weight:700}}
</style></head><body>
<h1>AutoDesk IT Health Monitor - Diagnostic Report</h1>
<p class="meta">Host: <b>{esc(str(report.get('hostname','')))}</b> &nbsp;|&nbsp;
Version: {esc(str(report.get('version','')))} &nbsp;|&nbsp;
Run at: {esc(str(report.get('started_local','')))} &nbsp;|&nbsp;
Duration: {report.get('duration_seconds', 0)} s</p>
<p class="overall">Overall readiness:
<span style="color:{_STATUS_COLORS.get('FAIL' if counts.get('FAIL') else ('WARNING' if counts.get('WARNING') else 'PASS'),'#333')}">
{esc(s.get('overall','UNKNOWN'))}</span></p>
<div class="summary">
<span>PASS: {counts.get('PASS',0)}</span><span>WARNING: {counts.get('WARNING',0)}</span>
<span>FAIL: {counts.get('FAIL',0)}</span><span>INFO: {counts.get('INFO',0)}</span></div>
<table><thead><tr><th>Timestamp</th><th>Category</th><th>Status</th><th>Check</th>
<th>Observed</th><th>Expected</th><th>Recommendation</th></tr></thead>
<tbody>{''.join(rows_html)}</tbody></table>
<p class="meta">Generated locally by AutoDesk IT Health Monitor. Report contains diagnostic data only.
Printer service/network status does not prove physical print capability.</p>
</body></html>"""
    return doc.encode("utf-8")


def safe_component(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", str(name))[:60]


def write_reports(report: dict, out_dir: str | None = None) -> dict[str, str]:
    """Write CSV + JSON + HTML files into reports/. Returns {format: path}."""
    out_dir = out_dir or REPORTS_DIR
    os.makedirs(out_dir, exist_ok=True)
    base = f"health_{safe_component(report.get('hostname','host'))}_{_stamp()}"
    paths = {}
    for fmt, data in (("csv", to_csv_bytes(report)),
                      ("json", to_json_bytes(report)),
                      ("html", to_html_bytes(report))):
        p = os.path.join(out_dir, f"{base}.{fmt}")
        with open(p, "wb") as fh:
            fh.write(data)
        paths[fmt] = p
    return paths
