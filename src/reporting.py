"""Report generation: JSON / CSV / Markdown / HTML / PDF + integrity hash.

All formats are produced from the same report dict returned by health_engine,
so a technician can hand off whatever their helpdesk accepts. Every export
embeds a SHA-256 'integrity stamp' computed over the canonical result data;
verify_report() re-computes it so tampered/edited reports are detectable.
The PDF is rendered by the dependency-free writer in src/pdf_report.py and is
verified with pypdf when available (CI) - never required at runtime.
"""
from __future__ import annotations

import csv
import hashlib
import html
import io
import json
import os
from datetime import datetime

from .check_model import CheckResult  # noqa: F401 (used in typing)

EXPORT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "exports")

STATUS_ICON = {"PASS": "✅", "WARNING": "⚠️", "FAIL": "❌", "INFO": "ℹ️"}
EVIDENCE_LABEL = {
    "confirmed": "CONFIRMED failure evidence",
    "warning": "Warning signal",
    "inconclusive": "INCONCLUSIVE - verify manually",
    "unsupported": "UNSUPPORTED on this host",
    "observation": "Observation",
}


def _stamp_payload(report: dict) -> dict:
    """Canonical, deterministic subset of the report used for the integrity hash."""
    return {
        "hostname": report.get("hostname", ""),
        "started_utc": report.get("started_utc", report.get("timestamp_utc", "")),
        "version": report.get("version", ""),
        "summary": report.get("summary", {}),
        "results": [r.to_dict() for r in report.get("results", [])],
    }


def compute_integrity(report: dict) -> str:
    blob = json.dumps(_stamp_payload(report), sort_keys=True, default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def verify_report(report: dict, expected_sha256: str | None = None) -> dict:
    """Recompute the integrity hash and compare against the stored one.

    Returns {'ok': bool, 'expected': str, 'actual': str, 'reason': str}. Pass
    expected_sha256 to verify an external copy (e.g. received from an agent).
    """
    actual = compute_integrity(report)
    expected = expected_sha256 or report.get("report_sha256", "")
    if not expected:
        return {"ok": False, "expected": "", "actual": actual,
                "reason": "no integrity stamp present on this report"}
    return {"ok": actual == expected, "expected": expected, "actual": actual,
            "reason": "" if actual == expected else
            "content differs from the signed stamp - report may have been edited"}


# --------------------------------------------------------------------------- #
# Formats
# --------------------------------------------------------------------------- #
def to_json(report: dict) -> str:
    d = dict(report)
    d["results"] = [r.to_dict() for r in report.get("results", [])]
    if d.get("findings"):
        d["findings"] = [f.to_dict() if hasattr(f, "to_dict") else f for f in d["findings"]]
    d.pop("_saved_paths", None)
    return json.dumps(d, indent=2, default=str, ensure_ascii=False)


def to_csv(report: dict) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["timestamp", "category", "check", "status", "verdict", "evidence",
                "duration_ms", "timeout_s", "observed", "expected", "recommendation"])
    s = report.get("summary", {})
    w.writerow([report.get("started_local", ""), "SUMMARY", "Overall readiness",
                s.get("overall", ""), "", "", report.get("duration_seconds", ""), "",
                f"counts={s.get('counts',{})}", "", ""])
    for r in report.get("results", []):
        w.writerow([r.timestamp, r.category, r.name, r.status, r.verdict, r.evidence,
                    r.duration_ms if r.duration_ms is not None else "",
                    r.timeout_seconds if r.timeout_seconds is not None else "",
                    r.observed, r.expected, r.recommendation])
    return buf.getvalue()


def to_markdown(report: dict) -> str:
    s = report["summary"]
    lines = [f"# {report['app_name']} — Health Report",
             "",
             f"- **Host:** `{report['hostname']}`",
             f"- **Started:** {report['started_local']} "
             f"(UTC {report.get('started_utc', report.get('timestamp_utc',''))})",
             f"- **Duration:** {report['duration_seconds']} s",
             f"- **Overall:** **{s['overall']}**",
             f"- **Checks:** {s['total']} — PASS {s['counts'].get('PASS',0)}, "
             f"WARNING {s['counts'].get('WARNING',0)}, FAIL {s['counts'].get('FAIL',0)}, "
             f"INFO {s['counts'].get('INFO',0)}",
             f"- **Evidence:** confirmed {s['evidence_counts'].get('confirmed',0)}, "
             f"warning {s['evidence_counts'].get('warning',0)}, "
             f"inconclusive {s['evidence_counts'].get('inconclusive',0)}, "
             f"unsupported {s['evidence_counts'].get('unsupported',0)}",
             ""]
    findings = report.get("findings") or []
    if findings:
        lines += ["## Probable root causes (rule-based)", ""]
        for f in findings:
            fd = f.to_dict() if hasattr(f, "to_dict") else f
            lines.append(f"### {fd['title']} — confidence {int(float(fd['confidence'])*100)}%")
            lines.append(f"*{fd['summary']}*")
            if fd.get("uncertainty"):
                lines.append(f"- Uncertainty: {fd['uncertainty']}")
            lines.append(f"- Evidence: {', '.join(fd.get('evidence') or [])}")
            lines.append(f"- Recommended action: {fd.get('recommendation','')}")
            lines.append("")
    problems = [r for r in report["results"] if r.status in ("FAIL", "WARNING")]
    if problems:
        lines += ["## Issues needing attention", "",
                  "| Status | Category | Check | Observed | Expected | Recommended action |",
                  "|---|---|---|---|---|---|"]
        for r in problems:
            lines.append(f"| {STATUS_ICON.get(r.status, r.status)} {r.status} "
                         f"({EVIDENCE_LABEL.get(r.evidence, r.evidence)}) "
                         f"| {r.category} | {r.name} | {r.observed[:180]} "
                         f"| {r.expected} | {r.recommendation} |")
        lines.append("")
    lines += ["## All checks", "",
              "| Status | Category | Check | Observed | Time |",
              "|---|---|---|---|---|"]
    for r in report["results"]:
        t = f"{r.duration_ms} ms" if r.duration_ms is not None else ""
        lines.append(f"| {STATUS_ICON.get(r.status, r.status)} {r.status} | {r.category} "
                     f"| {r.name} | {r.observed[:180]} | {t} |")
    lines += ["", "---",
              f"Generated locally by {report['app_name']} v{report['version']}. "
              "This tool only reads diagnostics; no remediation was performed.",
              f"Integrity SHA-256: `{report.get('report_sha256','')}`"]
    return "\n".join(lines)


CSS = """
body{font-family:'Segoe UI',Arial,sans-serif;background:#f4f6f8;color:#212529;margin:0}
.wrap{max-width:1000px;margin:auto;padding:24px}
.card{background:#fff;border-radius:10px;box-shadow:0 1px 4px rgba(0,0,0,.12);padding:18px;margin-bottom:18px}
h1{font-size:22px;margin:0 0 4px} .muted{color:#6c757d;font-size:13px}
.badge{display:inline-block;padding:6px 16px;border-radius:20px;font-weight:700;color:#fff}
.b-ready{background:#1f9d55}.b-warn{background:#e8a013}.b-fail{background:#d64545}
table{border-collapse:collapse;width:100%;font-size:13px}
th,td{border-bottom:1px solid #e6e9ec;padding:7px 9px;text-align:left;vertical-align:top}
th{background:#f0f2f4}
tr.FAIL td{background:#fdecec}tr.WARNING td{background:#fff7e3}tr.INFO td{color:#5f6b76}
.pill{padding:2px 8px;border-radius:10px;font-size:11px;font-weight:700;color:#fff}
.p-confirmed{background:#d64545}.p-warning{background:#e8a013}.p-inconclusive{background:#7c6bd6}
.p-unsupported{background:#8d99a6}.p-observation{background:#5f6b76}
.finding{border-left:4px solid #d64545;padding:8px 12px;margin:8px 0;background:#fffafa}
.meta{font-size:12px;color:#6c757d}
"""

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title><style>{css}</style></head>
<body><div class="wrap">
<div class="card">
  <h1>{app} — Workstation Readiness Report</h1>
  <div class="muted">Host <b>{host}</b> &nbsp;•&nbsp; Started {started} &nbsp;•&nbsp; Duration {dur}s
  &nbsp;•&nbsp; v{ver} &nbsp;•&nbsp; read-only diagnostics</div>
  <p><span class="badge {badgecls}">{overall}</span></p>
  <div class="meta">PASS {np} &nbsp; WARNING {nw} &nbsp; FAIL {nf} &nbsp; INFO {ni}<br>
  Evidence classes: confirmed {ec} • warning {ew} • inconclusive {ei} • unsupported {eu}</div>
</div>
{findings_html}
<div class="card"><h2>Issues needing attention</h2>{issues_table}</div>
<div class="card"><h2>All checks ({ntotal})</h2>{all_table}</div>
<div class="card meta">Generated locally by {app} v{ver}. No remediation was performed.<br>
Integrity SHA-256: <code>{sha}</code></div>
</div></body></html>
"""


def _rows_html(results, with_action=True) -> str:
    head = ("<tr><th>Status</th><th>Evidence</th><th>Category</th><th>Check</th>"
            "<th>Observed</th><th>Expected</th>")
    head += ("<th>Recommended action</th><th>Time</th>" if with_action else "<th>Time</th>")
    head += "</tr>"
    body = []
    for r in results:
        t = f"{r.duration_ms} ms" if r.duration_ms is not None else ""
        row = (f"<tr class='{r.status}'><td>{STATUS_ICON.get(r.status,'')} {r.status}</td>"
               f"<td><span class='pill p-{r.evidence}'>{r.evidence}</span></td>"
               f"<td>{html.escape(r.category)}</td><td>{html.escape(r.name)}</td>"
               f"<td>{html.escape(r.observed[:300])}</td><td>{html.escape(r.expected)}</td>")
        if with_action:
            row += f"<td>{html.escape(r.recommendation)}</td>"
        row += f"<td>{t}</td></tr>"
        body.append(row)
    if not body:
        return "<p class='muted'>None.</p>"
    return f"<table>{head}{''.join(body)}</table>"


def to_html(report: dict) -> str:
    s = report["summary"]
    ec = s.get("evidence_counts", {})
    overall = s["overall"]
    badge = {"READY": "b-ready", "READY WITH ISSUES": "b-warn"}.get(overall, "b-fail")
    findings = report.get("findings") or []
    fh = ""
    if findings:
        items = []
        for f in findings:
            fd = f.to_dict() if hasattr(f, "to_dict") else f
            unc = (f"<div class='meta'>Uncertainty: "
                   f"{html.escape(str(fd.get('uncertainty','')))}</div>"
                   if fd.get("uncertainty") else "")
            items.append(
                f"<div class='finding'><b>{html.escape(str(fd['title']))}</b> "
                f"<span class='meta'>confidence {int(float(fd['confidence'])*100)}%</span><br>"
                f"{html.escape(str(fd['summary']))}{unc}"
                f"<div class='meta'>Evidence: {html.escape(', '.join(fd.get('evidence') or []))}</div>"
                f"<div>Action: {html.escape(str(fd.get('recommendation','')))}</div></div>")
        fh = f"<div class='card'><h2>Probable root causes (rule-based)</h2>{''.join(items)}</div>"
    problems = [r for r in report["results"] if r.status in ("FAIL", "WARNING")]
    return HTML_TEMPLATE.format(
        title=f"{report['app_name']} — {report['hostname']}", css=CSS,
        app=html.escape(str(report["app_name"])), host=html.escape(str(report["hostname"])),
        started=html.escape(str(report["started_local"])),
        dur=report["duration_seconds"], ver=html.escape(str(report["version"])),
        badgecls=badge, overall=html.escape(overall),
        np=s["counts"].get("PASS", 0), nw=s["counts"].get("WARNING", 0),
        nf=s["counts"].get("FAIL", 0), ni=s["counts"].get("INFO", 0),
        ec=ec.get("confirmed", 0), ew=ec.get("warning", 0),
        ei=ec.get("inconclusive", 0), eu=ec.get("unsupported", 0),
        findings_html=fh,
        issues_table=_rows_html(problems, True),
        all_table=_rows_html(report["results"], False),
        ntotal=len(report["results"]),
        sha=html.escape(str(report.get("report_sha256", "(unsigned)"))))


def to_pdf(report: dict) -> bytes:
    """Render the report as PDF via the built-in dependency-free writer."""
    from .pdf_report import render_report_pdf
    return render_report_pdf(report)


# --------------------------------------------------------------------------- #
# Saving
# --------------------------------------------------------------------------- #
def save_report(report: dict, fmt: str = "markdown", out_dir: str | None = None) -> str:
    """Write the report to exports/ and return the path."""
    out_dir = out_dir or EXPORT_DIR
    os.makedirs(out_dir, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    host = "".join(c if c.isalnum() or c in "-_" else "-" for c in report.get("hostname", "host"))
    ext = {"json": "json", "csv": "csv", "markdown": "md", "html": "html", "pdf": "pdf"}[fmt]
    path = os.path.join(out_dir, f"health_report_{host}_{ts}.{ext}")
    if fmt == "pdf":
        with open(path, "wb") as fh:
            fh.write(to_pdf(report))
    else:
        content = {"json": to_json, "csv": to_csv,
                   "markdown": to_markdown, "html": to_html}[fmt](report)
        with open(path, "w", encoding="utf-8", newline="") as fh:
            fh.write(content)
    return path


def ticket_summary(report: dict) -> str:
    """Ticket-ready plain-text summary for pasting into any helpdesk system."""
    s = report["summary"]
    lines = [f"[AutoDesk IT Health Monitor] {report['hostname']} — {s['overall']}",
             f"When: {report['started_local']}   Duration: {report['duration_seconds']}s",
             f"Checks: {s['total']} (PASS {s['counts'].get('PASS',0)}, "
             f"WARNING {s['counts'].get('WARNING',0)}, FAIL {s['counts'].get('FAIL',0)})",
             f"Evidence: confirmed {s['evidence_counts'].get('confirmed',0)}, "
             f"inconclusive {s['evidence_counts'].get('inconclusive',0)}, "
             f"unsupported {s['evidence_counts'].get('unsupported',0)}", ""]
    for f in (report.get("findings") or [])[:5]:
        fd = f.to_dict() if hasattr(f, "to_dict") else f
        lines.append(f"PROBABLE CAUSE ({int(float(fd['confidence'])*100)}% conf): {fd['title']}")
        lines.append(f"  Action: {fd.get('recommendation','')}")
    for r in report["results"]:
        if r.status in ("FAIL", "WARNING"):
            lines.append(f"{r.status} [{r.evidence}] {r.category}/{r.name}: {r.observed[:150]}")
    lines += ["", f"Report integrity SHA-256: {report.get('report_sha256','')}"]
    return "\n".join(lines)
