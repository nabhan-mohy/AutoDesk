"""Minimal dependency-free PDF writer for health reports.

Produces a valid single/multi-page A4 PDF with Helvetica text - no external
packages (works on locked-down dealership PCs where pip is unavailable).
Used by reporting.py; falls back to 'HTML printable' if this module somehow
fails, so report generation itself can never crash the app.
"""
from __future__ import annotations

import zlib
from datetime import datetime


def _escape(s: str) -> str:
    return (s.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")
            .encode("latin-1", "replace").decode("latin-1"))


def _wrap(text: str, width: int) -> list[str]:
    words = str(text).split()
    lines, cur = [], ""
    for w in words:
        while len(w) > width:  # hard-break very long tokens (URLs)
            room = width - len(cur) - (1 if cur else 0)
            if room > 4:
                cur = (cur + " " + w[:room]).strip() if cur else w[:room]
                lines.append(cur)
                cur = ""
                w = w[room:]
            else:
                if cur:
                    lines.append(cur)
                    cur = ""
                lines.append(w[:width])
                w = w[width:]
        add = (w if not cur else " " + w)
        if len(cur) + len(add) <= width:
            cur += add
        else:
            lines.append(cur)
            cur = w
    if cur.strip():
        lines.append(cur.strip())
    return lines or [""]


class SimplePDF:
    """Very small page-based text PDF builder."""

    PAGE_W, PAGE_H = 595, 842          # A4 points
    MARGIN = 42
    LINE_H = 12

    def __init__(self, title: str = ""):
        self.title = title
        self.pages: list[list[tuple[int, str]]] = [[]]   # page -> [(size, text)]
        self._y = self.PAGE_H - self.MARGIN

    # -- drawing helpers ----------------------------------------------------- #
    def _new_page(self):
        self.pages.append([])
        self._y = self.PAGE_H - self.MARGIN

    def text(self, s: str, size: int = 10, bold: bool = False, color: tuple = (0, 0, 0)):
        prefix = "/F2" if bold else "/F1"
        col = f"{color[0]/255:.2f} {color[1]/255:.2f} {color[2]/255:.2f} rg"
        maxw = int((self.PAGE_W - 2 * self.MARGIN) / (size * 0.5))
        for line in _wrap(s, max(maxw, 20)):
            if self._y < self.MARGIN + 20:
                self._new_page()
            self.pages[-1].append((size, prefix, col, line))
            self._y -= self.LINE_H + (2 if size > 12 else 0)

    def gap(self, pts: int = 6):
        self._y -= pts

    def rule(self):
        if self._y < self.MARGIN + 24:
            self._new_page()
        self.pages[-1].append((-1, "", "", ""))     # marker for a horizontal line
        self._y -= 10

    # -- serialization -------------------------------------------------------- #
    def build(self) -> bytes:
        objs: list[bytes] = []

        def add(body: bytes) -> int:
            objs.append(body)
            return len(objs)  # 1-based object number

        font_r = add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
        font_b = add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>")

        page_ids: list[int] = []
        content_streams: list[bytes] = []
        for page in self.pages:
            ops: list[str] = ["BT", "/F1 10 Tf", "1 0 0 rg"]
            y = self.PAGE_H - self.MARGIN
            for item in page:
                size, prefix, col, line = item
                if size == -1:  # rule
                    ops.append("0 0 0 RG")
                    ops.append(f"{self.MARGIN} {y} m {self.PAGE_W - self.MARGIN} {y} l S")
                    y -= 10
                    continue
                ops.append(col)
                ops.append(f"{prefix} {size} Tf")
                ops.append(f"1 0 0 1 {self.MARGIN} {y} Tm")
                ops.append(f"({_escape(line)}) Tj")
                y -= self.LINE_H + (2 if size > 12 else 0)
            ops.append("ET")
            content_streams.append("\n".join(ops).encode("latin-1", "replace"))

        pages_obj_num = len(objs) + 1 + len(content_streams) * 2 + 1  # placeholder calc later
        # Build objects: for each page -> content stream obj, page obj
        page_obj_nums = []
        for cs in content_streams:
            comp = zlib.compress(cs)
            cnum = add(b"<< /Length %d /Filter /FlateDecode >>\nstream\n%s\nendstream"
                       % (len(comp), comp))
            pnum = add(b"PLACEHOLDER_PAGE")
            page_obj_nums.append((pnum, cnum))

        kids = " ".join(f"{p} 0 R" for p, _ in page_obj_nums)
        pages_num = add(f"<< /Type /Pages /Kids [{kids}] /Count {len(page_obj_nums)} >>".encode())
        # patch page objects now that we know the Pages object number
        for i, (pnum, cnum) in enumerate(page_obj_nums):
            objs[pnum - 1] = (
                f"<< /Type /Page /Parent {pages_num} 0 R /MediaBox [0 0 {self.PAGE_W} {self.PAGE_H}] "
                f"/Resources << /Font << /F1 {font_r} 0 R /F2 {font_b} 0 R >> >> "
                f"/Contents {cnum} 0 R >>").encode()
        info_num = add(f"<< /Producer (AutoDesk IT Health Monitor) /Title ({_escape(self.title)}) "
                       f"/CreationDate (D:{datetime.now().strftime('%Y%m%d%H%M%S')}) >>".encode())
        catalog_num = add(f"<< /Type /Catalog /Pages {pages_num} 0 R >>".encode())

        out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets = []
        for n, body in enumerate(objs, start=1):
            offsets.append(len(out))
            out += f"{n} 0 obj\n".encode() + body + b"\nendobj\n"
        xref_pos = len(out)
        out += f"xref\n0 {len(objs)+1}\n".encode()
        out += b"0000000000 65535 f \n"
        for off in offsets:
            out += f"{off:010d} 00000 n \n".encode()
        out += (f"trailer\n<< /Size {len(objs)+1} /Root {catalog_num} 0 R "
                f"/Info {info_num} 0 R >>\nstartxref\n{xref_pos}\n%%EOF\n").encode()
        return bytes(out)


def render_report_pdf(report: dict) -> bytes:
    """Render a CheckResult report into a compact, printable PDF."""
    GREEN, AMBER, RED, GREY = (26, 127, 55), (181, 137, 0), (198, 40, 40), (90, 98, 104)
    STATUS_COLOR = {"PASS": GREEN, "WARNING": AMBER, "FAIL": RED, "INFO": GREY}
    pdf = SimplePDF(title=f"Health Report {report.get('hostname','')}")
    s = report["summary"]
    pdf.text(str(report.get("app_name", "IT Health Monitor")), 16, bold=True)
    pdf.text("Workstation readiness report - read-only diagnostics", 10, color=GREY)
    pdf.gap(4); pdf.rule(); pdf.gap(4)
    overall = s.get("overall", "?")
    ocol = {"READY": GREEN, "READY WITH ISSUES": AMBER}.get(overall, RED)
    pdf.text(f"OVERALL: {overall}", 14, bold=True, color=ocol)
    c = s.get("counts", {})
    ev = s.get("evidence_counts", {})
    pdf.text(f"Host: {report.get('hostname','')}   Started: {report.get('started_local','')}   "
             f"Duration: {report.get('duration_seconds','?')} s", 9, color=GREY)
    pdf.text(f"Checks: {s.get('total',0)} | PASS {c.get('PASS',0)} | WARNING {c.get('WARNING',0)} | "
             f"FAIL {c.get('FAIL',0)} | INFO {c.get('INFO',0)}", 9)
    pdf.text(f"Evidence classes: confirmed {ev.get('confirmed',0)} | warning {ev.get('warning',0)} | "
             f"inconclusive {ev.get('inconclusive',0)} | unsupported {ev.get('unsupported',0)} | "
             f"observation {ev.get('observation',0)}", 9, color=GREY)
    findings = report.get("findings") or []
    if findings:
        pdf.gap(6)
        pdf.text("Probable root causes (rule-based, evidence-linked)", 12, bold=True)

        def fv(f, key, default=""):
            if isinstance(f, dict):
                return f.get(key, default)
            return getattr(f, key, default)

        for f in findings[:8]:
            title = fv(f, "title"); conf = float(fv(f, "confidence", 0) or 0)
            summ = fv(f, "summary"); unc = fv(f, "uncertainty")
            evd = fv(f, "evidence", []) or []; rec = fv(f, "recommendation")
            pdf.text(f"- {title}  [{int(conf*100)}% confidence]", 10, bold=True)
            pdf.text(f"  {summ}", 9)
            if unc:
                pdf.text(f"  Uncertainty: {unc}", 8, color=GREY)
            pdf.text(f"  Evidence: {', '.join(list(evd)[:6])}", 8, color=GREY)
            pdf.text(f"  Action: {rec}", 9)
    problems = [r for r in report["results"] if r.status in ("FAIL", "WARNING")]
    others = [r for r in report["results"] if r.status not in ("FAIL", "WARNING")]
    pdf.gap(6)
    pdf.text(f"Issues ({len(problems)})", 12, bold=True, color=RED)
    for r in problems:
        pdf.text(f"[{r.status}] {r.category} / {r.name}  ({r.evidence}"
                 f"{'' if r.duration_ms is None else f', {r.duration_ms} ms'})",
                 10, bold=True, color=STATUS_COLOR.get(r.status, GREY))
        pdf.text(f"  Observed: {r.observed[:300]}", 9)
        if r.expected:
            pdf.text(f"  Expected: {r.expected[:200]}", 9, color=GREY)
        if r.recommendation:
            pdf.text(f"  Action: {r.recommendation[:400]}", 9)
    pdf.gap(6)
    pdf.text(f"Passed / informational ({len(others)})", 12, bold=True, color=GREEN)
    for r in others:
        pdf.text(f"[{r.status}] {r.category} / {r.name}: {r.observed[:200]}"
                 + (f"  ({r.duration_ms} ms)" if r.duration_ms is not None else ""),
                 9, color=STATUS_COLOR.get(r.status, GREY))
    sha = report.get("report_sha256", "")
    pdf.gap(8); pdf.rule()
    pdf.text("Generated locally by AutoDesk IT Health Monitor v%s. No remediation was performed."
             % report.get("version", ""), 8, color=GREY)
    if sha:
        pdf.text(f"Report integrity SHA-256: {sha}", 8, color=GREY)
    return pdf.build()
