"""AutoDesk IT Health Monitor - Streamlit dashboard.

Launch with:  streamlit run app.py
Read-only diagnostics; no remediation actions are performed.
"""
from __future__ import annotations

import time
from datetime import datetime

import pandas as pd
import streamlit as st

from src.config_loader import load_config, CONFIG_PATH
from src.check_model import PASS, WARNING, FAIL, INFO
from src.health_engine import run_full_check
from src.reporting import to_csv_bytes, to_json_bytes, to_html_bytes, write_reports, REPORTS_DIR
from src.system_checks import run_system_checks
from src.network_checks import run_network_checks
from src.printer_checks import run_printer_checks

APP_TITLE = "AutoDesk IT Health Monitor"
APP_VERSION = "1.0.0"

st.set_page_config(page_title=APP_TITLE, page_icon="🖥️", layout="wide")

STATUS_STYLE = {
    PASS: ("#1a7f37", "✅"),
    WARNING: ("#b58900", "⚠️"),
    FAIL: ("#c62828", "❌"),
    INFO: ("#455a64", "ℹ️"),
}


def init_state():
    defaults = {"report": None, "last_scan": None, "duration": None, "df": None}
    for k, v in defaults.items():
        st.session_state.setdefault(k, v)


def store_report(report: dict):
    rows = [{
        "Timestamp": r.timestamp, "Category": r.category, "Status": r.status,
        "Check": r.name, "Observed value": r.observed, "Expected": r.expected,
        "Recommendation": r.recommendation,
    } for r in report["results"]]
    st.session_state.report = report
    st.session_state.df = pd.DataFrame(rows)
    st.session_state.last_scan = report["started_local"]
    st.session_state.duration = report["duration_seconds"]


@st.cache_data(show_spinner=False)
def _noop():
    return None


def render_summary(report: dict):
    counts = report["summary"]["counts"]
    overall = report["summary"]["overall"]
    color = {"READY": "#1a7f37", "READY WITH ISSUES": "#b58900", "NOT READY": "#c62828"}[overall]
    icon = {"READY": "🟢", "READY WITH ISSUES": "🟡", "NOT READY": "🔴"}[overall]
    st.markdown(
        f"<div style='background:{color};color:white;padding:14px 18px;border-radius:8px;"
        f"font-size:20px;font-weight:700;margin-bottom:12px'>{icon} Workstation readiness: {overall}"
        f"<span style='float:right;font-weight:400;font-size:14px'>Checks: {report['summary']['total']}"
        f" &nbsp;|&nbsp; Duration: {report['duration_seconds']} s</span></div>",
        unsafe_allow_html=True,
    )
    c1, c2, c3, c4 = st.columns(4)
    cards = [(PASS, counts.get(PASS, 0)), (WARNING, counts.get(WARNING, 0)),
             (FAIL, counts.get(FAIL, 0)), (INFO, counts.get(INFO, 0))]
    for col, (status, n) in zip([c1, c2, c3, c4], cards):
        hexcol, emoji = STATUS_STYLE[status]
        col.metric(f"{emoji} {status}", n, delta_color="off")


def render_results(df: pd.DataFrame):
    search = st.text_input("Search results", placeholder="Filter by check name, value or recommendation…")
    fcat = st.multiselect("Category", sorted(df["Category"].unique()), default=sorted(df["Category"].unique()))
    fst = st.multiselect("Status", [PASS, WARNING, FAIL, INFO], default=[PASS, WARNING, FAIL, INFO])
    view = df[df["Category"].isin(fcat) & df["Status"].isin(fst)]
    if search:
        mask = view.apply(lambda row: row.astype(str).str.contains(search, case=False).any(), axis=1)
        view = view[mask]
    st.dataframe(view, use_container_width=True, hide_index=True,
                 column_config={"Recommendation": st.column_config.TextColumn(width="large"),
                                "Observed value": st.column_config.TextColumn(width="large")})
    st.caption(f"Showing {len(view)} of {len(df)} results.")


def render_actions(report: dict):
    problems = [r for r in report["results"] if r.status in (FAIL, WARNING)]
    if not problems:
        st.success("No issues detected. No further action required.")
        return
    st.subheader("Recommended next actions")
    for r in sorted(problems, key=lambda x: (x.status != FAIL, x.category)):
        _, emoji = STATUS_STYLE[r.status]
        with st.expander(f"{emoji} [{r.category}] {r.name} — {r.status}"):
            st.markdown(f"**Observed:** {r.observed}")
            st.markdown(f"**Expected:** {r.expected}")
            st.markdown(f"**Action:** {r.recommendation}")


def render_downloads(report: dict):
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    host = report.get("hostname", "host").replace(" ", "_")
    d1, d2, d3 = st.columns(3)
    with d1:
        st.download_button("⬇️ Download CSV report", to_csv_bytes(report),
                           file_name=f"health_{host}_{stamp}.csv", mime="text/csv")
    with d2:
        st.download_button("⬇️ Download JSON report", to_json_bytes(report),
                           file_name=f"health_{host}_{stamp}.json", mime="application/json")
    with d3:
        st.download_button("⬇️ Download HTML report", to_html_bytes(report),
                           file_name=f"health_{host}_{stamp}.html", mime="text/html")


def main():
    init_state()
    cfg = load_config()

    st.title(f"🖥️ {APP_TITLE}")
    st.caption(f"v{APP_VERSION} · Automated PC / network / printer readiness checks for dealership "
               "showroom, billing and service-advisor workstations. Read-only: this tool never "
               "restarts services, clears queues or prints test pages.")

    if cfg.get("_load_error"):
        st.warning(cfg["_load_error"])
    if cfg.get("_validation_problems"):
        st.warning("Configuration issues: " + "; ".join(cfg["_validation_problems"]))

    with st.sidebar:
        st.header("Controls")
        run_all = st.button("🩺 Run Full Health Check", type="primary", use_container_width=True)
        st.divider()
        st.subheader("Individual checks")
        run_sys = st.button("Run System checks only", use_container_width=True)
        run_net = st.button("Run Network checks only", use_container_width=True)
        run_prn = st.button("Run Printer checks only", use_container_width=True)
        st.divider()
        rerun = st.button("🔄 Refresh / Rerun last scope", use_container_width=True)
        st.caption(f"Config: `{CONFIG_PATH}`")
        st.caption(f"Reports folder: `{REPORTS_DIR}`")

    def execute(categories: list[str]):
        progress = st.progress(0.0, text="Starting…")

        def cb(stage, frac):
            progress.progress(min(max(frac, 0.0), 1.0), text=stage)

        t0 = time.time()
        report = run_full_check(cfg, categories, progress_cb=cb)
        progress.progress(1.0, text=f"Completed in {time.time() - t0:.1f}s")
        try:
            paths = write_reports(report)
            report["_saved_paths"] = paths
        except OSError as exc:
            st.error(f"Could not write report files: {exc}")
        store_report(report)
        return report

    if run_all:
        execute(["System", "Network", "Printer"])
    elif run_sys:
        execute(["System"])
    elif run_net:
        execute(["Network"])
    elif run_prn:
        execute(["Printer"])
    elif rerun and st.session_state.report:
        cats = sorted({r.category for r in st.session_state.report["results"]})
        execute(cats or ["System", "Network", "Printer"])

    report = st.session_state.report
    if report is None:
        st.info("Click **Run Full Health Check** in the sidebar to start diagnostics. "
                "First run typically takes 10–30 seconds depending on network timeouts.")
        return

    st.subheader("Summary")
    render_summary(report)
    st.caption(f"Last scan: {st.session_state.last_scan} · Host: {report.get('hostname','')}")

    tab_sys, tab_net, tab_prn, tab_all, tab_dl = st.tabs(
        ["💻 System", "🌐 Network", "🖨️ Printers", "📋 All results", "📁 Reports"])

    df = st.session_state.df
    with tab_sys:
        render_resource_cards(report)
        render_results(df[df["Category"] == "System"])
    with tab_net:
        render_results(df[df["Category"] == "Network"])
    with tab_prn:
        st.caption("Note: OS-reported status and network reachability do NOT prove a device can "
                   "physically print (toner/paper/jams are not visible from software).")
        render_results(df[df["Category"] == "Printer"])
    with tab_all:
        render_results(df)
        render_actions(report)
    with tab_dl:
        render_downloads(report)
        saved = report.get("_saved_paths") or {}
        if saved:
            st.markdown("**Saved to disk:**")
            for fmt, p in saved.items():
                st.code(p, language=None)


def render_resource_cards(report: dict):
    details_by_name = {r.name: r.details for r in report["results"]}
    ident = details_by_name.get("Computer identity", {})
    cpu = details_by_name.get("CPU utilization", {})
    mem = details_by_name.get("Memory utilization", {})
    up = details_by_name.get("System uptime", {})
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Hostname", ident.get("hostname", "—"))
    c2.metric("CPU", f"{cpu.get('percent', '—')}%",
              f"{cpu.get('logical_cores', '—')} cores", delta_color="off")
    c3.metric("RAM used", f"{mem.get('percent', '—')}%",
              f"{mem.get('available_gb', '—')} GB free", delta_color="off")
    c4.metric("Uptime", f"{up.get('uptime_seconds', 0) // 3600}h {(up.get('uptime_seconds', 0) % 3600) // 60}m"
              if up.get("uptime_seconds") is not None else "—",
              ident.get("os", ""), delta_color="off")
    disks = [r for r in report["results"] if r.name.startswith("Disk space")]
    if disks:
        cols = st.columns(min(len(disks), 4))
        for col, d in zip(cols, disks):
            pct = d.details.get("percent", 0)
            col.metric(d.name.replace("Disk space ", "Drive "), f"{pct}%",
                       f"{d.details.get('free_gb', '—')} GB free", delta_color="off")


if __name__ == "__main__":
    main()
