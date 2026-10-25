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
    PASS: ("#1fe7a8", "✅"),
    WARNING: ("#ffc857", "⚠️"),
    FAIL: ("#ff5f7a", "❌"),
    INFO: ("#7dd3fc", "ℹ️"),
}

CUSTOM_CSS = """
<style>
    :root {
        --bg-1: #07111f;
        --bg-2: #0d1b2a;
        --panel: rgba(17, 26, 38, 0.72);
        --panel-strong: rgba(19, 31, 46, 0.9);
        --glass: rgba(255,255,255,0.06);
        --border: rgba(148, 163, 184, 0.18);
        --text: #eaf6ff;
        --muted: #a6bfd5;
        --cyan: #67e8f9;
        --blue: #60a5fa;
        --violet: #8b5cf6;
        --teal: #2dd4bf;
        --green: #34d399;
        --amber: #fbbf24;
        --red: #fb7185;
        --shadow: 0 22px 60px rgba(8, 15, 30, 0.65);
    }

    .stApp {
        background:
            radial-gradient(circle at top left, rgba(103, 232, 249, 0.18), transparent 25%),
            radial-gradient(circle at top right, rgba(139, 92, 246, 0.16), transparent 30%),
            linear-gradient(135deg, var(--bg-1), var(--bg-2) 30%, #091521 100%);
        color: var(--text);
    }

    .stApp::before {
        content: "";
        position: fixed;
        inset: 0;
        background: radial-gradient(circle at 20% 20%, rgba(103,232,249,0.12), transparent 20%),
                    radial-gradient(circle at 80% 0%, rgba(139,92,246,0.15), transparent 28%);
        pointer-events: none;
        animation: pulseGlow 12s ease-in-out infinite alternate;
    }

    @keyframes pulseGlow {
        0% { opacity: 0.7; transform: scale(1); }
        100% { opacity: 1; transform: scale(1.08); }
    }

    html, body, [data-testid="stAppViewContainer"], [data-testid="stMain"] {
        background: transparent;
    }

    .block-container {
        padding-top: 2rem;
        padding-bottom: 4rem;
    }

    .glass-panel {
        background: linear-gradient(180deg, rgba(18,29,42,0.9), rgba(12,19,31,0.8));
        border: 1px solid var(--border);
        border-radius: 22px;
        box-shadow: var(--shadow);
        backdrop-filter: blur(14px);
        -webkit-backdrop-filter: blur(14px);
    }

    .hero-box {
        position: relative;
        overflow: hidden;
        padding: 1.5rem 1.5rem 1.2rem 1.5rem;
        margin-bottom: 1.2rem;
        background: linear-gradient(135deg, rgba(14,24,36,0.95), rgba(15,23,42,0.82));
        border: 1px solid rgba(103,232,249,0.25);
        border-radius: 22px;
        box-shadow: 0 30px 60px rgba(12, 19, 31, 0.6);
    }

    .hero-box::after {
        content: "";
        position: absolute;
        inset: -25% auto auto -10%;
        width: 220px;
        height: 220px;
        background: radial-gradient(circle, rgba(103,232,249,0.28), transparent 60%);
        animation: drift 16s ease-in-out infinite alternate;
    }

    @keyframes drift {
        0% { transform: translate(0, 0) scale(1); }
        100% { transform: translate(30px, 18px) scale(1.15); }
    }

    .hero-title {
        font-size: 2.2rem !important;
        font-weight: 800 !important;
        letter-spacing: 0.02em;
        margin-bottom: 0.15rem;
        color: #f8fbff;
        position: relative;
        z-index: 1;
    }

    .hero-sub {
        color: var(--muted);
        font-size: 0.96rem;
        position: relative;
        z-index: 1;
    }

    .status-badge {
        display: inline-flex;
        align-items: center;
        gap: 0.55rem;
        padding: 0.7rem 1rem;
        border-radius: 999px;
        font-weight: 700;
        letter-spacing: 0.03em;
        border: 1px solid rgba(255,255,255,0.1);
        box-shadow: inset 0 0 24px rgba(255,255,255,0.04);
    }

    .summary-chip {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        padding: 0.45rem 0.8rem;
        border-radius: 999px;
        background: rgba(255,255,255,0.04);
        border: 1px solid rgba(148,163,184,0.15);
        color: var(--text);
        font-size: 0.8rem;
        min-width: 90px;
    }

    .metric-container {
        padding: 0.8rem 0.9rem;
        border-radius: 18px;
        background: linear-gradient(180deg, rgba(255,255,255,0.04), rgba(255,255,255,0.02));
        border: 1px solid rgba(148,163,184,0.12);
        box-shadow: inset 0 1px 0 rgba(255,255,255,0.04);
        transition: transform 0.2s ease, border-color 0.2s ease;
    }

    .metric-container:hover {
        transform: translateY(-2px);
        border-color: rgba(103,232,249,0.35);
    }

    .stMetric {
        background: transparent !important;
    }

    [data-testid="stMetricValue"] {
        color: #f8fbff !important;
        font-weight: 700 !important;
        font-size: 1.3rem !important;
    }

    [data-testid="stMetricLabel"] {
        color: var(--muted) !important;
        font-weight: 600 !important;
    }

    [data-testid="stMetricDelta"] {
        color: var(--muted) !important;
    }

    .stButton > button {
        border-radius: 12px !important;
        border: 1px solid rgba(103,232,249,0.25) !important;
        background: linear-gradient(135deg, rgba(16, 34, 52, 0.96), rgba(19, 31, 48, 0.9)) !important;
        color: #edf7ff !important;
        font-weight: 700 !important;
        letter-spacing: 0.02em;
        padding: 0.7rem 1rem !important;
        box-shadow: 0 10px 22px rgba(12, 20, 32, 0.5);
        transition: transform 0.18s ease, box-shadow 0.18s ease, border-color 0.18s ease;
    }

    .stButton > button:hover {
        transform: translateY(-1px);
        box-shadow: 0 14px 28px rgba(33, 112, 161, 0.28);
        border-color: rgba(103,232,249,0.5) !important;
    }

    .stButton > button:focus {
        box-shadow: 0 0 0 0.2rem rgba(103,232,249,0.25) !important;
    }

    .sidebar .sidebar-content {
        background: linear-gradient(180deg, rgba(9,18,31,0.96), rgba(10,17,26,0.96));
        border-right: 1px solid rgba(148,163,184,0.14);
    }

    .stDataFrame {
        background: rgba(9,15,21,0.5);
        border-radius: 18px;
        border: 1px solid rgba(148,163,184,0.10);
    }

    .stTabs [role="tablist"] {
        gap: 0.5rem;
    }

    .stTabs [role="tab"] {
        border-radius: 12px 12px 0 0;
        padding: 0.7rem 0.95rem;
        font-weight: 650;
        color: var(--muted);
        border: 1px solid transparent;
        background: rgba(255,255,255,0.02);
    }

    .stTabs [role="tab"][aria-selected="true"] {
        color: var(--text);
        background: linear-gradient(180deg, rgba(103,232,249,0.12), rgba(139,92,246,0.08));
        border-color: rgba(103,232,249,0.25);
    }

    .info-note {
        border-left: 3px solid rgba(103,232,249,0.8);
        background: rgba(103,232,249,0.06);
        color: #dffaff;
        border-radius: 0 14px 14px 0;
        padding: 0.8rem 1rem;
        margin: 0.75rem 0 1rem 0;
    }

    .problem-card {
        background: linear-gradient(135deg, rgba(255,255,255,0.04), rgba(255,255,255,0.02));
        border: 1px solid rgba(148,163,184,0.16);
        border-radius: 18px;
        padding: 1rem;
        margin-bottom: 0.8rem;
    }

    .success-box {
        color: #d7fff0;
        background: rgba(52, 211, 153, 0.08);
        border: 1px solid rgba(52,211,153,0.25);
        border-radius: 14px;
        padding: 0.8rem 1rem;
    }

    @media (max-width: 768px) {
        .hero-title { font-size: 1.75rem !important; }
        .block-container { padding-top: 1rem; }
    }
</style>
"""


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
    _COLORS = {"READY": "#24c18d", "READY WITH ISSUES": "#fbbf24", "NOT READY": "#ff5f7a"}
    _ICONS = {"READY": "🟢", "READY WITH ISSUES": "🟡", "NOT READY": "🔴"}
    color = _COLORS.get(overall, "#7dd3fc")
    icon = _ICONS.get(overall, "ℹ️")

    st.markdown(
        f"""
        <div class="hero-box glass-panel">
            <div style="display:flex; justify-content:space-between; align-items:center; gap:1rem; flex-wrap:wrap;">
                <div>
                    <div class="status-badge" style="background: rgba(255,255,255,0.02); border-color: rgba(255,255,255,0.08); color: {color};">
                        {icon} Workstation readiness: {overall}
                    </div>
                    <div style="margin-top: 0.8rem; color: var(--muted); font-size: 0.9rem;">
                        Checks: <strong style="color:#f8fbff;">{report['summary']['total']}</strong>
                        &nbsp;&nbsp;•&nbsp;&nbsp; Duration: <strong style="color:#f8fbff;">{report['duration_seconds']} s</strong>
                    </div>
                </div>
                <div style="display:flex; align-items:center; gap:0.5rem; flex-wrap:wrap;">
                    <span class="summary-chip">PASS {counts.get(PASS, 0)}</span>
                    <span class="summary-chip">WARN {counts.get(WARNING, 0)}</span>
                    <span class="summary-chip">FAIL {counts.get(FAIL, 0)}</span>
                    <span class="summary-chip">INFO {counts.get(INFO, 0)}</span>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    c1, c2, c3, c4 = st.columns(4)
    cards = [(PASS, counts.get(PASS, 0)), (WARNING, counts.get(WARNING, 0)),
             (FAIL, counts.get(FAIL, 0)), (INFO, counts.get(INFO, 0))]
    for col, (status, n) in zip([c1, c2, c3, c4], cards):
        hexcol, emoji = STATUS_STYLE[status]
        with col:
            st.markdown(f"<div class='metric-container'><div style='color:{hexcol}; font-weight:700; margin-bottom:0.35rem;'>{emoji} {status}</div><div style='font-size:1.9rem; font-weight:800; color:#f8fbff;'>{n}</div></div>", unsafe_allow_html=True)


def render_results(df: pd.DataFrame, key_prefix: str = "all"):
    search = st.text_input("Search results", placeholder="Filter by check name, value or recommendation…",
                           key=f"search_{key_prefix}")
    fcat = st.multiselect("Category", sorted(df["Category"].unique()), default=sorted(df["Category"].unique()),
                          key=f"cat_{key_prefix}")
    fst = st.multiselect("Status", [PASS, WARNING, FAIL, INFO], default=[PASS, WARNING, FAIL, INFO],
                         key=f"stat_{key_prefix}")
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
        st.markdown("<div class='success-box'>No issues detected. No further action required.</div>", unsafe_allow_html=True)
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

    st.markdown(CUSTOM_CSS, unsafe_allow_html=True)

    st.markdown(
        """
        <div class="hero-box glass-panel">
            <div class="hero-title">🖥️ AutoDesk IT Health Monitor</div>
            <div class="hero-sub">v1.0.0 · Automated PC / network / printer readiness checks for dealership showroom, billing and service-advisor workstations.</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

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
        st.markdown("<div class='info-note'>Click <strong>Run Full Health Check</strong> in the sidebar to start diagnostics. First run typically takes 10–30 seconds depending on network timeouts.</div>", unsafe_allow_html=True)
        return

    st.subheader("Summary")
    render_summary(report)
    st.caption(f"Last scan: {st.session_state.last_scan} · Host: {report.get('hostname','')}")

    tab_sys, tab_net, tab_prn, tab_all, tab_dl = st.tabs(
        ["💻 System", "🌐 Network", "🖨️ Printers", "📋 All results", "📁 Reports"])

    df = st.session_state.df
    with tab_sys:
        render_resource_cards(report)
        render_results(df[df["Category"] == "System"], key_prefix="sys")
    with tab_net:
        render_results(df[df["Category"] == "Network"], key_prefix="net")
    with tab_prn:
        st.markdown("<div class='info-note'>Note: OS-reported status and network reachability do NOT prove a device can physically print (toner/paper/jams are not visible from software).</div>", unsafe_allow_html=True)
        render_results(df[df["Category"] == "Printer"], key_prefix="prn")
    with tab_all:
        render_results(df, key_prefix="all")
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
            total_gb = d.details.get("total_gb") or 0
            pct = d.details.get("percent")
            if pct is None and total_gb:
                pct = round(100 * (1 - (d.details.get("free_gb", 0) / total_gb)), 1)
            col.metric(d.name.replace("Disk space ", "Drive "),
                       f"{pct if pct is not None else '—'}%",
                       f"{d.details.get('free_gb', '—')} GB free", delta_color="off")


if __name__ == "__main__":
    main()
