"""Local SQLite history: scan records, per-check results, incidents, assets.

Everything stays on the machine (data/history.sqlite next to the app by
default). No credentials or personal data beyond the computer name and the
current user name that diagnostics already collect.

Schema is intentionally simple and versioned; the module degrades gracefully
(reads return empty structures) if the database file is missing or corrupt so
the dashboard can never crash because of history problems.
"""
from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone

DB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
DEFAULT_DB_PATH = os.path.join(DB_DIR, "history.sqlite")

SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta(
    key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS scans(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_utc TEXT NOT NULL,
    hostname TEXT NOT NULL,
    app_version TEXT,
    overall TEXT,
    pass_count INTEGER DEFAULT 0,
    warn_count INTEGER DEFAULT 0,
    fail_count INTEGER DEFAULT 0,
    info_count INTEGER DEFAULT 0,
    duration_seconds REAL,
    cpu_percent REAL,
    memory_percent REAL,
    disk_min_free_gb REAL,
    dns_ok INTEGER,
    internet_ok INTEGER,
    printer_issues INTEGER,
    report_sha256 TEXT,
    payload_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scans_host_time ON scans(hostname, started_utc);
CREATE TABLE IF NOT EXISTS check_results(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    ts TEXT, category TEXT, name TEXT, status TEXT, evidence TEXT,
    observed TEXT, expected TEXT, recommendation TEXT,
    duration_ms INTEGER, verdict TEXT
);
CREATE INDEX IF NOT EXISTS idx_results_scan ON check_results(scan_id);
CREATE INDEX IF NOT EXISTS idx_results_status ON check_results(status, ts);
CREATE TABLE IF NOT EXISTS incidents(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_utc TEXT NOT NULL,
    updated_utc TEXT,
    hostname TEXT,
    symptom TEXT NOT NULL,
    affected_component TEXT,
    evidence TEXT,
    troubleshooting TEXT,
    recommendation TEXT,
    verification_result TEXT,
    status TEXT DEFAULT 'open',
    ticket_ref TEXT,
    scan_id INTEGER
);
CREATE TABLE IF NOT EXISTS assets(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    recorded_utc TEXT NOT NULL,
    hostname TEXT NOT NULL,
    asset_tag TEXT,
    manufacturer TEXT, model TEXT, os_caption TEXT, os_build TEXT,
    architecture TEXT, cpu_name TEXT, cpu_cores INTEGER,
    ram_gb REAL, disk_total_gb REAL, installed_apps TEXT,
    details_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_assets_host ON assets(hostname, recorded_utc);
"""


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def connect(path: str | None = None) -> sqlite3.Connection:
    path = path or os.environ.get("HEALTH_MONITOR_DB", DEFAULT_DB_PATH)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(_SCHEMA)
    cur = conn.execute("SELECT value FROM meta WHERE key='schema_version'")
    row = cur.fetchone()
    if row is None:
        conn.execute("INSERT INTO meta(key,value) VALUES('schema_version',?)",
                     (str(SCHEMA_VERSION),))
    conn.commit()
    return conn


# --------------------------------------------------------------------------- #
# Scans
# --------------------------------------------------------------------------- #
def save_scan(report: dict, conn: sqlite3.Connection | None = None,
              report_sha256: str = "") -> int:
    """Persist one health-check run + its individual results. Returns scan id."""
    own = conn is None
    conn = conn or connect()
    try:
        summary = report.get("summary", {})
        counts = summary.get("counts", {})
        det = {r.name: (r.details or {}) for r in report.get("results", [])}
        cpu = det.get("CPU utilization", {}).get("percent")
        mem = det.get("Memory utilization", {}).get("percent")
        disk_frees = [d.get("free_gb") for n, d in det.items()
                      if n.startswith("Disk space") and isinstance(d.get("free_gb"), (int, float))]
        dns_rows = [r for r in report.get("results", []) if r.name.startswith("DNS resolution")]
        dns_ok = (sum(1 for r in dns_rows if r.status == "PASS") > 0) if dns_rows else None
        inet_rows = [r for r in report.get("results", [])
                     if r.name.startswith("Internet endpoint")]
        internet_ok = (any(r.status == "PASS" for r in inet_rows) if inet_rows) or None
        printer_issues = sum(1 for r in report.get("results", [])
                             if r.category == "Printer" and r.status in ("WARNING", "FAIL"))
        payload = json.dumps({
            k: v for k, v in report.items()
            if k not in ("results", "_saved_paths")
        }, default=str)
        cur = conn.execute(
            """INSERT INTO scans(started_utc,hostname,app_version,overall,
               pass_count,warn_count,fail_count,info_count,duration_seconds,
               cpu_percent,memory_percent,disk_min_free_gb,dns_ok,internet_ok,
               printer_issues,report_sha256,payload_json)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (_utcnow(), report.get("hostname", ""), report.get("version", ""),
             summary.get("overall", ""), counts.get("PASS", 0), counts.get("WARNING", 0),
             counts.get("FAIL", 0), counts.get("INFO", 0),
             report.get("duration_seconds"), cpu, mem,
             min(disk_frees) if disk_frees else None,
             (1 if dns_ok else 0) if dns_ok is not None else None,
             (1 if internet_ok else 0) if internet_ok is not None else None,
             printer_issues, report_sha256, payload))
        scan_id = cur.lastrowid
        for r in report.get("results", []):
            conn.execute(
                """INSERT INTO check_results(scan_id,ts,category,name,status,
                   evidence,observed,expected,recommendation,duration_ms,verdict)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (scan_id, r.timestamp, r.category, r.name, r.status, r.evidence,
                 r.observed, r.expected, r.recommendation, r.duration_ms, r.verdict))
        conn.commit()
        return scan_id
    finally:
        if own:
            conn.close()


def list_scans(conn: sqlite3.Connection | None = None, limit: int = 200,
               hostname: str | None = None) -> list[dict]:
    own = conn is None
    conn = conn or connect()
    try:
        q = "SELECT * FROM scans"
        args: list = []
        if hostname:
            q += " WHERE hostname=?"
            args.append(hostname)
        q += " ORDER BY started_utc DESC LIMIT ?"
        args.append(int(limit))
        return [dict(r) for r in conn.execute(q, args)]
    except sqlite3.Error:
        return []
    finally:
        if own:
            conn.close()


def get_scan(scan_id: int, conn: sqlite3.Connection | None = None) -> dict | None:
    own = conn is None
    conn = conn or connect()
    try:
        row = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        if not row:
            return None
        d = dict(row)
        d["checks"] = [dict(r) for r in conn.execute(
            "SELECT * FROM check_results WHERE scan_id=? ORDER BY id", (scan_id,))]
        return d
    except sqlite3.Error:
        return None
    finally:
        if own:
            conn.close()


def previous_scan(before_id: int, hostname: str | None = None,
                  conn: sqlite3.Connection | None = None) -> dict | None:
    own = conn is None
    conn = conn or connect()
    try:
        q = "SELECT * FROM scans WHERE id<?"
        args: list = [before_id]
        if hostname:
            q += " AND hostname=?"
            args.append(hostname)
        q += " ORDER BY started_utc DESC LIMIT 1"
        row = conn.execute(q, args).fetchone()
        return dict(row) if row else None
    except sqlite3.Error:
        return None
    finally:
        if own:
            conn.close()


def search_results(status: list[str] | None = None, category: list[str] | None = None,
                   text: str = "", since_days: int | None = None, limit: int = 500,
                   conn: sqlite3.Connection | None = None) -> list[dict]:
    """Searchable diagnostic history with date and status filters."""
    own = conn is None
    conn = conn or connect()
    try:
        q = "SELECT cr.*, s.hostname FROM check_results cr JOIN scans s ON s.id=cr.scan_id WHERE 1=1"
        args: list = []
        if status:
            q += f" AND cr.status IN ({','.join('?' * len(status))})"
            args.extend(status)
        if category:
            q += f" AND cr.category IN ({','.join('?' * len(category))})"
            args.extend(category)
        if text:
            q += (" AND (cr.name LIKE ? OR cr.observed LIKE ? OR cr.recommendation LIKE ?)")
            like = f"%{text}%"
            args.extend([like, like, like])
        if since_days:
            cutoff = (datetime.now(timezone.utc) - timedelta(days=int(since_days))
                      ).isoformat(timespec="seconds")
            q += " AND cr.ts>=?"
            args.append(cutoff)
        q += " ORDER BY cr.id DESC LIMIT ?"
        args.append(int(limit))
        return [dict(r) for r in conn.execute(q, args)]
    except sqlite3.Error:
        return []
    finally:
        if own:
            conn.close()


def trend_points(metric: str, limit: int = 60, hostname: str | None = None,
                 conn: sqlite3.Connection | None = None) -> list[dict]:
    """Time series for CPU/memory/disk/connectivity trends (oldest first)."""
    col_map = {"cpu": "cpu_percent", "memory": "memory_percent",
               "disk_free_gb": "disk_min_free_gb", "dns_ok": "dns_ok",
               "internet_ok": "internet_ok", "printer_issues": "printer_issues"}
    col = col_map.get(metric)
    if not col:
        return []
    own = conn is None
    conn = conn or connect()
    try:
        q = f"SELECT started_utc, {col} AS value FROM scans WHERE {col} IS NOT NULL"
        args: list = []
        if hostname:
            q += " AND hostname=?"
            args.append(hostname)
        q += " ORDER BY started_utc DESC LIMIT ?"
        args.append(int(limit))
        rows = [dict(r) for r in conn.execute(q, args)]
        rows.reverse()
        return rows
    except sqlite3.Error:
        return []
    finally:
        if own:
            conn.close()


# --------------------------------------------------------------------------- #
# Incidents / tickets
# --------------------------------------------------------------------------- #
def create_incident(symptom: str, affected_component: str = "", evidence: str = "",
                    troubleshooting: str = "", recommendation: str = "",
                    verification_result: str = "", hostname: str = "",
                    scan_id: int | None = None, ticket_ref: str = "",
                    conn: sqlite3.Connection | None = None) -> int:
    own = conn is None
    conn = conn or connect()
    try:
        cur = conn.execute(
            """INSERT INTO incidents(created_utc,hostname,symptom,affected_component,
               evidence,troubleshooting,recommendation,verification_result,status,
               ticket_ref,scan_id) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
            (_utcnow(), hostname, symptom[:400], affected_component, evidence,
             troubleshooting, recommendation, verification_result, "open",
             ticket_ref, scan_id))
        conn.commit()
        return cur.lastrowid
    finally:
        if own:
            conn.close()


def update_incident(incident_id: int, fields: dict,
                    conn: sqlite3.Connection | None = None) -> bool:
    allowed = {"symptom", "affected_component", "evidence", "troubleshooting",
               "recommendation", "verification_result", "status", "ticket_ref"}
    own = conn is None
    conn = conn or connect()
    try:
        sets, args = [], []
        for k, v in fields.items():
            if k in allowed:
                sets.append(f"{k}=?")
                args.append(v)
        if not sets:
            return False
        sets.append("updated_utc=?")
        args.append(_utcnow())
        args.append(incident_id)
        cur = conn.execute(f"UPDATE incidents SET {', '.join(sets)} WHERE id=?", args)
        conn.commit()
        return cur.rowcount > 0
    finally:
        if own:
            conn.close()


def list_incidents(status: str | None = None, limit: int = 100,
                   conn: sqlite3.Connection | None = None) -> list[dict]:
    own = conn is None
    conn = conn or connect()
    try:
        q = "SELECT * FROM incidents"
        args: list = []
        if status:
            q += " WHERE status=?"
            args.append(status)
        q += " ORDER BY id DESC LIMIT ?"
        args.append(int(limit))
        return [dict(r) for r in conn.execute(q, args)]
    except sqlite3.Error:
        return []
    finally:
        if own:
            conn.close()


def incident_summary_text(inc: dict) -> str:
    """Ticket-ready plain-text block a technician can paste into any helpdesk."""
    lines = [
        f"[AutoDesk IT Health Monitor] Incident #{inc.get('id', '?')}",
        f"Created      : {inc.get('created_utc', '')}",
        f"Workstation  : {inc.get('hostname', '')}"
        + (f" (asset tag {inc['asset_tag']})" if inc.get("asset_tag") else ""),
        f"Status       : {inc.get('status', 'open')}"
        + (f" | Ticket ref: {inc['ticket_ref']}" if inc.get("ticket_ref") else ""),
        "",
        f"SYMPTOM:\n{inc.get('symptom', '')}",
        f"\nAFFECTED COMPONENT:\n{inc.get('affected_component', '-')}",
        f"\nEVIDENCE COLLECTED:\n{inc.get('evidence', '-')}",
        f"\nTROUBLESHOOTING PERFORMED:\n{inc.get('troubleshooting', '-')}",
        f"\nRECOMMENDATION:\n{inc.get('recommendation', '-')}",
        f"\nVERIFICATION RESULT:\n{inc.get('verification_result', '-')}",
    ]
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Asset inventory
# --------------------------------------------------------------------------- #
def save_asset(asset: dict, conn: sqlite3.Connection | None = None) -> int:
    own = conn is None
    conn = conn or connect()
    try:
        cur = conn.execute(
            """INSERT INTO assets(recorded_utc,hostname,asset_tag,manufacturer,model,
               os_caption,os_build,architecture,cpu_name,cpu_cores,ram_gb,
               disk_total_gb,installed_apps,details_json)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (_utcnow(), asset.get("hostname", ""), asset.get("asset_tag", ""),
             asset.get("manufacturer", ""), asset.get("model", ""),
             asset.get("os_caption", ""), asset.get("os_build", ""),
             asset.get("architecture", ""), asset.get("cpu_name", ""),
             asset.get("cpu_cores"), asset.get("ram_gb"),
             asset.get("disk_total_gb"),
             json.dumps(asset.get("installed_apps", [])),
             json.dumps(asset.get("details", {}), default=str)))
        conn.commit()
        return cur.lastrowid
    finally:
        if own:
            conn.close()


def latest_asset(hostname: str, conn: sqlite3.Connection | None = None) -> dict | None:
    own = conn is None
    conn = conn or connect()
    try:
        row = conn.execute(
            "SELECT * FROM assets WHERE hostname=? ORDER BY recorded_utc DESC LIMIT 1",
            (hostname,)).fetchone()
        return dict(row) if row else None
    except sqlite3.Error:
        return None
    finally:
        if own:
            conn.close()


def asset_history(hostname: str, limit: int = 50,
                  conn: sqlite3.Connection | None = None) -> list[dict]:
    own = conn is None
    conn = conn or connect()
    try:
        return [dict(r) for r in conn.execute(
            "SELECT * FROM assets WHERE hostname=? ORDER BY recorded_utc DESC LIMIT ?",
            (hostname, int(limit)))]
    except sqlite3.Error:
        return []
    finally:
        if own:
            conn.close()


def set_asset_tag(asset_id: int, tag: str,
                  conn: sqlite3.Connection | None = None) -> bool:
    own = conn is None
    conn = conn or connect()
    try:
        cur = conn.execute("UPDATE assets SET asset_tag=? WHERE id=?",
                           (tag[:80], asset_id))
        conn.commit()
        return cur.rowcount > 0
    finally:
        if own:
            conn.close()


# --------------------------------------------------------------------------- #
# Retention / cleanup policy
# --------------------------------------------------------------------------- #
def apply_retention(retain_days: int = 90, max_scans: int = 2000,
                    conn: sqlite3.Connection | None = None) -> dict:
    """Delete scans older than retain_days or beyond max_scans newest-first.

    Incidents are NEVER deleted automatically (they are technician records);
    only raw scan history and its per-check rows are pruned.
    """
    own = conn is None
    conn = conn or connect()
    try:
        removed = 0
        if retain_days and retain_days > 0:
            cutoff = (datetime.now(timezone.utc) - timedelta(days=int(retain_days))
                      ).isoformat(timespec="seconds")
            ids = [r["id"] for r in conn.execute(
                "SELECT id FROM scans WHERE started_utc < ?", (cutoff,))]
            for i in ids:
                conn.execute("DELETE FROM check_results WHERE scan_id=?", (i,))
                conn.execute("DELETE FROM scans WHERE id=?", (i,))
                removed += 1
        if max_scans and max_scans > 0:
            extra = [r["id"] for r in conn.execute(
                "SELECT id FROM scans ORDER BY started_utc DESC LIMIT -1 OFFSET ?",
                (int(max_scans),))]
            for i in extra:
                conn.execute("DELETE FROM check_results WHERE scan_id=?", (i,))
                conn.execute("DELETE FROM scans WHERE id=?", (i,))
                removed += 1
        conn.commit()
        return {"removed_scans": removed}
    finally:
        if own:
            conn.close()
