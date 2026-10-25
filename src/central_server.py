"""Central dashboard + authenticated agent mode (LAN-only, zero dependencies).

A single stdlib HTTP server that runs on ONE 'hub' workstation and collects
compact scan summaries from other dealership PCs ('agents'). Everything stays
inside the dealership LAN; nothing is exposed to the internet.

Security model (documented honestly in README limitations):
- Shared device registration: an admin registers a device token locally
  (register_device); the agent stores it in its config.json under agent.token.
- Agent -> server communication uses the Authorization: Bearer <token> header.
- Passwords are stored ONLY as salted SHA-256 hashes (PBKDF2-HMAC) in the hub's
  local SQLite DB; technician roles: admin / tech / viewer.
- Audit log records every API call with actor + action + timestamp.
- Transport is plain HTTP for LAN use only. Deploy behind TLS/VPN if crossing
  untrusted segments (see README).

Run the hub:   python -m src.central_server [port]
Agent upload:  automatic at the end of each scan when config.agent.enabled=true
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import history_db

HUB_DB = os.path.join(os.path.dirname(history_db.DEFAULT_DB_PATH), "central_hub.sqlite")

_LOCK = threading.Lock()

_SCHEMA = """
CREATE TABLE IF NOT EXISTS devices(
    token_hash TEXT PRIMARY KEY,
    hostname TEXT NOT NULL,
    registered_utc TEXT NOT NULL,
    revoked INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS users(
    username TEXT PRIMARY KEY,
    pw_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('admin','tech','viewer')),
    created_utc TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS device_scans(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    received_utc TEXT NOT NULL,
    hostname TEXT NOT NULL,
    overall TEXT, pass_count INTEGER, warn_count INTEGER, fail_count INTEGER,
    cpu_percent REAL, memory_percent REAL, disk_min_free_gb REAL,
    dns_ok INTEGER, internet_ok INTEGER, printer_issues INTEGER,
    report_sha256 TEXT, payload_json TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_devscan ON device_scans(hostname, received_utc);
CREATE TABLE IF NOT EXISTS audit_log(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, detail TEXT);
"""


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def connect(path: str | None = None) -> sqlite3.Connection:
    path = path or os.environ.get("HEALTH_HUB_DB", HUB_DB)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.executescript(_SCHEMA)
    conn.commit()
    return conn


# --------------------------------------------------------------------------- #
# credentials / registration
# --------------------------------------------------------------------------- #
def hash_password(password: str, salt: str | None = None) -> tuple[str, str]:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 120_000)
    return digest.hex(), salt


def register_user(conn: sqlite3.Connection, username: str, password: str,
                  role: str = "tech", actor: str = "system") -> bool:
    if role not in ("admin", "tech", "viewer"):
        return False
    if len(password) < 8:
        raise ValueError("password must be at least 8 characters")
    pw, salt = hash_password(password)
    with _LOCK:
        try:
            conn.execute(
                "INSERT INTO users(username,pw_hash,salt,role,created_utc) VALUES(?,?,?,?,?)",
                (username, pw, salt, role, _utcnow()))
            audit(conn, actor, f"register_user:{role}", username)
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False


def verify_user(conn: sqlite3.Connection, username: str, password: str) -> dict | None:
    row = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if not row:
        return None
    digest, _ = hash_password(password, row["salt"])
    if hmac.compare_digest(digest, row["pw_hash"]):
        return dict(row)
    return None


def register_device(conn: sqlite3.Connection, hostname: str,
                    actor: str = "admin") -> str:
    """Create a device token; returned ONCE in plaintext, only the hash is stored."""
    token = secrets.token_hex(24)
    th = hashlib.sha256(token.encode()).hexdigest()
    with _LOCK:
        conn.execute("INSERT OR REPLACE INTO devices(token_hash,hostname,registered_utc,revoked)"
                     " VALUES(?,?,?,0)", (th, hostname, _utcnow()))
        audit(conn, actor, "register_device", hostname)
        conn.commit()
    return token


def revoke_device(conn: sqlite3.Connection, hostname: str, actor: str = "admin") -> int:
    with _LOCK:
        cur = conn.execute("UPDATE devices SET revoked=1 WHERE hostname=?", (hostname,))
        audit(conn, actor, "revoke_device", hostname)
        conn.commit()
        return cur.rowcount


def auth_device(conn: sqlite3.Connection, token: str) -> str | None:
    if not token:
        return None
    th = hashlib.sha256(token.encode()).hexdigest()
    row = conn.execute("SELECT hostname,revoked FROM devices WHERE token_hash=?",
                       (th,)).fetchone()
    if row and not row["revoked"]:
        return row["hostname"]
    return None


def audit(conn: sqlite3.Connection, actor: str, action: str, detail: str = "") -> None:
    conn.execute("INSERT INTO audit_log(ts,actor,action,detail) VALUES(?,?,?,?)",
                 (_utcnow(), actor, action, detail[:300]))


# --------------------------------------------------------------------------- #
# ingestion / queries
# --------------------------------------------------------------------------- #
def ingest_scan(conn: sqlite3.Connection, hostname: str, payload: dict) -> int:
    s = payload.get("summary", {}) or {}
    counts = s.get("counts", {}) or {}
    metrics = payload.get("metrics", {}) or {}
    with _LOCK:
        cur = conn.execute(
            """INSERT INTO device_scans(received_utc,hostname,overall,pass_count,
               warn_count,fail_count,cpu_percent,memory_percent,disk_min_free_gb,
               dns_ok,internet_ok,printer_issues,report_sha256,payload_json)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (_utcnow(), hostname, s.get("overall", ""),
             counts.get("PASS", 0), counts.get("WARNING", 0), counts.get("FAIL", 0),
             metrics.get("cpu_percent"), metrics.get("memory_percent"),
             metrics.get("disk_min_free_gb"), metrics.get("dns_ok"),
             metrics.get("internet_ok"), metrics.get("printer_issues"),
             payload.get("report_sha256", ""),
             json.dumps(payload, default=str)[:4_000_000]))
        conn.commit()
        return cur.lastrowid


def fleet_status(conn: sqlite3.Connection, stale_hours: int = 24) -> list[dict]:
    """Latest scan per device + staleness flag."""
    rows = conn.execute(
        """SELECT d.hostname, MAX(d.received_utc) AS last_seen,
                  (SELECT overall FROM device_scans x WHERE x.hostname=d.hostname
                    ORDER BY received_utc DESC LIMIT 1) AS overall,
                  (SELECT fail_count FROM device_scans x WHERE x.hostname=d.hostname
                    ORDER BY received_utc DESC LIMIT 1) AS fail_count,
                  (SELECT warn_count FROM device_scans x WHERE x.hostname=d.hostname
                    ORDER BY received_utc DESC LIMIT 1) AS warn_count
           FROM device_scans d GROUP BY d.hostname ORDER BY last_seen DESC""").fetchall()
    out = []
    now = datetime.now(timezone.utc)
    for r in rows:
        d = dict(r)
        try:
            last = datetime.fromisoformat(d["last_seen"])
            d["stale"] = (now - last).total_seconds() > stale_hours * 3600
        except (TypeError, ValueError):
            d["stale"] = True
        out.append(d)
    return out


def device_history(conn: sqlite3.Connection, hostname: str, limit: int = 50) -> list[dict]:
    return [dict(r) for r in conn.execute(
        """SELECT received_utc,overall,pass_count,warn_count,fail_count,cpu_percent,
                  memory_percent,disk_min_free_gb,internet_ok,printer_issues
           FROM device_scans WHERE hostname=? ORDER BY received_utc DESC LIMIT ?""",
        (hostname, int(limit)))]


def compact_metrics_from_report(report: dict) -> dict:
    """Build the small metrics block agents send to the hub (no raw logs)."""
    det = {r.name: (r.details or {}) for r in report.get("results", [])}
    disks = [d.get("free_gb") for n, d in det.items()
             if n.startswith("Disk space") and isinstance(d.get("free_gb"), (int, float))]
    dns_rows = [r for r in report.get("results", []) if r.name.startswith("DNS resolution")]
    inet_rows = [r for r in report.get("results", []) if r.name.startswith("Internet endpoint")]
    return {
        "cpu_percent": det.get("CPU utilization", {}).get("percent"),
        "memory_percent": det.get("Memory utilization", {}).get("percent"),
        "disk_min_free_gb": min(disks) if disks else None,
        "dns_ok": (any(r.status == "PASS" for r in dns_rows) if dns_rows else None),
        "internet_ok": (any(r.status == "PASS" for r in inet_rows) if inet_rows else None),
        "printer_issues": sum(1 for r in report.get("results", [])
                              if r.category == "Printer" and r.status in ("WARNING", "FAIL")),
    }


def post_to_hub(cfg: dict, report: dict, timeout: float = 8.0) -> tuple[bool, str]:
    """Agent-side upload. Returns (ok, message). Never raises."""
    agent = cfg.get("agent", {}) or {}
    if not agent.get("enabled"):
        return False, "agent disabled"
    url = str(agent.get("server_url", "")).rstrip("/")
    token = str(agent.get("token", ""))
    if not url or not token:
        return False, "agent.server_url/token not configured"
    import urllib.error
    import urllib.request
    payload = {
        "hostname": report.get("hostname", ""),
        "version": report.get("version", ""),
        "started_local": report.get("started_local", ""),
        "duration_seconds": report.get("duration_seconds"),
        "summary": report.get("summary", {}),
        "metrics": compact_metrics_from_report(report),
        "findings": [f.to_dict() for f in report.get("findings", [])][:20],
        "report_sha256": report.get("report_sha256", ""),
    }
    data = json.dumps(payload, default=str).encode()
    req = urllib.request.Request(url.rstrip("/") + "/api/v1/scan", data=data,
                                 headers={"Content-Type": "application/json",
                                          "Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode(errors="replace")[:200]
        return True, f"uploaded ({resp.status}): {body}"
    except urllib.error.HTTPError as exc:
        return False, f"hub rejected ({exc.code}) - check device token/revocation"
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        return False, f"hub unreachable: {str(exc)[:120]}"


# --------------------------------------------------------------------------- #
# HTTP API
# --------------------------------------------------------------------------- #
class HubHandler(BaseHTTPRequestHandler):
    server_version = "AutoDeskHub/1.0"
    conn: sqlite3.Connection  # set on class by run_server

    def _send(self, code: int, obj) -> None:
        body = json.dumps(obj, default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if length > 4_000_000:
            raise ValueError("payload too large")
        raw = self.rfile.read(length) if length else b"{}"
        return json.loads(raw.decode())

    def _device(self) -> str | None:
        auth = self.headers.get("Authorization", "")
        token = auth[7:] if auth.lower().startswith("bearer ") else ""
        return auth_device(HubHandler.conn, token)

    def do_GET(self):  # noqa: N802
        if self.path == "/api/v1/health":
            return self._send(200, {"status": "ok"})
        if self.path == "/api/v1/fleet":
            host = self._device()
            if not host:
                return self._send(401, {"error": "device token required"})
            return self._send(200, {"fleet": fleet_status(HubHandler.conn)})
        if self.path.startswith("/api/v1/history/"):
            host = self._device()
            if not host:
                return self._send(401, {"error": "device token required"})
            name = self.path.split("/")[-1]
            return self._send(200, {"hostname": name,
                                    "scans": device_history(HubHandler.conn, name)})
        return self._send(404, {"error": "not found"})

    def do_POST(self):  # noqa: N802
        if self.path == "/api/v1/scan":
            host = self._device()
            if not host:
                return self._send(401, {"error": "invalid or revoked device token"})
            try:
                payload = self._read_json()
            except (ValueError, json.JSONDecodeError) as exc:
                return self._send(400, {"error": f"bad json: {exc}"})
            if str(payload.get("hostname", "")) != host:
                return self._send(403, {"error": "hostname mismatch for this device token"})
            sid = ingest_scan(HubHandler.conn, host, payload)
            with _LOCK:
                audit(HubHandler.conn, host, "ingest_scan", f"scan_id={sid}")
                HubHandler.conn.commit()
            return self._send(201, {"id": sid})
        return self._send(404, {"error": "not found"})

    def log_message(self, fmt, *args):  # quieter default logging
        pass


def run_server(port: int = 8600, db_path: str | None = None) -> None:
    HubHandler.conn = connect(db_path)
    httpd = ThreadingHTTPServer(("0.0.0.0", port), HubHandler)
    print(f"AutoDesk central hub listening on :{port} (LAN only - see README security notes)")
    httpd.serve_forever()


def main() -> None:  # pragma: no cover - CLI
    ap = argparse.ArgumentParser(description="AutoDesk IT Health Monitor central hub")
    ap.add_argument("port", nargs="?", type=int, default=8600)
    ap.add_argument("--add-user", nargs=3, metavar=("USER", "PASS", "ROLE"))
    ap.add_argument("--register-device", metavar="HOSTNAME")
    args = ap.parse_args()
    conn = connect()
    if args.add_user:
        u, p, r = args.add_user
        register_user(conn, u, p, r)
        print(f"user '{u}' role '{r}' registered")
    if args.register_device:
        tok = register_device(conn, args.register_device)
        print("Device token (show ONCE to the technician, store in agent config.json):")
        print(tok)
    if not (args.add_user or args.register_device):
        run_server(args.port)


if __name__ == "__main__":  # pragma: no cover
    main()
