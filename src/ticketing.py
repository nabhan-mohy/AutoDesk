"""Optional ticketing-system integration (helpdesk webhook).

Disabled by default. When config.ticketing.enabled is true and a webhook URL
is configured, an incident can be pushed as a JSON payload to the dealership's
ticket platform (Zendesk/Zabbix/ServiceNow-style generic webhook adapters are
trivial to add below). The call runs in a background thread with a timeout so
the dashboard never blocks; failures are surfaced as a message, never a crash.

Security notes:
- Only diagnostic text already shown on screen is transmitted.
- If TLS verification fails or the endpoint is unreachable, the incident stays
  local (SQLite) and the technician can still copy the ticket-ready summary.
"""
from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request

from . import history_db


def _payload_zendesk(inc: dict) -> dict:
    return {"ticket": {
        "subject": f"[PC Health] {inc.get('symptom','')[:120]}",
        "comment": {"body": history_db.incident_summary_text(inc)},
        "tags": ["autodesk-health-monitor", inc.get("hostname", "")],
    }}


def _payload_generic(inc: dict) -> dict:
    return {
        "source": "AutoDesk IT Health Monitor",
        "title": (inc.get("symptom") or "")[:140],
        "hostname": inc.get("hostname", ""),
        "asset_tag": inc.get("asset_tag", ""),
        "severity": "high" if "not ready" in str(inc.get("verification_result", "")).lower()
                    else "medium",
        "description": history_db.incident_summary_text(inc),
        "fields": {
            "affected_component": inc.get("affected_component", ""),
            "evidence": inc.get("evidence", ""),
            "troubleshooting": inc.get("troubleshooting", ""),
            "recommendation": inc.get("recommendation", ""),
            "verification": inc.get("verification_result", ""),
        },
    }


ADAPTERS = {"generic": _payload_generic, "zendesk": _payload_zendesk}


def push_incident(cfg: dict, incident: dict,
                  callback=None) -> None:
    """Push an incident to the configured ticketing webhook (background thread).

    callback(ok: bool, message: str) is invoked from that thread - callers
    should only use it to set session state / show a toast.
    """
    t = cfg.get("ticketing", {}) or {}
    if not t.get("enabled"):
        if callback:
            callback(False, "Ticketing integration disabled in config.json")
        return
    url = str(t.get("webhook_url", "")).strip()
    token = str(t.get("api_token", ""))
    adapter = ADAPTERS.get(str(t.get("adapter", "generic")), _payload_generic)
    timeout = float(t.get("timeout_seconds", 10))
    if not url:
        if callback:
            callback(False, "ticketing.webhook_url is empty")
        return

    def worker():
        try:
            data = json.dumps(adapter(incident)).encode()
            headers = {"Content-Type": "application/json"}
            if token:
                headers["Authorization"] = f"Bearer {token}"
            req = urllib.request.Request(url, data=data, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read().decode(errors="replace")[:200]
            ok, msg = True, f"Ticket created ({resp.status}): {body}"
        except urllib.error.HTTPError as exc:
            ok, msg = False, f"Ticketing server error {exc.code}: check webhook URL/token/adapter"
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            ok, msg = False, f"Ticketing server unreachable: {str(exc)[:120]} (incident saved locally)"
        except Exception as exc:  # defensive: never kill the app thread
            ok, msg = False, f"Ticket push failed: {exc}"
        if callback:
            try:
                callback(ok, msg)
            except Exception:
                pass

    threading.Thread(target=worker, daemon=True).start()
