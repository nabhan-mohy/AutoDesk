"""Optional OFFLINE explanation helper for root-cause findings.

Privacy-first: this module talks ONLY to a locally-running HTTP endpoint
(e.g. Ollama at http://localhost:11434). It is DISABLED by default; enabling
it requires an explicit config change. Nothing is ever sent to the internet,
and the prompt contains only diagnostic text already collected locally.

If the local model server is unreachable the caller simply shows the built-in
rule-based recommendation instead - no crash, no fallback to any cloud API.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request


def explain_locally(findings: list[dict], cfg: dict) -> str | None:
    """Return a plain-language paragraph explaining the top findings using a
    configured LOCAL LLM endpoint, or None when disabled/unreachable."""
    llm = (cfg.get("ai") or {})
    if not llm.get("enabled"):
        return None
    endpoint = str(llm.get("endpoint", "http://localhost:11434")).rstrip("/")
    # Hard safety: refuse anything that is not loopback/private - never proxy
    # dealership diagnostics to a remote host even if misconfigured.
    host = endpoint.split("//")[-1].split("/")[0].split(":")[0]
    if host not in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
        try:
            import ipaddress
            if not ipaddress.ip_address(host).is_loopback:
                return None  # non-local endpoint configured -> refuse silently
        except ValueError:
            return None
    top = findings[:5]
    lines = [f"- {f['title']} (confidence {int(f['confidence']*100)}%): {f['summary']}"
             for f in top]
    prompt = (
        "You are assisting a dealership IT support technician. Explain the following "
        "diagnostic findings in 3-4 simple sentences, then give the single most likely "
        "root cause and the safest first step. Do not invent facts beyond the evidence.\n\n"
        + "\n".join(lines))
    model = str(llm.get("model", "llama3"))
    timeout = float(llm.get("timeout_seconds", 20))
    payload = json.dumps({"model": model, "prompt": prompt, "stream": False,
                          "options": {"num_ctx": 2048}}).encode()
    try:
        req = urllib.request.Request(
            f"{endpoint}/api/generate", data=payload,
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
        text = data.get("response") or ""
        return text.strip() or None
    except (urllib.error.URLError, OSError, ValueError, TimeoutError):
        return None
