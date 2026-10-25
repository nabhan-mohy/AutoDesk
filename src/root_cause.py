"""Rule-based root-cause analysis + guided troubleshooting workflows.

Every conclusion is derived from check results already collected in this run
(no new probing, no invented facts). Each finding carries:
  - confidence (0..1) and an uncertainty note when evidence is partial,
  - the exact evidence rows that support it (linked by check name),
  - a recommendation, and
  - a guided workflow the technician can step through.

This module never performs remediation; 'approved remediation' steps are only
described as text for human execution.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict

from .check_model import CheckResult, FAIL, INFO, PASS, WARNING, CONFIRMED, INCONCLUSIVE


@dataclass
class RootCauseFinding:
    title: str
    component: str            # e.g. "Local network", "DNS", "Printer"
    confidence: float         # 0..1
    summary: str              # plain-language conclusion
    uncertainty: str = ""     # what could make this wrong
    evidence: list[str] = field(default_factory=list)   # supporting check names
    recommendation: str = ""
    workflow_id: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


# --------------------------------------------------------------------------- #
# Guided troubleshooting decision trees
# --------------------------------------------------------------------------- #
NETWORK_WIZARD_STEPS = [
    ("Adapter / physical link",
     ["Network interfaces", "IP configuration"],
     "Is any NIC up with an IPv4 address (not 169.254.x.x)? If not: reseat cable / reconnect Wi-Fi first."),
    ("IP configuration / DHCP",
     ["DHCP lease", "IP configuration"],
     "APIPA or static misconfiguration? Renew via ipconfig /release + /renew before blaming higher layers."),
    ("Gateway / routing",
     ["Default route summary", "Gateway reachability"],
     "Does the PC have a default route and does the gateway respond (ping OR TCP)? A failed ping alone is inconclusive - routers often block ICMP."),
    ("DNS",
     ["DNS servers configured", "DNS resolution", "DNS server configuration"],
     "Do internal AND external names resolve? Only-public DNS breaks DMS hostnames; slow lookups point at a struggling DC/DNS server."),
    ("External connectivity",
     ["Internet endpoint", "Internet connectivity summary", "Web proxy configuration"],
     "At least one internet endpoint reachable? If none answer but TCP works, suspect proxy/firewall filtering, not an outage."),
    ("Configured business service",
     ["Service TCP", "Business app HTTP", "Mapped drive"],
     "Finally test the actual dealership service (DMS DB port, portal URL, share). Internet working does NOT mean the internal app is up."),
]

PRINTER_WIZARD_STEPS = [
    ("Spooler service", ["Print Spooler service"],
     "If the spooler is stopped nothing can print on this PC. An authorized tech starts it via services.msc (this tool never does)."),
    ("Driver/queue presence", ["Installed printers", "Default printer"],
     "Printer installed and set as default? Billing PCs must default to the invoice printer."),
    ("Device-reported status", ["Printer status:"],
     "Offline/stopped flags are stale-prone OS hints - verify power/cable and print one document manually before declaring hardware down."),
    ("Queue backlog", ["Queue:"],
     "Many pending jobs indicate a stuck job or offline device upstream; inspect the first errored job manually."),
    ("Network reachability", ["Network printer:"],
     "For IP printers: ping/raw-port answers are indirect evidence. Cross-check with the printer's own network configuration page."),
]


def _find(results: list[CheckResult], prefix: str) -> list[CheckResult]:
    return [r for r in results if r.name.startswith(prefix) or prefix in r.name]


def _any_status(rs: list[CheckResult], *statuses: str) -> bool:
    return any(r.status in statuses for r in rs)


# --------------------------------------------------------------------------- #
# Rule engine
# --------------------------------------------------------------------------- #
def analyze(results: list[CheckResult]) -> list[RootCauseFinding]:
    """Derive root-cause findings from one scan's results."""
    findings: list[RootCauseFinding] = []
    by = {r.name: r for r in results}

    def has(name_prefix, statuses=(FAIL,)):
        return _any_status(_find(results, name_prefix), *statuses)

    iface_fail = has("Network interfaces")
    apipa = any("169.254." in r.observed for r in _find(results, "Network interfaces")) \
        or any("169.254." in r.observed for r in _find(results, "IP configuration"))
    gw_fail = has("Gateway reachability")
    gw_warn = has("Gateway reachability", WARNING)
    dns_fail = has("DNS resolution")
    dns_slow = has("DNS resolution", WARNING)
    only_public_dns = any(r.name == "DNS server configuration" and r.status == WARNING
                          for r in results)
    inet_summary_fail = any(r.name == "Internet connectivity summary" and r.status == FAIL
                            for r in results)
    all_endpoints_down = len(_find(results, "Internet endpoint")) > 0 and \
        not _any_status(_find(results, "Internet endpoint"), PASS)
    svc_fail = has("Service TCP")
    proxy_info = next((r for r in results if r.name == "Web proxy configuration"), None)
    vpn_up = any(r.name == "VPN / tunnel interfaces" and r.observed
                 and "No VPN" not in r.observed for r in results)
    spooler_down = any(r.name == "Print Spooler service" and r.status == FAIL
                       for r in results)
    printer_offline = has("Printer status:", WARNING)
    printer_unreach = has("Network printer:", FAIL)
    printer_unreach_warn = has("Network printer:", WARNING)
    events_bad = any(r.name.startswith("Event Log") and r.status == WARNING for r in results)
    unexpected_shutdown = any(
        r.name.startswith("Event Log") and ("6008" in r.observed or "ID 41" in r.observed)
        for r in results)
    cpu_high = has("CPU utilization", WARNING) or has("CPU utilization")
    mem_high = has("Memory utilization", WARNING) or has("Memory utilization")
    disk_low = any(r.name.startswith("Disk space") and r.status in (WARNING, FAIL)
                   for r in results)
    high_io = False  # sustained-disk signal (io check would set details); conservative
    asset_changed = any(r.name == "Asset inventory snapshot" and r.status == WARNING
                        for r in results)

    # ---- local network ----------------------------------------------------- #
    if iface_fail:
        findings.append(RootCauseFinding(
            title="No working network connection on this workstation",
            component="Local network / adapter", confidence=0.9,
            summary="No active IPv4 interface was found, so every downstream network symptom "
                    "(DNS, internet, DMS, printers) is expected and not independently diagnosable.",
            uncertainty="Rarely a transient adapter disable; re-run after enabling the adapter.",
            evidence=["Network interfaces"], workflow_id="network-wizard",
            recommendation="Fix the physical/link layer first: cable, Wi-Fi association, adapter "
                           "enabled state. Re-run the scan afterwards - other failures will likely clear."))
    elif apipa:
        findings.append(RootCauseFinding(
            title="DHCP did not assign an address (APIPA 169.254.x.x)",
            component="DHCP / local network", confidence=0.85,
            summary="The adapter self-assigned an APIPA address, meaning no DHCP offer arrived "
                    "even though link appears present.",
            uncertainty="A static-configured kiosk legitimately shows no DHCP; confirm intent.",
            evidence=["Network interfaces", "IP configuration (IPv4)", "DHCP lease"],
            workflow_id="network-wizard",
            recommendation="ipconfig /release then /renew. Still APIPA? Check switch port/VLAN and "
                           "the DHCP scope with the network team."))
    # ---- DNS --------------------------------------------------------------- #
    if dns_fail and not iface_fail:
        findings.append(RootCauseFinding(
            title="Name resolution failing while the network path exists",
            component="DNS", confidence=0.75,
            summary="At least one DNS lookup definitively failed although the adapter has an IP. "
                    "Applications addressing servers by hostname will fail even when IPs work.",
            uncertainty="If only external test names fail, upstream DNS filtering may be intended policy.",
            evidence=[r.name for r in _find(results, "DNS resolution") if r.status == FAIL]
                     + ["DNS servers configured"],
            workflow_id="network-wizard",
            recommendation="ipconfig /flushdns; verify the DNS server list (internal DC first); "
                           "test nslookup against the internal server explicitly."))
    if only_public_dns:
        findings.append(RootCauseFinding(
            title="Internal names cannot resolve: only public DNS configured",
            component="DNS configuration", confidence=0.8,
            summary="The adapter lists only public DNS servers. Dealership hosts (DMS server, "
                    "domain controller, file shares) are resolved by internal DNS and will fail.",
            uncertainty="Workgroup PCs without internal apps may legitimately use public DNS.",
            evidence=["DNS server configuration"], workflow_id="network-wizard",
            recommendation="Set the internal DNS server (usually the domain controller) as primary "
                           "in the adapter or DHCP scope option 006."))
    elif dns_slow and not dns_fail:
        findings.append(RootCauseFinding(
            title="DNS responses slow - early sign of a struggling DNS/DC",
            component="DNS", confidence=0.5,
            summary="Lookups succeeded but exceeded the configured time budget. Slow DNS commonly "
                    "precedes application timeouts in DMS logins.",
            uncertainty="One-time slowness can be transient load; re-run to confirm.",
            evidence=[r.name for r in _find(results, "DNS resolution") if r.status == WARNING],
            workflow_id="network-wizard",
            recommendation="Re-run once; if persistent, ask the server team to check the DNS "
                           "server/DC health and zone replication."))
    # ---- external ---------------------------------------------------------- #
    if inet_summary_fail:
        findings.append(RootCauseFinding(
            title="Confirmed outbound connectivity failure",
            component="Internet / gateway", confidence=0.85,
            summary="Every configured endpoint failed AND the gateway check independently failed "
                    "with corroborated evidence - this is treated as a real outage, not filtering.",
            uncertainty="Simultaneous upstream outage and local fault is possible but rare.",
            evidence=["Internet connectivity summary"]
                     + [r.name for r in _find(results, "Gateway reachability") if r.status == FAIL],
            workflow_id="network-wizard",
            recommendation="Check physical link, then IP/gateway configuration; escalate to the "
                           "network team with this report. Showroom Wi-Fi guests unaffected? Compare "
                           "a second workstation."))
    elif all_endpoints_down and not iface_fail:
        findings.append(RootCauseFinding(
            title="All test endpoints failed but evidence is inconclusive",
            component="Internet egress", confidence=0.4,
            summary="No configured HTTP endpoint answered, yet lower-layer checks do not confirm "
                    "an outage. Proxy filtering or HEAD-request blocking is the common cause.",
            uncertainty="Cannot distinguish blocked egress from a real WAN problem from this PC alone.",
            evidence=[r.name for r in _find(results, "Internet endpoint")]
                     + (["Web proxy configuration"] if proxy_info else []),
            workflow_id="network-wizard",
            recommendation="Open one URL in the browser. Works => endpoint/HEAD filtering; fails on "
                           "several PCs => escalate WAN. Add more reliable endpoints to config.json."))
    # ---- business service --------------------------------------------------- #
    if svc_fail:
        related_dns = dns_fail or only_public_dns
        findings.append(RootCauseFinding(
            title="Dealership business service unreachable",
            component="Business application / server side",
            confidence=0.7 if not related_dns else 0.35,
            summary="A configured internal service TCP probe failed. The workstation's own network "
                    "stack otherwise looks functional, pointing toward the service/server side"
            + (" - BUT DNS problems were also detected, which explains hostname failures; fix DNS first."
               if related_dns else "."),
            uncertainty="Firewall/ACL changes or a sleeping service both look identical from a client.",
            evidence=[r.name for r in _find(results, "Service TCP") if r.status == FAIL],
            workflow_id="network-wizard",
            recommendation="Confirm the service is running on the server, check Windows Firewall and "
                           "switch ACLs, then involve the DMS/vendor team. Do not conclude 'server "
                           "down' from one workstation without a second data point."))
    if vpn_up and (svc_fail or dns_fail):
        findings.append(RootCauseFinding(
            title="Active VPN may be capturing internal traffic",
            component="VPN / routing", confidence=0.5,
            summary="A VPN/tunnel adapter is up while internal name/service tests fail - split-"
                    "tunnel VPNs frequently override routes to dealership subnets.",
            uncertainty="Correlation only; some VPN setups route internal ranges correctly.",
            evidence=["VPN / tunnel interfaces"]
                     + [r.name for r in results if r.status == FAIL and r.category == "Network"],
            workflow_id="network-wizard",
            recommendation="Disconnect the VPN briefly and re-test the internal service. If it works, "
                           "fix split-tunnel/split-DNS policy."))
    # ---- printers ------------------------------------------------------------ #
    if spooler_down:
        findings.append(RootCauseFinding(
            title="Print Spooler stopped - printing impossible on this PC",
            component="Print subsystem", confidence=0.95,
            summary="The spooler service itself reports stopped; queue/device checks are moot until "
                    "it runs.",
            uncertainty="None material - service state is authoritative.",
            evidence=["Print Spooler service"], workflow_id="printer-wizard",
            recommendation="Authorized technician: services.msc > Print Spooler > Start, and review "
                           "why it stopped (Event Log System, source Service Control Manager). This "
                           "tool intentionally does not start services."))
    if printer_unreach and not iface_fail and not gw_fail:
        findings.append(RootCauseFinding(
            title="Configured network printer unreachable while rest of LAN works",
            component="Printer device / its network path", confidence=0.6,
            summary="Ping and raw port both failed for the printer, yet the workstation reaches "
                    "other targets - isolates the issue to the device or its switch port/VLAN.",
            uncertainty="Deep-sleep models and non-9100 ports produce the same signature.",
            evidence=[r.name for r in _find(results, "Network printer") if r.status == FAIL],
            workflow_id="printer-wizard",
            recommendation="Check printer power/network page, its switch port, and the correct JetDirect "
                           "port in config.json. Print a device configuration page to verify IP."))
    elif printer_unreach_warn and not spooler_down:
        findings.append(RootCauseFinding(
            title="Printer reachability unverified (inconclusive probes)",
            component="Printer device", confidence=0.3,
            summary="Network probes to the configured printer did not answer, but ICMP/raw-port "
                    "blocking and sleep modes are equally likely - no outage is claimed.",
            uncertainty="High: many MFDs silently drop ICMP and use different ports.",
            evidence=[r.name for r in _find(results, "Network printer") if r.status == WARNING],
            workflow_id="printer-wizard",
            recommendation="Verify from the device panel (network settings page) and send one manual "
                           "test document before treating the printer as down."))
    if printer_offline and not spooler_down:
        findings.append(RootCauseFinding(
            title="Windows marks a printer offline/not available",
            component="Printer (device-reported status)", confidence=0.45,
            summary="Win32_Printer reports Offline/Not-Available for at least one queue. These "
                    "hints go stale easily (USB re-plug, sleeping MFD).",
            uncertainty="Stale flag is common; a fresh spooler conversation often clears it.",
            evidence=[r.name for r in _find(results, "Printer status") if r.status == WARNING],
            workflow_id="printer-wizard",
            recommendation="Open the queue, check 'Use Printer Offline' toggle state, verify the "
                           "device, then send one test page manually (human decision)."))
    # ---- windows health ------------------------------------------------------ #
    if unexpected_shutdown:
        findings.append(RootCauseFinding(
            title="Recent unexpected shutdown/restart recorded",
            component="Power / system stability", confidence=0.8,
            summary="Event Log contains Kernel-Power 41 and/or Event ID 6008 - the machine died "
                    "without a clean shutdown within the analysis window.",
            uncertainty="User-held power button produces the same events as power loss.",
            evidence=[r.name for r in results if r.name.startswith("Event Log")],
            workflow_id=None,
            recommendation="Ask the user what happened; check UPS/power strip, recent Windows Update, "
                           "and (if repeats) driver reliability - correlate with BugCheck 1001 events."))
    elif events_bad:
        findings.append(RootCauseFinding(
            title="Recent Critical/Error events need correlation",
            component="Windows system/application", confidence=0.5,
            summary="The event-log analyzer found recent Critical/Error entries. They may or may "
                    "not relate to today's symptom - timestamps decide.",
            uncertainty="Background noise (update retries, optional components) inflates counts.",
            evidence=[r.name for r in results if r.name.startswith("Event Log")],
            workflow_id=None,
            recommendation="Match event timestamps against when the user noticed the problem; ignore "
                           "events unrelated to the symptom window."))
    # ---- performance --------------------------------------------------------- #
    if cpu_high and mem_high:
        findings.append(RootCauseFinding(
            title="Sustained CPU+RAM pressure on this workstation",
            component="Performance", confidence=0.6,
            summary="Both CPU and memory exceeded warning thresholds simultaneously; users will "
                    "experience general slowness and DMS latency.",
            uncertainty="Single-sample snapshot: a scheduled antivirus scan explains temporary spikes.",
            evidence=["CPU utilization", "Memory utilization",
                      "Top resource-consuming processes"],
            workflow_id=None,
            recommendation="Review the top-processes row, close runaway applications, verify scan "
                           "schedules outside business hours; consider RAM upgrade if chronic (see trends tab)."))
    elif disk_low:
        findings.append(RootCauseFinding(
            title="Low free disk space threatens updates and DMS caching",
            component="Storage", confidence=0.7,
            summary="At least one volume is below the free-space policy; Windows Update and "
                    "document caches fail first under this condition.",
            uncertainty="",
            evidence=[r.name for r in results if r.name.startswith("Disk space")
                      and r.status in (WARNING, FAIL)],
            workflow_id=None,
            recommendation="Disk Cleanup / Storage Sense, empty Recycle Bin, relocate user data to "
                           "the server share. Re-check after cleanup."))
    if asset_changed:
        findings.append(RootCauseFinding(
            title="Hardware/inventory changed since last record",
            component="Asset management", confidence=0.9,
            summary="The asset snapshot differs from the previous one (e.g. RAM/disk/model). Unrecorded "
                    "changes usually mean an undocumented swap or upgrade.",
            uncertainty="Approved maintenance may explain it - confirm with the change log.",
            evidence=["Asset inventory snapshot"], workflow_id=None,
            recommendation="Confirm the change was approved, update the asset register/tag and CMDB."))
    return findings


# --------------------------------------------------------------------------- #
# Before/after verification
# --------------------------------------------------------------------------- #
def compare_scans(current: list[CheckResult], previous: list[dict]) -> dict:
    """Compare current results vs a stored previous scan (history_db rows).

    Returns {'fixed': [...], 'regressed': [...], 'unchanged_problems': [...],
             'new_checks': [...]} using check-name keys.
    """
    prev_by_name = {c["name"]: c for c in previous.get("checks", [])}
    cur_by_name = {r.name: r for r in current}
    fixed, regressed, still, new = [], [], [], []
    for name, r in cur_by_name.items():
        p = prev_by_name.get(name)
        if p is None:
            new.append({"name": name, "status": r.status})
            continue
        order = {"PASS": 0, "INFO": 0, "WARNING": 1, "FAIL": 2}
        delta = order.get(r.status, 1) - order.get(p.get("status", "PASS"), 0)
        entry = {"name": name, "before": p.get("status"), "after": r.status,
                 "before_observed": (p.get("observed") or "")[:160],
                 "after_observed": r.observed[:160]}
        if delta < 0:
            fixed.append(entry)
        elif delta > 0:
            regressed.append(entry)
        elif r.status in (WARNING, FAIL):
            still.append(entry)
    return {"fixed": fixed, "regressed": regressed,
            "unchanged_problems": still, "new_checks": new}


def workflows_for(findings: list[RootCauseFinding]) -> dict:
    """Map wizard id -> ordered steps with linked evidence rows."""
    wanted = {f.workflow_id for f in findings if f.workflow_id}
    out = {}
    if "network-wizard" in wanted:
        out["network-wizard"] = NETWORK_WIZARD_STEPS
    if "printer-wizard" in wanted:
        out["printer-wizard"] = PRINTER_WIZARD_STEPS
    return out
