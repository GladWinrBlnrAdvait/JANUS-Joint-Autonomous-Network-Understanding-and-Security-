"""
Context builder: attach network/host context to a Finding.

States what was observed and what is unknown. "reachable_from_scanner" means
Nmap saw the application's port open from the scanner's vantage point; it does
NOT mean internet-facing. Failed collections are listed as data gaps so the
reasoner cannot silently assume (for example) that no firewall exists.
"""

from typing import Any, Dict, List

from reasoning.assets import AssetMap
from reasoning.models import Finding, FindingContext


def build_context(finding: Finding, bundle: Dict[str, Any], assets: AssetMap) -> FindingContext:
    ctx = FindingContext(target=finding.target)
    asset = assets.lookup(finding.target)
    if not asset or not asset.get("host"):
        ctx.data_gaps.append(
            f"no asset mapping for '{finding.target}': network exposure cannot be determined")
        return ctx

    ctx.host = asset["host"]
    ctx.app_port = asset.get("port")
    ctx.role = asset.get("role")

    host_evidence: List[Dict[str, Any]] = bundle.get("targets", {}).get(ctx.host, [])
    if not host_evidence:
        ctx.data_gaps.append(f"no evidence collected for host {ctx.host}")

    open_ports = set()
    for ev in host_evidence:
        ftype, data = ev["finding_type"], ev.get("evidence_data", {})
        if ftype == "open_service" and data.get("state") == "open":
            ctx.open_services.append({
                "port": data.get("port"), "protocol": data.get("protocol"),
                "service": data.get("service"), "product": data.get("product"),
                "version": data.get("version"), "evidence_id": ev["evidence_id"]})
            open_ports.add(data.get("port"))
            ctx.evidence_ids.append(ev["evidence_id"])
        elif ftype == "host_status":
            ctx.evidence_ids.append(ev["evidence_id"])
        elif ftype in ("collection_failed", "scan_error"):
            ctx.data_gaps.append(
                f"{data.get('operation', ftype)} unavailable on {ctx.host}: "
                f"{data.get('error', ev.get('description', 'unknown error'))} "
                f"[{ev['evidence_id']}]")
            ctx.evidence_ids.append(ev["evidence_id"])

    if ctx.app_port is None:
        ctx.exposure = "unknown"
        ctx.data_gaps.append(f"application port for '{finding.target}' not specified")
    elif ctx.app_port in open_ports:
        ctx.exposure = "reachable_from_scanner"
    elif host_evidence:
        ctx.exposure = "not_observed"
    ctx.open_services.sort(key=lambda s: (s["port"] is None, s["port"]))
    return ctx
