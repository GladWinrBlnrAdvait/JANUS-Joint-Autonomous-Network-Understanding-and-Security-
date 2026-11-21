import re
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List

from evidence.models import Evidence, make_evidence_id


class NmapError(Exception):
    """Nmap could not be run or returned a failure."""


class NmapParseError(ValueError):
    """Nmap XML was malformed or not Nmap output."""


# ---------------------------------------------------------------------------
# Existing functions (unchanged, kept so current tests keep working)
# ---------------------------------------------------------------------------

def run_nmap(target: str):
    """
    Run Nmap against an authorized target and return
    the raw Nmap output.
    """

    result = subprocess.run(
        ["nmap", target],
        capture_output=True,
        text=True,
        check=True
    )

    return result.stdout

def save_raw_output(output: str, target: str):
    """
    Save raw Nmap output to the JANUS evidence directory.
    """

    raw_directory = Path("data/raw")
    raw_directory.mkdir(parents=True, exist_ok=True)

    filename = f"nmap_{target.replace('.', '_')}.txt"
    output_path = raw_directory / filename

    output_path.write_text(output, encoding="utf-8")

    return output_path


def parse_nmap_output(output: str, target: str):
    """
    LEGACY: parse human-readable Nmap output. Fragile and uses
    non-unique IDs; prefer nmap_xml_to_evidence() for new work.
    """

    findings = []

    pattern = re.compile(
        r"^[ \t]*(\d+)/tcp\s+open\s+(\S+)",
        re.MULTILINE
    )

    matches = pattern.findall(output)

    for index, (port, service) in enumerate(matches, start=1):

        finding = Evidence(
            evidence_id=f"NMAP-{index:03d}",
            source="nmap",
            category="network",
            target=target,
            finding_type="open_service",
            severity="info",
            confidence=1.0,
            description=f"{service} service is exposed on TCP port {port}",
            location=f"{target}:{port}",
            evidence_data={
                "port": int(port),
                "protocol": "tcp",
                "service": service
            }
        )

        findings.append(finding)

    return findings


# ---------------------------------------------------------------------------
# New: XML-based collection and parsing
# ---------------------------------------------------------------------------

_SAFE_TARGET = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$")


def run_nmap_xml(target: str, timeout: int = 300, scope=None) -> str:
    """
    Run a service-detection scan and return Nmap's XML output.
    Target is validated so it can never be read as an Nmap option.
    """
    if not _SAFE_TARGET.match(target):
        raise NmapError(f"Refusing unsafe target: {target!r}")
    if scope is not None:
        scope.require(target)   # raises ScopeError if not authorized
    try:
        result = subprocess.run(
            ["nmap", "-sV", "-oX", "-", target],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
    except FileNotFoundError as exc:
        raise NmapError("nmap is not installed or not on PATH") from exc
    except subprocess.TimeoutExpired as exc:
        raise NmapError(f"nmap timed out after {timeout}s") from exc
    if result.returncode != 0:
        raise NmapError(f"nmap failed ({result.returncode}): {result.stderr.strip()}")
    return result.stdout


def parse_nmap_xml(xml_text: str) -> Dict[str, Any]:
    """
    Parse Nmap XML into plain data:
    {"tool_version": "Nmap 7.95", "hosts": [{"address", "status",
     "ports": [{"port","protocol","state","service","product","version",
                "extrainfo","service_method"}]}]}
    """
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise NmapParseError(f"Malformed Nmap XML: {exc}") from exc
    if root.tag != "nmaprun":
        raise NmapParseError("Not Nmap XML output (root element is not <nmaprun>)")

    hosts: List[Dict[str, Any]] = []
    for host in root.findall("host"):
        addr_el = host.find("address[@addrtype='ipv4']")
        if addr_el is None:
            addr_el = host.find("address")
        if addr_el is None:
            continue
        status_el = host.find("status")
        ports = []
        for port in host.findall("ports/port"):
            state_el = port.find("state")
            service_el = port.find("service")
            service = service_el.attrib if service_el is not None else {}
            try:
                number = int(port.get("portid"))
            except (TypeError, ValueError):
                continue
            ports.append({
                "port": number,
                "protocol": port.get("protocol", "tcp"),
                "state": state_el.get("state") if state_el is not None else "unknown",
                "service": service.get("name", "unknown"),
                "product": service.get("product"),
                "version": service.get("version"),
                "extrainfo": service.get("extrainfo"),
                "service_method": service.get("method"),
            })
        hosts.append({
            "address": addr_el.get("addr"),
            "status": status_el.get("state") if status_el is not None else "unknown",
            "ports": ports,
        })

    version = root.get("version")
    return {"tool_version": f"Nmap {version}" if version else None, "hosts": hosts}


def nmap_xml_to_evidence(xml_text: str, case_id: str, raw_ref: str = None) -> List[Evidence]:
    """
    Convert Nmap XML into Evidence. IDs are deterministic per
    case/host/port, so re-scans of the same service are recognisable.
    """
    parsed = parse_nmap_xml(xml_text)
    version = parsed["tool_version"]
    findings: List[Evidence] = []

    for host in parsed["hosts"]:
        address = host["address"]
        findings.append(Evidence(
            evidence_id=make_evidence_id("NMAP", case_id, address, "host_status"),
            source="nmap", category="network", target=address,
            finding_type="host_status", severity="info", confidence=1.0,
            description=f"Host {address} is {host['status']}",
            location=address,
            evidence_data={"status": host["status"]},
            case_id=case_id, tool_version=version, raw_ref=raw_ref,
        ))

        for p in host["ports"]:
            if p["state"] != "open":
                continue
            label = " ".join(x for x in (p["product"], p["version"]) if x)
            description = f"{p['service']} service is exposed on {p['protocol'].upper()} port {p['port']}"
            if label:
                description += f" ({label})"
            # service name guessed from the port table is weaker than a probed one
            confidence = 1.0 if p["service_method"] == "probed" else 0.7
            findings.append(Evidence(
                evidence_id=make_evidence_id(
                    "NMAP", case_id, address, p["protocol"], p["port"], "open_service"),
                source="nmap", category="network", target=address,
                finding_type="open_service", severity="info", confidence=confidence,
                description=description,
                location=f"{address}:{p['port']}",
                evidence_data=dict(p),
                case_id=case_id, tool_version=version, raw_ref=raw_ref,
            ))
    return findings