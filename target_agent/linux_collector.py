import subprocess


def collect_network_interfaces():
    """
    Collect network interface information from the Linux target.
    Compatible with older Python versions.
    """

    process = subprocess.Popen(
        ["/sbin/ip", "addr"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True
    )

    output, error = process.communicate()

    if process.returncode != 0:
        raise RuntimeError(
            "Failed to collect network interfaces: " + error
        )

    return output


def parse_interface_output(output):
    """
    Parse the output of 'ip addr' into structured interface data.
    """

    interfaces = []
    current_interface = None

    for line in output.splitlines():

        line = line.strip()

        if ":" in line and not line.startswith("inet"):
            parts = line.split(":", 2)

            if len(parts) >= 2 and parts[0].isdigit():

                current_interface = parts[1].strip()

                interfaces.append({
                    "name": current_interface,
                    "addresses": []
                })

        elif line.startswith("inet ") and current_interface:

            address = line.split()[1]

            interfaces[-1]["addresses"].append(address)

    return interfaces


def get_interface_data():
    """
    Collect and structure network interface information.
    """

    output = collect_network_interfaces()

    return parse_interface_output(output)


# ---------------------------------------------------------------------------
# New: whitelisted, read-only collection operations that produce Evidence.
# The functions above are unchanged so existing tests keep working.
# ---------------------------------------------------------------------------

import re
import shutil
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple

from evidence.models import Evidence, make_evidence_id

# Only these named operations can ever run. No arbitrary commands.
ALLOWED_OPERATIONS: Dict[str, Tuple[str, ...]] = {
    "interfaces": ("ip", "addr"),
    "routes": ("ip", "route"),
    "listening_sockets": ("ss", "-tuln"),
}


@dataclass
class CollectionResult:
    operation: str
    status: str            # "ok" | "failed" | "unavailable"
    output: str = ""
    error: str = ""


def _default_runner(command: List[str], timeout: int) -> Tuple[int, str, str]:
    process = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    return process.returncode, process.stdout, process.stderr


def run_operation(name: str, runner: Optional[Callable] = None,
                  timeout: int = 10) -> CollectionResult:
    """Run one named operation. Failures are returned, never raised."""
    if name not in ALLOWED_OPERATIONS:
        raise ValueError(f"Operation not allowed: {name!r}")
    command = list(ALLOWED_OPERATIONS[name])
    if runner is None:
        resolved = shutil.which(command[0])
        if resolved is None:
            return CollectionResult(name, "unavailable", error=f"{command[0]} not found")
        command[0] = resolved
        runner = _default_runner
    try:
        code, out, err = runner(command, timeout)
    except subprocess.TimeoutExpired:
        return CollectionResult(name, "failed", error=f"timed out after {timeout}s")
    except OSError as exc:
        return CollectionResult(name, "unavailable", error=str(exc))
    if code != 0:
        return CollectionResult(name, "failed", output=out, error=err.strip())
    return CollectionResult(name, "ok", output=out)


def parse_ip_addr(output: str) -> List[Dict]:
    """Parse `ip addr`: handles IPv4, IPv6, interface state and name@peer suffixes."""
    interfaces: List[Dict] = []
    for line in output.splitlines():
        header = re.match(r"^\d+:\s+(\S+?):\s+<([^>]*)>(.*)$", line)
        if header:
            state = re.search(r"\bstate\s+(\S+)", header.group(3))
            interfaces.append({
                "name": header.group(1).split("@")[0],
                "flags": header.group(2).split(","),
                "state": state.group(1) if state else "UNKNOWN",
                "ipv4": [], "ipv6": [],
            })
            continue
        parts = line.split()
        if interfaces and len(parts) >= 2 and parts[0] in ("inet", "inet6"):
            interfaces[-1]["ipv4" if parts[0] == "inet" else "ipv6"].append(parts[1])
    return interfaces


def parse_ip_route(output: str) -> List[Dict]:
    routes = []
    for line in output.splitlines():
        tokens = line.split()
        if not tokens:
            continue
        route = {"destination": tokens[0], "via": None, "dev": None, "src": None}
        for key in ("via", "dev", "src"):
            if key in tokens and tokens.index(key) + 1 < len(tokens):
                route[key] = tokens[tokens.index(key) + 1]
        routes.append(route)
    return routes


def parse_ss(output: str) -> List[Dict]:
    """Parse `ss -tuln` listening sockets and mark loopback-only ones."""
    sockets = []
    for line in output.splitlines():
        cols = line.split()
        if len(cols) < 5 or cols[0] not in ("tcp", "udp"):
            continue
        local = cols[4]
        address, _, port = local.rpartition(":")
        address = address.strip("[]")
        if not port.isdigit():
            continue
        loopback = address.startswith("127.") or address == "::1"
        sockets.append({
            "protocol": cols[0], "state": cols[1], "address": address or "*",
            "port": int(port), "scope": "loopback" if loopback else "network",
        })
    return sockets


def collect_host_evidence(case_id: str, target: str, store=None,
                          runner: Optional[Callable] = None) -> List[Evidence]:
    """
    Run all whitelisted operations and return Evidence. If a store is
    given, raw output is preserved and linked via raw_ref. A failed
    operation becomes explicit 'collection_failed' evidence.
    """
    parsers = {"interfaces": parse_ip_addr, "routes": parse_ip_route,
               "listening_sockets": parse_ss}
    evidence: List[Evidence] = []

    def make(op, ftype, key, description, data, raw_ref):
        return Evidence(
            evidence_id=make_evidence_id("HOST", case_id, target, ftype, *key),
            source="linux_collector", category="host", target=target,
            finding_type=ftype, severity="info", confidence=1.0,
            description=description, location=f"{target}:{key[0]}",
            evidence_data=data, case_id=case_id, raw_ref=raw_ref,
        )

    for op in ALLOWED_OPERATIONS:
        result = run_operation(op, runner=runner)
        if result.status != "ok":
            evidence.append(make(
                op, "collection_failed", (op,),
                f"Collection '{op}' {result.status}: {result.error}",
                {"operation": op, "status": result.status, "error": result.error}, None))
            continue
        raw_ref = None
        if store is not None:
            raw_ref = store.save_raw(case_id, f"linux_{op}", target, result.output)
        parsed = parsers[op](result.output)
        for item in parsed:
            if op == "interfaces":
                evidence.append(make(op, "network_interface", (item["name"],),
                    f"Interface {item['name']} is {item['state']} with "
                    f"{len(item['ipv4']) + len(item['ipv6'])} address(es)", item, raw_ref))
            elif op == "routes":
                evidence.append(make(op, "route", (item["destination"], item["dev"]),
                    f"Route to {item['destination']} via {item['via'] or 'direct'} "
                    f"on {item['dev']}", item, raw_ref))
            else:
                evidence.append(make(op, "listening_socket",
                    (item["protocol"], item["address"], item["port"]),
                    f"{item['protocol'].upper()} port {item['port']} listening on "
                    f"{item['address']} ({item['scope']})", item, raw_ref))
    return evidence