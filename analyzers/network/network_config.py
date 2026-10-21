import re
from dataclasses import dataclass, field
from typing import List


@dataclass
class NetworkContext:
    """
    Represents the network-level context of a JANUS target.
    """

    target: str
    host_up: bool
    open_ports: List[int] = field(default_factory=list)
    services: List[str] = field(default_factory=list)


def build_network_context(output: str, target: str):
    """
    Build network context from raw Nmap output.
    """

    host_up = "Host is up" in output

    pattern = re.compile(
        r"^[ \t]*(\d+)/tcp\s+open\s+(\S+)",
        re.MULTILINE
    )

    matches = pattern.findall(output)

    open_ports = []
    services = []

    for port, service in matches:
        open_ports.append(int(port))
        services.append(service)

    return NetworkContext(
        target=target,
        host_up=host_up,
        open_ports=open_ports,
        services=services
    )