"""
JANUS authorization scope.

Every active operation (scan, collection, remediation) must check its target
against an explicit allow-list first. Nothing outside the list is touched.
"""

import ipaddress
import json
from pathlib import Path
from typing import Iterable, List


class ScopeError(Exception):
    """Target is outside the authorized scope."""


class AuthorizedScope:
    def __init__(self, allowed: Iterable[str]):
        self._networks = []
        self._hostnames = set()
        for entry in allowed:
            entry = str(entry).strip()
            if not entry:
                continue
            try:
                self._networks.append(ipaddress.ip_network(entry, strict=False))
            except ValueError:
                self._hostnames.add(entry.lower())
        if not self._networks and not self._hostnames:
            raise ValueError("Scope is empty: refusing to create an allow-all scope")

    @classmethod
    def from_file(cls, path: str) -> "AuthorizedScope":
        """Load from JSON: {"allowed": ["192.168.56.0/24", "lab.local"]}"""
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(data.get("allowed", []))

    def is_allowed(self, target: str) -> bool:
        target = str(target).strip()
        try:
            network = ipaddress.ip_network(target, strict=False)
        except ValueError:
            return target.lower() in self._hostnames
        return any(
            network.version == allowed.version and network.subnet_of(allowed)
            for allowed in self._networks
        )

    def require(self, target: str) -> None:
        if not self.is_allowed(target):
            raise ScopeError(f"Target {target!r} is outside the authorized scope")