"""
JANUS common evidence model.

Every collector/analyzer (Nmap, Linux collector, SAST, DAST, ...) must
produce Evidence objects. Downstream layers (context, reasoning,
remediation, validation, reporting) only ever consume this structure.
"""

import hashlib
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, Optional

VALID_SEVERITIES = ("info", "low", "medium", "high", "critical")
VALID_STATUSES = ("new", "confirmed", "inferred", "disputed", "remediated", "rejected")


def make_evidence_id(prefix: str, *parts: Any) -> str:
    """
    Deterministic evidence ID: the same observation always gets the same ID,
    but IDs never collide across targets, cases, or scans.
    Example: NMAP-3f9a1c2b7d10
    """
    raw = "|".join(str(p) for p in parts)
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]
    return f"{prefix.upper()}-{digest}"


@dataclass
class Evidence:
    # --- required (same order as before, so existing code keeps working) ---
    evidence_id: str
    source: str
    category: str
    target: str
    finding_type: str
    severity: str          # how bad it is IF true
    confidence: float      # how sure we are that it IS true (0.0 - 1.0)

    # --- optional, original ---
    description: str = ""
    location: Optional[str] = None
    evidence_data: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    status: str = "new"

    # --- new: provenance and traceability ---
    case_id: Optional[str] = None       # assessment case this belongs to
    tool_version: Optional[str] = None  # e.g. "Nmap 7.95"
    raw_ref: Optional[str] = None       # path/ID of the preserved raw output

    def __post_init__(self):
        self.severity = str(self.severity).lower()
        if self.severity not in VALID_SEVERITIES:
            raise ValueError(
                f"Invalid severity '{self.severity}'. Allowed: {VALID_SEVERITIES}"
            )
        if not isinstance(self.confidence, (int, float)) or isinstance(self.confidence, bool):
            raise ValueError("confidence must be a number between 0.0 and 1.0")
        if not 0.0 <= float(self.confidence) <= 1.0:
            raise ValueError("confidence must be between 0.0 and 1.0")
        self.confidence = float(self.confidence)
        if self.status not in VALID_STATUSES:
            raise ValueError(
                f"Invalid status '{self.status}'. Allowed: {VALID_STATUSES}"
            )
        for name in ("evidence_id", "source", "category", "target", "finding_type"):
            if not str(getattr(self, name)).strip():
                raise ValueError(f"'{name}' must not be empty")

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Evidence":
        known = set(cls.__dataclass_fields__)
        return cls(**{k: v for k, v in data.items() if k in known})