from dataclasses import dataclass, field
from typing import Optional, Dict, Any
from datetime import datetime, timezone


@dataclass
class Evidence:
    evidence_id: str
    source: str
    category: str
    target: str
    finding_type: str
    severity: str
    confidence: float

    description: str = ""
    location: Optional[str] = None
    evidence_data: Dict[str, Any] = field(default_factory=dict)

    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    status: str = "new"