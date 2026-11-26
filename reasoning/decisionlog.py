"""
Append-only decision log: every LLM exchange and verdict is stored with the
prompt hash, so any recommendation can be traced and audited later.
"""

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional


class DecisionLog:
    def __init__(self, path: Optional[str] = None):
        self.path = Path(path) if path else None
        self.records = []
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, stage: str, finding_id: str, **fields: Any) -> Dict[str, Any]:
        rec = {"timestamp": datetime.now(timezone.utc).isoformat(),
               "stage": stage, "finding_id": finding_id, **fields}
        self.records.append(rec)
        if self.path:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec) + "\n")
        return rec


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
