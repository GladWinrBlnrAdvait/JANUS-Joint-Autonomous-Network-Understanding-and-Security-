"""
Asset map: which host/port a software target runs on.

The Evidence layer labels software evidence by application ("demo-app") and
network evidence by IP. Nothing in the evidence says one runs on the other, so
that link is supplied explicitly (config/assets.json) rather than guessed.
"""

import json
from pathlib import Path
from typing import Any, Dict, Optional


class AssetMap:
    def __init__(self, mapping: Optional[Dict[str, Dict[str, Any]]] = None):
        self._m = mapping or {}

    @classmethod
    def load(cls, path: str) -> "AssetMap":
        p = Path(path)
        if not p.exists():
            return cls({})
        return cls(json.loads(p.read_text(encoding="utf-8")))

    def lookup(self, target: str) -> Optional[Dict[str, Any]]:
        return self._m.get(target)
