"""
Operator-defined validation commands.

Each validation requirement a package can carry (security_retest, regression,
...) maps to ONE fixed argv chosen by the operator in a JSON file. The LLM never
supplies a command. The same list is handed to the executor as its allow-list,
so a command runs only if the operator wrote it here.

    {"commands": {"security_retest": ["{python}", "-m", "pytest", "-q", "check_exploit.py"]}}

"{python}" expands to the running interpreter.
"""

import json
import sys
from pathlib import Path
from typing import Dict, List, Optional


class ValidationPlan:
    def __init__(self, commands: Optional[Dict[str, List[str]]] = None):
        self._commands = {k: [sys.executable if a == "{python}" else a for a in v]
                          for k, v in (commands or {}).items()}

    @classmethod
    def load(cls, path: str) -> "ValidationPlan":
        return cls(json.loads(Path(path).read_text(encoding="utf-8")).get("commands", {}))

    def argv_for(self, requirement: str) -> Optional[List[str]]:
        argv = self._commands.get(requirement)
        return list(argv) if argv else None

    def allowed_commands(self) -> List[List[str]]:
        return [list(v) for v in self._commands.values()]
