"""Read-only access to the application source under test, confined to one root."""

from pathlib import Path
from typing import Optional

FULL_FILE_MAX_LINES = 300


class FileSourceProvider:
    def __init__(self, root: Optional[str]):
        self.root = Path(root).resolve() if root else None

    def read_bytes(self, rel_path: str) -> Optional[bytes]:
        if self.root is None:
            return None
        p = (self.root / rel_path).resolve()
        if self.root not in p.parents:
            return None                      # path escaped the source root
        if not p.is_file():
            return None
        return p.read_bytes()

    def read(self, rel_path: str) -> Optional[str]:
        raw = self.read_bytes(rel_path)
        return None if raw is None else raw.decode("utf-8", errors="replace")

    def for_prompt(self, rel_path: str, line: Optional[int], radius: int = 20):
        """Numbered source for the LLM: whole file if small, else a window."""
        text = self.read(rel_path)
        if text is None:
            return None
        lines = text.splitlines()
        if len(lines) <= FULL_FILE_MAX_LINES or not line:
            lo, hi, full = 1, len(lines), len(lines) <= FULL_FILE_MAX_LINES
        else:
            lo, hi, full = max(1, line - radius), min(len(lines), line + radius), False
        numbered = "\n".join(f"{n}: {lines[n - 1]}" for n in range(lo, hi + 1))
        return {"file": rel_path, "full_file": full, "first_line": lo,
                "last_line": hi, "numbered_source": numbered}
