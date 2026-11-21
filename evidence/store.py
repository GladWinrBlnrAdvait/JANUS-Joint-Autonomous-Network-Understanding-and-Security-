"""
JANUS evidence store (file-based, JSON).

Layout:
    <root>/cases/<case_id>/evidence/<evidence_id>__<rev>.json
    <root>/cases/<case_id>/raw/<timestamp>_<source>_<target>.<ext>
    <root>/cases/<case_id>/raw/<same name>.meta.json   (sha256 + timestamp)

Evidence is append-only. If the same evidence_id is stored again with
different evidence_data, a new revision is kept instead of overwriting, so
contradictory observations are preserved rather than silently lost.
"""

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from evidence.models import Evidence

_SAFE_NAME = re.compile(r"^[A-Za-z0-9._-]+$")


class StoreError(Exception):
    pass


def _check_name(value: str, label: str) -> str:
    """Reject anything that could escape the store directory."""
    if not value or not _SAFE_NAME.match(value) or value in (".", ".."):
        raise StoreError(f"Unsafe or empty {label}: {value!r}")
    return value


def _slug(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", text)


class EvidenceStore:
    def __init__(self, root: str = "data"):
        self.root = Path(root)

    # ---------- paths ----------
    def _case_dir(self, case_id: str) -> Path:
        return self.root / "cases" / _check_name(case_id, "case_id")

    def _evidence_dir(self, case_id: str) -> Path:
        return self._case_dir(case_id) / "evidence"

    def _revisions(self, case_id: str, evidence_id: str) -> List[Path]:
        _check_name(evidence_id, "evidence_id")
        directory = self._evidence_dir(case_id)
        if not directory.exists():
            return []
        return sorted(
            directory.glob(f"{evidence_id}__*.json"),
            key=lambda p: int(p.stem.rsplit("__", 1)[1]),
        )

    # ---------- evidence ----------
    def add(self, evidence: Evidence) -> bool:
        """
        Store evidence. Returns True if something new was written,
        False if an identical observation already exists.
        """
        if not evidence.case_id:
            raise StoreError("Evidence must have a case_id to be stored")
        _check_name(evidence.evidence_id, "evidence_id")

        revisions = self._revisions(evidence.case_id, evidence.evidence_id)
        if revisions:
            latest = Evidence.from_dict(json.loads(revisions[-1].read_text("utf-8")))
            if latest.evidence_data == evidence.evidence_data:
                return False

        directory = self._evidence_dir(evidence.case_id)
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / f"{evidence.evidence_id}__{len(revisions) + 1}.json"
        path.write_text(json.dumps(evidence.to_dict(), indent=2), encoding="utf-8")
        return True

    def add_many(self, items: List[Evidence]) -> int:
        return sum(1 for e in items if self.add(e))

    def get(self, case_id: str, evidence_id: str) -> Optional[Evidence]:
        revisions = self._revisions(case_id, evidence_id)
        if not revisions:
            return None
        return Evidence.from_dict(json.loads(revisions[-1].read_text("utf-8")))

    def history(self, case_id: str, evidence_id: str) -> List[Evidence]:
        """All revisions of one evidence ID, oldest first."""
        return [
            Evidence.from_dict(json.loads(p.read_text("utf-8")))
            for p in self._revisions(case_id, evidence_id)
        ]

    def list(self, case_id: str, *, target: Optional[str] = None,
             source: Optional[str] = None, category: Optional[str] = None,
             finding_type: Optional[str] = None) -> List[Evidence]:
        """Latest revision of every evidence item in a case, filtered."""
        directory = self._evidence_dir(case_id)
        if not directory.exists():
            return []
        ids = sorted({p.stem.rsplit("__", 1)[0] for p in directory.glob("*__*.json")})
        results = []
        for evidence_id in ids:
            item = self.get(case_id, evidence_id)
            if item is None:
                continue
            if target and item.target != target:
                continue
            if source and item.source != source:
                continue
            if category and item.category != category:
                continue
            if finding_type and item.finding_type != finding_type:
                continue
            results.append(item)
        return results

    # ---------- raw artifacts ----------
    def save_raw(self, case_id: str, source: str, target: str,
                 content: str, extension: str = "txt") -> str:
        """
        Preserve raw tool output. Never overwrites: each save gets a
        timestamped name. Returns a reference (path relative to the store
        root) to put in Evidence.raw_ref.
        """
        raw_dir = self._case_dir(case_id) / "raw"
        raw_dir.mkdir(parents=True, exist_ok=True)

        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        name = f"{stamp}_{_slug(source)}_{_slug(target)}.{_slug(extension)}"
        path = raw_dir / name
        data = content.encode("utf-8")
        path.write_bytes(data)

        meta = {
            "sha256": hashlib.sha256(data).hexdigest(),
            "saved_at": datetime.now(timezone.utc).isoformat(),
            "source": source,
            "target": target,
        }
        (raw_dir / (name + ".meta.json")).write_text(
            json.dumps(meta, indent=2), encoding="utf-8"
        )
        return path.relative_to(self.root).as_posix()

    def read_raw(self, raw_ref: str) -> str:
        return self._resolve_raw(raw_ref).read_text("utf-8")

    def verify_raw(self, raw_ref: str) -> bool:
        """True if the raw artifact still matches the hash recorded at save time."""
        path = self._resolve_raw(raw_ref)
        meta_path = path.with_name(path.name + ".meta.json")
        if not meta_path.exists():
            return False
        expected = json.loads(meta_path.read_text("utf-8"))["sha256"]
        return hashlib.sha256(path.read_bytes()).hexdigest() == expected

    def _resolve_raw(self, raw_ref: str) -> Path:
        path = (self.root / raw_ref).resolve()
        if self.root.resolve() not in path.parents:
            raise StoreError("raw_ref points outside the evidence store")
        if not path.is_file():
            raise StoreError(f"Raw artifact not found: {raw_ref}")
        return path