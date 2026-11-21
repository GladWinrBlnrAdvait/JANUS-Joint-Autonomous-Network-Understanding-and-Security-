"""
JANUS case bundle: the single structured hand-off from the Evidence layer
to the context, reasoning, remediation, validation and reporting layers.
"""

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from evidence.store import EvidenceStore, StoreError

SCHEMA_VERSION = "1.0"


def build_case_bundle(store: EvidenceStore, case_id: str) -> Dict[str, Any]:
    """
    Everything known about a case, grouped for downstream consumers:
    - targets:        latest evidence per target
    - contradictions: evidence IDs whose data changed between observations
    - failures:       collection/scan failures (missing data is explicit)
    - raw_artifacts:  every raw file referenced, with an integrity check
    """
    items = store.list(case_id)

    targets: Dict[str, list] = {}
    contradictions = []
    failures = []
    raw_refs = set()

    for item in items:
        targets.setdefault(item.target, []).append(item.to_dict())
        if item.raw_ref:
            raw_refs.add(item.raw_ref)
        if item.finding_type in ("collection_failed", "scan_error"):
            failures.append({"evidence_id": item.evidence_id,
                             "source": item.source,
                             "description": item.description})
        revisions = store.history(case_id, item.evidence_id)
        if len(revisions) > 1:
            contradictions.append({
                "evidence_id": item.evidence_id,
                "revisions": [r.to_dict() for r in revisions],
            })

    raw_artifacts = []
    for ref in sorted(raw_refs):
        try:
            ok = store.verify_raw(ref)
        except StoreError:
            ok = False
        raw_artifacts.append({"raw_ref": ref, "integrity": "verified" if ok else "FAILED"})

    return {
        "schema_version": SCHEMA_VERSION,
        "case_id": case_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "evidence_count": len(items),
            "targets": sorted(targets),
            "by_category": dict(Counter(i.category for i in items)),
            "by_severity": dict(Counter(i.severity for i in items)),
            "by_finding_type": dict(Counter(i.finding_type for i in items)),
            "contradictions": len(contradictions),
            "failures": len(failures),
        },
        "targets": targets,
        "contradictions": contradictions,
        "failures": failures,
        "raw_artifacts": raw_artifacts,
    }


def export_case_bundle(store: EvidenceStore, case_id: str, path: str = None) -> str:
    """Write the bundle as JSON and return the file path."""
    bundle = build_case_bundle(store, case_id)
    out = Path(path) if path else store.root / "cases" / case_id / "bundle.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(bundle, indent=2), encoding="utf-8")
    return str(out)