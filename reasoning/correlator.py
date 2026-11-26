"""
Correlation: case bundle -> deduplicated Findings.

Only software-category evidence of an actionable type seeds a Finding;
network/host evidence is context (see context.py), not a finding by itself.
Evidence with the same (target, vulnerability class, location) is merged.

Limitation: matching a SAST location (file:line) to a DAST location (URL path)
needs a route->code map that does not exist yet, so those stay separate findings.
"""

import re
from collections import defaultdict
from typing import Any, Dict, List

from evidence.models import Evidence, VALID_SEVERITIES, make_evidence_id
from reasoning.models import Finding

SEED_TYPES = ("sast_finding", "dast_finding", "dependency_finding", "fuzz_crash")
SKIP_STATUSES = ("rejected", "remediated")
_CWE = re.compile(r"CWE-\d+", re.IGNORECASE)


def vuln_class_of(ev: Evidence) -> str:
    """Prefer a CWE id; fall back to the tool's rule id, then the finding type."""
    cwe = ev.evidence_data.get("cwe")
    items = cwe if isinstance(cwe, list) else ([cwe] if cwe else [])
    for item in items:
        m = _CWE.search(str(item))
        if m:
            return m.group(0).upper()
    return str(ev.evidence_data.get("rule_id") or ev.finding_type)


def combine_confidence(by_source: Dict[str, float]) -> float:
    """
    Heuristic: strongest reading per tool, then noisy-OR across distinct tools,
    so agreement between independent tools raises confidence and repeats from
    one tool do not. This is a ranking aid, not a calibrated probability.
    """
    miss = 1.0
    for conf in by_source.values():
        miss *= (1.0 - conf)
    return round(1.0 - miss, 4)


def correlate(bundle: Dict[str, Any]) -> List[Finding]:
    case_id = bundle["case_id"]
    groups: Dict[tuple, List[Evidence]] = defaultdict(list)
    for items in bundle.get("targets", {}).values():
        for raw in items:
            ev = Evidence.from_dict(raw)
            if (ev.category != "software" or ev.finding_type not in SEED_TYPES
                    or ev.status in SKIP_STATUSES):
                continue
            groups[(ev.target, vuln_class_of(ev), ev.location or "")].append(ev)

    findings = []
    for (target, vclass, location), evs in sorted(groups.items()):
        by_source: Dict[str, float] = {}
        for e in evs:
            by_source[e.source] = max(by_source.get(e.source, 0.0), e.confidence)
        cwes = sorted({c.upper() for e in evs for c in _CWE.findall(" ".join(
            str(x) for x in (e.evidence_data.get("cwe") or [])))})
        top = max(evs, key=lambda e: VALID_SEVERITIES.index(e.severity))
        findings.append(Finding(
            finding_id=make_evidence_id("FIND", case_id, target, vclass, location),
            case_id=case_id,
            title=f"{vclass} at {location or target}",
            vuln_class=vclass, target=target, location=location or None,
            severity=top.severity, confidence=combine_confidence(by_source),
            evidence_ids=sorted(e.evidence_id for e in evs),
            sources=sorted(by_source), cwe=cwes,
            description=top.description,
        ))
    return findings
