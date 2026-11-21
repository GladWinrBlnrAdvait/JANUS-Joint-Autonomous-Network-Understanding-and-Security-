"""
JANUS evidence normalizer.

Turns tool-specific records (dicts produced by adapters) into validated
Evidence objects. Different tools describe severity and confidence in
different vocabularies; this module is the single place where they are
translated into the JANUS vocabulary.
"""

from typing import Any, Dict, Iterable, List, Optional, Tuple

from evidence.models import Evidence, VALID_SEVERITIES, make_evidence_id


class NormalizationError(ValueError):
    """Raised when a raw record cannot be turned into valid Evidence."""


_SEVERITY_ALIASES = {
    "informational": "info", "information": "info", "note": "info", "none": "info",
    "minor": "low",
    "moderate": "medium", "warning": "medium", "warn": "medium",
    "important": "high", "error": "high", "major": "high",
    "severe": "critical", "fatal": "critical",
}

_CONFIDENCE_WORDS = {
    "confirmed": 1.0, "certain": 1.0,
    "high": 0.85,
    "medium": 0.6, "moderate": 0.6,
    "low": 0.3, "tentative": 0.3,
}

_REQUIRED_KEYS = ("category", "target", "finding_type", "severity", "confidence")


def normalize_severity(value: Any) -> str:
    """Map a label or a CVSS-style score (0-10) to a JANUS severity."""
    if isinstance(value, bool):
        raise NormalizationError(f"Unusable severity: {value!r}")
    if isinstance(value, (int, float)):
        if not 0 <= value <= 10:
            raise NormalizationError(f"Numeric severity out of range 0-10: {value}")
        if value == 0:
            return "info"
        if value < 4:
            return "low"
        if value < 7:
            return "medium"
        if value < 9:
            return "high"
        return "critical"
    label = str(value).strip().lower()
    label = _SEVERITY_ALIASES.get(label, label)
    if label not in VALID_SEVERITIES:
        raise NormalizationError(f"Unknown severity: {value!r}")
    return label


def normalize_confidence(value: Any) -> float:
    """Map words, 0-1 fractions, or 0-100 percentages to a 0.0-1.0 float."""
    if isinstance(value, bool):
        raise NormalizationError(f"Unusable confidence: {value!r}")
    if isinstance(value, (int, float)):
        if 0 <= value <= 1:
            return float(value)
        if 1 < value <= 100:
            return value / 100.0
        raise NormalizationError(f"Confidence out of range: {value}")
    word = str(value).strip().lower()
    if word in _CONFIDENCE_WORDS:
        return _CONFIDENCE_WORDS[word]
    raise NormalizationError(f"Unknown confidence: {value!r}")


def normalize_record(
    raw: Dict[str, Any],
    *,
    source: str,
    case_id: Optional[str] = None,
    tool_version: Optional[str] = None,
    raw_ref: Optional[str] = None,
    id_prefix: Optional[str] = None,
) -> Evidence:
    """Convert one raw record into a validated Evidence object."""
    if not isinstance(raw, dict):
        raise NormalizationError(f"Record must be a dict, got {type(raw).__name__}")

    missing = [k for k in _REQUIRED_KEYS if raw.get(k) in (None, "")]
    if missing:
        raise NormalizationError(f"Missing required field(s): {', '.join(missing)}")

    evidence_id = raw.get("evidence_id") or make_evidence_id(
        id_prefix or source,
        case_id, raw["target"], raw["finding_type"], raw.get("location"),
    )

    try:
        return Evidence(
            evidence_id=evidence_id,
            source=source,
            category=str(raw["category"]),
            target=str(raw["target"]),
            finding_type=str(raw["finding_type"]),
            severity=normalize_severity(raw["severity"]),
            confidence=normalize_confidence(raw["confidence"]),
            description=str(raw.get("description", "")),
            location=raw.get("location"),
            evidence_data=dict(raw.get("evidence_data") or {}),
            case_id=case_id,
            tool_version=tool_version,
            raw_ref=raw_ref,
        )
    except (ValueError, TypeError) as exc:
        raise NormalizationError(str(exc)) from exc


def normalize_many(
    records: Iterable[Dict[str, Any]], **kwargs
) -> Tuple[List[Evidence], List[Dict[str, Any]]]:
    """
    Normalize a batch. One bad record never kills the batch: failures are
    returned explicitly as [{"index": n, "error": "..."}] so they can be
    reported instead of silently dropped.
    """
    evidence: List[Evidence] = []
    errors: List[Dict[str, Any]] = []
    for index, raw in enumerate(records):
        try:
            evidence.append(normalize_record(raw, **kwargs))
        except NormalizationError as exc:
            errors.append({"index": index, "error": str(exc)})
    return evidence, errors