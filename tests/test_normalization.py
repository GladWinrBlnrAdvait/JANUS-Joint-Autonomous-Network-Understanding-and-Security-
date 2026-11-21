import pytest
from evidence.normalizer import (
    NormalizationError, normalize_confidence, normalize_many,
    normalize_record, normalize_severity,
)


def test_severity_mapping():
    assert normalize_severity("Moderate") == "medium"
    assert normalize_severity("ERROR") == "high"
    assert normalize_severity(9.8) == "critical"
    assert normalize_severity(5.0) == "medium"
    for bad in ("banana", 11, True):
        with pytest.raises(NormalizationError):
            normalize_severity(bad)


def test_confidence_mapping():
    assert normalize_confidence("high") == 0.85
    assert normalize_confidence(80) == 0.8
    assert normalize_confidence(0.4) == 0.4
    for bad in ("maybe", 250, -1):
        with pytest.raises(NormalizationError):
            normalize_confidence(bad)


GOOD = {"category": "software", "target": "app.py", "finding_type": "sql_injection",
        "severity": "High", "confidence": "medium", "location": "app.py:42"}


def test_record_to_evidence():
    e = normalize_record(GOOD, source="semgrep", case_id="CASE-1", tool_version="1.0")
    assert e.severity == "high" and e.confidence == 0.6
    assert e.evidence_id.startswith("SEMGREP-") and e.case_id == "CASE-1"


def test_batch_reports_bad_records_instead_of_dropping_silently():
    bad = {"category": "software"}
    ev, errors = normalize_many([GOOD, bad, "junk"], source="semgrep", case_id="C")
    assert len(ev) == 1
    assert [e["index"] for e in errors] == [1, 2]