import pytest
from evidence.models import Evidence, make_evidence_id


def make(**overrides):
    base = dict(
        evidence_id="NMAP-001", source="nmap", category="network",
        target="192.168.56.10", finding_type="open_service",
        severity="info", confidence=1.0,
    )
    base.update(overrides)
    return Evidence(**base)


def test_defaults_and_old_style_construction():
    e = make()
    assert e.status == "new"
    assert e.case_id is None and e.raw_ref is None
    assert e.timestamp


def test_severity_normalised_and_validated():
    assert make(severity="HIGH").severity == "high"
    with pytest.raises(ValueError):
        make(severity="scary")


@pytest.mark.parametrize("bad", [-0.1, 1.5, "high", True])
def test_confidence_validated(bad):
    with pytest.raises(ValueError):
        make(confidence=bad)


def test_empty_required_field_rejected():
    with pytest.raises(ValueError):
        make(target=" ")


def test_round_trip():
    e = make(case_id="CASE-1", raw_ref="data/raw/x.txt", evidence_data={"port": 22})
    assert Evidence.from_dict(e.to_dict()) == e


def test_evidence_id_is_deterministic_and_distinct():
    a = make_evidence_id("nmap", "CASE-1", "10.0.0.1", 22)
    assert a == make_evidence_id("nmap", "CASE-1", "10.0.0.1", 22)
    assert a != make_evidence_id("nmap", "CASE-1", "10.0.0.2", 22)
    assert a.startswith("NMAP-")