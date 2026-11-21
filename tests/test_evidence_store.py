import pytest
from evidence.models import Evidence
from evidence.store import EvidenceStore, StoreError


def ev(eid="NMAP-aaa", data=None, case="CASE-1", target="10.0.0.1"):
    return Evidence(evidence_id=eid, source="nmap", category="network", target=target,
                    finding_type="open_service", severity="info", confidence=1.0,
                    evidence_data=data or {"port": 22}, case_id=case)


def test_add_get_list_filter(tmp_path):
    s = EvidenceStore(str(tmp_path))
    assert s.add(ev("A")) and s.add(ev("B", target="10.0.0.2"))
    assert s.get("CASE-1", "A").evidence_data == {"port": 22}
    assert len(s.list("CASE-1")) == 2
    assert [e.evidence_id for e in s.list("CASE-1", target="10.0.0.2")] == ["B"]
    assert s.list("NOPE") == [] and s.get("CASE-1", "ZZZ") is None


def test_duplicate_ignored_but_contradiction_preserved(tmp_path):
    s = EvidenceStore(str(tmp_path))
    assert s.add(ev("A")) is True
    assert s.add(ev("A")) is False                       # identical -> no new revision
    assert s.add(ev("A", data={"port": 2222})) is True   # differs -> kept as revision 2
    assert len(s.history("CASE-1", "A")) == 2
    assert s.get("CASE-1", "A").evidence_data == {"port": 2222}


def test_requires_case_id_and_blocks_path_traversal(tmp_path):
    s = EvidenceStore(str(tmp_path))
    e = ev("A"); e.case_id = None
    with pytest.raises(StoreError):
        s.add(e)
    with pytest.raises(StoreError):
        s.list("../../etc")
    with pytest.raises(StoreError):
        s.read_raw("../outside.txt")


def test_raw_roundtrip_and_tamper_detection(tmp_path):
    s = EvidenceStore(str(tmp_path))
    ref1 = s.save_raw("CASE-1", "nmap", "10.0.0.1", "<xml/>", "xml")
    ref2 = s.save_raw("CASE-1", "nmap", "10.0.0.1", "<xml/>", "xml")
    assert ref1 != ref2                                   # never overwritten
    assert s.read_raw(ref1) == "<xml/>" and s.verify_raw(ref1)
    (tmp_path / ref1).write_text("tampered")
    assert s.verify_raw(ref1) is False