import json
from evidence.bundle import build_case_bundle, export_case_bundle
from evidence.models import Evidence
from evidence.store import EvidenceStore


def ev(eid, target="10.0.0.1", ftype="open_service", data=None, raw_ref=None, cat="network"):
    return Evidence(evidence_id=eid, source="t", category=cat, target=target,
                    finding_type=ftype, severity="info", confidence=1.0,
                    evidence_data=data or {"port": 22}, case_id="C1", raw_ref=raw_ref)


def test_bundle_groups_summarises_and_flags(tmp_path):
    s = EvidenceStore(str(tmp_path))
    ref = s.save_raw("C1", "nmap", "10.0.0.1", "<x/>", "xml")
    s.add(ev("A", raw_ref=ref))
    s.add(ev("B", target="10.0.0.2", cat="software"))
    s.add(ev("F", ftype="collection_failed", data={"error": "no ip"}))
    s.add(ev("A", data={"port": 2222}, raw_ref=ref))       # contradiction

    b = build_case_bundle(s, "C1")
    assert b["schema_version"] == "1.0"
    assert b["summary"]["evidence_count"] == 3
    assert b["summary"]["targets"] == ["10.0.0.1", "10.0.0.2"]
    assert b["summary"]["by_category"] == {"network": 2, "software": 1}
    assert len(b["contradictions"]) == 1 and len(b["contradictions"][0]["revisions"]) == 2
    assert len(b["failures"]) == 1
    assert b["raw_artifacts"] == [{"raw_ref": ref, "integrity": "verified"}]


def test_tampered_raw_is_flagged_and_export_works(tmp_path):
    s = EvidenceStore(str(tmp_path))
    ref = s.save_raw("C1", "nmap", "10.0.0.1", "<x/>", "xml")
    s.add(ev("A", raw_ref=ref))
    (tmp_path / ref).write_text("tampered")
    path = export_case_bundle(s, "C1")
    assert json.load(open(path))["raw_artifacts"][0]["integrity"] == "FAILED"


def test_empty_case(tmp_path):
    b = build_case_bundle(EvidenceStore(str(tmp_path)), "NOPE")
    assert b["summary"]["evidence_count"] == 0 and b["targets"] == {}