from analyzers.network.nmap_analyzer import nmap_xml_to_evidence
from evidence.store import EvidenceStore
from tests.test_nmap_xml import SAMPLE


def test_scan_to_store_and_back(tmp_path):
    store = EvidenceStore(str(tmp_path))
    ref = store.save_raw("CASE-1", "nmap", "192.168.56.10", SAMPLE, "xml")
    store.add_many(nmap_xml_to_evidence(SAMPLE, "CASE-1", raw_ref=ref))

    services = store.list("CASE-1", finding_type="open_service")
    assert len(services) == 2
    assert all(store.verify_raw(e.raw_ref) for e in services)   # traceable to source

    # re-ingesting the same scan creates no duplicates
    assert store.add_many(nmap_xml_to_evidence(SAMPLE, "CASE-1", raw_ref=ref)) == 0