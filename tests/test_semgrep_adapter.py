import json
import pytest
from analyzers.software.semgrep_adapter import SemgrepError, semgrep_to_evidence
from evidence.store import EvidenceStore

SAMPLE = json.dumps({
    "version": "1.80.0",
    "results": [
        {"check_id": "python.flask.sql-injection", "path": "app.py",
         "start": {"line": 42, "col": 5}, "end": {"line": 42, "col": 40},
         "extra": {"message": "User input flows into SQL query", "severity": "ERROR",
                   "metadata": {"confidence": "HIGH", "cwe": ["CWE-89"], "category": "security"}}},
        {"check_id": "python.hardcoded-secret", "path": "config.py",
         "start": {"line": 7}, "end": {"line": 7},
         "extra": {"message": "Hardcoded secret", "severity": "WARNING", "metadata": {}}},
        {"check_id": "weird.rule", "path": "x.py", "start": {"line": 1},
         "extra": {"message": "bad severity", "severity": "BANANA"}},
    ],
    "errors": [{"message": "Syntax error in broken.py"}],
})


def test_conversion_and_vocabulary_mapping():
    ev, errors = semgrep_to_evidence(SAMPLE, "CASE-1", "myapp", raw_ref="cases/CASE-1/raw/s.json")
    sast = [e for e in ev if e.finding_type == "sast_finding"]
    assert len(sast) == 2
    sqli = next(e for e in sast if "sql" in e.evidence_data["rule_id"])
    assert sqli.severity == "high" and sqli.confidence == 0.85
    assert sqli.evidence_data["cwe"] == ["CWE-89"] and sqli.location == "app.py:42"
    secret = next(e for e in sast if "secret" in e.evidence_data["rule_id"])
    assert secret.severity == "medium" and secret.confidence == 0.6


def test_bad_record_reported_and_scan_error_preserved():
    ev, errors = semgrep_to_evidence(SAMPLE, "CASE-1", "myapp")
    assert len(errors) == 1 and "severity" in errors[0]["error"].lower()
    assert any(e.finding_type == "scan_error" for e in ev)


def test_malformed_input_is_explicit():
    with pytest.raises(SemgrepError):
        semgrep_to_evidence("not json", "C", "t")
    with pytest.raises(SemgrepError):
        semgrep_to_evidence("{}", "C", "t")


def test_same_store_as_network_evidence(tmp_path):
    from tests.test_nmap_xml import SAMPLE as NMAP_XML
    from analyzers.network.nmap_analyzer import nmap_xml_to_evidence
    store = EvidenceStore(str(tmp_path))
    sast, _ = semgrep_to_evidence(SAMPLE, "CASE-1", "myapp")
    store.add_many(sast)
    store.add_many(nmap_xml_to_evidence(NMAP_XML, "CASE-1"))
    assert {e.category for e in store.list("CASE-1")} == {"software", "network"}