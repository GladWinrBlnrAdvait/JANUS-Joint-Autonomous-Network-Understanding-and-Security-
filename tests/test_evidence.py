from evidence.models import Evidence


def test_evidence_creation():

    finding = Evidence(
        evidence_id="TEST-001",
        source="manual",
        category="network",
        target="192.168.56.40",
        finding_type="open_port",
        severity="medium",
        confidence=1.0,
        description="Port 21 is open",
        location="192.168.56.40:21"
    )

    assert finding.evidence_id == "TEST-001"
    assert finding.source == "manual"
    assert finding.category == "network"
    assert finding.severity == "medium"