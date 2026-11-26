from evidence.models import Evidence
from reasoning.assets import AssetMap
from reasoning.context import build_context
from reasoning.correlator import combine_confidence, correlate, vuln_class_of


def _ev(eid, source="semgrep", category="software", target="app", ftype="sast_finding",
        severity="high", conf=0.8, location="app.py:42", data=None, status="new"):
    return Evidence(evidence_id=eid, source=source, category=category, target=target,
                    finding_type=ftype, severity=severity, confidence=conf, location=location,
                    evidence_data=data if data is not None else {"cwe": ["CWE-89: SQL Injection"]},
                    status=status, case_id="C")


def _bundle(*evs):
    targets = {}
    for e in evs:
        targets.setdefault(e.target, []).append(e.to_dict())
    return {"case_id": "C", "targets": targets}


def test_vuln_class_prefers_cwe_then_rule():
    assert vuln_class_of(_ev("E1")) == "CWE-89"
    assert vuln_class_of(_ev("E2", data={"rule_id": "py.rule"})) == "py.rule"


def test_same_issue_from_two_tools_merges_and_raises_confidence():
    f = correlate(_bundle(_ev("E1", conf=0.7), _ev("E2", source="dast", ftype="dast_finding", conf=0.6)))
    assert len(f) == 1
    assert f[0].evidence_ids == ["E1", "E2"] and f[0].sources == ["dast", "semgrep"]
    assert f[0].confidence == combine_confidence({"a": 0.7, "b": 0.6}) == 0.88


def test_repeats_from_one_tool_do_not_inflate_confidence():
    assert combine_confidence({"semgrep": 0.8}) == 0.8


def test_network_info_rejected_and_remediated_are_not_findings():
    ev = [_ev("N1", category="network", ftype="open_service", severity="info", data={"port": 80}),
          _ev("R1", status="rejected"), _ev("R2", status="remediated", location="b.py:1")]
    assert correlate(_bundle(*ev)) == []


def test_different_locations_stay_separate():
    assert len(correlate(_bundle(_ev("E1"), _ev("E2", location="app.py:99")))) == 2


def _net(port=80):
    return [_ev("N1", category="network", target="10.0.0.5", ftype="open_service", severity="info",
                data={"port": port, "protocol": "tcp", "state": "open", "service": "http"}),
            _ev("H1", category="host", target="10.0.0.5", ftype="collection_failed", severity="info",
                data={"operation": "listening_sockets", "error": "ss not found"})]


def test_context_reachable_and_gaps_are_explicit():
    b = _bundle(_ev("E1"), *_net())
    f = correlate(b)[0]
    ctx = build_context(f, b, AssetMap({"app": {"host": "10.0.0.5", "port": 80}}))
    assert ctx.exposure == "reachable_from_scanner"
    assert ctx.open_services[0]["port"] == 80
    assert any("listening_sockets" in g and "H1" in g for g in ctx.data_gaps)
    assert {"N1", "H1"} <= set(ctx.evidence_ids)


def test_context_port_not_open_is_not_observed():
    b = _bundle(_ev("E1"), *_net(port=22))
    ctx = build_context(correlate(b)[0], b, AssetMap({"app": {"host": "10.0.0.5", "port": 80}}))
    assert ctx.exposure == "not_observed"


def test_unmapped_target_is_unknown_never_guessed():
    b = _bundle(_ev("E1"), *_net())
    ctx = build_context(correlate(b)[0], b, AssetMap({}))
    assert ctx.exposure == "unknown" and ctx.host is None
    assert "no asset mapping" in ctx.data_gaps[0]
