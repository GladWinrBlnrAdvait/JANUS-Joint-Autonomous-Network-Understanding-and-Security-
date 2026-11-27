"""Reasoning layer <-> controlled_execution (Part 3), using the REAL executor."""

import difflib
import hashlib
import json
import shutil
import sys
from pathlib import Path

import pytest

from controlled_execution import ControlledExecutor
from evidence.scope import AuthorizedScope
from reasoning.closed_loop import validate_and_refine
from reasoning.decisionlog import DecisionLog
from reasoning.handoff import HandoffError, result_to_validation, to_execution_package
from reasoning.llm import ScriptedLLM
from reasoning.models import (ChangeItem, Finding, FindingContext, RationaleItem, ReasoningResult,
                              RemediationPackage)
from reasoning.remediation import RemediationEngine
from reasoning.source import FileSourceProvider
from reasoning.validation_plan import ValidationPlan

DEMO = Path(__file__).resolve().parent.parent / "samples" / "demo-app"
FINDING = Finding(finding_id="FIND-1", case_id="C", title="t", vuln_class="CWE-89",
                  target="demo-app", severity="high", confidence=0.8, evidence_ids=["E1"],
                  sources=["semgrep"], location="app.py:42")
CTX = FindingContext(target="demo-app", host="192.168.56.10", app_port=80, exposure="reachable_from_scanner")
ASSESS = ReasoningResult("FIND-1", "likely_vulnerable", "string-built SQL", "high", "high",
                         ["app.py"], [RationaleItem("tool reports it", ["E1"])], ["code_patch"], 0.8)


def _diff(old, new, name="app.py"):
    return "\n".join(difflib.unified_diff(old.splitlines(), new.splitlines(),
                                          f"a/{name}", f"b/{name}", lineterm=""))


def _reply(diff):
    return json.dumps({"changes": [{"type": "code_patch", "file": "app.py", "diff": diff}],
                       "expected_security_effect": "s", "expected_functional_behaviour": "f",
                       "expected_network_behaviour": "n"})


@pytest.fixture
def lab(tmp_path):
    ws = tmp_path / "workspace"
    shutil.copytree(DEMO, ws)
    plan = ValidationPlan.load(str(DEMO / "validation.json"))
    ex = ControlledExecutor(str(ws), str(tmp_path / "snap"), AuthorizedScope(["192.168.56.0/24"]),
                            plan.allowed_commands())
    return ws, plan, ex, FileSourceProvider(str(ws))


ORIG = (DEMO / "app.py").read_text(encoding="utf-8")
FIX = ORIG.replace('''    query = f"SELECT role FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)''', '''    query = "SELECT role FROM users WHERE username = ? AND password = ?"
    cursor.execute(query, (username, password))''')
NOOP = ORIG.replace('"""Return the user\'s role if the credentials match, else None."""',
                    '"""Return the role (changed docstring only)."""')
BROKEN = FIX.replace("    return row[0] if row else None", "    return None")   # SQL fixed, login broken


def _engine(ws_source, replies, **kw):
    llm = ScriptedLLM(replies)
    return RemediationEngine(llm, DecisionLog(), ws_source, **kw), llm


def _run(lab, replies, **kw):
    ws, plan, ex, src = lab
    eng, llm = _engine(src, replies, **kw)
    pkg = eng.propose(FINDING, CTX, ASSESS)
    return validate_and_refine(FINDING, CTX, ASSESS, pkg, eng, ex, plan, src, DecisionLog()), llm, ws


def test_adapter_produces_exactly_what_the_executor_expects(lab):
    ws, plan, ex, src = lab
    eng, _ = _engine(src, [_reply(_diff(ORIG, FIX))])
    pkg = eng.propose(FINDING, CTX, ASSESS)
    d = to_execution_package(pkg, FINDING, CTX, plan, src)
    assert d["target"] == "192.168.56.10" and d["package_id"] == pkg.package_id
    assert d["changes"][0]["content"] == FIX
    assert d["changes"][0]["expected_sha256"] == hashlib.sha256(ORIG.encode()).hexdigest()
    assert {v["name"] for v in d["validation"]} == set(pkg.validation_requirements)
    assert all(v["argv"] in plan.allowed_commands() for v in d["validation"] if v["type"] == "command")


def test_good_patch_is_accepted_and_really_fixes_the_workspace(lab):
    out, _, ws = _run(lab, [_reply(_diff(ORIG, FIX))])
    assert out["outcome"] == "accepted" and out["attempts"][0]["decision"] == "ACCEPT"
    assert (ws / "app.py").read_text(encoding="utf-8") == FIX


def test_patch_that_applies_but_does_not_fix_is_rolled_back_then_refined(lab):
    out, llm, ws = _run(lab, [_reply(_diff(ORIG, NOOP)), _reply(_diff(ORIG, FIX))])
    assert out["outcome"] == "accepted" and out["package"].attempt == 2
    assert out["attempts"][0]["decision"] == "REJECT" and out["attempts"][0]["rolled_back"]
    assert "security_retest" in llm.calls[1]["user"]          # real failure reached the model
    assert (ws / "app.py").read_text(encoding="utf-8") == FIX


def test_patch_that_fixes_the_bug_but_breaks_login_is_caught_by_regression(lab):
    out, _, ws = _run(lab, [_reply(_diff(ORIG, BROKEN))], max_attempts=1)
    assert out["outcome"] == "escalated"
    failed = [c["name"] for c in out["attempts"][0]["checks"] if not c["passed"]]
    assert failed == ["regression"]                           # exploit blocked, function broken
    assert (ws / "app.py").read_text(encoding="utf-8") == ORIG   # rolled back


def test_out_of_scope_host_is_escalated_not_retried(lab):
    ws, plan, ex, src = lab
    eng, llm = _engine(src, [_reply(_diff(ORIG, FIX))] * 3)
    pkg = eng.propose(FINDING, Fctx := FindingContext(target="demo-app", host="10.9.9.9", app_port=80), ASSESS)
    out = validate_and_refine(FINDING, Fctx, ASSESS, pkg, eng, ex, plan, src, DecisionLog())
    assert out["outcome"] == "escalated" and len(llm.calls) == 1
    assert "outside the authorized scope" in out["attempts"][0]["error"]
    assert (ws / "app.py").read_text(encoding="utf-8") == ORIG


def test_source_drift_is_caught_by_the_hash_precondition(lab):
    ws, plan, ex, src = lab
    eng, _ = _engine(src, [_reply(_diff(ORIG, FIX))])
    pkg = eng.propose(FINDING, CTX, ASSESS)
    d = to_execution_package(pkg, FINDING, CTX, plan, src)
    (ws / "app.py").write_text(ORIG + "# edited by someone else\n", encoding="utf-8")
    from controlled_execution.engine import ExecutionError
    with pytest.raises(ExecutionError, match="hash mismatch"):
        ex.execute(d)


def test_missing_validation_command_blocks_instead_of_weakening(lab):
    ws, plan, ex, src = lab
    eng, _ = _engine(src, [_reply(_diff(ORIG, FIX))])
    pkg = eng.propose(FINDING, CTX, ASSESS)
    with pytest.raises(HandoffError, match="regression"):
        to_execution_package(pkg, FINDING, CTX, ValidationPlan({"security_retest": ["x"]}), src)


def test_unexecutable_changes_are_blocked_with_a_reason(lab):
    ws, plan, ex, src = lab
    rule = RemediationPackage("FIND-1", "C", 1, "proposed", "rc", "high",
                              changes=[ChangeItem("network_rule", description="block 23/tcp")],
                              validation_requirements=["network"])
    with pytest.raises(HandoffError, match="human approval"):
        to_execution_package(rule, FINDING, CTX, plan, src)
    dep = RemediationPackage("FIND-1", "C", 1, "proposed", "rc", "high",
                             changes=[ChangeItem("dependency_upgrade", package="x", to_version="2")],
                             validation_requirements=["regression"])
    with pytest.raises(HandoffError, match="not available"):          # no requirements.txt in workspace
        to_execution_package(dep, FINDING, CTX, plan, src)
    with pytest.raises(HandoffError, match="no host"):
        to_execution_package(dep, FINDING, FindingContext(target="demo-app"), plan, src)


def test_crlf_files_keep_their_line_endings(tmp_path):
    (tmp_path / "app.py").write_bytes(ORIG.replace("\n", "\r\n").encode())
    src = FileSourceProvider(str(tmp_path))
    eng, _ = _engine(src, [_reply(_diff(ORIG, FIX))])
    pkg = eng.propose(FINDING, CTX, ASSESS)
    d = to_execution_package(pkg, FINDING, CTX, ValidationPlan(
        {k: ["x"] for k in ("security_retest", "regression", "new_vulnerability_scan")}), src)
    assert d["changes"][0]["content"] == FIX.replace("\n", "\r\n")
    assert d["changes"][0]["expected_sha256"] == hashlib.sha256(ORIG.replace("\n", "\r\n").encode()).hexdigest()


def test_unknown_check_names_in_result_are_ignored_and_unrun_stay_not_run():
    pkg = RemediationPackage("F", "C", 1, "proposed", "rc", "high",
                             validation_requirements=["security_retest", "regression"])
    vr = result_to_validation({"checks": [{"name": "security_retest", "passed": True, "details": ""},
                                          {"name": "other", "passed": False, "details": "x"}]}, pkg)
    assert vr.security_test == "PASS" and vr.regression_tests == "NOT_RUN"
    assert not vr.accepted(pkg.validation_requirements)


def test_pipeline_end_to_end_with_executor(tmp_path):
    from analyzers.network.nmap_analyzer import nmap_xml_to_evidence
    from analyzers.software.semgrep_adapter import semgrep_to_evidence
    from evidence.bundle import export_case_bundle
    from evidence.store import EvidenceStore
    from reasoning.pipeline import run_case
    from reasoning.stub import OfflineStubLLM
    import tests.test_reasoning_pipeline as base
    store = EvidenceStore(str(tmp_path / "data"))
    store.add_many(nmap_xml_to_evidence(base.NMAP, "CASE-X"))
    store.add_many(semgrep_to_evidence(base.SEMGREP, "CASE-X", "demo-app")[0])
    bundle = export_case_bundle(store, "CASE-X")
    ws = tmp_path / "ws"
    shutil.copytree(DEMO, ws)
    plan = ValidationPlan.load(str(DEMO / "validation.json"))
    ex = ControlledExecutor(str(ws), str(tmp_path / "snap"), AuthorizedScope(["192.168.56.0/24"]),
                            plan.allowed_commands())
    out = run_case(bundle, OfflineStubLLM(), str(DEMO.parent.parent / "config" / "assets.json"),
                   str(ws), ex, plan)
    assert out["outcomes"] == {"accepted": 1}
    assert "?" in (ws / "app.py").read_text(encoding="utf-8")
    log = (Path(out["out_dir"]) / "decisions.jsonl").read_text()
    assert '"stage": "execution"' in log and '"decision": "ACCEPT"' in log


# ---------------- baseline ("before") and config / dependency changes ----------------

def test_baseline_runs_the_checks_on_unmodified_code_and_changes_nothing(lab):
    out, _, ws = _run(lab, [_reply(_diff(ORIG, FIX))])
    base = {c["name"]: c["passed"] for c in out["baseline"]["checks"]}
    assert base == {"security_retest": False, "regression": True, "new_vulnerability_scan": False}
    after = {c["name"]: c["passed"] for c in out["attempts"][-1]["checks"]}
    assert all(after.values())                      # fails before, passes after = fix proven
    assert (ws / "app.py").read_text(encoding="utf-8") == FIX


def test_baseline_leaves_original_bytes_untouched(lab):
    from reasoning.handoff import baseline_package
    ws, plan, ex, src = lab
    eng, _ = _engine(src, [_reply(_diff(ORIG, FIX))])
    pkg = eng.propose(FINDING, CTX, ASSESS)
    ex.execute(baseline_package(to_execution_package(pkg, FINDING, CTX, plan, src), src))
    assert (ws / "app.py").read_bytes() == ORIG.encode("utf-8")


def _cfg(tmp_path, name, text):
    (tmp_path / name).write_bytes(text.encode("utf-8"))
    return FileSourceProvider(str(tmp_path))


def test_dependency_upgrade_edits_only_the_pinned_line(tmp_path):
    from reasoning.handoff import file_change
    src = _cfg(tmp_path, "requirements.txt", "flask==1.0\nRequests[security]==2.19.0  # old\npytest>=7\n")
    c = ChangeItem("dependency_upgrade", package="requests", from_version="2.19.0", to_version="2.32.0")
    out = file_change(c, src)
    assert out["content"] == "flask==1.0\nRequests[security]==2.32.0  # old\npytest>=7\n"
    with pytest.raises(HandoffError, match="not '==9.9'"):
        file_change(ChangeItem("dependency_upgrade", package="flask", from_version="9.9", to_version="2"), src)
    with pytest.raises(HandoffError, match="not listed"):
        file_change(ChangeItem("dependency_upgrade", package="django", to_version="5"), src)


def test_config_change_edits_one_explicit_setting(tmp_path):
    from reasoning.handoff import file_change
    src = _cfg(tmp_path, "sshd_config", "# comment\r\nPermitRootLogin yes\r\nPort 22\r\n")
    c = ChangeItem("config_change", file="sshd_config", key="permitrootlogin", old_value="yes", new_value="no")
    assert file_change(c, src)["content"] == "# comment\r\nPermitRootLogin no\r\nPort 22\r\n"   # CRLF kept
    wrong = ChangeItem("config_change", file="sshd_config", key="Port", old_value="2222", new_value="22")
    with pytest.raises(HandoffError, match="currently '22'"):
        file_change(wrong, src)
    unset = ChangeItem("config_change", file="sshd_config", key="X11Forwarding", new_value="no")
    with pytest.raises(HandoffError, match="not set explicitly"):
        file_change(unset, src)


def test_ini_style_config_keeps_its_separator(tmp_path):
    from reasoning.handoff import file_change
    src = _cfg(tmp_path, "app.ini", "debug = true\nname: demo\n")
    out = file_change(ChangeItem("config_change", file="app.ini", key="debug", new_value="false"), src)
    assert out["content"] == "debug = false\nname: demo\n"


def test_a_config_fix_runs_through_the_real_executor_with_a_network_check(lab):
    ws, plan, ex, src = lab
    (ws / "service.conf").write_text("debug=true\nport=80\n", encoding="utf-8")
    reply = json.dumps({"changes": [{"type": "config_change", "file": "service.conf", "key": "debug",
                                     "old_value": "true", "new_value": "false"}],
                        "expected_security_effect": "s", "expected_functional_behaviour": "f",
                        "expected_network_behaviour": "n"})
    eng, _ = _engine(src, [reply])
    pkg = eng.propose(FINDING, CTX, ReasoningResult(**{**ASSESS.__dict__,
                      "recommended_change_types": ["config_change"]}))
    assert "network" in pkg.validation_requirements
    d = to_execution_package(pkg, FINDING, CTX, plan, src)
    assert d["changes"][0]["content"] == "debug=false\nport=80\n"
    assert {"name": "network", "type": "tcp_reachable", "host": "192.168.56.10", "port": 80} in d["validation"]


def test_invalid_config_proposal_is_rejected_at_proposal_time_with_the_real_value(tmp_path):
    (tmp_path / "service.conf").write_text("debug=true\n", encoding="utf-8")
    src = FileSourceProvider(str(tmp_path))
    bad = json.dumps({"changes": [{"type": "config_change", "file": "service.conf", "key": "debug",
                                   "old_value": "yes", "new_value": "false"}]})
    good = json.dumps({"changes": [{"type": "config_change", "file": "service.conf", "key": "debug",
                                    "old_value": "true", "new_value": "false"}]})
    eng, llm = _engine(src, [bad, good])
    pkg = eng.propose(FINDING, CTX, ReasoningResult(**{**ASSESS.__dict__,
                      "recommended_change_types": ["config_change"]}))
    assert pkg.status == "proposed" and "currently 'true'" in llm.calls[1]["user"]
