import difflib
import json

import pytest

from reasoning.decisionlog import DecisionLog
from reasoning.llm import ReasoningError, ScriptedLLM
from reasoning.models import (Finding, FindingContext, ReasoningResult, RationaleItem,
                              ValidationResult)
from reasoning.remediation import RemediationEngine, required_checks
from reasoning.source import FileSourceProvider

SRC = "a = 1\nquery = 'bad'\nb = 2\n"
FIXED = "a = 1\nquery = 'good'\nb = 2\n"
GOOD = "\n".join(difflib.unified_diff(SRC.splitlines(), FIXED.splitlines(), "a/app.py",
                                      "b/app.py", lineterm=""))
BAD = GOOD.replace(" a = 1", " a = 999")           # context that is not in the file

FINDING = Finding(finding_id="FIND-1", case_id="C", title="t", vuln_class="CWE-89", target="app",
                  severity="high", confidence=0.8, evidence_ids=["E1"], sources=["semgrep"],
                  location="app.py:2")
CTX = FindingContext(target="app")


def _assessment(types=("code_patch",)):
    return ReasoningResult("FIND-1", "likely_vulnerable", "rc", "high", "high", ["app.py"],
                           [RationaleItem("c", ["E1"])], list(types), 0.8)


def _reply(changes):
    return json.dumps({"changes": changes, "expected_security_effect": "s",
                       "expected_functional_behaviour": "f", "expected_network_behaviour": "n"})


def _engine(tmp_path, replies, **kw):
    (tmp_path / "app.py").write_text(SRC, encoding="utf-8")
    llm = ScriptedLLM(replies)
    return RemediationEngine(llm, DecisionLog(), FileSourceProvider(str(tmp_path)), **kw), llm


def _patch(diff):
    return {"type": "code_patch", "file": "app.py", "diff": diff}


def test_valid_patch_becomes_proposed_package(tmp_path):
    eng, _ = _engine(tmp_path, [_reply([_patch(GOOD)])])
    pkg = eng.propose(FINDING, CTX, _assessment())
    assert pkg.status == "proposed" and pkg.changes[0].change_type == "code_patch"
    assert pkg.validation_requirements == ["security_retest", "regression", "new_vulnerability_scan"]


def test_patch_that_does_not_apply_is_rejected_and_retried(tmp_path):
    eng, llm = _engine(tmp_path, [_reply([_patch(BAD)]), _reply([_patch(GOOD)])])
    pkg = eng.propose(FINDING, CTX, _assessment())
    assert pkg.status == "proposed"
    assert "does not apply" in llm.calls[1]["user"]


def test_disallowed_change_type_is_rejected(tmp_path):
    eng, _ = _engine(tmp_path, [_reply([{"type": "network_rule", "description": "x"}])] * 3)
    with pytest.raises(ReasoningError, match="not allowed"):
        eng.propose(FINDING, CTX, _assessment(("code_patch",)))


def test_code_patch_impossible_without_source_goes_to_human():
    eng = RemediationEngine(ScriptedLLM([]), DecisionLog(), FileSourceProvider(None))
    pkg = eng.propose(FINDING, CTX, _assessment())
    assert pkg.status == "needs_human" and pkg.changes == []


def test_empty_changes_means_needs_human(tmp_path):
    eng, _ = _engine(tmp_path, [_reply([])])
    assert eng.propose(FINDING, CTX, _assessment()).status == "needs_human"


def test_required_checks_add_network_for_config_and_exploit_for_dast():
    from reasoning.models import ChangeItem
    cfg = ChangeItem("config_change", file="sshd_config", key="PermitRootLogin", new_value="no")
    assert "network" in required_checks(FINDING, [cfg])
    dast = Finding(**{**FINDING.to_dict(), "sources": ["dast"]})
    assert "exploit_retest" in required_checks(dast, [])


def test_feedback_loop_refines_then_escalates(tmp_path):
    eng, llm = _engine(tmp_path, [_reply([_patch(GOOD)])] * 3, max_attempts=2)
    pkg = eng.propose(FINDING, CTX, _assessment())
    fail = ValidationResult(pkg.package_id, security_test="PASS", regression_tests="FAIL",
                            new_vulnerabilities="PASS", failure_reasons=["login() broke"])
    pkg2 = eng.refine(pkg, FINDING, CTX, _assessment(), fail)
    assert pkg2.attempt == 2 and pkg2.status == "proposed"
    assert "login() broke" in llm.calls[1]["user"]            # failure fed back to the model
    pkg3 = eng.refine(pkg2, FINDING, CTX, _assessment(),
                      ValidationResult(pkg2.package_id, regression_tests="FAIL"))
    assert pkg3.status == "escalated" and len(pkg3.previous_failures) == 2


def test_refine_is_a_noop_when_everything_passed(tmp_path):
    eng, llm = _engine(tmp_path, [_reply([_patch(GOOD)])])
    pkg = eng.propose(FINDING, CTX, _assessment())
    ok = ValidationResult(pkg.package_id, security_test="PASS", regression_tests="PASS",
                          new_vulnerabilities="PASS")
    assert eng.refine(pkg, FINDING, CTX, _assessment(), ok) is pkg
    assert len(llm.calls) == 1
