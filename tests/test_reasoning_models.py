import pytest

from reasoning.models import (ChangeItem, Finding, RemediationPackage, ValidationResult,
                              safe_relative_path)


def _finding(**kw):
    base = dict(finding_id="FIND-1", case_id="C", title="t", vuln_class="CWE-89", target="app",
                severity="high", confidence=0.8, evidence_ids=["E1"], sources=["semgrep"],
                location="app.py:42")
    base.update(kw)
    return Finding(**base)


def test_finding_requires_evidence():
    with pytest.raises(ValueError):
        _finding(evidence_ids=[])


def test_finding_rejects_bad_severity_and_confidence():
    with pytest.raises(ValueError):
        _finding(severity="severe")
    with pytest.raises(ValueError):
        _finding(confidence=1.5)


def test_source_file_and_line():
    assert _finding().source_file_and_line() == ("app.py", 42)
    assert _finding(location="/login").source_file_and_line() == (None, None)
    assert _finding(location="../x.py:3").source_file_and_line() == (None, None)


@pytest.mark.parametrize("path", ["/etc/passwd", "../x", "a/../../b", "C:/x", "", "  "])
def test_unsafe_paths_rejected(path):
    assert not safe_relative_path(path)


def test_change_item_validation():
    with pytest.raises(ValueError):
        ChangeItem(change_type="code_patch", file="app.py")          # no diff
    with pytest.raises(ValueError):
        ChangeItem(change_type="config_change", file="../x", key="k", new_value="v")
    with pytest.raises(ValueError):
        ChangeItem(change_type="shell_command", description="rm -rf /")


def test_network_rule_always_requires_approval():
    c = ChangeItem(change_type="network_rule", description="block 23/tcp", requires_approval=False)
    assert c.requires_approval is True


def test_package_id_is_deterministic_per_attempt():
    a = RemediationPackage("F", "C", 1, "proposed", "rc", "high")
    b = RemediationPackage("F", "C", 1, "proposed", "rc", "high")
    c = RemediationPackage("F", "C", 2, "proposed", "rc", "high")
    assert a.package_id == b.package_id != c.package_id


def test_not_run_is_never_a_pass():
    v = ValidationResult(package_id="P", security_test="PASS", regression_tests="PASS")
    req = ["security_retest", "regression", "new_vulnerability_scan"]
    assert not v.accepted(req)
    assert v.failed_checks(req) == ["new_vulnerability_scan"]
    v.new_vulnerabilities = "PASS"
    assert v.accepted(req)


def test_validation_result_rejects_bad_value():
    with pytest.raises(ValueError):
        ValidationResult(package_id="P", security_test="MAYBE")
