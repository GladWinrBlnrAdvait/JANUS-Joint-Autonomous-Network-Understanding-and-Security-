"""
Bridge between the reasoning layer and controlled_execution (Part 3).

reasoning.models.RemediationPackage   rich and explainable (diffs, rationale, named checks)
        |  to_execution_package()
        v
controlled_execution RemediationPackage dict   executable (full file content + sha256,
                                               host target, concrete check specs)
        |  executor.execute()
        v
ExecutionResult  --result_to_validation()-->  reasoning.models.ValidationResult

Nothing is silently weakened: if a required check cannot be expressed (no operator
command, no app port) or a change type cannot be executed yet, the hand-off is
refused with an explicit reason instead of running a package with less validation.
"""

import hashlib
import re
from typing import Any, Dict, List

from reasoning.models import (CHECK_FIELDS, Finding, FindingContext, RemediationPackage,
                              ValidationResult)
from reasoning.patching import PatchError, apply_unified_diff
from reasoning.source import FileSourceProvider
from reasoning.validation_plan import ValidationPlan


class HandoffError(RuntimeError):
    pass


_PIN = re.compile(
    r"^(?P<lead>\s*)(?P<name>[A-Za-z0-9][A-Za-z0-9_.\-]*)(?P<extras>\[[^\]]*\])?"
    r"(?P<spec>\s*(?:==|>=|<=|~=|!=|>|<)\s*[^\s#;,]+(?:\s*,\s*(?:==|>=|<=|~=|!=|>|<)\s*[^\s#;,]+)*)?"
    r"(?P<rest>.*)$")
_CFG = re.compile(r"^(?P<lead>\s*)(?P<key>[A-Za-z0-9][A-Za-z0-9_.\-]*)(?P<sep>\s*[=:]\s*|\s+)(?P<value>.*?)\s*$")


def _read(source: FileSourceProvider, path: str):
    raw = source.read_bytes(path)
    if raw is None:
        raise HandoffError(f"source file '{path}' is not available in the workspace")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HandoffError(f"'{path}' is not UTF-8 text") from exc
    return raw, text


def _finish(path: str, raw: bytes, original: str, new_lf: str) -> Dict[str, Any]:
    content = new_lf.replace("\n", "\r\n") if "\r\n" in original else new_lf   # keep line endings
    return {"path": path, "content": content, "expected_sha256": hashlib.sha256(raw).hexdigest()}


def _norm_pkg(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _dependency_change(change, source: FileSourceProvider) -> Dict[str, Any]:
    path = change.file or "requirements.txt"
    raw, text = _read(source, path)
    lines = text.replace("\r\n", "\n").split("\n")
    hits = []
    for i, line in enumerate(lines):
        if not line.strip() or line.lstrip().startswith(("#", "-")):
            continue
        m = _PIN.match(line)
        if m and _norm_pkg(m.group("name")) == _norm_pkg(change.package):
            hits.append((i, m))
    if len(hits) != 1:
        raise HandoffError(f"package '{change.package}' is {'not listed' if not hits else 'listed more than once'} in {path}")
    i, m = hits[0]
    current = (m.group("spec") or "").replace(" ", "")
    if change.from_version and current != f"=={change.from_version}":
        raise HandoffError(f"{path} currently has '{current or 'no version'}' for {change.package}, "
                           f"not '=={change.from_version}'")
    lines[i] = (f"{m.group('lead')}{m.group('name')}{m.group('extras') or ''}"
                f"=={change.to_version}{m.group('rest')}")
    return _finish(path, raw, text, "\n".join(lines))


def _config_change(change, source: FileSourceProvider) -> Dict[str, Any]:
    raw, text = _read(source, change.file)
    lines = text.replace("\r\n", "\n").split("\n")
    hits = []
    for i, line in enumerate(lines):
        if not line.strip() or line.lstrip().startswith(("#", ";")):
            continue
        m = _CFG.match(line)
        if m and m.group("key").lower() == change.key.lower():
            hits.append((i, m))
    if len(hits) != 1:
        raise HandoffError(f"key '{change.key}' is {'not set explicitly' if not hits else 'set more than once'} "
                           f"in {change.file}; needs a human")
    i, m = hits[0]
    if change.old_value is not None and m.group("value") != change.old_value:
        raise HandoffError(f"{change.file}: '{change.key}' is currently '{m.group('value')}', "
                           f"not '{change.old_value}'")
    lines[i] = f"{m.group('lead')}{m.group('key')}{m.group('sep')}{change.new_value}"
    return _finish(change.file, raw, text, "\n".join(lines))


def _code_change(change, source: FileSourceProvider) -> Dict[str, Any]:
    raw, text = _read(source, change.file)
    try:
        patched = apply_unified_diff(text.replace("\r\n", "\n"), change.diff)
    except PatchError as exc:
        raise HandoffError(f"patch no longer applies: {exc}") from exc
    return _finish(change.file, raw, text, patched)


def file_change(change, source: FileSourceProvider) -> Dict[str, Any]:
    """One ChangeItem -> the executor's {path, content, expected_sha256}."""
    kind = {"code_patch": _code_change, "dependency_upgrade": _dependency_change,
            "config_change": _config_change}.get(change.change_type)
    if kind is None:
        raise HandoffError(f"'{change.change_type}' cannot be executed automatically; "
                           "it needs human application")
    return kind(change, source)


def baseline_package(exec_pkg: Dict[str, Any], source: FileSourceProvider) -> Dict[str, Any]:
    """Same checks, but every file is rewritten with its OWN current content.
    Running it measures the checks on the unmodified system (the 'before' state)."""
    changes = []
    for ch in exec_pkg["changes"]:
        raw, text = _read(source, ch["path"])
        changes.append({"path": ch["path"], "content": text,
                        "expected_sha256": hashlib.sha256(raw).hexdigest()})
    return {**exec_pkg, "changes": changes, "package_id": exec_pkg["package_id"] + "-baseline",
            "rationale": "baseline: no-op rewrite to run the checks on unmodified code"}


def to_execution_package(pkg: RemediationPackage, finding: Finding, context: FindingContext,
                         plan: ValidationPlan, source: FileSourceProvider) -> Dict[str, Any]:
    if pkg.status != "proposed" or not pkg.changes:
        raise HandoffError(f"package status is '{pkg.status}'; nothing to execute")
    if any(c.requires_approval for c in pkg.changes):
        raise HandoffError("package contains changes that require human approval")
    if not context.host:
        raise HandoffError("no host known for this target (asset map); cannot check authorized scope")

    validation: List[Dict[str, Any]] = []
    missing: List[str] = []
    for req in pkg.validation_requirements:
        if req == "network":
            if context.app_port is None:
                missing.append(req)
            else:
                validation.append({"name": req, "type": "tcp_reachable",
                                   "host": context.host, "port": int(context.app_port)})
            continue
        argv = plan.argv_for(req)
        if argv is None:
            missing.append(req)
        else:
            validation.append({"name": req, "type": "command", "argv": argv})
    if missing:
        raise HandoffError("no validation configured for required check(s): "
                           + ", ".join(missing))

    return {"case_id": pkg.case_id, "target": context.host,
            "finding_ids": [pkg.finding_id], "package_id": pkg.package_id,
            "rationale": pkg.root_cause + " | " + " ".join(r.claim for r in pkg.rationale),
            "changes": [file_change(c, source) for c in pkg.changes],
            "validation": validation}


def result_to_validation(result, pkg: RemediationPackage) -> ValidationResult:
    """ExecutionResult (object or dict) -> ValidationResult. Unrun checks stay NOT_RUN."""
    data = result if isinstance(result, dict) else result.to_dict()
    vr = ValidationResult(package_id=pkg.package_id)
    for check in data["checks"]:
        field_name = CHECK_FIELDS.get(check["name"])
        if field_name is None:
            continue
        setattr(vr, field_name, "PASS" if check["passed"] else "FAIL")
        if not check["passed"]:
            vr.failure_reasons.append(f"{check['name']}: {str(check['details'])[-400:]}")
    return vr
