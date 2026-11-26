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
from typing import Any, Dict, List

from reasoning.models import (CHECK_FIELDS, Finding, FindingContext, RemediationPackage,
                              ValidationResult)
from reasoning.patching import PatchError, apply_unified_diff
from reasoning.source import FileSourceProvider
from reasoning.validation_plan import ValidationPlan


class HandoffError(RuntimeError):
    pass


def _file_change(change, source: FileSourceProvider) -> Dict[str, Any]:
    if change.change_type != "code_patch":
        raise HandoffError(
            f"'{change.change_type}' cannot be executed automatically yet; "
            "it needs human application")
    raw = source.read_bytes(change.file)
    if raw is None:
        raise HandoffError(f"source file '{change.file}' is not available in the workspace")
    text = raw.decode("utf-8")
    crlf = "\r\n" in text
    try:
        patched = apply_unified_diff(text.replace("\r\n", "\n"), change.diff)
    except PatchError as exc:
        raise HandoffError(f"patch no longer applies: {exc}") from exc
    if crlf:                                  # keep the file's own line endings
        patched = patched.replace("\n", "\r\n")
    return {"path": change.file, "content": patched,
            "expected_sha256": hashlib.sha256(raw).hexdigest()}


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
            "changes": [_file_change(c, source) for c in pkg.changes],
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
