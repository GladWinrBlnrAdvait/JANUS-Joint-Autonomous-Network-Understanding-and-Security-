"""
Remediation: ReasoningResult -> RemediationPackage, and the feedback loop.

The LLM proposes changes; code decides what is acceptable:
  * code patches must apply exactly to the real file (patching.py)
  * only change types allowed for this finding are accepted
  * validation requirements are derived deterministically, never by the LLM
"""

from typing import Any, Dict, List, Optional

from reasoning import prompts
from reasoning.decisionlog import DecisionLog
from reasoning.llm import LLMClient, call_json
from reasoning.models import (CHANGE_TYPES, ChangeItem, Finding, FindingContext,
                              RemediationPackage, ReasoningResult, ValidationResult)
from reasoning.patching import PatchError, validate_patch
from reasoning.source import FileSourceProvider


def required_checks(finding: Finding, changes: List[ChangeItem]) -> List[str]:
    checks = ["security_retest", "regression", "new_vulnerability_scan"]
    if any(s in ("dast", "fuzzer", "fuzzing") for s in finding.sources):
        checks.append("exploit_retest")
    if any(c.change_type in ("config_change", "network_rule") for c in changes):
        checks.append("network")
    return checks


class RemediationEngine:
    def __init__(self, llm: LLMClient, log: DecisionLog,
                 source: Optional[FileSourceProvider] = None,
                 max_retries: int = 2, max_attempts: int = 3):
        self.llm, self.log, self.source = llm, log, source
        self.max_retries, self.max_attempts = max_retries, max_attempts

    # -- helpers --------------------------------------------------------
    def _parse_changes(self, obj: Dict[str, Any], allowed_types, path, original):
        try:
            raw = obj["changes"]
            if not isinstance(raw, list):
                raise ValueError("'changes' must be a list")
            changes = []
            for c in raw:
                c = dict(c)
                ctype = c.pop("type", None)
                if ctype not in allowed_types:
                    raise ValueError(f"change type '{ctype}' is not allowed here; "
                                     f"allowed: {list(allowed_types)}")
                item = ChangeItem(change_type=ctype, **{k: (str(v) if v is not None else None)
                                                         for k, v in c.items()})
                if ctype == "code_patch":
                    if item.file != path:
                        raise ValueError(f"code_patch must target '{path}', got '{item.file}'")
                    try:
                        validate_patch(item.diff, path, original)
                    except PatchError as exc:
                        raise ValueError(f"patch does not apply to the real file: {exc}")
                changes.append(item)
            return (changes, str(obj.get("expected_security_effect", "")),
                    str(obj.get("expected_functional_behaviour", "")),
                    str(obj.get("expected_network_behaviour", "")))
        except (KeyError, TypeError) as exc:
            raise ValueError(f"missing or malformed field: {exc!r}") from exc

    # -- public API -----------------------------------------------------
    def propose(self, finding: Finding, context: FindingContext, assessment: ReasoningResult,
                attempt: int = 1, previous_failures: Optional[List[str]] = None,
                previous_changes: Optional[List[Dict[str, Any]]] = None) -> RemediationPackage:
        previous_failures = previous_failures or []
        path, line = finding.source_file_and_line()
        original = self.source.read(path) if (self.source and path) else None
        allowed = [t for t in (assessment.recommended_change_types or CHANGE_TYPES)
                   if t != "code_patch" or original is not None]
        base = dict(finding_id=finding.finding_id, case_id=finding.case_id, attempt=attempt,
                    root_cause=assessment.root_cause, risk=assessment.risk,
                    rationale=assessment.rationale, previous_failures=previous_failures)
        if not allowed:
            return RemediationPackage(status="needs_human", notes=(
                "No automatic change type is possible (source not available for a code patch)."),
                **base)

        allowed_ids = set(finding.evidence_ids) | set(context.evidence_ids)
        src = self.source.for_prompt(path, line) if (self.source and path and original) else None
        user = prompts.remediate_prompt(finding.to_dict(), context.to_dict(), assessment.to_dict(),
                                        allowed_ids, allowed, src, previous_failures,
                                        previous_changes or [])
        changes, sec, func, net = call_json(
            self.llm, self.log, "remediate", finding.finding_id, prompts.REMEDIATE_SYSTEM, user,
            lambda o: self._parse_changes(o, allowed, path, original), self.max_retries)

        pkg = RemediationPackage(
            status="proposed" if changes else "needs_human",
            changes=changes, expected_security_effect=sec,
            expected_functional_behaviour=func, expected_network_behaviour=net,
            validation_requirements=required_checks(finding, changes),
            notes="" if changes else "Model found no safe automatic change.", **base)
        self.log.record("package", finding.finding_id, package=pkg.to_dict())
        return pkg

    def _escalate(self, package, failures, note) -> RemediationPackage:
        esc = RemediationPackage(
            finding_id=package.finding_id, case_id=package.case_id, attempt=package.attempt,
            status="escalated", root_cause=package.root_cause, risk=package.risk,
            changes=package.changes, rationale=package.rationale,
            validation_requirements=package.validation_requirements,
            previous_failures=failures, notes=note)
        self.log.record("package", package.finding_id, package=esc.to_dict())
        return esc

    def refine(self, package: RemediationPackage, finding: Finding, context: FindingContext,
               assessment: ReasoningResult, validation: ValidationResult) -> RemediationPackage:
        """Closed loop: a failed validation goes back in as evidence for a better fix."""
        if validation.error:                     # executor could not run: a new patch cannot help
            reason = f"attempt {package.attempt} could not be executed: {validation.error}"
            self.log.record("validation_feedback", finding.finding_id,
                            package_id=package.package_id, error=validation.error)
            return self._escalate(package, package.previous_failures + [reason],
                                  "Execution could not run; human review required.")
        failed = validation.failed_checks(package.validation_requirements)
        if not failed:
            return package                       # nothing to fix
        reason = (f"attempt {package.attempt} failed checks {failed}"
                  + (": " + "; ".join(validation.failure_reasons) if validation.failure_reasons else ""))
        failures = package.previous_failures + [reason]
        self.log.record("validation_feedback", finding.finding_id,
                        package_id=package.package_id, failed_checks=failed, reason=reason)
        if package.attempt >= self.max_attempts:
            return self._escalate(package, failures,
                                  f"No validated fix after {self.max_attempts} attempts; "
                                  "human review required.")
        return self.propose(finding, context, assessment, attempt=package.attempt + 1,
                            previous_failures=failures,
                            previous_changes=[c.to_dict() for c in package.changes])
