"""
The closed loop: package -> controlled execution -> validation -> refine -> repeat.

The executor snapshots, applies, runs the independent checks and rolls back on
failure. This module only decides what happens next: stop on ACCEPT, feed the
failure back to the model (up to max_attempts), or escalate to a human.
"""

from typing import Any, Dict, List

from controlled_execution.engine import ExecutionError
from evidence.scope import ScopeError
from reasoning.decisionlog import DecisionLog
from reasoning.handoff import (HandoffError, baseline_package, result_to_validation,
                               to_execution_package)
from reasoning.llm import ReasoningError
from reasoning.models import (Finding, FindingContext, ReasoningResult, RemediationPackage,
                              ValidationResult)
from reasoning.remediation import RemediationEngine
from reasoning.source import FileSourceProvider
from reasoning.validation_plan import ValidationPlan


def _baseline(exec_pkg, executor, source, log, finding_id) -> Dict[str, Any]:
    """Checks on the unmodified code. A failure here is information, not an error:
    the security re-test SHOULD fail before the fix. The executor restores the workspace."""
    try:
        res = executor.execute(baseline_package(exec_pkg, source))
        out = {"decision": res.decision, "checks": res.checks}
    except (ExecutionError, ScopeError, HandoffError) as exc:
        out = {"error": str(exc)}
    log.record("baseline", finding_id, **out)
    return out


def validate_and_refine(finding: Finding, context: FindingContext, assessment: ReasoningResult,
                        pkg: RemediationPackage, engine: RemediationEngine, executor,
                        plan: ValidationPlan, source: FileSourceProvider,
                        log: DecisionLog) -> Dict[str, Any]:
    """Returns {"outcome", "package", "attempts": [...], "baseline"}.
    outcome: accepted | escalated | blocked | needs_human | error"""
    attempts: List[Dict[str, Any]] = []
    baseline = None
    while True:
        if pkg.status != "proposed":
            return {"outcome": pkg.status, "package": pkg, "attempts": attempts, "baseline": baseline}
        try:
            exec_pkg = to_execution_package(pkg, finding, context, plan, source)
        except HandoffError as exc:
            log.record("handoff_blocked", finding.finding_id, package_id=pkg.package_id,
                       reason=str(exc))
            attempts.append({"package_id": pkg.package_id, "blocked": str(exc)})
            return {"outcome": "blocked", "package": pkg, "attempts": attempts, "baseline": baseline}

        if baseline is None:            # 'before': run the checks on the unmodified code, once
            baseline = _baseline(exec_pkg, executor, source, log, finding.finding_id)
        try:
            result = executor.execute(exec_pkg)
            vr = result_to_validation(result, pkg)
            record = {"package_id": pkg.package_id, "decision": result.decision,
                      "rolled_back": result.rolled_back, "checks": result.checks}
        except (ExecutionError, ScopeError) as exc:
            vr = ValidationResult(package_id=pkg.package_id, error=str(exc),
                                  failure_reasons=[str(exc)])
            record = {"package_id": pkg.package_id, "decision": "ERROR", "error": str(exc)}
        log.record("execution", finding.finding_id, **record)
        attempts.append(record)

        if not vr.error and vr.accepted(pkg.validation_requirements) \
                and record.get("decision") == "ACCEPT":
            return {"outcome": "accepted", "package": pkg, "attempts": attempts, "baseline": baseline}
        try:
            pkg = engine.refine(pkg, finding, context, assessment, vr)
        except ReasoningError as exc:
            attempts.append({"error": str(exc)})
            return {"outcome": "error", "package": pkg, "attempts": attempts, "baseline": baseline}
