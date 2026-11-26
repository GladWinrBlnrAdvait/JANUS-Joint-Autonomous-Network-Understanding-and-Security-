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
from reasoning.handoff import HandoffError, result_to_validation, to_execution_package
from reasoning.llm import ReasoningError
from reasoning.models import (Finding, FindingContext, ReasoningResult, RemediationPackage,
                              ValidationResult)
from reasoning.remediation import RemediationEngine
from reasoning.source import FileSourceProvider
from reasoning.validation_plan import ValidationPlan


def validate_and_refine(finding: Finding, context: FindingContext, assessment: ReasoningResult,
                        pkg: RemediationPackage, engine: RemediationEngine, executor,
                        plan: ValidationPlan, source: FileSourceProvider,
                        log: DecisionLog) -> Dict[str, Any]:
    """Returns {"outcome", "package", "attempts": [...]}.
    outcome: accepted | escalated | blocked | needs_human | error"""
    attempts: List[Dict[str, Any]] = []
    while True:
        if pkg.status != "proposed":
            return {"outcome": pkg.status, "package": pkg, "attempts": attempts}
        try:
            exec_pkg = to_execution_package(pkg, finding, context, plan, source)
        except HandoffError as exc:
            log.record("handoff_blocked", finding.finding_id, package_id=pkg.package_id,
                       reason=str(exc))
            attempts.append({"package_id": pkg.package_id, "blocked": str(exc)})
            return {"outcome": "blocked", "package": pkg, "attempts": attempts}

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
            return {"outcome": "accepted", "package": pkg, "attempts": attempts}
        try:
            pkg = engine.refine(pkg, finding, context, assessment, vr)
        except ReasoningError as exc:
            attempts.append({"error": str(exc)})
            return {"outcome": "error", "package": pkg, "attempts": attempts}
