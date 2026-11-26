"""Cyber reasoning: Finding + Context -> ReasoningResult (validated, cited, logged)."""

from typing import Any, Dict, Optional

from reasoning import prompts
from reasoning.decisionlog import DecisionLog
from reasoning.llm import LLMClient, call_json
from reasoning.models import Finding, FindingContext, RationaleItem, ReasoningResult
from reasoning.source import FileSourceProvider


def _parse_assessment(obj: Dict[str, Any], finding_id: str, allowed: set) -> ReasoningResult:
    try:
        rationale = []
        for item in obj["rationale"]:
            ids = list(item["evidence_ids"])
            if not str(item["claim"]).strip() or not ids:
                raise ValueError("every rationale item needs a claim and at least one evidence id")
            unknown = [i for i in ids if i not in allowed]
            if unknown:
                raise ValueError(f"cited evidence ids that were not provided: {unknown}")
            rationale.append(RationaleItem(claim=str(item["claim"]), evidence_ids=ids))
        if not rationale:
            raise ValueError("rationale must not be empty")
        return ReasoningResult(
            finding_id=finding_id, verdict=obj["verdict"], root_cause=str(obj["root_cause"]),
            exploitability=obj["exploitability"], risk=obj["risk"],
            affected=[str(a) for a in obj["affected"]], rationale=rationale,
            recommended_change_types=list(obj["recommended_change_types"]),
            confidence=obj["confidence"])
    except (KeyError, TypeError) as exc:
        raise ValueError(f"missing or malformed field: {exc!r}") from exc


class CyberReasoner:
    def __init__(self, llm: LLMClient, log: DecisionLog,
                 source: Optional[FileSourceProvider] = None, max_retries: int = 2):
        self.llm, self.log, self.source, self.max_retries = llm, log, source, max_retries

    def assess(self, finding: Finding, context: FindingContext) -> ReasoningResult:
        allowed = set(finding.evidence_ids) | set(context.evidence_ids)
        path, line = finding.source_file_and_line()
        src = self.source.for_prompt(path, line) if (self.source and path) else None
        user = prompts.reason_prompt(finding.to_dict(), context.to_dict(), allowed, src)
        result = call_json(self.llm, self.log, "reason", finding.finding_id,
                           prompts.REASON_SYSTEM, user,
                           lambda o: _parse_assessment(o, finding.finding_id, allowed),
                           self.max_retries)
        self.log.record("assessment", finding.finding_id, result=result.to_dict())
        return result
