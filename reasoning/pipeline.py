"""
End-to-end driver: case bundle -> reasoning records + remediation packages.

Output (next to the bundle, under <case>/reasoning/):
  remediation_packages.json   final package per finding (after validation if an executor is given)
  analysis.json               findings, context, assessments, packages, errors
  decisions.jsonl             append-only audit log of every LLM exchange
  report.html                 human-readable report (open in a browser)
"""

import json
from pathlib import Path
from typing import Any, Dict, List

from reasoning.assets import AssetMap
from reasoning.closed_loop import validate_and_refine
from reasoning.context import build_context
from reasoning.correlator import correlate
from reasoning.decisionlog import DecisionLog
from reasoning.llm import LLMClient, ReasoningError
from reasoning.reasoner import CyberReasoner
from reasoning.report import write_report
from reasoning.remediation import RemediationEngine
from reasoning.source import FileSourceProvider
from reasoning.validation_plan import ValidationPlan


def run_case(bundle_path: str, llm: LLMClient, assets_path: str = "config/assets.json",
             source_root: str = None, executor=None,
             plan: ValidationPlan = None) -> Dict[str, Any]:
    """With `executor` (controlled_execution.ControlledExecutor) and `plan`, each proposed
    package is also executed, independently validated and refined (closed loop).
    `source_root` must then be the executor's workspace."""
    bundle = json.loads(Path(bundle_path).read_text(encoding="utf-8"))
    out_dir = Path(bundle_path).parent / "reasoning"
    out_dir.mkdir(parents=True, exist_ok=True)
    log = DecisionLog(out_dir / "decisions.jsonl")
    assets, source = AssetMap.load(assets_path), FileSourceProvider(source_root)
    reasoner = CyberReasoner(llm, log, source)
    engine = RemediationEngine(llm, log, source)

    records: List[Dict[str, Any]] = []
    for finding in correlate(bundle):
        rec: Dict[str, Any] = {"finding": finding.to_dict(), "context": None,
                               "assessment": None, "package": None, "outcome": None,
                               "error": None}
        try:
            ctx = build_context(finding, bundle, assets)
            rec["context"] = ctx.to_dict()
            assessment = reasoner.assess(finding, ctx)
            rec["assessment"] = assessment.to_dict()
            if assessment.verdict != "likely_false_positive":
                pkg = engine.propose(finding, ctx, assessment)
                rec["outcome"] = pkg.status
                if executor is not None:
                    loop = validate_and_refine(finding, ctx, assessment, pkg, engine, executor,
                                               plan or ValidationPlan(), source, log)
                    pkg, rec["outcome"], rec["attempts"] = (loop["package"], loop["outcome"],
                                                            loop["attempts"])
                rec["package"] = pkg.to_dict()
        except ReasoningError as exc:               # explicit failure, never silent
            rec["error"] = str(exc)
        records.append(rec)

    packages = [r["package"] for r in records if r["package"]]
    (out_dir / "remediation_packages.json").write_text(
        json.dumps({"case_id": bundle["case_id"], "packages": packages}, indent=2),
        encoding="utf-8")
    (out_dir / "analysis.json").write_text(
        json.dumps({"case_id": bundle["case_id"], "records": records}, indent=2),
        encoding="utf-8")
    report = write_report(str(out_dir), bundle_path)
    outcomes: Dict[str, int] = {}
    for r in records:
        if r.get("outcome"):
            outcomes[r["outcome"]] = outcomes.get(r["outcome"], 0) + 1
    return {"case_id": bundle["case_id"], "findings": len(records), "packages": len(packages),
            "errors": sum(1 for r in records if r["error"]), "outcomes": outcomes,
            "out_dir": str(out_dir), "report": report}
