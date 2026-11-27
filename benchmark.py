"""
JANUS benchmark: run every sample app through the full loop and report metrics.

    python benchmark.py                  # offline stub model (measures the plumbing, not AI quality)
    python benchmark.py --llm anthropic  # real model: the meaningful measurement

For each samples/<name>/ it: builds a case from the recorded scan data
(semgrep.json + sample Nmap), copies the app to a throw-away workspace, runs
reason -> propose -> baseline -> execute -> validate -> refine, then records:
  outcome, attempts, 'before' vs 'after' check results, time, citation coverage.
Results: data/benchmark/benchmark_results.json and benchmark_report.md
"""

import argparse
import json
import shutil
import time
from pathlib import Path
from typing import Any, Dict, List

from analyzers.network.nmap_analyzer import nmap_xml_to_evidence
from analyzers.software.semgrep_adapter import semgrep_to_evidence
from controlled_execution import ControlledExecutor
from demo import SAMPLE_NMAP
from evidence.bundle import export_case_bundle
from evidence.scope import AuthorizedScope
from evidence.store import EvidenceStore
from reasoning.pipeline import run_case
from reasoning.validation_plan import ValidationPlan


def run_sample(sample: Path, llm, out_root: Path, assets: str, scope: str) -> Dict[str, Any]:
    case = json.loads((sample / "case.json").read_text(encoding="utf-8"))
    name, case_id = case["name"], f"BENCH-{case['name']}"
    work = out_root / name
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)

    store = EvidenceStore(str(work / "data"))
    store.add_many(nmap_xml_to_evidence(SAMPLE_NMAP, case_id))
    store.add_many(semgrep_to_evidence((sample / "semgrep.json").read_text(encoding="utf-8"),
                                       case_id, name)[0])
    bundle = export_case_bundle(store, case_id)

    workspace = work / "workspace"
    shutil.copytree(sample, workspace, ignore=shutil.ignore_patterns("case.json", "semgrep.json", "__pycache__"))
    plan = ValidationPlan.load(str(sample / "validation.json"))
    executor = ControlledExecutor(str(workspace), str(work / "snapshots"),
                                  AuthorizedScope([scope]), plan.allowed_commands())

    t0 = time.perf_counter()
    summary = run_case(bundle, llm, assets, str(workspace), executor, plan)
    seconds = time.perf_counter() - t0

    out = Path(summary["out_dir"])
    rec = json.loads((out / "analysis.json").read_text(encoding="utf-8"))["records"][0]
    calls = [json.loads(x) for x in (out / "decisions.jsonl").read_text(encoding="utf-8").splitlines() if x.strip()]
    ran = [a for a in rec.get("attempts", []) if "checks" in a]
    before = {c["name"]: c["passed"] for c in (rec.get("baseline") or {}).get("checks", [])}
    after = {c["name"]: c["passed"] for c in (ran[-1]["checks"] if ran else [])}
    sec = "security_retest"
    return {
        "sample": name, "cwe": case["cwe"], "outcome": rec.get("outcome") or "error",
        "attempts": len(ran), "first_try": bool(ran) and ran[0]["decision"] == "ACCEPT",
        "security_before": before.get(sec), "security_after": after.get(sec),
        "regression_before": before.get("regression"), "regression_after": after.get("regression"),
        "confirmed_fix": before.get(sec) is False and after.get(sec) is True,
        "cited": bool(rec.get("assessment")) and all(r["evidence_ids"] for r in rec["assessment"]["rationale"]),
        "llm_calls": sum(1 for c in calls if c["stage"] in ("reason", "remediate")),
        "seconds": round(seconds, 2), "model": getattr(llm, "model", "?"),
        "report": str(out / "report.html"),
    }


def aggregate(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    n = len(rows)
    executed = [r for r in rows if r["attempts"]]
    accepted = [r for r in rows if r["outcome"] == "accepted"]
    pct = lambda a, b: round(100.0 * a / b, 1) if b else None
    return {
        "samples": n, "accepted": len(accepted), "needs_human_or_failed": n - len(accepted),
        "patch_success_rate_pct": pct(len(accepted), n),
        "first_attempt_success_pct": pct(sum(r["first_try"] for r in rows), n),
        "confirmed_fixes": sum(r["confirmed_fix"] for r in rows),
        "regression_pass_after_pct": pct(sum(1 for r in executed if r["regression_after"]), len(executed)),
        "avg_attempts_when_executed": round(sum(r["attempts"] for r in executed) / len(executed), 2) if executed else None,
        "avg_seconds_per_finding": round(sum(r["seconds"] for r in rows) / n, 2) if n else None,
        "findings_with_cited_reasoning_pct": pct(sum(r["cited"] for r in rows), n),
    }


def markdown(rows, agg, model: str) -> str:
    yn = lambda v: "n/a" if v is None else ("PASS" if v else "FAIL")
    out = [f"# JANUS benchmark\n\nModel: **{model}**\n"]
    if model == "offline-stub":
        out.append("> The offline stub only knows these sample patterns. These numbers show the "
                   "pipeline works end to end; they say nothing about AI quality.\n")
    out += ["| Sample | CWE | Outcome | Attempts | Security before | Security after | Regression after | Seconds |",
            "|---|---|---|---|---|---|---|---|"]
    for r in rows:
        out.append(f"| {r['sample']} | {r['cwe']} | {r['outcome']} | {r['attempts']} | {yn(r['security_before'])} "
                   f"| {yn(r['security_after'])} | {yn(r['regression_after'])} | {r['seconds']} |")
    out += ["", "| Metric | Value |", "|---|---|"] + [f"| {k} | {v} |" for k, v in agg.items()]
    return "\n".join(out) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--samples", default="samples")
    ap.add_argument("--out", default="data/benchmark")
    ap.add_argument("--assets", default="config/assets.json")
    ap.add_argument("--scope", default="192.168.56.0/24")
    ap.add_argument("--llm", choices=["stub", "anthropic"], default="stub")
    args = ap.parse_args()

    if args.llm == "anthropic":
        from reasoning.llm import AnthropicClient
        llm = AnthropicClient()
    else:
        from reasoning.stub import OfflineStubLLM
        llm = OfflineStubLLM()
        print("[offline stub model: measures the plumbing, not AI quality]")

    out_root = Path(args.out)
    rows = [run_sample(s, llm, out_root, args.assets, args.scope)
            for s in sorted(Path(args.samples).iterdir()) if (s / "case.json").exists()]
    agg = aggregate(rows)
    out_root.mkdir(parents=True, exist_ok=True)
    (out_root / "benchmark_results.json").write_text(json.dumps({"rows": rows, "aggregate": agg}, indent=2), encoding="utf-8")
    md = markdown(rows, agg, getattr(llm, "model", "?"))
    (out_root / "benchmark_report.md").write_text(md, encoding="utf-8")
    print(md)
    print(f"Saved: {(out_root / 'benchmark_report.md').as_posix()}")


if __name__ == "__main__":
    main()
