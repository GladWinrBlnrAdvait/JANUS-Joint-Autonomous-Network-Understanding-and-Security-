"""
JANUS Reasoning layer demo (offline by default).

    python demo.py                                # creates data/cases/CASE-DEMO/bundle.json
    python demo_reasoning.py                      # reason + propose a fix (stub model, no API key)
    python demo_reasoning.py --execute            # ...and apply it with controlled_execution,
                                                  #    validate independently, roll back on failure
    python demo_reasoning.py --execute --open     # ...and open report.html in your browser
    python demo_reasoning.py --llm anthropic      # real model (needs ANTHROPIC_API_KEY)
"""

import argparse
import json
import shutil
from pathlib import Path

from reasoning.pipeline import run_case
from reasoning.validation_plan import ValidationPlan


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bundle", default="data/cases/CASE-DEMO/bundle.json")
    ap.add_argument("--assets", default="config/assets.json")
    ap.add_argument("--source", default="samples/demo-app", help="application source (copied to a workspace with --execute)")
    ap.add_argument("--llm", choices=["stub", "anthropic"], default="stub")
    ap.add_argument("--execute", action="store_true", help="apply + validate with controlled_execution")
    ap.add_argument("--scope", default="192.168.56.0/24", help="authorized network for --execute")
    ap.add_argument("--open", action="store_true", help="open the report in your browser when done")
    ap.add_argument("--validation", default=None, help="validation plan JSON (default: <source>/validation.json)")
    args = ap.parse_args()

    if args.llm == "anthropic":
        from reasoning.llm import AnthropicClient
        llm = AnthropicClient()
    else:
        from reasoning.stub import OfflineStubLLM
        llm = OfflineStubLLM()
        print("[offline stub model: rule-based, not real AI reasoning]")

    executor = plan = None
    source = args.source
    if args.execute:
        from controlled_execution import ControlledExecutor
        from evidence.scope import AuthorizedScope
        case_dir = Path(args.bundle).parent
        workspace = case_dir / "workspace"
        if workspace.exists():
            shutil.rmtree(workspace)
        shutil.copytree(args.source, workspace)          # disposable lab copy
        plan = ValidationPlan.load(args.validation or str(Path(args.source) / "validation.json"))
        executor = ControlledExecutor(str(workspace), str(case_dir / "snapshots"),
                                      authorized_scope=AuthorizedScope([args.scope]),
                                      allowed_commands=plan.allowed_commands())
        source = str(workspace)

    summary = run_case(args.bundle, llm, args.assets, source, executor, plan)
    print(json.dumps(summary, indent=2))
    report = Path(summary["report"])
    print(f"\nReport: {report.as_posix()}  (open it in a browser, or re-run with --open)")
    if args.open:
        import webbrowser
        webbrowser.open(report.resolve().as_uri())


if __name__ == "__main__":
    main()
