import json
import shutil
from pathlib import Path

from analyzers.network.nmap_analyzer import nmap_xml_to_evidence
from analyzers.software.semgrep_adapter import semgrep_to_evidence
from controlled_execution import ControlledExecutor
from evidence.bundle import export_case_bundle
from evidence.scope import AuthorizedScope
from evidence.store import EvidenceStore
from reasoning.pipeline import run_case
from reasoning.report import build_report_html
from reasoning.stub import OfflineStubLLM
from reasoning.validation_plan import ValidationPlan
import tests.test_reasoning_pipeline as base

ROOT = Path(__file__).resolve().parent.parent
DEMO = ROOT / "samples" / "demo-app"


def _run(tmp_path, execute=True):
    store = EvidenceStore(str(tmp_path / "data"))
    store.add_many(nmap_xml_to_evidence(base.NMAP, "CASE-R"))
    store.add_many(semgrep_to_evidence(base.SEMGREP, "CASE-R", "demo-app")[0])
    bundle = export_case_bundle(store, "CASE-R")
    ex = plan = None
    src = str(DEMO)
    if execute:
        ws = tmp_path / "ws"
        shutil.copytree(DEMO, ws)
        plan = ValidationPlan.load(str(DEMO / "validation.json"))
        ex = ControlledExecutor(str(ws), str(tmp_path / "snap"), AuthorizedScope(["192.168.56.0/24"]),
                                plan.allowed_commands())
        src = str(ws)
    out = run_case(bundle, OfflineStubLLM(), str(ROOT / "config" / "assets.json"), src, ex, plan)
    return out, bundle


def test_report_is_written_and_shows_the_real_outcome(tmp_path):
    out, _ = _run(tmp_path)
    html = Path(out["report"]).read_text(encoding="utf-8")
    assert "Fix verified and kept" in html and "ACCEPT" in html
    assert "security_retest" in html and "regression" in html
    assert 'class="add"' in html and 'class="del"' in html          # coloured diff
    assert "offline rule-based stub" in html                         # honest banner


def test_report_without_execution_says_nothing_was_validated(tmp_path):
    out, _ = _run(tmp_path, execute=False)
    html = Path(out["report"]).read_text(encoding="utf-8")
    assert "Fix proposed, not yet validated" in html and "No validation was run" in html


def test_report_is_self_contained(tmp_path):
    html = Path(_run(tmp_path)[0]["report"]).read_text(encoding="utf-8")
    assert "http://" not in html and "https://" not in html and "<script" not in html


def test_untrusted_text_is_escaped(tmp_path):
    out, bundle = _run(tmp_path)
    analysis = json.loads((Path(out["out_dir"]) / "analysis.json").read_text())
    evil = '<script>alert("x")</script>'
    analysis["records"][0]["finding"]["description"] = evil
    analysis["records"][0]["assessment"]["root_cause"] = evil
    html = build_report_html(analysis, json.loads(Path(bundle).read_text()), [])
    assert "<script>alert" not in html and "&lt;script&gt;" in html


def test_failed_run_shows_rollback_and_retry(tmp_path):
    out, bundle = _run(tmp_path)
    analysis = json.loads((Path(out["out_dir"]) / "analysis.json").read_text())
    rec = analysis["records"][0]
    failed = {"package_id": "P1", "decision": "REJECT", "rolled_back": True,
              "checks": [{"name": "regression", "check_type": "command", "passed": False, "details": "login broke"}]}
    rec["attempts"] = [failed] + rec["attempts"]
    html = build_report_html(analysis, json.loads(Path(bundle).read_text()), [])
    assert "Earlier attempts" in html and "login broke" in html


def test_stub_reasoning_cites_the_right_kind_of_evidence(tmp_path):
    from evidence.models import Evidence
    store = EvidenceStore(str(tmp_path / "data"))
    store.add_many(nmap_xml_to_evidence(base.NMAP, "CASE-R"))
    store.add_many(semgrep_to_evidence(base.SEMGREP, "CASE-R", "demo-app")[0])
    store.add_many([Evidence(evidence_id="HOST-0a1b2c3d4e5f", source="linux_collector", category="host",
                             target="192.168.56.10", finding_type="collection_failed",
                             severity="info", confidence=1.0, case_id="CASE-R",
                             evidence_data={"operation": "listening_sockets", "error": "ss not found"})])
    bundle = export_case_bundle(store, "CASE-R")
    out = run_case(bundle, OfflineStubLLM(), str(ROOT / "config" / "assets.json"), str(DEMO))
    rec = json.loads((Path(out["out_dir"]) / "analysis.json").read_text())["records"][0]
    claims = {r["claim"]: r["evidence_ids"] for r in rec["assessment"]["rationale"]}
    port_ids = next(v for k, v in claims.items() if "port 80" in k)
    gap_ids = next(v for k, v in claims.items() if "could not be collected" in k)
    open_svc = {sv["evidence_id"] for sv in rec["context"]["open_services"] if sv["port"] == 80}
    assert set(port_ids) <= open_svc and port_ids          # port claim cites the Nmap open-port item
    assert gap_ids == ["HOST-0a1b2c3d4e5f"]                       # gap claim cites the failed collection


def test_report_shows_before_vs_after_per_check(tmp_path):
    html = Path(_run(tmp_path)[0]["report"]).read_text(encoding="utf-8")
    assert "Before (unmodified)" in html and "After (change applied)" in html
    assert "Fix confirmed" in html and "No regression" in html
