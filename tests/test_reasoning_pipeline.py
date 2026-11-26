"""Integration with the real Evidence layer, plus proof the proposed patch actually works."""

import json
import sqlite3
from pathlib import Path

from analyzers.network.nmap_analyzer import nmap_xml_to_evidence
from analyzers.software.semgrep_adapter import semgrep_to_evidence
from evidence.bundle import export_case_bundle
from evidence.store import EvidenceStore
from reasoning.patching import apply_unified_diff
from reasoning.pipeline import run_case
from reasoning.stub import OfflineStubLLM

ROOT = Path(__file__).resolve().parent.parent
NMAP = """<?xml version="1.0"?><nmaprun scanner="nmap" version="7.95"><host><status state="up"/>
<address addr="192.168.56.10" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="80"><state state="open"/><service name="http" method="table"/></port>
</ports></host></nmaprun>"""
SEMGREP = json.dumps({"version": "1.80.0", "results": [{
    "check_id": "python.sql-injection", "path": "app.py", "start": {"line": 42}, "end": {"line": 42},
    "extra": {"message": "SQL built from user input", "severity": "ERROR",
              "metadata": {"confidence": "HIGH", "cwe": ["CWE-89"]}}}], "errors": []})


def _bundle(tmp_path):
    store = EvidenceStore(str(tmp_path / "data"))
    store.add_many(nmap_xml_to_evidence(NMAP, "CASE-T"))
    ev, _ = semgrep_to_evidence(SEMGREP, "CASE-T", "demo-app")
    store.add_many(ev)
    return export_case_bundle(store, "CASE-T")


def _login_module(source, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    ns = {"__name__": "demo_app"}
    exec(compile(source, "app.py", "exec"), ns)
    ns["init_db"]()
    return ns["login"]


def test_full_pipeline_and_patch_really_fixes_the_injection(tmp_path, monkeypatch):
    bundle = _bundle(tmp_path)
    out = run_case(bundle, OfflineStubLLM(), str(ROOT / "config" / "assets.json"),
                   str(ROOT / "samples" / "demo-app"))
    assert (out["findings"], out["packages"], out["errors"]) == (1, 1, 0)

    reasoning = Path(out["out_dir"])
    pkgs = json.loads((reasoning / "remediation_packages.json").read_text())["packages"]
    analysis = json.loads((reasoning / "analysis.json").read_text())["records"][0]
    assert analysis["context"]["exposure"] == "reachable_from_scanner"
    assert (reasoning / "decisions.jsonl").read_text().strip()      # audit trail exists
    pkg = pkgs[0]
    assert pkg["status"] == "proposed" and pkg["package_id"].startswith("REM-")

    original = (ROOT / "samples" / "demo-app" / "app.py").read_text(encoding="utf-8")
    patched = apply_unified_diff(original, pkg["changes"][0]["diff"])

    injection = "' OR '1'='1"
    vulnerable = _login_module(original, tmp_path, monkeypatch)
    assert vulnerable("admin", injection) == "admin"                 # proves the bug is real
    (tmp_path / "demo.db").unlink()
    fixed = _login_module(patched, tmp_path, monkeypatch)
    assert fixed("admin", injection) is None                         # exploit blocked
    assert fixed("admin", "change-me") == "admin"                    # behaviour preserved
    assert fixed("admin", "wrong") is None


def test_unmapped_target_still_produces_output_with_explicit_gap(tmp_path):
    bundle = _bundle(tmp_path)
    out = run_case(bundle, OfflineStubLLM(), str(tmp_path / "missing.json"),
                   str(ROOT / "samples" / "demo-app"))
    rec = json.loads((Path(out["out_dir"]) / "analysis.json").read_text())["records"][0]
    assert rec["context"]["exposure"] == "unknown"
    assert "no asset mapping" in rec["context"]["data_gaps"][0]
