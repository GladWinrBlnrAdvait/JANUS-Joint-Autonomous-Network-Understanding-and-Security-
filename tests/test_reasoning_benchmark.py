"""Every sample app runs through the real pipeline + real executor; metrics are computed correctly."""

from pathlib import Path

import pytest

import benchmark
from reasoning.stub import OfflineStubLLM

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "samples"
ASSETS = str(ROOT / "config" / "assets.json")
FIXABLE = ["demo-app", "notes-app", "token-app", "calc-app"]


def _run(name, tmp_path):
    return benchmark.run_sample(SAMPLES / name, OfflineStubLLM(), tmp_path, ASSETS, "192.168.56.0/24")


@pytest.mark.parametrize("name", FIXABLE)
def test_each_sample_is_fixed_and_the_fix_is_proven(name, tmp_path):
    r = _run(name, tmp_path)
    assert r["outcome"] == "accepted" and r["first_try"]
    assert r["security_before"] is False and r["security_after"] is True     # fails before, passes after
    assert r["regression_before"] is True and r["regression_after"] is True  # nothing broke
    assert r["confirmed_fix"] and r["cited"]


def test_unfixable_sample_is_reported_honestly_not_forced(tmp_path):
    r = _run("auth-app", tmp_path)
    assert r["outcome"] == "needs_human" and r["attempts"] == 0 and not r["confirmed_fix"]


def test_original_sample_sources_are_never_modified(tmp_path):
    before = {p: p.read_bytes() for p in SAMPLES.rglob("app.py")}
    _run("notes-app", tmp_path)
    assert all(p.read_bytes() == b for p, b in before.items())


def test_aggregate_metrics():
    rows = [
        dict(outcome="accepted", attempts=1, first_try=True, confirmed_fix=True, regression_after=True, seconds=1.0, cited=True),
        dict(outcome="accepted", attempts=2, first_try=False, confirmed_fix=True, regression_after=True, seconds=3.0, cited=True),
        dict(outcome="needs_human", attempts=0, first_try=False, confirmed_fix=False, regression_after=None, seconds=0.0, cited=True),
        dict(outcome="escalated", attempts=3, first_try=False, confirmed_fix=False, regression_after=False, seconds=2.0, cited=False),
    ]
    a = benchmark.aggregate(rows)
    assert a["patch_success_rate_pct"] == 50.0 and a["first_attempt_success_pct"] == 25.0
    assert a["confirmed_fixes"] == 2 and a["regression_pass_after_pct"] == round(100 * 2 / 3, 1)
    assert a["avg_attempts_when_executed"] == 2.0 and a["findings_with_cited_reasoning_pct"] == 75.0
