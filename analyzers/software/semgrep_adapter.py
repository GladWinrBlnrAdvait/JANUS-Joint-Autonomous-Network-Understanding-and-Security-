"""
Semgrep (SAST) adapter: Semgrep JSON -> JANUS Evidence.
Run with:  semgrep --json --config auto <path>
"""

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Tuple

from evidence.models import Evidence, make_evidence_id
from evidence.normalizer import normalize_many


class SemgrepError(Exception):
    pass


def run_semgrep(path: str, config: str = "auto", timeout: int = 600) -> str:
    """Run Semgrep on a local path and return its JSON output."""
    if not Path(path).exists():
        raise SemgrepError(f"Path does not exist: {path}")
    exe = shutil.which("semgrep")
    if exe is None:
        raise SemgrepError("semgrep is not installed (pip install semgrep)")
    try:
        result = subprocess.run(
            [exe, "--json", "--config", config, path],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise SemgrepError(f"semgrep timed out after {timeout}s") from exc
    # Semgrep exits 1 when findings exist; only >1 is a real failure
    if result.returncode > 1:
        raise SemgrepError(f"semgrep failed ({result.returncode}): {result.stderr.strip()}")
    return result.stdout


def semgrep_to_evidence(json_text: str, case_id: str, target: str,
                        raw_ref: str = None) -> Tuple[List[Evidence], List[Dict[str, Any]]]:
    """
    Convert Semgrep JSON into (evidence, errors). Records that cannot be
    normalized are returned in `errors`, and Semgrep's own scan errors
    become explicit 'scan_error' evidence rather than disappearing.
    """
    try:
        data = json.loads(json_text)
    except json.JSONDecodeError as exc:
        raise SemgrepError(f"Malformed Semgrep JSON: {exc}") from exc
    if not isinstance(data, dict) or "results" not in data:
        raise SemgrepError("Not Semgrep JSON output (no 'results' key)")

    version = f"Semgrep {data['version']}" if data.get("version") else None
    records = []
    for r in data["results"]:
        extra = r.get("extra", {}) or {}
        meta = extra.get("metadata", {}) or {}
        rule = r.get("check_id", "unknown-rule")
        location = f"{r.get('path', '?')}:{(r.get('start') or {}).get('line', '?')}"
        records.append({
            "evidence_id": make_evidence_id("SEMGREP", case_id, target, rule, location),
            "category": "software",
            "target": target,
            "finding_type": "sast_finding",
            "severity": extra.get("severity", "info"),
            "confidence": meta.get("confidence", "medium"),
            "description": extra.get("message", rule),
            "location": location,
            "evidence_data": {
                "rule_id": rule,
                "cwe": meta.get("cwe"),
                "semgrep_category": meta.get("category"),
                "start": r.get("start"), "end": r.get("end"),
            },
        })

    evidence, errors = normalize_many(
        records, source="semgrep", case_id=case_id,
        tool_version=version, raw_ref=raw_ref,
    )

    for err in data.get("errors", []) or []:
        message = err.get("message") or str(err)
        evidence.append(Evidence(
            evidence_id=make_evidence_id("SEMGREP", case_id, target, "scan_error", message),
            source="semgrep", category="software", target=target,
            finding_type="scan_error", severity="info", confidence=1.0,
            description=f"Semgrep reported an error: {message}",
            evidence_data={"error": err}, case_id=case_id,
            tool_version=version, raw_ref=raw_ref,
        ))
    return evidence, errors