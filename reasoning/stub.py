"""
OfflineStubLLM: a deterministic, rule-based stand-in for a real model.

It exists so the pipeline, contracts and tests can run with no API key and no
cost. It is NOT AI reasoning: it recognises one pattern (string-built SQL,
CWE-89) and returns "uncertain / needs human" for everything else. Use
AnthropicClient (or another LLMClient) for real analysis.
"""

import difflib
import json
import re

from reasoning.llm import LLMClient
from reasoning.prompts import DATA_CLOSE, DATA_OPEN

_SQL_LINE = re.compile(r"^(\s*)query = f\"(.*)\{(\w+)\}'(.*)\{(\w+)\}'\"\s*$")


def _payload(user: str) -> dict:
    s = user.index(DATA_OPEN) + len(DATA_OPEN)
    return json.loads(user[s:user.index(DATA_CLOSE)])


class OfflineStubLLM(LLMClient):
    model = "offline-stub"

    def complete(self, system: str, user: str) -> str:
        p = _payload(user)
        return json.dumps(self._reason(p) if p["task"] == "reason" else self._remediate(p))

    def _reason(self, p):
        f, ctx = p["finding"], p["context"]
        ids = f["evidence_ids"]
        gaps = ctx.get("data_gaps", [])
        if f["vuln_class"] != "CWE-89":
            return {"verdict": "uncertain", "root_cause": "No offline rule for this class.",
                    "exploitability": "unknown", "risk": f["severity"], "affected": [f["target"]],
                    "rationale": [{"claim": "Reported by a tool; not analysed by the stub.",
                                   "evidence_ids": ids[:1]}],
                    "recommended_change_types": [], "confidence": 0.3}
        rationale = [{"claim": "The scanner reports string-built SQL at "
                               f"{f['location']} (CWE-89).", "evidence_ids": ids}]
        if ctx.get("exposure") == "reachable_from_scanner" and ctx.get("evidence_ids"):
            rationale.append({"claim": f"The application port {ctx['app_port']} was seen open "
                              "from the scanner, so the code path is network-reachable.",
                              "evidence_ids": ctx["evidence_ids"][:1]})
        if gaps:
            rationale.append({"claim": "Host firewall/socket state could not be collected, so "
                              "exposure beyond the scanner's view is unknown.",
                              "evidence_ids": ctx["evidence_ids"][-1:] or ids[:1]})
        return {"verdict": "likely_vulnerable",
                "root_cause": "User input is concatenated into an SQL string instead of being "
                              "passed as bound parameters.",
                "exploitability": "high" if ctx.get("exposure") == "reachable_from_scanner" else "medium",
                "risk": "high", "affected": [f["location"] or f["target"]],
                "rationale": rationale, "recommended_change_types": ["code_patch"],
                "confidence": 0.8}

    def _remediate(self, p):
        src = p.get("source")
        none = {"changes": [], "expected_security_effect": "No offline fix available.",
                "expected_functional_behaviour": "", "expected_network_behaviour": ""}
        if not src or not src.get("full_file") or "code_patch" not in p["allowed_change_types"]:
            return none
        old = [re.sub(r"^\d+: ", "", l) for l in src["numbered_source"].split("\n")]
        new, changed = list(old), False
        for i, line in enumerate(old):
            m = _SQL_LINE.match(line)
            if m and i + 1 < len(old) and old[i + 1].strip() == "cursor.execute(query)":
                ind = m.group(1)
                new[i] = f'{ind}query = "{m.group(2).rstrip(chr(39))}?{m.group(4).rstrip(chr(39))}?"'
                new[i + 1] = f"{ind}cursor.execute(query, ({m.group(3)}, {m.group(5)}))"
                changed = True
                break
        if not changed:
            return none
        diff = "\n".join(difflib.unified_diff(old, new, f"a/{src['file']}", f"b/{src['file']}",
                                              lineterm="", n=3))
        return {"changes": [{"type": "code_patch", "file": src["file"], "diff": diff}],
                "expected_security_effect": "User input is bound as parameters, so it can no "
                                           "longer change the SQL structure.",
                "expected_functional_behaviour": "login() returns the same role for valid "
                                                "credentials and None otherwise.",
                "expected_network_behaviour": "no network-visible change"}
