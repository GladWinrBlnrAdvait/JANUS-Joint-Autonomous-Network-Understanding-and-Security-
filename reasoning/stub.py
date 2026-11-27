"""
OfflineStubLLM: a deterministic, rule-based stand-in for a real model.

It exists so the pipeline, contracts, tests and benchmark can run with no API
key and no cost. It is NOT AI reasoning: it recognises four exact code patterns
(CWE-89, 22, 798, 95) from the sample apps and answers "uncertain / needs a
human" for everything else. Scores obtained with it measure the plumbing, not
model quality. Use AnthropicClient (or another LLMClient) for real analysis.
"""

import difflib
import json
import re

from reasoning.llm import LLMClient
from reasoning.prompts import DATA_CLOSE, DATA_OPEN

_SQL_LINE = re.compile(r"^(\s*)query = f\"(.*)\{(\w+)\}'(.*)\{(\w+)\}'\"\s*$")
_SECRET_LINE = re.compile(r'^SECRET_KEY = "[^"]+"\s*(#.*)?$')

ROOT_CAUSE = {
    "CWE-89": "User input is concatenated into an SQL string instead of being passed as bound parameters.",
    "CWE-22": "A user-controlled file name is joined to a base directory without checking that the "
              "resulting path stays inside that directory.",
    "CWE-798": "A secret key is hard-coded in the source, so anyone who can read the code has the key.",
    "CWE-95": "User input is passed to eval(), which executes arbitrary Python code.",
}
EFFECT = {
    "CWE-89": "User input is bound as parameters, so it can no longer change the SQL structure.",
    "CWE-22": "The resolved path must stay inside the notes folder, so traversal names are refused.",
    "CWE-798": "The key is read from the environment, so it is no longer stored in source code.",
    "CWE-95": "Only plain arithmetic is evaluated, so injected code is refused.",
}
KEEP = {
    "CWE-89": "login() returns the same role for valid credentials and None otherwise.",
    "CWE-22": "Normal notes are still readable and missing notes still raise FileNotFoundError.",
    "CWE-798": "sign() and verify() still produce and check stable signatures.",
    "CWE-95": "Ordinary arithmetic such as 2+3*4 still evaluates correctly.",
}


def _payload(user: str) -> dict:
    s = user.index(DATA_OPEN) + len(DATA_OPEN)
    return json.loads(user[s:user.index(DATA_CLOSE)])


# ---- one fixer per class: old lines -> new lines (or None if the pattern is not found) ----
def _fix_sql(old):
    for i, line in enumerate(old):
        m = _SQL_LINE.match(line)
        if m and i + 1 < len(old) and old[i + 1].strip() == "cursor.execute(query)":
            ind, new = m.group(1), list(old)
            new[i] = f'{ind}query = "{m.group(2).rstrip(chr(39))}?{m.group(4).rstrip(chr(39))}?"'
            new[i + 1] = f"{ind}cursor.execute(query, ({m.group(3)}, {m.group(5)}))"
            return new


def _fix_path(old):
    for i, line in enumerate(old):
        if line == "    path = os.path.join(NOTES_DIR, name)":
            return old[:i] + [
                "    base = os.path.realpath(NOTES_DIR)",
                "    path = os.path.realpath(os.path.join(NOTES_DIR, name))",
                "    if os.path.commonpath([base, path]) != base:",
                '        raise ValueError("invalid note name")'] + old[i + 1:]


def _fix_secret(old):
    if "import os" not in old:
        return None
    for i, line in enumerate(old):
        if _SECRET_LINE.match(line):
            return old[:i] + ['SECRET_KEY = os.environ["APP_SECRET_KEY"]'] + old[i + 1:]


_SAFE_EVAL = '''import ast
import operator

_OPS = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul,
        ast.Div: operator.truediv, ast.USub: operator.neg}


def _safe_eval(expression):
    def walk(node):
        if isinstance(node, ast.Expression):
            return walk(node.body)
        if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
            return node.value
        if isinstance(node, ast.BinOp) and type(node.op) in _OPS:
            return _OPS[type(node.op)](walk(node.left), walk(node.right))
        if isinstance(node, ast.UnaryOp) and type(node.op) in _OPS:
            return _OPS[type(node.op)](walk(node.operand))
        raise ValueError("unsupported expression")
    return walk(ast.parse(expression, mode="eval"))


'''.split("\n")[:-1]


def _fix_eval(old):
    if "    return eval(expression)" not in old or "def calculate(expression):" not in old:
        return None
    new = list(old)
    new[new.index("    return eval(expression)")] = "    return _safe_eval(expression)"
    at = new.index("def calculate(expression):")
    return new[:at] + _SAFE_EVAL + new[at:]


FIXERS = {"CWE-89": _fix_sql, "CWE-22": _fix_path, "CWE-798": _fix_secret, "CWE-95": _fix_eval}


class OfflineStubLLM(LLMClient):
    model = "offline-stub"

    def complete(self, system: str, user: str) -> str:
        p = _payload(user)
        return json.dumps(self._reason(p) if p["task"] == "reason" else self._remediate(p))

    def _reason(self, p):
        f, ctx = p["finding"], p["context"]
        cls, ids, gaps = f["vuln_class"], f["evidence_ids"], ctx.get("data_gaps", [])
        if cls not in ROOT_CAUSE:
            return {"verdict": "uncertain", "root_cause": "No offline rule for this class.",
                    "exploitability": "unknown", "risk": f["severity"], "affected": [f["target"]],
                    "rationale": [{"claim": "Reported by a tool; not analysed by the stub.",
                                   "evidence_ids": ids[:1]}],
                    "recommended_change_types": [], "confidence": 0.3}
        rationale = [{"claim": f"The scanner reports a {cls} issue at {f['location']}.",
                      "evidence_ids": ids}]
        port_ev = [sv["evidence_id"] for sv in ctx.get("open_services", [])
                   if sv.get("port") == ctx.get("app_port") and sv.get("evidence_id")]
        if ctx.get("exposure") == "reachable_from_scanner" and port_ev:
            rationale.append({"claim": f"The application port {ctx['app_port']} was seen open "
                              "from the scanner, so the code path is network-reachable.",
                              "evidence_ids": port_ev[:1]})
        gap_ids = [i for g in gaps for i in re.findall(r"\[([A-Z]+-[0-9a-f]+)\]", g)]
        if gap_ids:
            rationale.append({"claim": "Host firewall/socket state could not be collected, so "
                              "exposure beyond the scanner's view is unknown.",
                              "evidence_ids": gap_ids[:1]})
        return {"verdict": "likely_vulnerable", "root_cause": ROOT_CAUSE[cls],
                "exploitability": "high" if ctx.get("exposure") == "reachable_from_scanner" else "medium",
                "risk": "high", "affected": [f["location"] or f["target"]],
                "rationale": rationale, "recommended_change_types": ["code_patch"],
                "confidence": 0.8}

    def _remediate(self, p):
        cls, src = p["finding"]["vuln_class"], p.get("source")
        none = {"changes": [], "expected_security_effect": "No offline fix available.",
                "expected_functional_behaviour": "", "expected_network_behaviour": ""}
        fixer = FIXERS.get(cls)
        if not fixer or not src or not src.get("full_file") or "code_patch" not in p["allowed_change_types"]:
            return none
        old = [re.sub(r"^\d+: ", "", l) for l in src["numbered_source"].split("\n")]
        new = fixer(old)
        if new is None:
            return none
        diff = "\n".join(difflib.unified_diff(old, new, f"a/{src['file']}", f"b/{src['file']}",
                                              lineterm="", n=3))
        return {"changes": [{"type": "code_patch", "file": src["file"], "diff": diff}],
                "expected_security_effect": EFFECT[cls], "expected_functional_behaviour": KEEP[cls],
                "expected_network_behaviour": "no network-visible change"}
