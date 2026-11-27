"""
Case report: one self-contained HTML page (open it in any browser, no server).

Built only from files the pipeline already wrote, so it shows what really
happened and invents nothing:
  <case>/reasoning/analysis.json, decisions.jsonl   and   <case>/bundle.json

"Before" comes from the collected evidence (what the scanners reported).
"After" comes from the independent validation checks. Every piece of text from
tools, source code or the model is HTML-escaped, since it is untrusted.
"""

import json
from datetime import datetime, timezone
from html import escape as esc
from pathlib import Path
from typing import Any, Dict, List

OUTCOMES = {
    "accepted": ("Fix verified and kept", "ok"),
    "escalated": ("No validated fix: needs human review", "bad"),
    "blocked": ("Fix proposed but not applied automatically", "warn"),
    "needs_human": ("No safe automatic fix: needs human", "warn"),
    "proposed": ("Fix proposed, not yet validated", "warn"),
    "invalid": ("Model output was invalid", "bad"),
    "error": ("Analysis failed", "bad"),
}

CSS = """
:root{--bg:#f6f7fb;--card:#fff;--text:#1f2430;--muted:#667085;--line:#e4e7ee;--navy:#2f3c7e;--maroon:#af241d;
--ok:#1a7f4b;--okbg:#e5f5ec;--bad:#b42318;--badbg:#fdeceb;--warn:#a15c07;--warnbg:#fff3df;--code:#f3f4f8}
@media (prefers-color-scheme:dark){:root{--bg:#14161c;--card:#1d2028;--text:#e8eaf0;--muted:#9aa3b5;--line:#2c313c;
--navy:#8d9bea;--maroon:#ff8a80;--ok:#6ddc9b;--okbg:#17301f;--bad:#ff8a80;--badbg:#3a1b1a;--warn:#f5b455;--warnbg:#3a2a12;--code:#12141a}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 system-ui,Segoe UI,Arial,sans-serif}
.wrap{max-width:980px;margin:0 auto;padding:24px 16px 60px}
h1{margin:0 0 4px;font-size:26px;color:var(--maroon)}h2{margin:0 0 10px;font-size:18px;color:var(--navy)}
h3{margin:18px 0 6px;font-size:13px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}
.sub{color:var(--muted);margin-bottom:18px}
.banner{background:var(--warnbg);color:var(--warn);border:1px solid var(--warn);border-radius:10px;padding:10px 14px;margin-bottom:16px;font-weight:600}
.tiles{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:20px}
.tile{flex:1 1 120px;background:var(--card);border:1px solid var(--line);border-radius:12px;padding:12px 14px}
.tile b{display:block;font-size:26px;color:var(--navy)}.tile span{color:var(--muted);font-size:13px}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:18px 20px;margin-bottom:18px}
.top{display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap;align-items:center}
.badge{display:inline-block;border-radius:999px;padding:3px 11px;font-size:12.5px;font-weight:700}
.ok{background:var(--okbg);color:var(--ok)}.bad{background:var(--badbg);color:var(--bad)}.warn{background:var(--warnbg);color:var(--warn)}
.sev{background:var(--code);color:var(--text)}
.kv{display:grid;grid-template-columns:150px 1fr;gap:4px 12px}.kv div:nth-child(odd){color:var(--muted)}
.cols{display:grid;grid-template-columns:1fr 1fr;gap:16px}@media(max-width:720px){.cols{grid-template-columns:1fr}.kv{grid-template-columns:1fr}}
.box{background:var(--code);border-radius:10px;padding:12px 14px}
table{width:100%;border-collapse:collapse;font-size:14px}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600}
pre{margin:0;overflow:auto;background:var(--code);border-radius:10px;padding:12px 14px;font:13px/1.45 Consolas,Menlo,monospace}
.add{color:var(--ok)}.del{color:var(--bad)}.hunk{color:var(--navy)}
code{background:var(--code);border-radius:5px;padding:1px 5px;font-size:13px}
.small{font-size:13px;color:var(--muted)}ul{margin:4px 0 0 18px;padding:0}
"""


def _badge(text: str, cls: str) -> str:
    return f'<span class="badge {cls}">{esc(str(text))}</span>'


def _kv(rows) -> str:
    return '<div class="kv">' + "".join(
        f"<div>{esc(k)}</div><div>{v}</div>" for k, v in rows) + "</div>"


def _diff_html(diff: str) -> str:
    out = []
    for line in diff.splitlines():
        cls = ("add" if line.startswith("+") and not line.startswith("+++")
               else "del" if line.startswith("-") and not line.startswith("---")
               else "hunk" if line.startswith("@@") else "")
        out.append(f'<span class="{cls}">{esc(line)}</span>' if cls else esc(line))
    return "<pre>" + "\n".join(out) + "</pre>"


def _checks_table(checks: List[Dict[str, Any]]) -> str:
    rows = "".join(
        f"<tr><td>{esc(str(c.get('name')))}</td><td>{esc(str(c.get('check_type')))}</td>"
        f"<td>{_badge('PASS', 'ok') if c.get('passed') else _badge('FAIL', 'bad')}</td>"
        f"<td class='small'>{esc(str(c.get('details', ''))[-300:])}</td></tr>" for c in checks)
    return f"<table><tr><th>Check</th><th>Type</th><th>Result</th><th>Details</th></tr>{rows}</table>"


def _finding_card(rec: Dict[str, Any]) -> str:
    f, ctx, a, pkg = rec["finding"], rec.get("context"), rec.get("assessment"), rec.get("package")
    outcome = rec.get("outcome")
    label, cls = OUTCOMES.get(outcome or "", ("No fix proposed", "warn"))
    if rec.get("error"):
        label, cls = OUTCOMES["error"]
    elif a and a["verdict"] == "likely_false_positive":
        label, cls = "Judged a likely false positive: no change made", "ok"

    h = [f'<div class="card"><div class="top"><h2>{esc(f["title"])}</h2>'
         f'<div>{_badge(label, cls)}</div></div>']
    h.append(f'<div class="small">Finding {esc(f["finding_id"])} · target <code>{esc(f["target"])}</code></div>')

    # BEFORE / AFTER
    h.append('<h3>Before and after</h3><div class="cols">')
    h.append('<div class="box"><b>Before (what the scanners reported)</b>' + _kv([
        ("Severity", _badge(f["severity"], "sev")),
        ("Confidence", f'{f["confidence"]:.0%} from {esc(", ".join(f["sources"]))}'),
        ("Location", f'<code>{esc(f.get("location") or "n/a")}</code>'),
        ("Evidence", esc(", ".join(f["evidence_ids"]))),
        ("Description", esc(f.get("description") or ""))]) + "</div>")
    after = "<b>After (independent validation)</b>"
    attempts = [x for x in rec.get("attempts", []) if "checks" in x]
    if attempts:
        last = attempts[-1]
        after += _kv([("Decision", _badge(last["decision"], "ok" if last["decision"] == "ACCEPT" else "bad")),
                      ("Rolled back", "yes" if last.get("rolled_back") else "no"),
                      ("Attempts", str(len(attempts)))]) + _checks_table(last["checks"])
    elif rec.get("attempts") and rec["attempts"][-1].get("blocked"):
        after += f'<p>Not executed: {esc(rec["attempts"][-1]["blocked"])}</p>'
    else:
        after += "<p>No validation was run (run with <code>--execute</code>).</p>"
    h.append(f'<div class="box">{after}</div></div>')

    if ctx:
        h.append("<h3>Context</h3>" + _kv([
            ("Host / port", esc(f'{ctx.get("host")} : {ctx.get("app_port")}')),
            ("Exposure", esc(ctx["exposure"])),
            ("Open services", esc(", ".join(f'{s["port"]}/{s["service"]}' for s in ctx["open_services"]) or "none seen")),
        ]))
        if ctx["data_gaps"]:
            h.append("<div class='small'>Unknown / not collected:<ul>" +
                     "".join(f"<li>{esc(g)}</li>" for g in ctx["data_gaps"]) + "</ul></div>")

    if a:
        h.append("<h3>Reasoning</h3>" + _kv([
            ("Verdict", esc(a["verdict"])), ("Root cause", esc(a["root_cause"])),
            ("Exploitability", esc(a["exploitability"])), ("Risk", _badge(a["risk"], "sev")),
            ("Model confidence", f'{a["confidence"]:.0%}')]))
        h.append("<div class='small'>Why (each claim cites its evidence):<ul>" + "".join(
            f'<li>{esc(r["claim"])} <code>{esc(", ".join(r["evidence_ids"]))}</code></li>'
            for r in a["rationale"]) + "</ul></div>")

    if pkg and pkg.get("changes"):
        h.append("<h3>Proposed change</h3>")
        for ch in pkg["changes"]:
            if ch.get("diff"):
                h.append(f'<div class="small">{esc(ch["change_type"])} · <code>{esc(ch.get("file") or "")}</code></div>'
                         + _diff_html(ch["diff"]))
            else:
                h.append(f'<div class="box">{esc(ch["change_type"])}: {esc(ch.get("description") or json.dumps(ch))}</div>')
        h.append(_kv([("Expected security effect", esc(pkg.get("expected_security_effect", ""))),
                      ("Must keep working", esc(pkg.get("expected_functional_behaviour", "")))]))
    if len(attempts) > 1:
        h.append("<h3>Earlier attempts</h3>")
        for i, at in enumerate(attempts[:-1], 1):
            h.append(f'<div class="small">Attempt {i}: {esc(at["decision"])}, rolled back: '
                     f'{"yes" if at.get("rolled_back") else "no"}</div>' + _checks_table(at["checks"]))
    if pkg and pkg.get("previous_failures"):
        h.append("<div class='small'>Failure feedback given to the model:<ul>" + "".join(
            f"<li>{esc(x)}</li>" for x in pkg["previous_failures"]) + "</ul></div>")
    if rec.get("error"):
        h.append(f'<div class="box">{esc(rec["error"])}</div>')
    h.append("</div>")
    return "".join(h)


def build_report_html(analysis: Dict[str, Any], bundle: Dict[str, Any], decisions: List[Dict[str, Any]]) -> str:
    recs = analysis["records"]
    models = sorted({d.get("model") for d in decisions if d.get("model")})
    counts: Dict[str, int] = {}
    for r in recs:
        k = r.get("outcome") or ("error" if r.get("error") else "none")
        counts[k] = counts.get(k, 0) + 1
    tiles = [("Findings", len(recs)), ("Verified & kept", counts.get("accepted", 0)),
             ("Needs a human", counts.get("escalated", 0) + counts.get("blocked", 0) + counts.get("needs_human", 0)),
             ("Evidence items", bundle.get("summary", {}).get("evidence_count", 0)),
             ("Model calls", len(decisions))]
    banner = ""
    if "offline-stub" in models:
        banner = ('<div class="banner">Generated with the offline rule-based stub model, '
                  "not real AI reasoning. Results show the pipeline works, not model quality.</div>")
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    body = (f'<h1>JANUS Remediation Report</h1><div class="sub">Case <b>{esc(analysis["case_id"])}</b> · '
            f'generated {now} · model: {esc(", ".join(models) or "none")}</div>{banner}'
            '<div class="tiles">' + "".join(f'<div class="tile"><b>{v}</b><span>{esc(k)}</span></div>' for k, v in tiles)
            + "</div>" + ("".join(_finding_card(r) for r in recs) or "<p>No findings in this case.</p>"))
    return ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            f"<title>JANUS report {esc(analysis['case_id'])}</title><style>{CSS}</style></head>"
            f'<body><div class="wrap">{body}</div></body></html>')


def write_report(reasoning_dir: str, bundle_path: str) -> str:
    d = Path(reasoning_dir)
    analysis = json.loads((d / "analysis.json").read_text(encoding="utf-8"))
    bundle = json.loads(Path(bundle_path).read_text(encoding="utf-8"))
    log = d / "decisions.jsonl"
    decisions = [json.loads(x) for x in log.read_text(encoding="utf-8").splitlines() if x.strip()] if log.exists() else []
    out = d / "report.html"
    out.write_text(build_report_html(analysis, bundle, decisions), encoding="utf-8")
    return str(out)


if __name__ == "__main__":
    import sys
    case_dir = Path(sys.argv[1] if len(sys.argv) > 1 else "data/cases/CASE-DEMO")
    print(write_report(str(case_dir / "reasoning"), str(case_dir / "bundle.json")))
