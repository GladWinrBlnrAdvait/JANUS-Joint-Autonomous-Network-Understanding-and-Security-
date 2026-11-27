# JANUS
### Joint Autonomous Network Understanding & Security

AI-assisted cyber reasoning system for unified software and network security evidence, contextual remediation, and independent validation.

JANUS is a developing AI-assisted cybersecurity research project focused on combining software and network security evidence, reasoning about security findings, and validating remediation in a controlled environment.

## Core Concept

**Evidence → Context → Reasoning → Remediation → Independent Validation**

JANUS aims to correlate evidence from multiple security-analysis sources into a common representation. Its proposed workflow includes contextual analysis, controlled remediation, and independent checks to determine whether a fix improves security while preserving required system behaviour.

## Current Development Status

The current prototype implements the **Security Analysis & Evidence Layer**:

| Module | Purpose |
|---|---|
| `evidence/models.py` | Common `Evidence` model: IDs, case ID, source, tool version, severity (how bad) kept separate from confidence (how sure), status, raw-output reference. Validates input. |
| `evidence/normalizer.py` | Translates tool vocabularies (labels, CVSS scores, confidence words) into JANUS values. Bad records are reported, never silently dropped. |
| `evidence/store.py` | File-based, append-only store organized by case. Raw output preserved with SHA-256 hashes. Contradictory observations kept as revisions. |
| `evidence/scope.py` | Authorized-target allow-list checked before active operations. |
| `evidence/bundle.py` | Per-case JSON hand-off for downstream layers: evidence by target, contradictions, failures, raw-artifact integrity. |
| `analyzers/network/nmap_analyzer.py` | Runs Nmap (XML output), parses hosts, ports and services into Evidence. Legacy text parser retained. |
| `analyzers/software/semgrep_adapter.py` | Converts Semgrep (SAST) JSON into Evidence. |
| `target_agent/linux_collector.py` | Whitelisted read-only host collection: interfaces, routes, listening sockets. No arbitrary command execution. |
| `controlled_execution/` | Part 3 prototype: scoped transactional file remediation, snapshots, rollback, and independent file/command/TCP validation. |
| `demo.py` | End-to-end demonstration. |

Design principles: traceability to raw output, explicit representation of failures, preserved contradictions, restricted collection, and authorization-first scanning.

## Planned Development

- Additional network configuration evidence collection (firewall, service status).
- Further software security integrations: DAST, dependency analysis, and fuzzing.
- Evidence correlation and contextual reasoning.
- Context correlation, reasoning and remediation planning: implemented in `reasoning/` (see below). Still pending: a run against a real LLM, and DAST/dependency/fuzzing evidence.
- `controlled_execution/` now provides an initial controlled execution and independent validation prototype (see its README).

These capabilities are planned work and are not yet represented as fully implemented features.

## Development Environment

- Python 3
- Git
- Nmap
- pytest
- Windows development environment
- Metasploitable virtual machine for authorized lab testing

The target Linux VM uses an older Python runtime, so target-side code must account for its compatibility constraints.

## Setup

```
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

## Run the tests

```
python -m pytest -v
```

## Run the demo

Offline, using sample data:

```
python demo.py
```

Live Nmap against an authorized lab target (requires Nmap installed):

```
python demo.py --live <TARGET_IP> --scope <ALLOWED_NETWORK>
```

Output: `data/cases/<case_id>/bundle.json` plus raw artifacts under `data/cases/<case_id>/raw/`.

## Cyber Reasoning & Remediation Layer

Consumes `bundle.json` from the Evidence layer and produces explainable remediation packages.

```
bundle.json -> correlate -> context -> reason (LLM) -> remediate (LLM) -> remediation_packages.json
                                                                  ^                  |
                                                                  +-- refine <-- validation result
```

| Module | Purpose |
| --- | --- |
| `reasoning/models.py` | Contracts: `Finding`, `RemediationPackage`, `ValidationResult` (`NOT_RUN` never counts as a pass). |
| `reasoning/correlator.py` | Merges evidence into deduplicated findings; heuristic confidence across independent tools. |
| `reasoning/context.py` | Adds network/host context from the bundle; unknowns are listed as `data_gaps`, never assumed. |
| `reasoning/assets.py`, `config/assets.json` | Explicit software-target -> host/port map (the evidence layer does not link them). |
| `reasoning/reasoner.py`, `remediation.py` | LLM steps. Output is schema-validated, evidence citations are checked, bad output is retried then rejected. |
| `reasoning/patching.py` | Strict pure-Python unified-diff applier: a patch is accepted only if it applies exactly to the real file. |
| `reasoning/decisionlog.py` | Append-only audit log (`decisions.jsonl`) of every LLM exchange with prompt hashes. |
| `reasoning/handoff.py` | Converts a reasoning package into `controlled_execution`'s format (full file content + `expected_sha256`, host target, concrete checks) and converts its result back. Refuses to run with weaker validation than required. |
| `reasoning/closed_loop.py`, `validation_plan.py` | Execute -> validate -> refine loop (max 3 attempts, then escalate to a human). Validation commands come from an operator-written JSON plan, never from the LLM; the same list is the executor's allow-list. |
| `reasoning/report.py` | Builds `report.html`: one self-contained page (before vs after, reasoning with cited evidence, colored diff, per-check results, earlier attempts). All tool/model text is HTML-escaped. |
| `reasoning/llm.py`, `stub.py` | `LLMClient` interface, Anthropic HTTPS client, scripted test LLM, offline rule-based stub. |

Run (offline, no API key; the stub is rule-based, not real AI):

```
python demo.py
python demo_reasoning.py             # reason + propose a fix
python demo_reasoning.py --execute   # also apply it with controlled_execution, validate, roll back on failure
```

With `--execute` the demo copies `samples/demo-app` into `data/cases/<case>/workspace`, applies the fix there, and runs
`check_exploit.py` (the SQL injection must no longer work), `check_regression.py` (login must still work) and
`check_static_scan.py` (a stand-in for re-running Semgrep). The validation commands live in `samples/demo-app/validation.json`.

Output under `data/cases/<case_id>/reasoning/`: `report.html` (open in a browser), `remediation_packages.json`, `analysis.json`, `decisions.jsonl`.
Install test dependencies with `pip install -r requirements.txt`.
Real model: set `ANTHROPIC_API_KEY` (optionally `JANUS_LLM_MODEL`) and run `python demo_reasoning.py --llm anthropic`.

Reasoning-layer limitations: the Anthropic client has not been run against the live API; only `code_patch` changes can be executed
automatically (config, dependency and firewall changes are proposed but handed to a human); the reasoner reads source from the same
workspace the executor writes to; code patches are single-file;
SAST and DAST findings are not yet linked (needs a route-to-code map); firewall/ACL changes are proposals that always require approval.

## Known Limitations

- The Semgrep adapter has been tested against sample JSON in Semgrep's documented format; validate against a real scan before relying on it.
- Scope checking is only enforced where a `scope` is passed; entry points must always supply one.
- Storage is file-based JSON, suitable for lab-scale use, not concurrent multi-writer use.
- DAST, dependency analysis, fuzzing, firewall and service-status collection are not yet implemented.
- Context correlation, reasoning, remediation, validation and reporting are separate JANUS components.

## Safety and Scope

JANUS is being developed for authorized security testing in controlled environments. Scanning and evidence collection should only be performed against systems for which permission has been granted.

## Project Status

**Research prototype — under active development.** Part 3 is an initial workspace-based prototype; it is not yet a VM/container isolation layer.

JANUS does not currently guarantee vulnerability discovery, successful remediation, or production-safe autonomous changes.