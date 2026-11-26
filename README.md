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
- Context correlation, reasoning, and remediation planning remain planned.
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