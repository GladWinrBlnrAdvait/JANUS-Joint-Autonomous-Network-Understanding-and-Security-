# JANUS: Joint Autonomous Network Understanding & Security

AI-assisted cybersecurity analysis and remediation framework. Central workflow:

**Evidence → Context → Reasoning → Remediation → Independent Validation**

This repository currently contains the **Security Analysis & Evidence Layer**:
the part of JANUS that collects, normalizes, stores and hands off security
evidence to the downstream layers.

## What the evidence layer does

| Module | Purpose |
|---|---|
| `evidence/models.py` | Common `Evidence` model: IDs, case ID, source, tool version, severity (how bad) kept separate from confidence (how sure), status, raw-output reference. Validates input. |
| `evidence/normalizer.py` | Translates tool vocabularies (labels, CVSS scores, confidence words) into JANUS values. Bad records are reported, never silently dropped. |
| `evidence/store.py` | File-based, append-only store organized by case. Raw output preserved with SHA-256 hashes. Contradictory observations kept as revisions. |
| `evidence/scope.py` | Authorized-target allow-list. Active operations check it before touching a target. |
| `evidence/bundle.py` | Per-case JSON hand-off for downstream layers: evidence by target, contradictions, failures, raw-artifact integrity. |
| `analyzers/network/nmap_analyzer.py` | Runs Nmap (XML output), parses hosts, ports and services into Evidence. Legacy text parser retained. |
| `analyzers/software/semgrep_adapter.py` | Converts Semgrep (SAST) JSON into Evidence. |
| `target_agent/linux_collector.py` | Whitelisted read-only host collection: interfaces, routes, listening sockets. No arbitrary command execution. |
| `demo.py` | End-to-end demonstration. |

## Design principles

- **Traceability:** every Evidence item can be traced to preserved raw output with an integrity hash.
- **Explicit failure:** failed or unavailable collection becomes `collection_failed` / `scan_error` evidence instead of vanishing.
- **Contradictions preserved:** changed observations become new revisions, not overwrites.
- **Restricted collection:** only named, read-only operations can run on a target.
- **Authorization first:** scans are checked against an explicit scope.

## Setup

```
python -m venv .venv
.venv\Scripts\activate          # Windows
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

## Basic usage

```python
from analyzers.network.nmap_analyzer import run_nmap_xml, nmap_xml_to_evidence
from evidence.scope import AuthorizedScope
from evidence.store import EvidenceStore
from evidence.bundle import export_case_bundle

store = EvidenceStore("data")
xml = run_nmap_xml("192.168.56.10", scope=AuthorizedScope(["192.168.56.0/24"]))
ref = store.save_raw("CASE-001", "nmap", "192.168.56.10", xml, "xml")
store.add_many(nmap_xml_to_evidence(xml, "CASE-001", raw_ref=ref))
export_case_bundle(store, "CASE-001")
```

## Known limitations

- The Semgrep adapter has been tested against sample JSON in Semgrep's documented format; validate it against a real scan before relying on it.
- The Linux collector must run on the target host (Linux). It reports `collection_failed` where `ip` / `ss` are unavailable.
- Scope checking is only enforced where a `scope` is passed; entry points must always supply one.
- Storage is file-based JSON, suitable for lab-scale use, not concurrent multi-writer use.
- DAST, dependency analysis, fuzzing, firewall and service-status collection are not yet implemented.
- Context correlation, reasoning, remediation, validation and reporting are separate JANUS components.

## Results

*To be completed from real lab runs. Do not record figures that were not measured.*