"""
JANUS Evidence Layer demo.

Offline (no tools needed):   python demo.py
Live Nmap on your lab:       python demo.py --live 192.168.56.10 --scope 192.168.56.0/24
"""

import argparse
import json

from analyzers.network.nmap_analyzer import nmap_xml_to_evidence, run_nmap_xml
from analyzers.software.semgrep_adapter import semgrep_to_evidence
from evidence.bundle import export_case_bundle
from evidence.scope import AuthorizedScope
from evidence.store import EvidenceStore
from target_agent.linux_collector import collect_host_evidence

SAMPLE_NMAP = """<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.95"><host><status state="up"/>
<address addr="192.168.56.10" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9.6" method="probed"/></port>
<port protocol="tcp" portid="80"><state state="open"/><service name="http" method="table"/></port>
</ports></host></nmaprun>"""

SAMPLE_SEMGREP = json.dumps({"version": "1.80.0", "results": [{
    "check_id": "python.flask.sql-injection", "path": "app.py",
    "start": {"line": 42}, "end": {"line": 42},
    "extra": {"message": "User input flows into SQL query", "severity": "ERROR",
              "metadata": {"confidence": "HIGH", "cwe": ["CWE-89"]}}}], "errors": []})


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--live", help="target to scan with real Nmap")
    parser.add_argument("--scope", help="allowed network, e.g. 192.168.56.0/24")
    parser.add_argument("--case", default="CASE-DEMO")
    args = parser.parse_args()

    store = EvidenceStore("data")
    target = args.live or "192.168.56.10"

    if args.live:
        if not args.scope:
            raise SystemExit("--live requires --scope (authorized network)")
        xml = run_nmap_xml(target, scope=AuthorizedScope([args.scope]))
    else:
        xml = SAMPLE_NMAP

    # 1. network evidence, raw output preserved
    ref = store.save_raw(args.case, "nmap", target, xml, "xml")
    store.add_many(nmap_xml_to_evidence(xml, args.case, raw_ref=ref))

    # 2. software evidence
    sast, errors = semgrep_to_evidence(SAMPLE_SEMGREP, args.case, "demo-app")
    store.add_many(sast)

    # 3. host evidence (works on Linux; shows explicit failures elsewhere)
    store.add_many(collect_host_evidence(args.case, target, store=store))

    # 4. hand-off bundle for the next JANUS layers
    path = export_case_bundle(store, args.case)
    summary = json.load(open(path))["summary"]
    print(f"Bundle written to {path}")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()