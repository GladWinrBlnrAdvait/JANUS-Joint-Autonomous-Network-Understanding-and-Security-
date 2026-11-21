import pytest
from analyzers.network.nmap_analyzer import (
    NmapError, NmapParseError, nmap_xml_to_evidence, parse_nmap_xml, run_nmap_xml,
)

SAMPLE = """<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.95">
 <host><status state="up"/><address addr="192.168.56.10" addrtype="ipv4"/>
  <ports>
   <port protocol="tcp" portid="22"><state state="open"/>
     <service name="ssh" product="OpenSSH" version="9.6" method="probed"/></port>
   <port protocol="tcp" portid="80"><state state="open"/>
     <service name="http" method="table"/></port>
   <port protocol="tcp" portid="23"><state state="closed"/>
     <service name="telnet" method="table"/></port>
  </ports></host>
</nmaprun>"""


def test_parse_structure():
    data = parse_nmap_xml(SAMPLE)
    assert data["tool_version"] == "Nmap 7.95"
    assert len(data["hosts"][0]["ports"]) == 3


def test_evidence_only_for_open_ports_plus_host_status():
    ev = nmap_xml_to_evidence(SAMPLE, "CASE-1", raw_ref="cases/CASE-1/raw/x.xml")
    types = sorted(e.finding_type for e in ev)
    assert types == ["host_status", "open_service", "open_service"]
    ssh = next(e for e in ev if e.evidence_data.get("port") == 22)
    assert ssh.confidence == 1.0 and "OpenSSH 9.6" in ssh.description
    http = next(e for e in ev if e.evidence_data.get("port") == 80)
    assert http.confidence == 0.7
    assert all(e.case_id == "CASE-1" and e.raw_ref for e in ev)


def test_ids_stable_across_runs_and_unique_per_case():
    a = {e.evidence_id for e in nmap_xml_to_evidence(SAMPLE, "CASE-1")}
    b = {e.evidence_id for e in nmap_xml_to_evidence(SAMPLE, "CASE-1")}
    c = {e.evidence_id for e in nmap_xml_to_evidence(SAMPLE, "CASE-2")}
    assert a == b and a.isdisjoint(c)


def test_malformed_xml_is_explicit_error():
    with pytest.raises(NmapParseError):
        parse_nmap_xml("<nmaprun><host>")
    with pytest.raises(NmapParseError):
        parse_nmap_xml("<html></html>")


def test_unsafe_target_refused():
    with pytest.raises(NmapError):
        run_nmap_xml("-iL /etc/passwd")
    with pytest.raises(NmapError):
        run_nmap_xml("10.0.0.1; rm -rf /")