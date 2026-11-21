import pytest
from evidence.store import EvidenceStore
from target_agent.linux_collector import (
    collect_host_evidence, parse_ip_addr, parse_ip_route, parse_ss, run_operation,
)

IP_ADDR = """1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
    inet6 ::1/128 scope host
2: eth0@if5: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default
    link/ether 08:00:27:aa:bb:cc brd ff:ff:ff:ff:ff:ff
    inet 192.168.56.10/24 brd 192.168.56.255 scope global eth0
    inet6 fe80::a00:27ff:feaa:bbcc/64 scope link
"""
IP_ROUTE = """default via 192.168.56.1 dev eth0 proto dhcp metric 100
192.168.56.0/24 dev eth0 proto kernel scope link src 192.168.56.10
"""
SS = """Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port
tcp   LISTEN 0      128    0.0.0.0:22         0.0.0.0:*
tcp   LISTEN 0      128    127.0.0.1:5432     0.0.0.0:*
tcp   LISTEN 0      128    [::]:80            [::]:*
udp   UNCONN 0      0      0.0.0.0:68         0.0.0.0:*
"""
OUTPUTS = {"ip addr": IP_ADDR, "ip route": IP_ROUTE, "ss -tuln": SS}


def fake_runner(command, timeout):
    return 0, OUTPUTS[" ".join(command)], ""


def test_parse_ip_addr_ipv4_ipv6_and_suffix():
    ifaces = parse_ip_addr(IP_ADDR)
    assert [i["name"] for i in ifaces] == ["lo", "eth0"]
    eth0 = ifaces[1]
    assert eth0["state"] == "UP"
    assert eth0["ipv4"] == ["192.168.56.10/24"] and len(eth0["ipv6"]) == 1


def test_parse_ip_route():
    routes = parse_ip_route(IP_ROUTE)
    assert routes[0]["destination"] == "default" and routes[0]["via"] == "192.168.56.1"
    assert routes[1]["src"] == "192.168.56.10"


def test_parse_ss_scope():
    socks = {s["port"]: s for s in parse_ss(SS)}
    assert socks[22]["scope"] == "network" and socks[5432]["scope"] == "loopback"
    assert socks[80]["address"] == "::" and socks[68]["protocol"] == "udp"


def test_disallowed_operation_refused():
    with pytest.raises(ValueError):
        run_operation("rm -rf /")


def test_failure_is_explicit_evidence():
    def broken(command, timeout):
        return 1, "", "permission denied"
    ev = collect_host_evidence("CASE-1", "192.168.56.10", runner=broken)
    assert {e.finding_type for e in ev} == {"collection_failed"}
    assert len(ev) == 3


def test_full_collection_with_store(tmp_path):
    store = EvidenceStore(str(tmp_path))
    ev = collect_host_evidence("CASE-1", "192.168.56.10", store=store, runner=fake_runner)
    kinds = [e.finding_type for e in ev]
    assert kinds.count("network_interface") == 2
    assert kinds.count("route") == 2 and kinds.count("listening_socket") == 4
    assert store.add_many(ev) == len(ev)
    assert all(store.verify_raw(e.raw_ref) for e in ev)