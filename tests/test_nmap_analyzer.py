from analyzers.network.nmap_analyzer import parse_nmap_output


def test_nmap_parser():

    sample_output = """
    Starting Nmap 7.991
    Nmap scan report for 192.168.56.102
    Host is up.

    PORT     STATE SERVICE
    21/tcp   open  ftp
    22/tcp   open  ssh
    80/tcp   open  http
    3306/tcp open  mysql
    """

    findings = parse_nmap_output(
        sample_output,
        "192.168.56.102"
    )

    assert len(findings) == 4

    assert findings[0].evidence_id == "NMAP-001"
    assert findings[0].source == "nmap"
    assert findings[0].category == "network"
    assert findings[0].finding_type == "open_service"

    assert findings[0].evidence_data["port"] == 21
    assert findings[0].evidence_data["service"] == "ftp"

    assert findings[3].evidence_data["port"] == 3306