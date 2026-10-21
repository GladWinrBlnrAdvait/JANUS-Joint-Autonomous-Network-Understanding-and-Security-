from analyzers.network.network_config import build_network_context


def test_network_context():

    sample_output = """
    Nmap scan report for 192.168.56.102
    Host is up (0.049s latency).

    PORT     STATE SERVICE
    21/tcp   open  ftp
    22/tcp   open  ssh
    80/tcp   open  http
    3306/tcp open  mysql
    """

    context = build_network_context(
        sample_output,
        "192.168.56.102"
    )

    assert context.target == "192.168.56.102"
    assert context.host_up is True

    assert context.open_ports == [21, 22, 80, 3306]

    assert context.services == [
        "ftp",
        "ssh",
        "http",
        "mysql"
    ]