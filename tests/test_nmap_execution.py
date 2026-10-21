from analyzers.network.nmap_analyzer import run_nmap


def test_nmap_execution():

    output = run_nmap("192.168.56.102")

    assert output
    assert "Nmap scan report" in output
    assert "PORT" in output