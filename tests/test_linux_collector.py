from target_agent.linux_collector import parse_interface_output


def test_interface_data():

    sample_output = """
    1: lo: <LOOPBACK,UP,LOWER_UP>
        inet 127.0.0.1/8

    2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP>
        inet 192.168.56.102/24
    """

    interfaces = parse_interface_output(sample_output)

    assert len(interfaces) == 2

    assert interfaces[0]["name"] == "lo"
    assert interfaces[0]["addresses"] == ["127.0.0.1/8"]

    assert interfaces[1]["name"] == "eth0"
    assert interfaces[1]["addresses"] == ["192.168.56.102/24"]