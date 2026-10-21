import subprocess


def collect_network_interfaces():
    """
    Collect network interface information from the Linux target.
    Compatible with older Python versions.
    """

    process = subprocess.Popen(
        ["/sbin/ip", "addr"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True
    )

    output, error = process.communicate()

    if process.returncode != 0:
        raise RuntimeError(
            "Failed to collect network interfaces: " + error
        )

    return output


def parse_interface_output(output):
    """
    Parse the output of 'ip addr' into structured interface data.
    """

    interfaces = []
    current_interface = None

    for line in output.splitlines():

        line = line.strip()

        if ":" in line and not line.startswith("inet"):
            parts = line.split(":", 2)

            if len(parts) >= 2 and parts[0].isdigit():

                current_interface = parts[1].strip()

                interfaces.append({
                    "name": current_interface,
                    "addresses": []
                })

        elif line.startswith("inet ") and current_interface:

            address = line.split()[1]

            interfaces[-1]["addresses"].append(address)

    return interfaces


def get_interface_data():
    """
    Collect and structure network interface information.
    """

    output = collect_network_interfaces()

    return parse_interface_output(output)