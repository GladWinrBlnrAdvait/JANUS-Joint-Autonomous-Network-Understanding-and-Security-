import re
import subprocess
from pathlib import Path
from evidence.models import Evidence




def run_nmap(target: str):
    """
    Run Nmap against an authorized target and return
    the raw Nmap output.
    """

    result = subprocess.run(
        ["nmap", target],
        capture_output=True,
        text=True,
        check=True
    )

    return result.stdout

def save_raw_output(output: str, target: str):
    """
    Save raw Nmap output to the JANUS evidence directory.
    """

    raw_directory = Path("data/raw")
    raw_directory.mkdir(parents=True, exist_ok=True)

    filename = f"nmap_{target.replace('.', '_')}.txt"
    output_path = raw_directory / filename

    output_path.write_text(output, encoding="utf-8")

    return output_path


def parse_nmap_output(output: str, target: str):
    """
    Parse basic Nmap TCP service output and convert
    discovered open services into JANUS Evidence objects.
    """

    findings = []

    pattern = re.compile(
    r"^[ \t]*(\d+)/tcp\s+open\s+(\S+)",
    re.MULTILINE
)

    matches = pattern.findall(output)

    for index, (port, service) in enumerate(matches, start=1):

        finding = Evidence(
            evidence_id=f"NMAP-{index:03d}",
            source="nmap",
            category="network",
            target=target,
            finding_type="open_service",
            severity="info",
            confidence=1.0,
            description=f"{service} service is exposed on TCP port {port}",
            location=f"{target}:{port}",
            evidence_data={
                "port": int(port),
                "protocol": "tcp",
                "service": service
            }
        )

        findings.append(finding)

    return findings