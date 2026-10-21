from analyzers.network.nmap_analyzer import (
    run_nmap,
    save_raw_output
)


def test_nmap_raw_output_storage():

    target = "192.168.56.102"

    output = run_nmap(target)

    output_path = save_raw_output(output, target)

    assert output_path.exists()
    assert output_path.name == "nmap_192_168_56_102.txt"

    saved_output = output_path.read_text(encoding="utf-8")

    assert saved_output == output
    assert "Nmap scan report" in saved_output