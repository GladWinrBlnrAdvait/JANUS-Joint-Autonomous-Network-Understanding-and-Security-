"""
DEMO STAND-IN for re-running a SAST scanner (e.g. Semgrep) over the workspace.
Flags SQL statements built with f-strings, % or + in any .py file. Exit code 1 if any.
In a real lab, point the 'new_vulnerability_scan' command at Semgrep instead.
"""
import pathlib
import re
import sys

SQL = re.compile(r"""(?i)(f["'].*\b(select|insert|update|delete)\b.*\{)|(["'].*\b(select|insert|update|delete)\b.*["']\s*(%|\+))""")
hits = []
for path in pathlib.Path(".").rglob("*.py"):
    if path.name.startswith("check_"):
        continue
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if SQL.search(line):
            hits.append(f"{path}:{n}: {line.strip()}")
print("\n".join(hits) or "no string-built SQL found")
sys.exit(1 if hits else 0)
