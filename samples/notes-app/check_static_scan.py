"""
DEMO STAND-IN for re-running a SAST scanner (e.g. Semgrep) over the workspace.
Flags dangerous constructs in any .py file (except check_*.py). Exit code 1 if any.
In a real lab, point 'new_vulnerability_scan' at Semgrep instead.
"""
import pathlib
import re
import sys

PATTERNS = [
    (r"\beval\(", "eval()"), (r"\bexec\(", "exec()"), (r"os\.system\(", "os.system()"),
    (r"shell\s*=\s*True", "shell=True"), (r"pickle\.loads?\(", "pickle"),
    (r"hashlib\.(md5|sha1)\(", "weak hash"),
    (r"""(?i)(secret|password|passwd|api_?key|token)\w*\s*=\s*["'][^"']{4,}["']""", "hard-coded secret"),
    (r"""f["'].*\b(SELECT|INSERT|UPDATE|DELETE)\b.*\{""", "SQL built from input"),
]
hits = []
for path in pathlib.Path(".").rglob("*.py"):
    if path.name.startswith(("check_", "_")):
        continue
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        for pattern, label in PATTERNS:
            if re.search(pattern, line):
                hits.append(f"{path}:{n}: {label}: {line.strip()}")
print("\n".join(hits) or "no dangerous constructs found")
sys.exit(1 if hits else 0)
