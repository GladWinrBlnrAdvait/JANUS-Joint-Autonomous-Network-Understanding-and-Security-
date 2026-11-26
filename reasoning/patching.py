"""
Strict, pure-Python unified-diff handling (works on Windows, no `patch` binary).

An LLM-written diff is only accepted if it applies EXACTLY to the real file:
context and removed lines must match at the stated position. No fuzz, no
guessing. This check is deterministic and independent of the LLM.
"""

import re
from typing import List, Tuple

_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
MAX_CHANGED_LINES = 200


class PatchError(ValueError):
    pass


def _strip_prefix(path: str) -> str:
    path = path.strip().split("\t")[0]
    return path[2:] if path[:2] in ("a/", "b/") else path


def diff_target_file(diff: str) -> str:
    """File named by the '+++' header (without a/ b/ prefix)."""
    for line in diff.splitlines():
        if line.startswith("+++ "):
            return _strip_prefix(line[4:])
    raise PatchError("diff has no '+++' header")


def parse_hunks(diff: str) -> List[Tuple[int, int, List[str]]]:
    lines = diff.splitlines()
    i = 0
    while i < len(lines) and not lines[i].startswith("--- "):
        i += 1
    if i + 1 >= len(lines) or not lines[i + 1].startswith("+++ "):
        raise PatchError("diff must start with '--- ' and '+++ ' headers")
    i += 2
    hunks = []
    while i < len(lines):
        m = _HUNK.match(lines[i])
        if not m:
            if lines[i].strip() == "":
                i += 1
                continue
            raise PatchError(f"unexpected line outside a hunk: {lines[i][:60]!r}")
        old_start = int(m.group(1))
        old_len = int(m.group(2)) if m.group(2) is not None else 1
        body = []
        i += 1
        while i < len(lines) and not lines[i].startswith("@@"):
            if lines[i].startswith("\\"):
                i += 1
                continue
            if not lines[i] or lines[i][0] not in " +-":
                raise PatchError(f"bad hunk line: {lines[i][:60]!r}")
            body.append(lines[i])
            i += 1
        if sum(1 for b in body if b[0] in " -") != old_len:
            raise PatchError("hunk header line count does not match its body")
        hunks.append((old_start, old_len, body))
    if not hunks:
        raise PatchError("diff contains no hunks")
    return hunks


def apply_unified_diff(original: str, diff: str) -> str:
    hunks = parse_hunks(diff)
    changed = sum(1 for _, _, body in hunks for b in body if b[0] in "+-")
    if changed > MAX_CHANGED_LINES:
        raise PatchError(f"patch changes {changed} lines (limit {MAX_CHANGED_LINES})")
    src = original.splitlines()
    out: List[str] = []
    pos = 0                                   # next unconsumed index in src
    for old_start, old_len, body in hunks:
        start = old_start - 1 if old_len else old_start
        if start < pos or start > len(src):
            raise PatchError("hunks overlap, are out of order, or lie outside the file")
        out.extend(src[pos:start])
        pos = start
        for b in body:
            tag, text = b[0], b[1:]
            if tag in " -":
                if pos >= len(src) or src[pos] != text:
                    raise PatchError(
                        f"context mismatch at line {pos + 1}: expected {text!r}, "
                        f"file has {src[pos] if pos < len(src) else '<end of file>'!r}")
                if tag == " ":
                    out.append(text)
                pos += 1
            else:
                out.append(text)
    out.extend(src[pos:])
    result = "\n".join(out)
    return result + "\n" if original.endswith("\n") or not original else result


def validate_patch(diff: str, expected_file: str, original: str) -> str:
    """Return the patched text, or raise PatchError."""
    target = diff_target_file(diff)
    if target != expected_file:
        raise PatchError(f"diff targets '{target}' but the finding is in '{expected_file}'")
    return apply_unified_diff(original, diff)
