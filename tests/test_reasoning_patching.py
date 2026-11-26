import difflib

import pytest

from reasoning.patching import (PatchError, apply_unified_diff, diff_target_file,
                                validate_patch)

ORIG = "".join(f"line {i}\n" for i in range(1, 21))


def _diff(old, new, name="f.py"):
    return "\n".join(difflib.unified_diff(old.splitlines(), new.splitlines(),
                                          f"a/{name}", f"b/{name}", lineterm=""))


def test_roundtrip_with_difflib():
    new = ORIG.replace("line 5\n", "FIVE\n").replace("line 15\n", "")
    assert apply_unified_diff(ORIG, _diff(ORIG, new)) == new


def test_insertion_and_trailing_newline_kept():
    new = ORIG + "line 21\n"
    assert apply_unified_diff(ORIG, _diff(ORIG, new)) == new


def test_context_mismatch_is_rejected():
    changed = ORIG.replace("line 5\n", "DIFFERENT\n")
    with pytest.raises(PatchError, match="context mismatch"):
        apply_unified_diff(changed, _diff(ORIG, ORIG.replace("line 5\n", "x\n")))


def test_wrong_hunk_counts_rejected():
    d = _diff(ORIG, ORIG.replace("line 5\n", "x\n")).replace("@@ -2,7 +2,7 @@", "@@ -2,9 +2,9 @@")
    with pytest.raises(PatchError):
        apply_unified_diff(ORIG, d)


def test_garbage_and_empty_diff_rejected():
    with pytest.raises(PatchError):
        apply_unified_diff(ORIG, "not a diff")
    with pytest.raises(PatchError):
        apply_unified_diff(ORIG, "--- a/f\n+++ b/f\n")


def test_validate_patch_checks_target_file():
    d = _diff(ORIG, ORIG.replace("line 5\n", "x\n"), "other.py")
    assert diff_target_file(d) == "other.py"
    with pytest.raises(PatchError, match="targets"):
        validate_patch(d, "f.py", ORIG)


def test_size_limit():
    big_new = "".join(f"new {i}\n" for i in range(300))
    with pytest.raises(PatchError, match="limit"):
        apply_unified_diff(ORIG, _diff(ORIG, big_new))
