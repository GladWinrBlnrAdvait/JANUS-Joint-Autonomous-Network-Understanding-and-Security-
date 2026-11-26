import hashlib
from pathlib import Path
import pytest
from evidence.scope import AuthorizedScope
from controlled_execution import ControlledExecutor
from controlled_execution.engine import ExecutionError


def make_executor(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "app.txt").write_text("before", encoding="utf-8")
    return workspace, ControlledExecutor(str(workspace), str(tmp_path / "snapshots"),
        authorized_scope=AuthorizedScope(["192.168.56.0/24"]))


def package(validation):
    return {"case_id": "CASE-1", "target": "192.168.56.10",
        "finding_ids": ["F-1"], "rationale": "test remediation",
        "changes": [{"path": "app.txt", "content": "after"}],
        "validation": validation}


def test_successful_validation_accepts_change(tmp_path):
    workspace, executor = make_executor(tmp_path)
    result = executor.execute(package([{"type": "file_contains", "path": "app.txt", "value": "after"}]))
    assert result.decision == "ACCEPT"
    assert not result.rolled_back
    assert (workspace / "app.txt").read_text() == "after"
    assert Path(result.snapshot).is_dir()


def test_failed_validation_rolls_back(tmp_path):
    workspace, executor = make_executor(tmp_path)
    result = executor.execute(package([{"type": "file_contains", "path": "app.txt", "value": "missing"}]))
    assert result.decision == "REJECT"
    assert result.rolled_back
    assert (workspace / "app.txt").read_text() == "before"


def test_no_validation_is_rejected_and_rolled_back(tmp_path):
    workspace, executor = make_executor(tmp_path)
    result = executor.execute(package([]))
    assert result.decision == "REJECT"
    assert result.rolled_back
    assert (workspace / "app.txt").read_text() == "before"


def test_path_traversal_is_rejected(tmp_path):
    _, executor = make_executor(tmp_path)
    item = package([{"type": "file_exists", "path": "app.txt"}])
    item["changes"][0]["path"] = "../outside.txt"
    with pytest.raises(ExecutionError):
        executor.execute(item)


def test_scope_is_mandatory_and_enforced(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    executor = ControlledExecutor(str(workspace), str(tmp_path / "snapshots"))
    with pytest.raises(ExecutionError):
        executor.execute(package([{"type": "file_exists", "path": "app.txt"}]))


def test_expected_hash_precondition(tmp_path):
    workspace, executor = make_executor(tmp_path)
    item = package([{"type": "file_exists", "path": "app.txt"}])
    item["changes"][0]["expected_sha256"] = "0" * 64
    with pytest.raises(ExecutionError):
        executor.execute(item)
    assert (workspace / "app.txt").read_text() == "before"
