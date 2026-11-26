"""Transactional remediation in a designated workspace, followed by independent checks.

This module never executes remediation-provided shell commands. Remediation is
limited to writing regular files beneath an explicitly configured workspace.
Validation commands use argv (never a shell) and must match an operator-supplied
allow-list exactly. A failed check triggers automatic rollback.
"""
import hashlib
import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
import uuid
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional

from .models import RemediationPackage

class ExecutionError(Exception):
    pass

@dataclass
class ValidationCheck:
    name: str
    check_type: str
    passed: bool
    details: str

@dataclass
class ExecutionResult:
    package_id: str
    decision: str
    snapshot: str
    checks: List[Dict[str, Any]]
    changed_files: List[str]
    rolled_back: bool
    started_at: float
    finished_at: float

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

class ControlledExecutor:
    def __init__(self, workspace: str, snapshot_dir: str,
                 authorized_scope=None, allowed_commands=None, timeout: int = 60):
        self.workspace = Path(workspace).resolve()
        self.snapshot_dir = Path(snapshot_dir).resolve()
        self.authorized_scope = authorized_scope
        self.allowed_commands = [list(x) for x in (allowed_commands or [])]
        self.timeout = max(1, min(int(timeout), 300))

    def _safe_path(self, relative: str) -> Path:
        candidate = Path(relative)
        if candidate.is_absolute() or not relative or ".." in candidate.parts:
            raise ExecutionError("Change path must be a safe relative path")
        destination = (self.workspace / candidate).resolve()
        if self.workspace not in destination.parents:
            raise ExecutionError("Change path escapes the workspace")
        # Reject symlinks in any existing component, including the leaf.
        current = self.workspace
        for part in candidate.parts:
            current = current / part
            if current.is_symlink():
                raise ExecutionError("Symlink paths are not allowed")
        return destination

    def _snapshot(self) -> Path:
        if not self.workspace.is_dir():
            raise ExecutionError("Workspace must already exist")
        self.snapshot_dir.mkdir(parents=True, exist_ok=True)
        name = "snapshot-" + uuid.uuid4().hex
        target = self.snapshot_dir / name
        shutil.copytree(str(self.workspace), str(target), symlinks=True)
        return target

    def _restore(self, snapshot: Path) -> None:
        # Remove current workspace contents, then restore the captured state.
        for child in self.workspace.iterdir():
            if child.is_dir() and not child.is_symlink():
                shutil.rmtree(str(child))
            else:
                child.unlink()
        for child in snapshot.iterdir():
            destination = self.workspace / child.name
            if child.is_dir() and not child.is_symlink():
                shutil.copytree(str(child), str(destination), symlinks=True)
            elif child.is_symlink():
                destination.symlink_to(os.readlink(str(child)))
            else:
                shutil.copy2(str(child), str(destination))

    @staticmethod
    def _sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(65536), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def _apply(self, package: RemediationPackage) -> List[str]:
        changed = []
        seen = set()
        for change in package.changes:
            path = self._safe_path(change.path)
            if str(path) in seen:
                raise ExecutionError("A remediation package cannot change a path twice")
            seen.add(str(path))
            if path.exists():
                if not path.is_file():
                    raise ExecutionError("Only regular files may be changed")
                if change.expected_sha256 and self._sha256(path) != change.expected_sha256:
                    raise ExecutionError("Precondition hash mismatch: " + change.path)
            elif change.expected_sha256:
                raise ExecutionError("Expected existing file is missing: " + change.path)
            path.parent.mkdir(parents=True, exist_ok=True)
            fd, temporary = tempfile.mkstemp(prefix=".janus-", dir=str(path.parent))
            try:
                with os.fdopen(fd, "w", encoding="utf-8", newline="") as stream:
                    stream.write(change.content)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary, str(path))
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)
            changed.append(change.path)
        return changed

    def _run_check(self, spec: Dict[str, Any]) -> ValidationCheck:
        name = str(spec.get("name", spec.get("type", "validation")))
        kind = spec.get("type")
        try:
            if kind in ("file_exists", "file_contains", "file_not_contains"):
                path = self._safe_path(spec["path"])
                exists = path.is_file()
                if kind == "file_exists":
                    passed, detail = exists == bool(spec.get("expected", True)), "file existence checked"
                elif not exists:
                    passed, detail = False, "file does not exist"
                else:
                    content = path.read_text(encoding="utf-8")
                    needle = str(spec["value"])
                    matched = needle in content
                    passed = matched if kind == "file_contains" else not matched
                    detail = "content assertion evaluated"
            elif kind == "command":
                argv = spec.get("argv")
                if not isinstance(argv, list) or not argv or not all(isinstance(x, str) for x in argv):
                    raise ExecutionError("Command check requires a non-empty argv list")
                if argv not in self.allowed_commands:
                    raise ExecutionError("Command is not in the validation allow-list")
                completed = subprocess.run(argv, cwd=str(self.workspace), shell=False,
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    universal_newlines=True, timeout=self.timeout)
                expected = int(spec.get("expected_exit_code", 0))
                passed = completed.returncode == expected
                detail = "exit code %s (expected %s); output: %s" % (
                    completed.returncode, expected, completed.stdout[-2000:])
            elif kind == "tcp_reachable":
                host, port = str(spec["host"]), int(spec["port"])
                if self.authorized_scope is None:
                    raise ExecutionError("TCP validation requires an authorized scope")
                self.authorized_scope.require(host)
                with socket.create_connection((host, port), timeout=min(self.timeout, 5)):
                    pass
                passed, detail = True, "TCP connection succeeded"
            elif kind == "tcp_unreachable":
                host, port = str(spec["host"]), int(spec["port"])
                if self.authorized_scope is None:
                    raise ExecutionError("TCP validation requires an authorized scope")
                self.authorized_scope.require(host)
                try:
                    connection = socket.create_connection((host, port), timeout=min(self.timeout, 5))
                    connection.close()
                    passed, detail = False, "TCP connection unexpectedly succeeded"
                except OSError:
                    passed, detail = True, "TCP connection was not established"
            else:
                raise ExecutionError("Unsupported validation check type: %r" % kind)
            return ValidationCheck(name, str(kind), bool(passed), detail)
        except Exception as exc:
            return ValidationCheck(name, str(kind), False, "%s: %s" % (type(exc).__name__, exc))

    def execute(self, package, *, dry_run: bool = False) -> ExecutionResult:
        if isinstance(package, dict):
            package = RemediationPackage.from_dict(package)
        if not isinstance(package, RemediationPackage):
            raise TypeError("package must be RemediationPackage or dict")
        if self.authorized_scope is None:
            raise ExecutionError("An explicit AuthorizedScope is required for remediation")
        self.authorized_scope.require(package.target)
        # Validate all paths before taking action.
        for change in package.changes:
            self._safe_path(change.path)
        started = time.time()
        snapshot = self._snapshot()
        package_id = package.package_id or uuid.uuid4().hex
        changed, checks, rolled_back = [], [], False
        try:
            if dry_run:
                checks.append(ValidationCheck("dry_run", "execution", True,
                                              "Package validated; no files changed"))
                decision = "DRY_RUN"
            else:
                changed = self._apply(package)
                checks = [self._run_check(item) for item in package.validation]
                if not checks:
                    checks = [ValidationCheck("validation_defined", "policy", False,
                                              "No independent validation checks were supplied")]
                decision = "ACCEPT" if all(item.passed for item in checks) else "REJECT"
                if decision == "REJECT":
                    self._restore(snapshot)
                    rolled_back = True
        except Exception:
            self._restore(snapshot)
            rolled_back = True
            raise
        return ExecutionResult(package_id, decision, str(snapshot),
            [asdict(item) for item in checks], changed, rolled_back, started, time.time())
