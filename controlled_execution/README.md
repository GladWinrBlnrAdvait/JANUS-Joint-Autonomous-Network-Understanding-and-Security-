# JANUS Controlled Execution & Independent Validation

This module is the Part 3 hand-off: it accepts a structured remediation package,
checks authorization, snapshots a designated workspace, applies restricted file
changes, runs independent checks, and accepts or rolls back the change.

## Safety model

- An explicit `AuthorizedScope` is mandatory. The package target must be in scope.
- Remediation can only write regular files below the configured workspace. It
  cannot run shell commands, delete files, or write outside the workspace.
- Optional `expected_sha256` values prevent applying a patch to an unexpected file.
- Every run creates a pre-change snapshot. Failed checks automatically restore it.
- Validation commands use `subprocess` with `shell=False` and must exactly match
  the operator-provided `allowed_commands` list.
- TCP checks require the target host to be in the same explicit authorized scope.
- A package with no validation checks is rejected, not silently accepted.

## Example

```python
from evidence.scope import AuthorizedScope
from controlled_execution import ControlledExecutor

scope = AuthorizedScope(["192.168.56.0/24"])
executor = ControlledExecutor(
    workspace="lab/workspace",
    snapshot_dir="lab/snapshots",
    authorized_scope=scope,
    allowed_commands=[["python", "-m", "pytest", "-q"]],
)
package = {
    "case_id": "CASE-001",
    "target": "192.168.56.10",
    "finding_ids": ["SAST-123"],
    "rationale": "Escape untrusted input before rendering.",
    "changes": [{"path": "app.py", "content": "# corrected application code\\n"}],
    "validation": [
        {"name": "regression suite", "type": "command",
         "argv": ["python", "-m", "pytest", "-q"]},
        {"name": "patched file exists", "type": "file_exists", "path": "app.py"}
    ]
}
result = executor.execute(package)
print(result.to_dict())  # decision: ACCEPT or REJECT
```

Run the full repository tests with `python -m pytest -q`.

This is a research prototype, not a VM/container hypervisor. The configured
workspace must itself be a disposable lab checkout/container mount. Snapshot
folders are retained for audit/manual recovery; production deployment needs
operator review, concurrency locking, stronger isolation, and signed packages.
