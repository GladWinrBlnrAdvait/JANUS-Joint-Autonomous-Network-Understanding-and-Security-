"""Validated data contracts for controlled remediation."""
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

@dataclass
class FileChange:
    path: str
    content: str
    expected_sha256: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "FileChange":
        return cls(path=data["path"], content=data["content"],
                   expected_sha256=data.get("expected_sha256"))

@dataclass
class RemediationPackage:
    case_id: str
    target: str
    finding_ids: List[str]
    rationale: str
    changes: List[FileChange]
    validation: List[Dict[str, Any]] = field(default_factory=list)
    package_id: str = ""

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RemediationPackage":
        required = ("case_id", "target", "finding_ids", "rationale", "changes")
        missing = [key for key in required if key not in data]
        if missing:
            raise ValueError("Missing remediation fields: " + ", ".join(missing))
        if not data["finding_ids"]:
            raise ValueError("A remediation must reference at least one finding")
        if not data["changes"]:
            raise ValueError("A remediation must contain at least one file change")
        return cls(case_id=str(data["case_id"]), target=str(data["target"]),
                   finding_ids=list(data["finding_ids"]), rationale=str(data["rationale"]),
                   changes=[FileChange.from_dict(x) for x in data["changes"]],
                   validation=list(data.get("validation", [])),
                   package_id=str(data.get("package_id", "")))
