"""
Data contracts of the reasoning layer.

Three hand-off objects, in the same style as evidence.models.Evidence:
  Finding            correlated, deduplicated issue (Evidence layer -> reasoning)
  RemediationPackage proposed fix + what to check (reasoning -> Validation layer)
  ValidationResult   outcome of independent checks (Validation layer -> reasoning)
"""

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Sequence

from evidence.models import VALID_SEVERITIES, make_evidence_id

VERDICTS = ("likely_vulnerable", "uncertain", "likely_false_positive")
EXPLOITABILITY = ("unknown", "low", "medium", "high")
EXPOSURES = ("reachable_from_scanner", "not_observed", "unknown")
CHANGE_TYPES = ("code_patch", "dependency_upgrade", "config_change", "network_rule")
PACKAGE_STATUSES = ("proposed", "needs_human", "escalated", "invalid")
TEST_RESULTS = ("PASS", "FAIL", "NOT_RUN")

# Named checks a package can require; each maps to a ValidationResult field.
CHECK_FIELDS = {
    "security_retest": "security_test",
    "exploit_retest": "exploit_test",
    "regression": "regression_tests",
    "network": "network_tests",
    "new_vulnerability_scan": "new_vulnerabilities",
}


def safe_relative_path(path: str) -> bool:
    """True for a plain relative path with no traversal (used for every file a change touches)."""
    if not path or not str(path).strip():
        return False
    p = str(path).replace("\\", "/")
    if p.startswith("/") or (len(p) > 1 and p[1] == ":"):
        return False
    return ".." not in p.split("/")


@dataclass
class Finding:
    """One correlated issue, possibly backed by several pieces of evidence."""
    finding_id: str
    case_id: str
    title: str
    vuln_class: str                  # e.g. "CWE-89", or the rule id if no CWE
    target: str
    severity: str
    confidence: float                # combined; see correlator for the (heuristic) rule
    evidence_ids: List[str]
    sources: List[str]
    location: Optional[str] = None
    cwe: List[str] = field(default_factory=list)
    description: str = ""

    def __post_init__(self):
        self.severity = str(self.severity).lower()
        if self.severity not in VALID_SEVERITIES:
            raise ValueError(f"Invalid severity '{self.severity}'")
        if not 0.0 <= float(self.confidence) <= 1.0:
            raise ValueError("confidence must be between 0.0 and 1.0")
        if not self.evidence_ids:
            raise ValueError("a Finding must reference at least one piece of evidence")

    def source_file_and_line(self):
        """('app.py', 42) from location 'app.py:42'; (None, None) if not that shape."""
        if self.location and ":" in self.location:
            path, _, line = self.location.rpartition(":")
            if line.isdigit() and safe_relative_path(path):
                return path, int(line)
        return None, None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class FindingContext:
    """Environment around a finding. Unknowns are stated, never assumed."""
    target: str
    host: Optional[str] = None
    app_port: Optional[int] = None
    role: Optional[str] = None
    exposure: str = "unknown"
    open_services: List[Dict[str, Any]] = field(default_factory=list)
    data_gaps: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)   # context evidence the LLM may cite

    def __post_init__(self):
        if self.exposure not in EXPOSURES:
            raise ValueError(f"Invalid exposure '{self.exposure}'")

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RationaleItem:
    claim: str
    evidence_ids: List[str]


@dataclass
class ReasoningResult:
    finding_id: str
    verdict: str
    root_cause: str
    exploitability: str
    risk: str
    affected: List[str]
    rationale: List[RationaleItem]
    recommended_change_types: List[str]
    confidence: float

    def __post_init__(self):
        if self.verdict not in VERDICTS:
            raise ValueError(f"Invalid verdict '{self.verdict}'. Allowed: {VERDICTS}")
        if self.exploitability not in EXPLOITABILITY:
            raise ValueError(f"Invalid exploitability '{self.exploitability}'")
        self.risk = str(self.risk).lower()
        if self.risk not in VALID_SEVERITIES:
            raise ValueError(f"Invalid risk '{self.risk}'")
        if not 0.0 <= float(self.confidence) <= 1.0:
            raise ValueError("confidence must be between 0.0 and 1.0")
        for t in self.recommended_change_types:
            if t not in CHANGE_TYPES:
                raise ValueError(f"Invalid change type '{t}'. Allowed: {CHANGE_TYPES}")
        if not str(self.root_cause).strip():
            raise ValueError("root_cause must not be empty")

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ChangeItem:
    """One concrete change. Always data, never a shell command."""
    change_type: str
    file: Optional[str] = None
    diff: Optional[str] = None            # code_patch: unified diff
    package: Optional[str] = None         # dependency_upgrade
    from_version: Optional[str] = None
    to_version: Optional[str] = None
    key: Optional[str] = None             # config_change
    old_value: Optional[str] = None
    new_value: Optional[str] = None
    description: str = ""
    requires_approval: bool = False

    def __post_init__(self):
        if self.change_type not in CHANGE_TYPES:
            raise ValueError(f"Invalid change type '{self.change_type}'. Allowed: {CHANGE_TYPES}")
        if self.file is not None and not safe_relative_path(self.file):
            raise ValueError(f"Unsafe file path '{self.file}' (must be relative, no '..')")
        need = {
            "code_patch": ("file", "diff"),
            "dependency_upgrade": ("package", "to_version"),
            "config_change": ("file", "key", "new_value"),
            "network_rule": ("description",),
        }[self.change_type]
        for name in need:
            if not getattr(self, name):
                raise ValueError(f"{self.change_type} requires '{name}'")
        if self.change_type == "network_rule":
            self.requires_approval = True   # firewall/ACL changes are never auto-approved

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RemediationPackage:
    finding_id: str
    case_id: str
    attempt: int
    status: str
    root_cause: str
    risk: str
    changes: List[ChangeItem] = field(default_factory=list)
    expected_security_effect: str = ""
    expected_functional_behaviour: str = ""
    expected_network_behaviour: str = ""
    validation_requirements: List[str] = field(default_factory=list)
    rationale: List[RationaleItem] = field(default_factory=list)
    previous_failures: List[str] = field(default_factory=list)
    notes: str = ""

    def __post_init__(self):
        if self.status not in PACKAGE_STATUSES:
            raise ValueError(f"Invalid status '{self.status}'. Allowed: {PACKAGE_STATUSES}")
        for r in self.validation_requirements:
            if r not in CHECK_FIELDS:
                raise ValueError(f"Unknown validation requirement '{r}'")

    @property
    def package_id(self) -> str:
        return make_evidence_id("REM", self.finding_id, self.attempt)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["package_id"] = self.package_id
        return d


@dataclass
class ValidationResult:
    """What the Validation layer returns. NOT_RUN never counts as a pass."""
    package_id: str
    security_test: str = "NOT_RUN"
    exploit_test: str = "NOT_RUN"
    regression_tests: str = "NOT_RUN"
    network_tests: str = "NOT_RUN"
    new_vulnerabilities: str = "NOT_RUN"      # PASS = no new vulnerability appeared
    behaviour_changed: Optional[bool] = None
    failure_reasons: List[str] = field(default_factory=list)
    error: Optional[str] = None     # the executor could not run (scope, hash, path...); not fixable by a new patch

    def __post_init__(self):
        for f in CHECK_FIELDS.values():
            if getattr(self, f) not in TEST_RESULTS:
                raise ValueError(f"{f} must be one of {TEST_RESULTS}")

    def accepted(self, required: Sequence[str]) -> bool:
        """ACCEPT only if every required check is an explicit PASS."""
        return all(getattr(self, CHECK_FIELDS[r]) == "PASS" for r in required)

    def failed_checks(self, required: Sequence[str]) -> List[str]:
        return [r for r in required if getattr(self, CHECK_FIELDS[r]) != "PASS"]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ValidationResult":
        known = set(cls.__dataclass_fields__)
        return cls(**{k: v for k, v in data.items() if k in known})
