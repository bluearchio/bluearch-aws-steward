from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

ASSESSMENT_MODES = ("guided", "focused", "full_report", "architectural_review")
ASSESSMENT_OBJECTIVES = (
    "cost_optimization",
    "security",
    "reliability",
    "operations",
    "performance_efficiency",
    "all",
)
REPORT_PROFILES = ("executive", "technical", "remediation", "complete")


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class Rule:
    id: str
    short_id: str
    service: str
    scenario: str
    risk_detail: str
    severity: str
    detector: str
    remediation: Dict[str, Any]
    parameters: Dict[str, Any] = field(default_factory=dict)
    catalog_service: Optional[str] = None
    capabilities: List[str] = field(default_factory=list)
    evaluation_kind: str = "configuration"
    objectives: List[str] = field(default_factory=list)
    access_tier: str = "free"


@dataclass(frozen=True)
class ResourceRef:
    provider: str
    service: str
    resource_type: str
    resource_id: str
    region: Optional[str] = None
    account_id: Optional[str] = None
    arn: Optional[str] = None
    display_name: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {key: value for key, value in asdict(self).items() if value is not None}


@dataclass(frozen=True)
class ArchitectureNode:
    node_id: str
    kind: str
    resource_ref: ResourceRef
    source: str
    confidence: str
    observed_at: str
    facts: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            **asdict(self),
            "resource_ref": self.resource_ref.to_dict(),
        }


@dataclass(frozen=True)
class ArchitectureEdge:
    source_node_id: str
    target_node_id: str
    relationship_type: str
    source: str
    confidence: str
    observed_at: str
    evidence_provenance: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ReviewIntent:
    operation: str
    focus: List[ResourceRef]
    objectives: List[str] = field(default_factory=list)
    answers: Dict[str, Any] = field(default_factory=dict)
    max_relationship_hops: int = 1

    def to_dict(self) -> Dict[str, Any]:
        return {
            "operation": self.operation,
            "focus": [resource.to_dict() for resource in self.focus],
            "objectives": list(self.objectives),
            "answers": dict(self.answers),
            "max_relationship_hops": self.max_relationship_hops,
        }


@dataclass
class RemediationPlan:
    summary: str
    safety_level: str
    requires_approval: bool
    actions: List[str]
    verification: str


@dataclass
class Finding:
    finding_id: str
    rule_id: str
    rule_short_id: str
    service: str
    resource: str
    severity: str
    risk_detail: str
    scenario: str
    evidence: Dict[str, Any]
    remediation: RemediationPlan
    resource_ref: Optional[ResourceRef] = None

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        if self.resource_ref is None:
            data.pop("resource_ref", None)
        else:
            data["resource_ref"] = self.resource_ref.to_dict()
        return data


@dataclass
class ScanResult:
    schema_version: str
    generated_at: str
    service: str
    provider: str
    profile: Optional[str]
    endpoint_url: Optional[str]
    region: str
    findings: List[Finding] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["findings"] = [finding.to_dict() for finding in self.findings]
        return data


@dataclass
class ScanEvent:
    type: str
    timestamp: str
    service: str
    resource: Optional[str] = None
    finding: Optional[Finding] = None
    result: Optional[ScanResult] = None
    message: Optional[str] = None
    data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        if self.finding:
            data["finding"] = self.finding.to_dict()
        if self.result:
            data["result"] = self.result.to_dict()
        return data


@dataclass(frozen=True)
class AssessmentIntent:
    mode: str
    objectives: List[str]
    services: List[str]
    result_preferences: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
