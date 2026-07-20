from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional

from bluearch_aws_steward.detectors.common import supported_rules_by_detector
from bluearch_aws_steward.models import Finding, Rule
from bluearch_aws_steward.providers.base import AwsProvider, AwsProviderError


class EvaluationContext:
    """Tracks capability and permission failures without reporting skipped rules as passing."""

    def __init__(self, client: AwsProvider, service: str, rule_filter: str | None) -> None:
        self.client = client
        self.rules, self.rules_skipped = supported_rules_by_detector(client, service, rule_filter)
        self.capability_errors: List[Dict[str, Any]] = []
        self.extended_resources_scanned = 0
        self._failed_detectors: set[str] = set()

    def rule(self, detector: str) -> Optional[Rule]:
        if detector in self._failed_detectors:
            return None
        return self.rules.get(detector)

    def read(
        self,
        detectors: str | Iterable[str],
        operation: str,
        **parameters: Any,
    ) -> Optional[Dict[str, Any]]:
        detector_names = [detectors] if isinstance(detectors, str) else list(detectors)
        relevant = [name for name in detector_names if name in self.rules]
        if not relevant:
            return None
        reader = getattr(self.client, "read", None)
        if not callable(reader):
            self._fail(
                relevant, operation, "Provider does not implement the allowlisted read interface."
            )
            return None
        try:
            return reader(operation, **parameters)
        except AwsProviderError as exc:
            self._fail(relevant, operation, exc.detail or str(exc))
            return None

    def fail(self, detectors: str | Iterable[str], operation: str, detail: str) -> None:
        names = [detectors] if isinstance(detectors, str) else list(detectors)
        self._fail([name for name in names if name in self.rules], operation, detail)

    @property
    def rules_evaluated(self) -> int:
        return len(self.rules) - len(self._failed_detectors)

    def completed_findings(self, findings: Iterable[Finding]) -> List[Finding]:
        active_rule_ids = {
            rule.id
            for detector, rule in self.rules.items()
            if detector not in self._failed_detectors
        }
        return [finding for finding in findings if finding.rule_id in active_rule_ids]

    def _fail(self, detectors: List[str], operation: str, detail: str) -> None:
        for detector in detectors:
            if detector in self._failed_detectors:
                continue
            self._failed_detectors.add(detector)
            rule = self.rules[detector]
            self.rules_skipped.append(
                {
                    "rule": rule.short_id,
                    "reason": "aws_read_failed",
                    "operation": operation,
                }
            )
        if detectors:
            self.capability_errors.append(
                {
                    "operation": operation,
                    "detail": detail,
                    "affected_rules": sorted(self.rules[name].short_id for name in detectors),
                }
            )
