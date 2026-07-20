"""Read optional AWS recommendation sources through the typed provider allowlist."""

from __future__ import annotations

from copy import deepcopy
from datetime import date, datetime
from decimal import Decimal
from typing import Any, Dict, Iterable, List, Optional, Tuple

from bluearch_aws_steward.finding_sources import normalize_external_findings
from bluearch_aws_steward.models import utc_now_iso
from bluearch_aws_steward.providers.base import AwsProvider, AwsProviderError

JSON = Dict[str, Any]

SIGNAL_SOURCE_CHOICES = (
    "native",
    "security-hub",
    "compute-optimizer",
    "cost-optimization-hub",
)

_SOURCE_OPERATIONS = {
    "security-hub": (("securityhub.get_findings", "securityhub-asff", {"Findings": "Findings"}),),
    "compute-optimizer": (
        (
            "compute-optimizer.get_ec2_instance_recommendations",
            "compute-optimizer-json",
            {"instanceRecommendations": "instanceRecommendations"},
        ),
        (
            "compute-optimizer.get_ebs_volume_recommendations",
            "compute-optimizer-json",
            {"volumeRecommendations": "volumeRecommendations"},
        ),
        (
            "compute-optimizer.get_lambda_function_recommendations",
            "compute-optimizer-json",
            {"lambdaFunctionRecommendations": "lambdaFunctionRecommendations"},
        ),
    ),
    "cost-optimization-hub": (
        (
            "cost-optimization-hub.list_recommendations",
            "cost-optimization-hub-json",
            {"items": "items"},
        ),
    ),
}


def collect_live_signal_results(
    provider: AwsProvider,
    sources: Iterable[str],
    *,
    region: str,
    account_id: Optional[str] = None,
) -> Tuple[List[JSON], List[JSON]]:
    """Return normalized live snapshots and non-fatal capability errors."""

    snapshots: List[JSON] = []
    errors: List[JSON] = []
    capabilities = provider.capabilities()
    for source in _normalized_sources(sources):
        if source == "native":
            continue
        for operation, import_source, result_keys in _SOURCE_OPERATIONS[source]:
            if operation not in capabilities:
                errors.append(
                    {
                        "source": source,
                        "operation": operation,
                        "reason": "provider_capability_missing",
                    }
                )
                continue
            try:
                response = provider.read(operation, **_operation_parameters(operation))
                payload = {
                    output_key: _json_compatible(list(response.get(input_key) or []))
                    for input_key, output_key in result_keys.items()
                }
                snapshot = normalize_external_findings(import_source, payload)
                snapshots.append(
                    _mark_live_snapshot(
                        snapshot,
                        source=source,
                        region=region,
                        account_id=account_id,
                        operation=operation,
                    )
                )
            except (AwsProviderError, ValueError) as exc:
                errors.append(
                    {
                        "source": source,
                        "operation": operation,
                        "reason": "aws_read_failed",
                        "detail": getattr(exc, "detail", None) or str(exc),
                    }
                )
    return snapshots, errors


def _normalized_sources(sources: Iterable[str]) -> List[str]:
    normalized = list(dict.fromkeys(str(source).strip().lower() for source in sources if source))
    unsupported = sorted(set(normalized) - set(SIGNAL_SOURCE_CHOICES))
    if unsupported:
        raise ValueError(
            f"Unsupported signal sources: {', '.join(unsupported)}. "
            f"Supported: {', '.join(SIGNAL_SOURCE_CHOICES)}"
        )
    return normalized


def _operation_parameters(operation: str) -> JSON:
    if operation == "securityhub.get_findings":
        return {
            "Filters": {
                "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
            }
        }
    return {}


def _mark_live_snapshot(
    snapshot: JSON,
    *,
    source: str,
    region: str,
    account_id: Optional[str],
    operation: str,
) -> JSON:
    result = deepcopy(snapshot)
    result["region"] = region
    result["account_id"] = account_id
    result["generated_at"] = utc_now_iso()
    for finding in result.get("findings") or []:
        evidence = dict(finding.get("evidence") or {})
        evidence.update(
            {
                "finding_source": source,
                "external_content_trust": "trusted_aws_api_signal",
                "requires_live_revalidation": False,
                "source_operation": operation,
                "live_validation": {
                    "status": "source_current",
                    "observed_at": result["generated_at"],
                    "reason": "The recommendation was read from its AWS source in this assessment.",
                },
            }
        )
        if account_id and not evidence.get("source_account_id"):
            evidence["source_account_id"] = account_id
        finding["evidence"] = evidence
        resource_ref = finding.get("resource_ref")
        if isinstance(resource_ref, dict):
            resource_ref.setdefault("region", region)
            if account_id:
                resource_ref.setdefault("account_id", account_id)
    summary = dict(result.get("summary") or {})
    summary.update(
        {
            "finding_source": source,
            "source_operation": operation,
            "external_snapshot": False,
            "live_source_read": True,
            "live_revalidation_required_before_write": True,
        }
    )
    result["summary"] = summary
    return result


def _json_compatible(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _json_compatible(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_compatible(item) for item in value]
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, Decimal):
        return float(value)
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)
