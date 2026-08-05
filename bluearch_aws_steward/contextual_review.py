from __future__ import annotations

import hashlib
import json
import re
from copy import deepcopy
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from bluearch_aws_steward.iac_context import (
    IacContextError,
    parse_iac_context,
    resource_ref_from_iac,
)
from bluearch_aws_steward.iac_review import evaluate_iac_context
from bluearch_aws_steward.knowledge_packs import (
    REVIEW_OPERATIONS,
    native_rule_waf_mappings,
    profile_for_service,
    question_definitions,
    waf_practice_index,
)
from bluearch_aws_steward.models import ResourceRef, ReviewIntent, utc_now_iso
from bluearch_aws_steward.providers.normalize import (
    normalize_cloudtrail_trail,
    normalize_ebs_volume,
    normalize_elastic_ip,
    normalize_lambda_function,
    normalize_log_group,
    normalize_rds_instance,
)
from bluearch_aws_steward.relationships import collect_live_relationships
from bluearch_aws_steward.scanner import AWS_SCAN_SERVICES

JSON = Dict[str, Any]
MAX_FOCUS_RESOURCES = 5
MAX_RELATIONSHIP_HOPS = 2
MAX_GRAPH_NODES = 25
MAX_CONTEXT_QUESTIONS = 5
MAX_READ_OPERATIONS = 50
AwsProviderFactory = Callable[[JSON], Any]
AssessmentRunner = Callable[..., JSON]


class ContextualReviewError(ValueError):
    """Raised for an invalid or unsafe contextual-review request."""


class ReadBudgetExceeded(ContextualReviewError):
    pass


def prepare_contextual_review(arguments: JSON) -> Tuple[JSON, Optional[JSON]]:
    prepared = dict(arguments)
    prompt = str(arguments.get("prompt") or "").strip()
    review_context = arguments.get("review_context") or {}
    if not isinstance(review_context, dict):
        raise ContextualReviewError("review_context must be an object.")
    review_context = deepcopy(review_context)

    operation = str(review_context.get("operation") or _operation_from_prompt(prompt) or "review")
    if operation not in REVIEW_OPERATIONS:
        raise ContextualReviewError(
            f"Unsupported review operation: {operation}. Supported: {', '.join(REVIEW_OPERATIONS)}"
        )
    hops = review_context.get("max_relationship_hops", arguments.get("max_relationship_hops", 1))
    if (
        isinstance(hops, bool)
        or not isinstance(hops, int)
        or not 0 <= hops <= MAX_RELATIONSHIP_HOPS
    ):
        raise ContextualReviewError(
            f"review_context.max_relationship_hops must be between 0 and {MAX_RELATIONSHIP_HOPS}."
        )

    answers = review_context.get("answers") or {}
    if not isinstance(answers, dict):
        raise ContextualReviewError("review_context.answers must be an object.")
    answers = deepcopy(answers)
    for question_id in (
        "environment",
        "criticality",
        "owner",
        "data_classification",
        "access_pattern",
        "retention",
        "recovery",
        "traffic",
        "growth",
        "consumers",
        "exposure",
        "compliance",
    ):
        if question_id in arguments:
            answers[question_id] = arguments[question_id]

    iac_config = review_context.get("iac") or {}
    if iac_config and not isinstance(iac_config, dict):
        raise ContextualReviewError("review_context.iac must be an object.")
    try:
        iac_context = parse_iac_context(iac_config)
    except IacContextError as exc:
        raise ContextualReviewError(str(exc)) from exc

    explicit_refs = review_context.get("resource_refs") or []
    if not isinstance(explicit_refs, list):
        raise ContextualReviewError("review_context.resource_refs must be an array.")
    if arguments.get("focus_resource"):
        selected_iac = next(
            (
                resource
                for resource in iac_context["resources"]
                if str(arguments["focus_resource"])
                in {
                    str(resource.get("address") or ""),
                    str(resource.get("resource_id") or ""),
                    str(resource.get("node_id") or ""),
                }
            ),
            None,
        )
        if selected_iac is not None:
            explicit_refs = [*explicit_refs, resource_ref_from_iac(selected_iac).to_dict()]
        else:
            explicit_refs = [
                *explicit_refs,
                {
                    "resource": arguments["focus_resource"],
                    "service": arguments.get("focus_service") or _single_service(arguments),
                },
            ]
    focus = [_normalize_resource_ref(value, arguments) for value in explicit_refs]
    focus_source = "explicit_resource_refs" if focus else None

    if not focus:
        changed = [resource for resource in iac_context["resources"] if resource.get("changed")]
        if len(changed) > MAX_FOCUS_RESOURCES:
            return prepared, _focus_selection_required(arguments, changed)
        if changed:
            focus = [resource_ref_from_iac(resource) for resource in changed]
            focus_source = "iac_changed_resources"

    if not focus:
        inferred = _focus_from_prompt(prompt, arguments)
        if inferred is not None:
            focus = [inferred]
            focus_source = "prompt_identifier"

    if len(focus) > MAX_FOCUS_RESOURCES:
        raise ContextualReviewError(f"At most {MAX_FOCUS_RESOURCES} focus resources are allowed.")
    if not focus:
        return prepared, _focus_required(arguments)

    unknown_services = sorted({resource.service for resource in focus} - set(AWS_SCAN_SERVICES))
    if unknown_services:
        raise ContextualReviewError(
            f"Unsupported contextual review scopes: {', '.join(unknown_services)}"
        )

    required_facts: List[str] = []
    for service in dict.fromkeys(resource.service for resource in focus):
        required_facts.extend(profile_for_service(service).get("required_facts") or [])
    required_facts = list(dict.fromkeys(required_facts))
    missing_facts = [
        fact
        for fact in required_facts
        if fact not in answers or answers.get(fact) in (None, "", "skipped")
    ]
    if missing_facts and not bool(answers.get("_continue_with_unknowns")):
        return prepared, _context_questions_required(
            arguments,
            review_context={
                **review_context,
                "operation": operation,
                "resource_refs": [resource.to_dict() for resource in focus],
                "answers": answers,
                "max_relationship_hops": hops,
            },
            question_ids=missing_facts[:MAX_CONTEXT_QUESTIONS],
        )

    for fact in missing_facts:
        answers[fact] = "unknown"
    objectives = _objectives_from_prompt(prompt) or ["all"]
    intent = ReviewIntent(
        operation=operation,
        focus=focus,
        objectives=objectives,
        answers=answers,
        max_relationship_hops=hops,
    )
    services = list(dict.fromkeys(resource.service for resource in focus))
    prepared.update(
        {
            "assessment_mode": "architectural_review",
            "review_context": {
                **review_context,
                "operation": operation,
                "resource_refs": [resource.to_dict() for resource in focus],
                "answers": answers,
                "max_relationship_hops": hops,
            },
            "objectives": objectives,
            "objective": objectives[0] if len(objectives) == 1 else "all",
            "services": services,
            "service": services[0] if len(services) == 1 else "all",
            "_review_intent": intent.to_dict(),
            "_focus_source": focus_source,
            "_iac_context": iac_context,
            "_assessment_intent": {
                "mode": "architectural_review",
                "objectives": objectives,
                "services": services,
                "result_preferences": deepcopy(arguments.get("result_preferences") or {}),
            },
        }
    )
    return prepared, None


def run_contextual_review(
    arguments: JSON,
    *,
    provider_factory: AwsProviderFactory,
    base_runner: AssessmentRunner,
) -> JSON:
    intent = dict(arguments.get("_review_intent") or {})
    focus = [_normalize_resource_ref(value, arguments) for value in intent.get("focus") or []]
    if not focus:
        raise ContextualReviewError("The contextual assessment has no resolved focus resource.")
    iac_context = deepcopy(arguments.get("_iac_context") or {})
    observed_at = utc_now_iso()
    live_focus = [resource for resource in focus if resource.provider not in {"iac", "design"}]
    provider = (
        provider_factory(arguments) if live_focus and arguments.get("scan_result") is None else None
    )
    budgeted_provider = (
        BudgetedAwsProvider(provider, MAX_READ_OPERATIONS, focus=live_focus) if provider else None
    )

    complete_opportunities: List[JSON] = []
    complete_findings: List[JSON] = []
    service_errors: List[JSON] = []
    capability_errors: List[JSON] = []
    rules_skipped: List[JSON] = []
    scanned_services: List[str] = []
    scan_summaries: List[JSON] = []
    partial_callback = arguments.get("_partial_callback")

    services = list(dict.fromkeys(resource.service for resource in focus))
    for service in services:
        service_focus = [resource for resource in focus if resource.service == service]
        service_live_focus = [
            resource for resource in service_focus if resource.provider not in {"iac", "design"}
        ]
        if not service_live_focus and arguments.get("scan_result") is None:
            continue
        profile = profile_for_service(service)
        scan_arguments = {
            **arguments,
            "service": service,
            "services": [service],
            "objective": "all",
            "objectives": ["all"],
            "rule_filter": ",".join(profile["native_rules"]),
            "max_returned_resources": 200,
            "max_returned_findings": 200,
            "_assessment_intent": {
                "mode": "architectural_review",
                "objectives": ["all"],
                "services": [service],
                "result_preferences": {},
            },
        }
        scan_arguments.pop("_partial_callback", None)
        if budgeted_provider is not None:
            scan_arguments["_provider_instance"] = budgeted_provider
        if service == "s3" and len(service_live_focus) == 1:
            scan_arguments["bucket_prefix"] = service_live_focus[0].resource_id
        try:
            service_result = base_runner(
                scan_arguments,
                provider_factory=lambda _: budgeted_provider,
            )
        except ReadBudgetExceeded as exc:
            capability_errors.append(
                {
                    "service": service,
                    "reason": "contextual_read_budget_exhausted",
                    "detail": str(exc),
                }
            )
            break
        scanned_services.append(service)
        scan_summaries.append(deepcopy(service_result.get("summary") or {}))
        service_errors.extend(service_result.get("service_errors") or [])
        capability_errors.extend(service_result.get("capability_errors") or [])
        rules_skipped.extend(service_result.get("rules_skipped") or [])
        selected = _filter_opportunities_for_focus(
            service_result.get("complete_opportunities")
            or service_result.get("opportunities")
            or [],
            service_focus,
        )
        selected_ids = {
            str(item.get("opportunity_id") or item.get("finding_id")) for item in selected
        }
        complete_opportunities.extend(selected)
        complete_findings.extend(
            finding
            for finding in service_result.get("complete_findings") or []
            if str(finding.get("finding_id")) in selected_ids
        )
        if callable(partial_callback):
            partial_callback(
                _partial_contextual_result(
                    arguments,
                    focus,
                    complete_opportunities,
                    scanned_services,
                    services,
                    observed_at,
                )
            )

    iac_review = evaluate_iac_context(iac_context, focus)
    complete_opportunities.extend(iac_review["findings"])

    graph = _build_architecture_graph(
        focus,
        iac_context,
        budgeted_provider,
        complete_opportunities,
        max_hops=int(intent.get("max_relationship_hops") or 1),
    )
    practice_results = _evaluate_practices(
        focus=focus,
        opportunities=complete_opportunities,
        answers=intent.get("answers") or {},
        scan_summaries=scan_summaries,
        iac_context=iac_context,
        iac_review=iac_review,
        capability_errors=capability_errors,
        operation=str(intent.get("operation") or "review"),
    )
    recommendations = _contextual_recommendations(
        complete_opportunities,
        focus,
        practice_results,
        intent,
    )
    requested_objectives = set(intent.get("objectives") or []) - {"all"}
    cross_pillar_concerns = [
        {
            "opportunity_id": item.get("opportunity_id"),
            "rule": item.get("rule"),
            "resource": item.get("resource"),
            "severity": item.get("severity"),
            "matched_objectives": item.get("matched_objectives") or [],
            "reason": "Confirmed high-impact concern preserved outside the requested objective.",
        }
        for item in recommendations
        if requested_objectives
        and str(item.get("severity") or "").casefold() in {"critical", "high"}
        and not requested_objectives.intersection(item.get("matched_objectives") or [])
    ]
    read_ledger = budgeted_provider.ledger if budgeted_provider is not None else []
    aws_read_count = sum(
        1 for item in read_ledger if item.get("aws_call", True) and not item.get("cache_hit")
    )
    budget_limited = bool(budgeted_provider and budgeted_provider.exhausted) or any(
        item.get("reason") == "contextual_read_budget_exhausted" for item in capability_errors
    )
    focus_services = set(services)
    excluded_services = sorted(set(AWS_SCAN_SERVICES) - focus_services)
    summary: JSON = {
        "assessment_mode": "architectural_review",
        "focus_resources": len(focus),
        "architecture_nodes": len(graph["nodes"]),
        "architecture_edges": len(graph["edges"]),
        "findings": len(recommendations),
        "opportunities": len(recommendations),
        "complete_findings": len(recommendations),
        "native_findings_observed": len(complete_opportunities),
        "contextually_excluded_findings": len(complete_opportunities) - len(recommendations),
        "resources": len({item.get("resource") for item in recommendations}),
        "resources_scanned": sum(
            int(item.get("resources_scanned") or 0) for item in scan_summaries
        ),
        "rules_evaluated": sum(int(item.get("rules_evaluated") or 0) for item in scan_summaries),
        "scan_errors": sum(int(item.get("scan_errors") or 0) for item in scan_summaries),
        "services_requested": services,
        "services_scanned": scanned_services,
        "full_account_scan": False,
        "read_operations": aws_read_count,
        "read_budget": MAX_READ_OPERATIONS,
        "read_budget_exhausted": budget_limited,
        "well_architected_practices": len(practice_results),
        "practice_statuses": _status_counts(practice_results),
        "detection_coverage": {
            "scope": "contextual_knowledge_pack",
            "services_requested": services,
            "automated_rules_evaluated": sum(
                int(item.get("rules_evaluated") or 0) for item in scan_summaries
            ),
            "complete_catalog_evaluation": False,
            "result_interpretation": (
                "Only practices selected by the contextual knowledge packs and native rules for the "
                "focus neighborhood were evaluated. Unknown and manual practices are not passing."
            ),
        },
    }
    summary["resources_scanned"] += len(
        {item.get("resource") for item in iac_review["controls"] if item.get("resource")}
    )
    return {
        "schema_version": "assessment-0.2",
        "prompt": arguments.get("prompt"),
        "assessment_mode": "architectural_review",
        "operation": intent.get("operation"),
        "objective": arguments.get("objective") or "all",
        "service": services[0] if len(services) == 1 else services,
        "services": services,
        "provider": arguments.get("provider") or "aws-sdk",
        "profile": arguments.get("profile"),
        "region": arguments.get("region"),
        "account_id": arguments.get("_account_id"),
        "observed_at": observed_at,
        "focus": {
            "resolution_source": arguments.get("_focus_source"),
            "resources": [resource.to_dict() for resource in focus],
            "selected_knowledge": [
                _public_profile(profile_for_service(service)) for service in services
            ],
        },
        "architecture_neighborhood": graph,
        "context_questions": {
            "answers": deepcopy(intent.get("answers") or {}),
            "unknown_facts": sorted(
                key
                for key, value in (intent.get("answers") or {}).items()
                if value in (None, "", "unknown", "skipped")
            ),
            "ephemeral": True,
            "retention_seconds": 900,
        },
        "well_architected_review": _group_practices_by_pillar(practice_results),
        "recommendations": recommendations,
        "hidden_relevant_concerns": cross_pillar_concerns,
        "evidence_ledger": {
            "operations": read_ledger,
            "operation_count": aws_read_count,
            "operation_budget": MAX_READ_OPERATIONS,
            "budget_exhausted": budget_limited,
            "deduplicated_reads": budgeted_provider.cache_hits if budgeted_provider else 0,
            "write_operations": 0,
            "source_reads": [
                {
                    "operation": "iac.read_file",
                    "path": path,
                    "source": "declared_workspace",
                    "status": "completed",
                }
                for path in iac_context.get("source_files") or []
            ],
            "complete_provenance": not budget_limited and not graph.get("relationship_errors"),
        },
        "excluded_scope": {
            "services": excluded_services,
            "reason": "No observed typed relationship required these service collectors.",
            "full_account_scan_not_performed": True,
        },
        "limitations": _review_limitations(
            graph,
            iac_context,
            budget_limited,
            read_ledger=read_ledger,
        ),
        "summary": summary,
        "service_errors": service_errors,
        "capability_errors": capability_errors,
        "rules_skipped": rules_skipped,
        "rules": sorted({str(item.get("rule")) for item in recommendations}),
        "resources": sorted(
            {str(item.get("resource")) for item in recommendations if item.get("resource")}
        ),
        "opportunities": recommendations[: int(arguments.get("max_returned_findings") or 20)],
        "complete_opportunities": recommendations,
        "complete_findings": recommendations,
        "solution_cards": recommendations[: int(arguments.get("max_returned_findings") or 20)],
        "grouped_solutions": _group_recommendations(recommendations),
        "mcp": {
            "read_only": True,
            "write_actions_applied": False,
            "persistent_inventory": False,
            "hosted_model_used": False,
        },
        "response_contract": {
            "show_architecture_context": True,
            "show_unknowns": True,
            "show_excluded_scope": True,
            "show_hidden_cross_pillar_concerns": True,
            "pdf_offer_on_terminal_results": True,
            "aws_writes_applied": False,
        },
        "answer_guidance": [
            "Lead with the focus resource, operation, and architecture neighborhood.",
            "Separate confirmed risks, aligned practices, required input, and unknown evidence.",
            "Include high-impact cross-pillar concerns even when another objective was requested.",
            "Do not describe an unobserved relationship as absent.",
            "State that this focused review did not perform a full-account scan or apply writes.",
        ],
        "iac_context": {
            key: deepcopy(value)
            for key, value in iac_context.items()
            if key not in {"workspace_root"}
        },
    }


class BudgetedAwsProvider:
    """Deduplicate contextual reads and stop before the logical read budget is exceeded."""

    _HIGH_LEVEL_METHODS = {
        "list_buckets",
        "list_log_groups",
        "list_ebs_volumes",
        "list_elastic_ips",
        "get_iam_account_summary",
        "list_cloudtrail_trails",
        "list_rds_instances",
        "list_lambda_functions",
        "get_public_access_block",
        "get_bucket_policy",
        "get_bucket_encryption_rules",
        "get_bucket_lifecycle_rules",
        "get_bucket_versioning_status",
    }

    def __init__(
        self,
        provider: Any,
        limit: int,
        *,
        focus: Optional[List[ResourceRef]] = None,
    ) -> None:
        self._provider = provider
        self._limit = limit
        self._focus = list(focus or [])
        self._cache: Dict[str, Any] = {}
        self.ledger: List[JSON] = []
        self.cache_hits = 0
        self.exhausted = False

    def capabilities(self) -> Any:
        return self._provider.capabilities()

    def list_buckets(self) -> List[str]:
        # S3 has no targeted list-buckets operation. The subsequent bucket-control
        # reads validate access to the exact requested bucket without inventorying
        # unrelated buckets in the account.
        return sorted(resource.resource_id for resource in self._focus_for_service("s3"))

    def list_log_groups(self) -> List[JSON]:
        response = self.read("logs.describe_log_groups")
        groups = [normalize_log_group(item) for item in response.get("logGroups") or []]
        return sorted(groups, key=lambda item: str(item.get("name") or ""))

    def list_ebs_volumes(self) -> List[JSON]:
        response = self.read("ec2.describe_volumes")
        volumes = [normalize_ebs_volume(item) for item in response.get("Volumes") or []]
        return sorted(volumes, key=lambda item: str(item.get("volume_id") or ""))

    def list_elastic_ips(self) -> List[JSON]:
        response = self.read("ec2.describe_addresses")
        addresses = [normalize_elastic_ip(item) for item in response.get("Addresses") or []]
        return sorted(addresses, key=lambda item: str(item.get("allocation_id") or ""))

    def get_iam_account_summary(self) -> JSON:
        response = self.read("iam.get_account_summary")
        return dict(response.get("SummaryMap") or {})

    def list_cloudtrail_trails(self) -> List[JSON]:
        response = self.read("cloudtrail.describe_trails", includeShadowTrails=False)
        trails: List[JSON] = []
        for trail in response.get("trailList") or []:
            name = trail.get("TrailARN") or trail.get("Name")
            status = self.read("cloudtrail.get_trail_status", Name=name) if name else {}
            trails.append(normalize_cloudtrail_trail(trail, status))
        return sorted(trails, key=lambda item: str(item.get("name") or ""))

    def list_rds_instances(self) -> List[JSON]:
        response = self.read("rds.describe_db_instances")
        instances = [normalize_rds_instance(item) for item in response.get("DBInstances") or []]
        return sorted(instances, key=lambda item: str(item.get("identifier") or ""))

    def list_lambda_functions(self) -> List[JSON]:
        focus = self._focus_for_service("lambda")
        if not focus:
            response = self.read("lambda.list_functions")
            functions = response.get("Functions") or []
        else:
            functions = [
                self.read("lambda.get_function_configuration", FunctionName=resource.resource_id)
                for resource in focus
            ]
        normalized = [normalize_lambda_function(item) for item in functions if item]
        return sorted(normalized, key=lambda item: str(item.get("name") or ""))

    def get_public_access_block(self, bucket: str) -> JSON:
        return dict(
            self._invoke("get_public_access_block", self._provider.get_public_access_block, bucket)
        )

    def get_bucket_policy(self, bucket: str) -> Optional[JSON]:
        result = self._invoke("get_bucket_policy", self._provider.get_bucket_policy, bucket)
        return dict(result) if isinstance(result, dict) else None

    def get_bucket_encryption_rules(self, bucket: str) -> List[JSON]:
        return list(
            self._invoke(
                "get_bucket_encryption_rules",
                self._provider.get_bucket_encryption_rules,
                bucket,
            )
        )

    def get_bucket_lifecycle_rules(self, bucket: str) -> List[JSON]:
        return list(
            self._invoke(
                "get_bucket_lifecycle_rules",
                self._provider.get_bucket_lifecycle_rules,
                bucket,
            )
        )

    def get_bucket_versioning_status(self, bucket: str) -> Optional[str]:
        result = self._invoke(
            "get_bucket_versioning_status",
            self._provider.get_bucket_versioning_status,
            bucket,
        )
        return str(result) if result is not None else None

    def read(self, operation: str, **parameters: Any) -> JSON:
        resolved = _focused_discovery_response(operation, parameters, self._focus)
        if resolved is not None:
            self.ledger.append(
                {
                    "operation": operation,
                    "parameters": _redacted_parameters((), parameters),
                    "observed_at": utc_now_iso(),
                    "cache_hit": False,
                    "status": "resolved_from_explicit_focus",
                    "aws_call": False,
                    "focus_mode": "explicit_focus",
                }
            )
            return deepcopy(resolved)
        focused_parameters, focus_mode = _focused_read_parameters(
            operation,
            parameters,
            self._focus,
        )
        result = self._invoke(
            operation,
            self._provider.read,
            operation,
            **focused_parameters,
        )
        if self.ledger:
            self.ledger[-1]["focus_mode"] = focus_mode
        return _filter_focused_response(operation, result, self._focus)

    def caller_identity(self) -> JSON:
        return self._invoke("sts.get_caller_identity", self._provider.caller_identity)

    def operations_executed(self) -> List[str]:
        return [str(item["operation"]) for item in self.ledger if not item.get("cache_hit")]

    def _focus_for_service(self, service: str) -> List[ResourceRef]:
        return [resource for resource in self._focus if resource.service == service]

    def __getattr__(self, name: str) -> Any:
        target = getattr(self._provider, name)
        if name not in self._HIGH_LEVEL_METHODS or not callable(target):
            return target

        def bounded(*args: Any, **kwargs: Any) -> Any:
            return self._invoke(name, target, *args, **kwargs)

        return bounded

    def _invoke(self, operation: str, target: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        cache_key = _operation_cache_key(operation, args, kwargs)
        if cache_key in self._cache:
            self.cache_hits += 1
            self.ledger.append(
                {
                    "operation": operation,
                    "parameters": _redacted_parameters(args, kwargs),
                    "observed_at": utc_now_iso(),
                    "cache_hit": True,
                    "status": "cached",
                    "aws_call": True,
                }
            )
            return deepcopy(self._cache[cache_key])
        executed = sum(
            1 for item in self.ledger if item.get("aws_call", True) and not item.get("cache_hit")
        )
        if executed >= self._limit:
            self.exhausted = True
            raise ReadBudgetExceeded(
                f"The contextual review reached its {self._limit}-operation read budget."
            )
        observed_at = utc_now_iso()
        try:
            result = target(*args, **kwargs)
        except Exception:
            self.ledger.append(
                {
                    "operation": operation,
                    "parameters": _redacted_parameters(args, kwargs),
                    "observed_at": observed_at,
                    "cache_hit": False,
                    "status": "error",
                    "aws_call": True,
                }
            )
            raise
        self._cache[cache_key] = deepcopy(result)
        self.ledger.append(
            {
                "operation": operation,
                "parameters": _redacted_parameters(args, kwargs),
                "observed_at": observed_at,
                "cache_hit": False,
                "status": "completed",
                "aws_call": True,
            }
        )
        return result


def _focused_read_parameters(
    operation: str,
    parameters: JSON,
    focus: List[ResourceRef],
) -> Tuple[JSON, str]:
    selected = [resource for resource in focus if _operation_service(operation) == resource.service]
    if not selected:
        return dict(parameters), "not_applicable"
    values = [resource.resource_id for resource in selected]
    arns = [resource.arn for resource in selected if resource.arn]
    prepared = dict(parameters)
    if operation == "logs.describe_log_groups" and len(values) == 1:
        prepared.setdefault("logGroupNamePrefix", values[0])
    elif operation == "cloudtrail.describe_trails":
        prepared.setdefault("trailNameList", values)
    elif operation == "rds.describe_db_instances" and len(values) == 1:
        prepared.setdefault("DBInstanceIdentifier", values[0])
    elif operation == "efs.describe_file_systems" and len(values) == 1:
        prepared.setdefault("FileSystemId", values[0])
    elif operation == "ec2.describe_instances":
        instance_ids = [value for value in values if value.startswith("i-")]
        if instance_ids:
            prepared.setdefault("InstanceIds", instance_ids)
    elif operation == "ec2.describe_volumes":
        volume_ids = [value for value in values if value.startswith("vol-")]
        if volume_ids:
            prepared.setdefault("VolumeIds", volume_ids)
    elif operation == "ec2.describe_addresses":
        allocation_ids = [value for value in values if value.startswith("eipalloc-")]
        public_ips = [value for value in values if re.fullmatch(r"[0-9a-fA-F:.]+", value)]
        if allocation_ids:
            prepared.setdefault("AllocationIds", allocation_ids)
        elif public_ips:
            prepared.setdefault("PublicIps", public_ips)
    elif operation == "ec2.describe_security_groups":
        group_ids = [value for value in values if value.startswith("sg-")]
        if group_ids:
            prepared.setdefault("GroupIds", group_ids)
    elif operation == "ec2.describe_vpcs":
        vpc_ids = [value for value in values if value.startswith("vpc-")]
        if vpc_ids:
            prepared.setdefault("VpcIds", vpc_ids)
    elif operation == "ec2.describe_snapshots":
        snapshot_ids = [value for value in values if value.startswith("snap-")]
        if snapshot_ids:
            prepared.setdefault("SnapshotIds", snapshot_ids)
    elif operation == "ec2.describe_images":
        image_ids = [value for value in values if value.startswith("ami-")]
        if image_ids:
            prepared.setdefault("ImageIds", image_ids)
    elif operation == "elbv2.describe_load_balancers":
        if arns:
            prepared.setdefault("LoadBalancerArns", arns)
        elif values:
            prepared.setdefault("Names", values)
    elif operation == "secretsmanager.list_secrets":
        prepared.setdefault("Filters", [{"Key": "name", "Values": values}])
    elif operation == "sqs.list_queues" and len(values) == 1:
        prepared.setdefault("QueueNamePrefix", values[0])
    targeted = prepared != parameters
    caller_targeted = _operation_already_targeted(operation, prepared)
    return prepared, "targeted_api" if targeted or caller_targeted else "focused_response_filter"


def _focused_discovery_response(
    operation: str,
    parameters: JSON,
    focus: List[ResourceRef],
) -> Optional[JSON]:
    service = _operation_service(operation)
    selected = [resource for resource in focus if resource.service == service]
    if not selected:
        return None
    if operation == "dynamodb.list_tables":
        return {"TableNames": [resource.resource_id for resource in selected]}
    if operation == "eks.list_clusters":
        return {"clusters": [resource.resource_id for resource in selected]}
    if operation == "kms.list_keys":
        return {
            "Keys": [
                {
                    "KeyId": resource.resource_id,
                    **({"KeyArn": resource.arn} if resource.arn else {}),
                }
                for resource in selected
            ]
        }
    if operation == "sns.list_topics":
        arns = [arn for resource in selected if (arn := _resource_arn(resource))]
        return {"Topics": [{"TopicArn": arn} for arn in arns]} if arns else None
    if operation == "apigateway.get_rest_apis":
        return {
            "items": [
                {
                    "id": resource.resource_id,
                    "name": resource.display_name or resource.resource_id,
                }
                for resource in selected
            ]
        }
    return None


def _resource_arn(resource: ResourceRef) -> Optional[str]:
    if resource.arn:
        return resource.arn
    if not resource.region or not resource.account_id:
        return None
    if resource.service == "sns":
        return f"arn:aws:sns:{resource.region}:{resource.account_id}:{resource.resource_id}"
    return None


def _operation_already_targeted(operation: str, parameters: JSON) -> bool:
    identifiers = {
        "s3": ("Bucket",),
        "cloudtrail": ("Name", "trailNameList"),
        "logs": ("logGroupNamePrefix", "logGroupIdentifiers"),
        "ec2": (
            "InstanceIds",
            "VolumeIds",
            "AllocationIds",
            "PublicIps",
            "GroupIds",
            "VpcIds",
            "SnapshotIds",
            "ImageIds",
        ),
        "lambda": ("FunctionName", "Resource"),
        "rds": ("DBInstanceIdentifier",),
        "efs": ("FileSystemId",),
        "eks": ("name", "clusterName"),
        "kms": ("KeyId",),
        "secretsmanager": ("SecretId", "Filters"),
        "sns": ("TopicArn", "ResourceArn"),
        "sqs": ("QueueUrl", "QueueNamePrefix"),
        "apigateway": ("restApiId", "resourceArn"),
        "elbv2": ("LoadBalancerArns", "Names", "ResourceArns"),
        "dynamodb": ("TableName", "ResourceArn"),
        "ecs": ("cluster", "services", "taskDefinition"),
        "config": ("resourceType", "resourceId"),
    }
    return any(
        parameters.get(key) not in (None, "", [], {})
        for key in identifiers.get(operation.split(".", 1)[0], ())
    )


def _filter_focused_response(operation: str, response: JSON, focus: List[ResourceRef]) -> JSON:
    service = _operation_service(operation)
    tokens = {
        value
        for resource in focus
        if resource.service == service
        for value in (resource.resource_id, resource.arn, resource.display_name)
        if value
    }
    if not tokens or not isinstance(response, dict):
        return response
    result_keys = {
        "logs.describe_log_groups": ("logGroups",),
        "cloudtrail.describe_trails": ("trailList",),
        "ec2.describe_security_groups": ("SecurityGroups",),
        "ec2.describe_network_interfaces": ("NetworkInterfaces",),
        "ec2.describe_volumes": ("Volumes",),
        "ec2.describe_addresses": ("Addresses",),
        "ec2.describe_vpcs": ("Vpcs",),
        "ec2.describe_flow_logs": ("FlowLogs",),
        "ec2.describe_snapshots": ("Snapshots",),
        "ec2.describe_images": ("Images",),
        "ec2.describe_instances": ("Reservations",),
        "efs.describe_file_systems": ("FileSystems",),
        "lambda.list_functions": ("Functions",),
        "rds.describe_db_instances": ("DBInstances",),
        "dynamodb.list_tables": ("TableNames",),
        "ecs.list_task_definitions": ("taskDefinitionArns",),
        "ecs.list_clusters": ("clusterArns",),
        "ecs.list_services": ("serviceArns",),
        "eks.list_clusters": ("clusters",),
        "elbv2.describe_load_balancers": ("LoadBalancers",),
        "kms.list_keys": ("Keys",),
        "secretsmanager.list_secrets": ("SecretList",),
        "sns.list_topics": ("Topics",),
        "sqs.list_queues": ("QueueUrls",),
        "apigateway.get_rest_apis": ("items",),
    }.get(operation, ())
    if not result_keys:
        return response
    filtered = deepcopy(response)
    for key in result_keys:
        values = filtered.get(key)
        if isinstance(values, list):
            filtered[key] = [
                value
                for value in values
                if any(token in json.dumps(value, sort_keys=True, default=str) for token in tokens)
            ]
    return filtered


def _operation_service(operation: str) -> str:
    prefix = operation.split(".", 1)[0]
    return {
        "logs": "cloudwatch",
        "elbv2": "alb",
        "apigateway": "api-gateway",
        "secretsmanager": "secrets-manager",  # pragma: allowlist secret
    }.get(prefix, prefix)


def _normalize_resource_ref(value: Any, arguments: JSON) -> ResourceRef:
    if isinstance(value, ResourceRef):
        return value
    if isinstance(value, str):
        value = {"resource": value}
    if not isinstance(value, dict):
        raise ContextualReviewError("Each review_context.resource_refs entry must be an object.")
    raw_resource = str(
        value.get("resource")
        or value.get("arn")
        or value.get("resource_id")
        or value.get("id")
        or ""
    ).strip()
    if not raw_resource:
        raise ContextualReviewError(
            "Each focus resource requires resource_id, ARN, or resource URI."
        )
    service = str(value.get("service") or _service_from_resource(raw_resource) or "").strip()
    if not service:
        raise ContextualReviewError(
            f"Unable to determine the AWS service for focus resource {raw_resource!r}."
        )
    service = _normalize_service(service)
    resource_id = str(value.get("resource_id") or _resource_id(raw_resource)).strip()
    resource_type = str(value.get("resource_type") or _default_resource_type(service, raw_resource))
    arn = str(value.get("arn") or (raw_resource if raw_resource.startswith("arn:") else "")) or None
    return ResourceRef(
        provider=str(value.get("provider") or ("aws" if arn or raw_resource else "design")),
        service=service,
        resource_type=resource_type,
        resource_id=resource_id,
        region=str(value.get("region") or arguments.get("region") or "") or None,
        account_id=str(value.get("account_id") or arguments.get("_account_id") or "") or None,
        arn=arn,
        display_name=str(value.get("display_name") or resource_id),
    )


def _focus_from_prompt(prompt: str, arguments: JSON) -> Optional[ResourceRef]:
    arn_match = re.search(r"\barn:aws(?:-[a-z]+)?:[A-Za-z0-9-]+:[^\s,;]+", prompt)
    if arn_match:
        return _normalize_resource_ref(arn_match.group(0).rstrip(".)]"), arguments)
    uri_match = re.search(
        r"\b(?:s3|ebs|ec2|rds|lambda|efs|eks|ecs|kms|sns|sqs|alb|api-gateway)://[^\s,;]+",
        prompt,
        re.IGNORECASE,
    )
    if uri_match:
        return _normalize_resource_ref(uri_match.group(0).rstrip(".)]"), arguments)
    service = _single_service(arguments) or _service_from_prompt(prompt)
    if not service:
        return None
    patterns = {
        "s3": r"\b(?:s3\s+)?bucket\s+(?:named\s+)?[`'\"]?([a-z0-9][a-z0-9.-]{1,62})",
        "lambda": r"\b(?:lambda\s+)?function\s+(?:named\s+)?[`'\"]?([A-Za-z0-9-_]+)",
        "rds": r"\b(?:rds\s+)?(?:database|instance)\s+(?:named\s+)?[`'\"]?([A-Za-z0-9-]+)",
        "eks": r"\b(?:eks\s+)?cluster\s+(?:named\s+)?[`'\"]?([A-Za-z0-9-_]+)",
        "dynamodb": r"\b(?:dynamodb\s+)?table\s+(?:named\s+)?[`'\"]?([A-Za-z0-9_.-]+)",
        "sqs": r"\b(?:sqs\s+)?queue\s+(?:named\s+)?[`'\"]?([A-Za-z0-9_-]+)",
        "sns": r"\b(?:sns\s+)?topic\s+(?:named\s+)?[`'\"]?([A-Za-z0-9_-]+)",
        "ec2": r"\b(?:ec2\s+)?instance\s+(?:named\s+)?[`'\"]?(i-[0-9a-f]+|[A-Za-z0-9._-]+)",
        "efs": r"\b(?:efs\s+)?file\s*system\s+(?:named\s+)?[`'\"]?(fs-[0-9a-f]+|[A-Za-z0-9._-]+)",
        "kms": r"\b(?:kms\s+)?key\s+(?:named\s+|alias\s+)?[`'\"]?(alias/[A-Za-z0-9/_-]+|[A-Za-z0-9-]+)",
        "ecs": r"\b(?:ecs\s+)?(?:service|task\s+definition|cluster)\s+(?:named\s+)?[`'\"]?([A-Za-z0-9._-]+)",
        "alb": r"\b(?:application\s+|alb\s+)?load\s*balancer\s+(?:named\s+)?[`'\"]?([A-Za-z0-9._-]+)",
        "api-gateway": r"\b(?:rest\s+|http\s+)?api\s+(?:named\s+)?[`'\"]?([A-Za-z0-9._-]+)",
        "cloudtrail": r"\b(?:cloudtrail\s+)?trail\s+(?:named\s+)?[`'\"]?([A-Za-z0-9._-]+)",
        "cloudwatch": r"\blog\s*group\s+(?:named\s+)?[`'\"]?([A-Za-z0-9._/-]+)",
        "iam": r"\b(?:iam\s+)?(?:role|user|policy|group)\s+(?:named\s+)?[`'\"]?([A-Za-z0-9._+=,@-]+)",
        "secrets-manager": r"\bsecret\s+(?:named\s+)?[`'\"]?([A-Za-z0-9._/+=@-]+)",
    }
    match = re.search(patterns.get(service, r"$^"), prompt, re.IGNORECASE)
    if not match:
        return None
    return _normalize_resource_ref({"resource_id": match.group(1), "service": service}, arguments)


def _focus_required(arguments: JSON) -> JSON:
    return {
        "status": "input_required",
        "ready": False,
        "reason": "architectural_review_focus_required",
        "message": "Which resource or proposed AWS change should Steward review?",
        "agent_instruction": (
            "Do not guess among resources. Ask for an exact ARN, resource identifier, or explicit IaC "
            "path. Offer a full assessment only as a separate explicit choice."
        ),
        "questions": [
            {
                "id": "focus_resource",
                "prompt": "Enter an exact ARN or resource identifier.",
                "response_type": "text",
            },
            {
                "id": "focus_service",
                "prompt": "Select the resource service.",
                "response_type": "single_select",
                "options": [
                    {
                        "value": service,
                        "label": service,
                        "description": f"Review one {service} resource.",
                    }
                    for service in AWS_SCAN_SERVICES
                ],
            },
        ],
        "possible_responses": [
            {
                "id": "select_resource",
                "label": "Review one existing resource",
                "user_response": "I will provide the exact resource identifier and service.",
            },
            {
                "id": "review_iac",
                "label": "Review a proposed IaC change",
                "user_response": "I will provide an explicit workspace root and IaC path.",
            },
            {
                "id": "full_assessment",
                "label": "Run an explicit full assessment",
                "user_response": "Run the complete supported account assessment instead.",
                "arguments": {
                    "assessment_mode": "full_report",
                    "objectives": ["all"],
                    "services": ["all"],
                },
            },
        ],
        "input_request": {
            "mode": "form",
            "message": "Select one AWS resource for this contextual review.",
            "requestedSchema": {
                "type": "object",
                "properties": {
                    "focus_resource": {"type": "string", "title": "Resource ARN or identifier"},
                    "focus_service": {
                        "type": "string",
                        "title": "AWS service",
                        "enum": list(AWS_SCAN_SERVICES),
                    },
                },
                "required": ["focus_resource", "focus_service"],
            },
        },
        "resume": {
            "tool": "bluearch_assess",
            "arguments": _public_resume_arguments(arguments),
            "merge_user_input": ["focus_resource", "focus_service"],
        },
        "security": {"credentials_requested": False, "aws_calls": False},
    }


def _focus_selection_required(arguments: JSON, resources: List[JSON]) -> JSON:
    options = [
        {
            "value": str(resource["address"]),
            "label": str(resource.get("display_name") or resource["address"]),
            "description": f"{resource['service']} from {resource['source_path']}",
        }
        for resource in resources[:25]
    ]
    return {
        "status": "input_required",
        "ready": False,
        "reason": "iac_focus_selection_required",
        "message": "The IaC change contains more than five resources. Select one exact focus resource.",
        "questions": [
            {
                "id": "focus_resource",
                "prompt": "Which changed IaC resource should Steward review first?",
                "response_type": "single_select",
                "options": options,
            }
        ],
        "possible_responses": [
            {
                "id": f"iac_focus_{index}",
                "label": option["label"],
                "user_response": f"Review {option['value']}.",
                "arguments": {"focus_resource": option["value"]},
            }
            for index, option in enumerate(options)
        ],
        "input_request": {
            "mode": "form",
            "message": "Select one changed IaC resource.",
            "requestedSchema": {
                "type": "object",
                "properties": {
                    "focus_resource": {
                        "type": "string",
                        "enum": [item["value"] for item in options],
                    }
                },
                "required": ["focus_resource"],
            },
        },
        "resume": {
            "tool": "bluearch_assess",
            "arguments": _public_resume_arguments(arguments),
            "merge_user_input": ["focus_resource"],
        },
        "security": {"credentials_requested": False, "aws_calls": False},
    }


def _context_questions_required(
    arguments: JSON,
    *,
    review_context: JSON,
    question_ids: List[str],
) -> JSON:
    definitions = question_definitions(question_ids)
    properties = {
        question["id"]: {
            "type": "string",
            "title": question["prompt"],
            "description": question["description"],
            "enum": question["options"],
        }
        for question in definitions
    }
    resume_arguments = _public_resume_arguments(arguments)
    resume_arguments["review_context"] = review_context
    return {
        "status": "input_required",
        "ready": False,
        "reason": "architectural_review_context_required",
        "message": "Steward needs a few facts to determine which architecture practices apply.",
        "agent_instruction": (
            "Ask no more than these five contextual questions. Do not infer answers. The user may "
            "select unknown and the review must preserve that uncertainty."
        ),
        "questions": [
            {
                "id": question["id"],
                "prompt": question["prompt"],
                "description": question["description"],
                "response_type": "single_select",
                "options": [
                    {
                        "value": option,
                        "label": option.replace("_", " ").title(),
                        "description": question["description"],
                    }
                    for option in question["options"]
                ],
            }
            for question in definitions
        ],
        "possible_responses": [
            {
                "id": "continue_with_unknowns",
                "label": "Continue with unknowns",
                "user_response": "Continue without these answers and mark them unknown.",
                "arguments": {question_id: "unknown" for question_id in question_ids},
            }
        ],
        "input_request": {
            "mode": "form",
            "message": "Provide context or select Unknown for each item.",
            "requestedSchema": {
                "type": "object",
                "properties": properties,
                "required": question_ids,
            },
        },
        "resume": {
            "tool": "bluearch_assess",
            "arguments": resume_arguments,
            "merge_user_input": question_ids,
        },
        "security": {"credentials_requested": False, "aws_calls": False},
    }


def _build_architecture_graph(
    focus: List[ResourceRef],
    iac_context: JSON,
    provider: Optional[BudgetedAwsProvider],
    opportunities: List[JSON],
    *,
    max_hops: int,
) -> JSON:
    nodes: Dict[str, JSON] = {}
    edges: List[JSON] = []
    observed_at = utc_now_iso()
    for resource in focus:
        node_id = _resource_node_id(resource)
        nodes[node_id] = {
            "node_id": node_id,
            "kind": "focus",
            "resource_ref": resource.to_dict(),
            "source": "request",
            "confidence": "high",
            "observed_at": observed_at,
            "facts": {},
        }

    iac_resources = {str(item["node_id"]): item for item in iac_context.get("resources") or []}
    iac_edges = list(iac_context.get("relationships") or [])
    focus_iac_nodes = {
        node_id
        for node_id, item in iac_resources.items()
        if any(_iac_matches_focus(item, resource) for resource in focus)
    }
    iac_frontier = set(focus_iac_nodes)
    included_iac = set(focus_iac_nodes)
    for _ in range(max_hops):
        iac_next_nodes: set[str] = set()
        for edge in iac_edges:
            iac_source_id = str(edge.get("source_node_id"))
            iac_target_id = str(edge.get("target_node_id"))
            if iac_source_id in iac_frontier:
                iac_next_nodes.add(iac_target_id)
            if iac_target_id in iac_frontier:
                iac_next_nodes.add(iac_source_id)
        iac_next_nodes -= included_iac
        included_iac.update(iac_next_nodes)
        iac_frontier = iac_next_nodes
    for node_id in sorted(included_iac):
        if len(nodes) >= MAX_GRAPH_NODES:
            break
        item = iac_resources[node_id]
        ref = resource_ref_from_iac(item)
        nodes[node_id] = {
            "node_id": node_id,
            "kind": "iac_resource",
            "resource_ref": ref.to_dict(),
            "source": item.get("source_kind"),
            "confidence": item.get("confidence"),
            "observed_at": item.get("observed_at"),
            "facts": item.get("facts") or {},
            "unresolved_fields": item.get("unresolved_fields") or [],
            "source_path": item.get("source_path"),
            "address": item.get("address"),
        }
    for edge in iac_edges:
        if edge.get("source_node_id") in nodes and edge.get("target_node_id") in nodes:
            edges.append(deepcopy(edge))

    for resource in focus:
        focus_node_id = _resource_node_id(resource)
        for node_id in sorted(focus_iac_nodes):
            item = iac_resources[node_id]
            if not _iac_matches_focus(item, resource) or node_id == focus_node_id:
                continue
            edges.append(
                {
                    "source_node_id": focus_node_id,
                    "target_node_id": node_id,
                    "relationship_type": "declared_by",
                    "source": "iac_live_correlation",
                    "confidence": "high",
                    "observed_at": observed_at,
                    "evidence_provenance": {
                        "source_path": item.get("source_path"),
                        "address": item.get("address"),
                    },
                }
            )

    direct_errors: List[JSON] = []
    if provider is not None and max_hops > 0:
        direct_frontier = [
            resource for resource in focus if resource.provider not in {"iac", "design"}
        ]
        direct_visited = {_resource_node_id(resource) for resource in direct_frontier}
        traversable = {
            "attached_to",
            "deployed_in",
            "encrypted_by",
            "invoked_by",
            "logs_to",
            "protected_by",
            "replicates_to",
            "routes_to",
            "runs_task",
            "runs_on",
        }
        for depth in range(max_hops):
            direct_next_refs: List[ResourceRef] = []
            for resource in direct_frontier:
                if len(nodes) >= MAX_GRAPH_NODES or provider.exhausted:
                    break
                collected = collect_live_relationships(provider, resource)
                direct_errors.extend(collected.get("errors") or [])
                source_id = _resource_node_id(resource)
                for relationship in collected.get("relationships") or []:
                    if len(nodes) >= MAX_GRAPH_NODES:
                        break
                    target = _normalize_resource_ref(relationship["target"], {})
                    target_id = _resource_node_id(target)
                    nodes.setdefault(
                        target_id,
                        {
                            "node_id": target_id,
                            "kind": "related_resource",
                            "resource_ref": target.to_dict(),
                            "source": relationship["source"],
                            "confidence": relationship["confidence"],
                            "observed_at": observed_at,
                            "facts": {},
                        },
                    )
                    edges.append(
                        {
                            "source_node_id": source_id,
                            "target_node_id": target_id,
                            "relationship_type": relationship["relationship_type"],
                            "source": relationship["source"],
                            "confidence": relationship["confidence"],
                            "observed_at": observed_at,
                            "evidence_provenance": relationship["evidence_provenance"],
                        }
                    )
                    if (
                        depth + 1 < max_hops
                        and relationship["relationship_type"] in traversable
                        and target.service in AWS_SCAN_SERVICES
                        and target_id not in direct_visited
                    ):
                        direct_next_refs.append(target)
                        direct_visited.add(target_id)
            direct_frontier = direct_next_refs
            if not direct_frontier or provider.exhausted:
                break

    evidence_graph = _evidence_relationships(opportunities, focus)
    for node in evidence_graph["nodes"]:
        if len(nodes) >= MAX_GRAPH_NODES:
            break
        nodes.setdefault(str(node["node_id"]), node)
    edges.extend(
        edge
        for edge in evidence_graph["edges"]
        if edge.get("source_node_id") in nodes and edge.get("target_node_id") in nodes
    )

    config_errors: List[JSON] = []
    if provider is not None and max_hops > 0:
        config_frontier = [
            resource for resource in focus if resource.provider not in {"iac", "design"}
        ]
        config_visited = {_resource_node_id(resource) for resource in config_frontier}
        traversable = {
            "attached_to",
            "associated_with",
            "contains",
            "deployed_in",
            "encrypted_by",
            "logs_to",
            "protected_by",
            "routes_to",
        }
        for depth in range(max_hops):
            config_next_refs: List[ResourceRef] = []
            for resource in config_frontier:
                if len(nodes) >= MAX_GRAPH_NODES:
                    break
                try:
                    config_graph = _aws_config_relationships(provider, resource)
                except Exception as exc:  # AWS Config is a best-effort relationship source.
                    config_errors.append(
                        {
                            "resource": resource.resource_id,
                            "source": "aws_config",
                            "detail": str(exc),
                        }
                    )
                    continue
                for node in config_graph["nodes"]:
                    if len(nodes) >= MAX_GRAPH_NODES:
                        break
                    nodes.setdefault(str(node["node_id"]), node)
                accepted_edges = [
                    edge
                    for edge in config_graph["edges"]
                    if edge.get("source_node_id") in nodes and edge.get("target_node_id") in nodes
                ]
                edges.extend(accepted_edges)
                if depth + 1 >= max_hops:
                    continue
                traversable_targets = {
                    str(edge.get("target_node_id"))
                    for edge in accepted_edges
                    if edge.get("relationship_type") in traversable
                }
                for related in config_graph.get("related_resources") or []:
                    related_ref = _normalize_resource_ref(related, {})
                    node_id = _resource_node_id(related_ref)
                    if node_id in traversable_targets and node_id not in config_visited:
                        config_next_refs.append(related_ref)
                        config_visited.add(node_id)
            config_frontier = config_next_refs
            if not config_frontier:
                break

    return {
        "nodes": list(nodes.values())[:MAX_GRAPH_NODES],
        "edges": _deduplicate_edges(edges),
        "summary": {
            "focus_nodes": len(focus),
            "observed_nodes": min(len(nodes), MAX_GRAPH_NODES),
            "observed_relationships": len(_deduplicate_edges(edges)),
            "sources": sorted({str(edge.get("source") or "unknown") for edge in edges}),
        },
        "node_limit": MAX_GRAPH_NODES,
        "relationship_hops": max_hops,
        "node_limit_reached": len(nodes) >= MAX_GRAPH_NODES,
        "partial": bool(direct_errors or config_errors) or len(nodes) >= MAX_GRAPH_NODES,
        "relationship_errors": [*direct_errors, *config_errors],
        "absence_is_not_proof": True,
    }


def _aws_config_relationships(provider: BudgetedAwsProvider, resource: ResourceRef) -> JSON:
    config_type = _config_resource_type(resource.resource_type)
    if config_type is None:
        return {"nodes": [], "edges": []}
    response = provider.read(
        "config.get_resource_config_history",
        resourceType=config_type,
        resourceId=resource.resource_id,
        chronologicalOrder="Reverse",
        limit=1,
    )
    items = response.get("configurationItems") or response.get("ConfigurationItems") or []
    if not items:
        return {"nodes": [], "edges": []}
    item = items[0]
    captured_at = str(item.get("configurationItemCaptureTime") or utc_now_iso())
    focus_node_id = _resource_node_id(resource)
    nodes: List[JSON] = []
    edges: List[JSON] = []
    for relationship in item.get("relationships") or []:
        related_id = str(relationship.get("resourceId") or "").strip()
        related_type = str(relationship.get("resourceType") or "").strip()
        if not related_id:
            continue
        service, resource_type = _from_config_resource_type(related_type)
        related = ResourceRef(
            provider="aws-config",
            service=service,
            resource_type=resource_type,
            resource_id=related_id,
            region=resource.region,
            account_id=resource.account_id,
            display_name=str(relationship.get("resourceName") or related_id),
        )
        target_id = _resource_node_id(related)
        nodes.append(
            {
                "node_id": target_id,
                "kind": "related_resource",
                "resource_ref": related.to_dict(),
                "source": "aws_config",
                "confidence": "medium",
                "observed_at": captured_at,
                "facts": {},
            }
        )
        edges.append(
            {
                "source_node_id": focus_node_id,
                "target_node_id": target_id,
                "relationship_type": _normalize_relationship_name(
                    str(relationship.get("relationshipName") or "related_to")
                ),
                "source": "aws_config",
                "confidence": "medium",
                "observed_at": captured_at,
                "evidence_provenance": {
                    "operation": "config.get_resource_config_history",
                    "configuration_state_id": item.get("configurationStateId"),
                    "stale_possible": True,
                },
            }
        )
    return {
        "nodes": nodes,
        "edges": edges,
        "related_resources": [node["resource_ref"] for node in nodes],
    }


def _evidence_relationships(opportunities: List[JSON], focus: List[ResourceRef]) -> JSON:
    nodes: Dict[str, JSON] = {}
    edges: List[JSON] = []
    relationship_keys = (
        ("kms", "encrypted_by", "kms", "aws.kms.key"),
        ("role", "assumes_role", "iam", "aws.iam.role"),
        ("security_group", "protected_by", "ec2", "aws.ec2.security-group"),
        ("subnet", "deployed_in", "ec2", "aws.ec2.subnet"),
        ("vpc", "deployed_in", "ec2", "aws.ec2.vpc"),
        ("log_group", "logs_to", "cloudwatch", "aws.logs.log-group"),
        ("topic", "publishes_to", "sns", "aws.sns.topic"),
        ("queue", "publishes_to", "sqs", "aws.sqs.queue"),
        ("target_group", "routes_to", "alb", "aws.elasticloadbalancingv2.target-group"),
        ("load_balancer", "routes_to", "alb", "aws.elasticloadbalancingv2.load-balancer"),
        ("snapshot", "backed_up_by", "ec2", "aws.ec2.snapshot"),
        ("backup", "backed_up_by", "backup", "aws.backup.recovery-point"),
        ("nodegroup", "runs_on", "eks", "aws.eks.nodegroup"),
    )
    for opportunity in opportunities:
        matched_focus = next(
            (resource for resource in focus if _finding_matches_focus(opportunity, resource)),
            None,
        )
        if matched_focus is None:
            continue
        source_id = _resource_node_id(matched_focus)
        evidence = opportunity.get("evidence") or {}
        observed_at = str((evidence.get("observation") or {}).get("observed_at") or utc_now_iso())
        for key, value in _flatten_evidence(evidence):
            normalized_key = re.sub(r"[^a-z0-9]+", "_", key.casefold()).strip("_")
            if any(token in normalized_key for token in ("secret", "password", "token", "policy")):
                continue
            mapping = next(
                (entry for entry in relationship_keys if entry[0] in normalized_key),
                None,
            )
            if mapping is None or not _relationship_identifier(value):
                continue
            _, relationship_type, service, resource_type = mapping
            target = ResourceRef(
                provider="aws-evidence",
                service=service,
                resource_type=resource_type,
                resource_id=str(value),
                region=matched_focus.region,
                account_id=matched_focus.account_id,
                arn=str(value) if str(value).startswith("arn:") else None,
                display_name=str(value),
            )
            target_id = _resource_node_id(target)
            nodes.setdefault(
                target_id,
                {
                    "node_id": target_id,
                    "kind": "related_resource",
                    "resource_ref": target.to_dict(),
                    "source": "native_collector_evidence",
                    "confidence": "high",
                    "observed_at": observed_at,
                    "facts": {},
                },
            )
            edges.append(
                {
                    "source_node_id": source_id,
                    "target_node_id": target_id,
                    "relationship_type": relationship_type,
                    "source": "native_collector_evidence",
                    "confidence": "high",
                    "observed_at": observed_at,
                    "evidence_provenance": {
                        "rule": opportunity.get("rule"),
                        "evidence_field": key,
                        "source": (evidence.get("observation") or {}).get("source")
                        or "aws_control_plane",
                    },
                }
            )
    return {"nodes": list(nodes.values()), "edges": _deduplicate_edges(edges)}


def _flatten_evidence(value: Any, path: str = "") -> Iterable[Tuple[str, Any]]:
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}" if path else str(key)
            yield from _flatten_evidence(child, child_path)
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value[:10]):
            yield from _flatten_evidence(child, f"{path}[{index}]")
    else:
        yield path, value


def _relationship_identifier(value: Any) -> bool:
    if not isinstance(value, str) or not 2 <= len(value) <= 512:
        return False
    return bool(
        value.startswith("arn:")
        or re.match(
            r"^(?:sg|subnet|vpc|vol|snap|fs|i|lt|eni|igw|nat|eipalloc)-[a-z0-9-]+$",
            value,
            re.IGNORECASE,
        )
        or re.match(r"^[A-Za-z0-9][A-Za-z0-9._/@:+-]{2,255}$", value)
    )


def _evaluate_practices(
    *,
    focus: List[ResourceRef],
    opportunities: List[JSON],
    answers: JSON,
    scan_summaries: List[JSON],
    iac_context: JSON,
    iac_review: JSON,
    capability_errors: List[JSON],
    operation: str,
) -> List[JSON]:
    practice_index = waf_practice_index()
    mappings = native_rule_waf_mappings()
    finding_rules = {str(item.get("rule") or item.get("rule_short_id")) for item in opportunities}
    iac_controls = list(iac_review.get("controls") or [])
    iac_evaluated_rules = set(iac_review.get("evaluated_rules") or [])
    iac_unknown_rules = set(iac_review.get("unknown_rules") or [])
    services = list(dict.fromkeys(resource.service for resource in focus))
    evaluated_rules = sum(int(summary.get("rules_evaluated") or 0) for summary in scan_summaries)
    scan_complete = (
        bool(scan_summaries)
        and not capability_errors
        and all(int(summary.get("scan_errors") or 0) == 0 for summary in scan_summaries)
    )
    unresolved_iac = sorted(
        {
            field
            for resource in iac_context.get("resources") or []
            if any(_iac_matches_focus(resource, target) for target in focus)
            for field in resource.get("unresolved_fields") or []
        }
    )
    results: List[JSON] = []
    for service in services:
        profile = profile_for_service(service)
        profile_rules = set(profile["native_rules"])
        for practice_id in profile["waf_practices"]:
            mapped_rules = sorted(
                short_id
                for short_id, mapping in mappings.items()
                if short_id in profile_rules and practice_id in mapping["practice_ids"]
            )
            matched_rules = sorted(set(mapped_rules) & finding_rules)
            missing_context = sorted(
                fact
                for fact in profile.get("required_facts") or []
                if answers.get(fact) in (None, "", "unknown", "skipped")
            )
            applicability, applicability_evidence = _practice_applicability(
                profile,
                practice_id,
                operation=operation,
                answers=answers,
            )
            evidence: List[JSON] = []
            if applicability == "not_applicable":
                status = "not_applicable"
                evidence = [applicability_evidence]
            elif matched_rules:
                status = "risk"
                evidence = [
                    {
                        "type": "native_finding",
                        "rule": item.get("rule"),
                        "resource": item.get("resource"),
                        "evidence": item.get("evidence") or {},
                    }
                    for item in opportunities
                    if str(item.get("rule")) in matched_rules
                ]
            elif applicability == "requires_input":
                status = "requires_input"
                evidence = [applicability_evidence]
            elif missing_context:
                status = "requires_input"
                evidence = [{"type": "missing_context", "facts": missing_context}]
            elif mapped_rules and set(mapped_rules).issubset(iac_evaluated_rules):
                status = "aligned"
                evidence = [
                    {
                        "type": "iac_controls_evaluated",
                        "controls": [
                            item for item in iac_controls if item.get("rule") in mapped_rules
                        ],
                    }
                ]
            elif mapped_rules and set(mapped_rules).intersection(iac_unknown_rules):
                status = "unknown"
                evidence = [
                    {
                        "type": "iac_controls_unknown",
                        "controls": [
                            item for item in iac_controls if item.get("rule") in mapped_rules
                        ],
                    }
                ]
            elif mapped_rules and scan_complete and evaluated_rules:
                status = "aligned"
                evidence = [
                    {
                        "type": "native_rules_evaluated",
                        "rules": mapped_rules,
                        "finding_count": 0,
                    }
                ]
            elif mapped_rules:
                status = "unknown"
                evidence = [
                    {
                        "type": "evidence_unavailable",
                        "rules": mapped_rules,
                        "reason": "The required live or IaC evidence was not fully available.",
                    }
                ]
            else:
                status = "not_evaluated"
                evidence = [
                    {
                        "type": "manual_practice",
                        "reason": "This relevant practice has no deterministic evidence in this review.",
                    }
                ]
            practice = deepcopy(practice_index[practice_id])
            practice.update(
                {
                    "service": service,
                    "status": status,
                    "applicable": status != "not_applicable",
                    "applicability": applicability_evidence,
                    "mapped_native_rules": mapped_rules,
                    "matched_native_rules": matched_rules,
                    "missing_context": missing_context,
                    "unresolved_iac_fields": unresolved_iac,
                    "evidence": evidence,
                }
            )
            results.append(practice)
    return results


def _practice_applicability(
    profile: JSON,
    practice_id: str,
    *,
    operation: str,
    answers: JSON,
) -> Tuple[str, JSON]:
    operations = profile.get("operations") or list(REVIEW_OPERATIONS)
    if operation not in operations:
        return "not_applicable", {
            "type": "operation_not_applicable",
            "operation": operation,
            "supported_operations": operations,
        }
    predicates = (profile.get("applicability") or {}).get("predicates") or []
    for predicate in predicates:
        if practice_id not in (predicate.get("practice_ids") or []):
            continue
        fact = str(predicate.get("fact") or "")
        value = answers.get(fact)
        if value in (None, "", "unknown", "skipped"):
            return "requires_input", {
                "type": "applicability_input_required",
                "fact": fact,
                "practice_id": practice_id,
            }
        expected = set(predicate.get("values") or [])
        operator = str(predicate.get("operator") or "in")
        matches = value in expected
        applicable = matches if operator == "in" else not matches
        if not applicable:
            return "not_applicable", {
                "type": "applicability_predicate",
                "fact": fact,
                "operator": operator,
                "values": sorted(expected),
                "observed": value,
            }
    return "applicable", {
        "type": "validated_knowledge_pack",
        "operation": operation,
        "profile": profile.get("service"),
    }


def _contextual_recommendations(
    opportunities: List[JSON],
    focus: List[ResourceRef],
    practices: List[JSON],
    intent: JSON,
) -> List[JSON]:
    by_rule: Dict[str, List[str]] = {}
    practice_statuses_by_rule: Dict[str, List[str]] = {}
    for practice in practices:
        for rule in practice.get("mapped_native_rules") or []:
            practice_statuses_by_rule.setdefault(str(rule), []).append(
                str(practice.get("status") or "unknown")
            )
        for rule in practice.get("matched_native_rules") or []:
            by_rule.setdefault(str(rule), []).append(str(practice["practice_id"]))
    profiles = {
        service: profile_for_service(service) for service in {item.service for item in focus}
    }
    answers = intent.get("answers") or {}
    missing_context = sorted(
        key for key, value in answers.items() if value in (None, "", "unknown", "skipped")
    )
    recommendations = []
    for item in opportunities:
        rule = str(item.get("rule") or "")
        applicability_statuses = practice_statuses_by_rule.get(rule) or []
        if applicability_statuses and set(applicability_statuses) == {"not_applicable"}:
            continue
        recommendation = deepcopy(item)
        service = str(item.get("service") or "")
        profile = profiles.get(service) or profile_for_service(service)
        recommendation.update(
            {
                "well_architected_practices": by_rule.get(rule, []),
                "business_impact": profile["business_impact"],
                "confidence": _finding_confidence(item),
                "safe_correction": profile["safe_correction"],
                "verification": (item.get("remediation") or {}).get("verification")
                or profile["verification"],
                "missing_context": missing_context,
                "operation_context": intent.get("operation"),
                "ranking": {
                    "requested_objective_match": bool(
                        set(intent.get("objectives") or [])
                        & set(item.get("matched_objectives") or [])
                    ),
                    "cross_pillar_risk_preserved": True,
                    "severity_precedes_objective_preference": True,
                },
                "approval_required": True,
                "write_actions_applied": False,
            }
        )
        recommendations.append(recommendation)
    objective = set(intent.get("objectives") or [])
    return sorted(
        recommendations,
        key=lambda item: (
            -_severity_rank(str(item.get("severity") or "low")),
            -int(bool(objective & set(item.get("matched_objectives") or []))),
            str(item.get("rule") or ""),
            str(item.get("resource") or ""),
        ),
    )


def _filter_opportunities_for_focus(items: Iterable[JSON], focus: List[ResourceRef]) -> List[JSON]:
    return [
        item for item in items if any(_finding_matches_focus(item, resource) for resource in focus)
    ]


def _finding_matches_focus(item: JSON, focus: ResourceRef) -> bool:
    resource = str(item.get("resource") or "")
    resource_ref = item.get("resource_ref") or {}
    candidates = {
        resource,
        str(resource_ref.get("resource_id") or ""),
        str(resource_ref.get("arn") or ""),
        str(resource_ref.get("display_name") or ""),
    }
    identifiers = {focus.resource_id, focus.arn or "", focus.display_name or ""}
    if any(identifier and identifier in candidates for identifier in identifiers):
        return True
    return any(identifier and identifier in resource for identifier in identifiers)


def _partial_contextual_result(
    arguments: JSON,
    focus: List[ResourceRef],
    opportunities: List[JSON],
    scanned_services: List[str],
    requested_services: List[str],
    observed_at: str,
) -> JSON:
    return {
        "schema_version": "assessment-0.2",
        "assessment_mode": "architectural_review",
        "prompt": arguments.get("prompt"),
        "observed_at": observed_at,
        "focus": {"resources": [resource.to_dict() for resource in focus]},
        "opportunities": deepcopy(opportunities),
        "complete_opportunities": deepcopy(opportunities),
        "summary": {
            "partial": True,
            "services_requested": requested_services,
            "services_scanned": scanned_services,
            "findings": len(opportunities),
            "full_account_scan": False,
        },
        "mcp": {"read_only": True, "write_actions_applied": False},
    }


def _public_profile(profile: JSON) -> JSON:
    return {
        key: deepcopy(profile[key])
        for key in (
            "service",
            "family",
            "pack_release",
            "pack_schema_version",
            "reviewed_at",
            "catalog_revision",
            "resource_types",
            "operations",
            "applicability",
            "waf_practices",
            "native_rules",
            "relationship_collectors",
            "evidence_requirements",
        )
    }


def _group_practices_by_pillar(practices: List[JSON]) -> JSON:
    pillars: Dict[str, List[JSON]] = {}
    for practice in practices:
        practice_pillars = practice.get("pillars") or ["unclassified"]
        for pillar in practice_pillars:
            pillars.setdefault(str(pillar), []).append(deepcopy(practice))
    return {
        "pillars": [
            {
                "pillar": pillar,
                "status_counts": _status_counts(items),
                "practices": items,
            }
            for pillar, items in sorted(pillars.items())
        ],
        "practice_count": len(practices),
        "status_counts": _status_counts(practices),
        "manual_controls_never_inferred_aligned": True,
    }


def _group_recommendations(recommendations: List[JSON]) -> List[JSON]:
    grouped: Dict[str, List[JSON]] = {}
    for recommendation in recommendations:
        grouped.setdefault(str(recommendation.get("service") or "unknown"), []).append(
            recommendation
        )
    return [
        {
            "group": service,
            "count": len(items),
            "highest_severity": max(
                (str(item.get("severity") or "low") for item in items),
                key=_severity_rank,
            ),
            "items": items,
        }
        for service, items in sorted(grouped.items())
    ]


def _review_limitations(
    graph: JSON,
    iac_context: JSON,
    budget_limited: bool,
    *,
    read_ledger: List[JSON],
) -> List[JSON]:
    limitations: List[JSON] = [
        {
            "code": "focused_scope",
            "message": "This was a focused architecture review, not a full-account assessment.",
        },
        {
            "code": "dependency_absence",
            "message": "An unobserved relationship does not prove that no dependency exists.",
        },
        {
            "code": "point_in_time",
            "message": "Live and IaC evidence represents a point-in-time review and is not persisted.",
        },
    ]
    if graph.get("partial"):
        limitations.append(
            {
                "code": "partial_relationships",
                "message": "Some relationships could not be collected.",
            }
        )
    if budget_limited:
        limitations.append(
            {
                "code": "read_budget",
                "message": "The read-operation budget limited evidence collection; missing evidence is unknown.",
            }
        )
    broad_reads = sorted(
        {
            str(item.get("operation"))
            for item in read_ledger
            if item.get("aws_call", True) and item.get("focus_mode") == "focused_response_filter"
        }
    )
    if broad_reads:
        limitations.append(
            {
                "code": "non_targetable_service_reads",
                "message": (
                    "Some AWS APIs do not support exact resource selectors. Steward filtered their "
                    "responses to the focus resource and did not evaluate unrelated resources."
                ),
                "operations": broad_reads,
            }
        )
    for warning in iac_context.get("warnings") or []:
        limitations.append({"code": str(warning.get("reason") or "iac_warning"), **warning})
    return limitations


def _status_counts(practices: Iterable[JSON]) -> JSON:
    counts = {
        "risk": 0,
        "aligned": 0,
        "requires_input": 0,
        "unknown": 0,
        "not_applicable": 0,
        "not_evaluated": 0,
    }
    for practice in practices:
        status = str(practice.get("status") or "unknown")
        counts[status] = counts.get(status, 0) + 1
    return counts


def _finding_confidence(item: JSON) -> str:
    observation = (item.get("evidence") or {}).get("observation") or {}
    return str(observation.get("confidence") or ("high" if item.get("evidence") else "medium"))


def _severity_rank(value: str) -> int:
    return {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}.get(value.casefold(), 0)


def _operation_from_prompt(prompt: str) -> Optional[str]:
    text = prompt.casefold()
    patterns = (
        ("delete", ("delete", "remove", "decommission", "retire")),
        ("troubleshoot", ("debug", "troubleshoot", "broken", "failing", "why is")),
        ("optimize", ("optimize", "reduce cost", "rightsize", "performance")),
        ("create", ("deploy", "create", "provision", "building", "proposed")),
        ("update", ("update", "change", "modify", "upgrade")),
        ("review", ("review", "assess", "inspect")),
    )
    return next(
        (operation for operation, tokens in patterns if any(token in text for token in tokens)),
        None,
    )


def _objectives_from_prompt(prompt: str) -> List[str]:
    text = prompt.casefold()
    tokens = {
        "cost_optimization": ("cost", "saving", "waste", "rightsize"),
        "security": ("security", "secure", "exposure", "encrypt", "permission"),
        "reliability": ("reliability", "recovery", "backup", "availability"),
        "operations": ("operations", "operational", "logging", "monitor"),
        "performance_efficiency": ("performance", "latency", "throughput", "scaling"),
    }
    return [
        objective for objective, values in tokens.items() if any(value in text for value in values)
    ]


def _service_from_prompt(prompt: str) -> Optional[str]:
    text = prompt.casefold()
    aliases = {
        "api gateway": "api-gateway",
        "secrets manager": "secrets-manager",
        "cloudwatch": "cloudwatch",
        "cloudtrail": "cloudtrail",
        "dynamodb": "dynamodb",
        "lambda": "lambda",
        "bucket": "s3",
        "s3": "s3",
        "eks": "eks",
        "kubernetes": "eks",
        "ecs": "ecs",
        "rds": "rds",
        "database": "rds",
        "load balancer": "alb",
        "alb": "alb",
        "efs": "efs",
        "kms": "kms",
        "sns": "sns",
        "sqs": "sqs",
        "iam": "iam",
        "ec2": "ec2",
        "ebs": "ec2",
    }
    matches = {service for token, service in aliases.items() if token in text}
    return next(iter(matches)) if len(matches) == 1 else None


def _service_from_resource(resource: str) -> Optional[str]:
    if resource.startswith("arn:"):
        parts = resource.split(":", 5)
        return _normalize_service(parts[2]) if len(parts) > 2 else None
    scheme = resource.split("://", 1)[0] if "://" in resource else None
    return _normalize_service(scheme) if scheme else None


def _normalize_service(service: str) -> str:
    return {
        "elasticloadbalancing": "alb",
        "elasticloadbalancingv2": "alb",
        "apigateway": "api-gateway",
        "secretsmanager": "secrets-manager",  # pragma: allowlist secret
        "logs": "cloudwatch",
        "ebs": "ec2",
        "networking": "ec2",
    }.get(service.casefold(), service.casefold())


def _single_service(arguments: JSON) -> Optional[str]:
    services = arguments.get("services")
    if isinstance(services, list) and len(services) == 1 and services[0] != "all":
        return _normalize_service(str(services[0]))
    service = str(arguments.get("service") or "").strip()
    return _normalize_service(service) if service and service != "all" else None


def _resource_id(resource: str) -> str:
    if resource.startswith("arn:"):
        suffix = resource.split(":", 5)[-1]
        return re.split(r"[/:]", suffix)[-1]
    return resource.split("://", 1)[-1].split("/")[-1]


def _default_resource_type(service: str, resource: str) -> str:
    suffixes = {
        "iam": "account",
        "cloudtrail": "trail",
        "cloudwatch": "log-group",
        "s3": "bucket",
        "efs": "file-system",
        "ec2": "volume" if resource.startswith("ebs://") or "vol-" in resource else "instance",
        "kms": "key",
        "secrets-manager": "secret",
        "lambda": "function",
        "ecs": "service",
        "eks": "cluster",
        "rds": "db-instance",
        "dynamodb": "table",
        "alb": "load-balancer",
        "api-gateway": "rest-api",
        "sns": "topic",
        "sqs": "queue",
    }
    prefixes = {
        "cloudwatch": "aws.logs",
        "alb": "aws.elasticloadbalancingv2",
        "api-gateway": "aws.apigateway",
        "secrets-manager": "aws.secretsmanager",
    }
    return f"{prefixes.get(service, f'aws.{service}')}.{suffixes.get(service, 'resource')}"


def _resource_node_id(resource: ResourceRef) -> str:
    identity = resource.arn or f"{resource.service}:{resource.resource_type}:{resource.resource_id}"
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]
    return f"resource:{digest}"


def _iac_matches_focus(item: JSON, resource: ResourceRef) -> bool:
    candidates = {
        str(item.get("resource_id") or ""),
        str(item.get("address") or ""),
        str(item.get("display_name") or ""),
        str(item.get("arn") or ""),
    }
    return resource.resource_id in candidates or bool(resource.arn and resource.arn in candidates)


def _config_resource_type(resource_type: str) -> Optional[str]:
    reverse = {
        "aws.s3.bucket": "AWS::S3::Bucket",
        "aws.ec2.instance": "AWS::EC2::Instance",
        "aws.ec2.volume": "AWS::EC2::Volume",
        "aws.ec2.security-group": "AWS::EC2::SecurityGroup",
        "aws.ec2.vpc": "AWS::EC2::VPC",
        "aws.lambda.function": "AWS::Lambda::Function",
        "aws.rds.db-instance": "AWS::RDS::DBInstance",
        "aws.dynamodb.table": "AWS::DynamoDB::Table",
        "aws.efs.file-system": "AWS::EFS::FileSystem",
        "aws.kms.key": "AWS::KMS::Key",
        "aws.sns.topic": "AWS::SNS::Topic",
        "aws.sqs.queue": "AWS::SQS::Queue",
        "aws.elasticloadbalancingv2.load-balancer": "AWS::ElasticLoadBalancingV2::LoadBalancer",
        "aws.ecs.service": "AWS::ECS::Service",
        "aws.eks.cluster": "AWS::EKS::Cluster",
    }
    return reverse.get(resource_type)


def _from_config_resource_type(resource_type: str) -> Tuple[str, str]:
    normalized = resource_type.replace("AWS::", "").split("::", 1)
    service = _normalize_service(normalized[0]) if normalized else "unknown"
    return service, f"aws.{service}.{normalized[-1].casefold()}"


def _normalize_relationship_name(value: str) -> str:
    text = re.sub(r"[^a-z0-9]+", "_", value.casefold()).strip("_")
    aliases = {
        "is_attached_to": "attached_to",
        "is_associated_with": "associated_with",
        "contains": "contains",
    }
    return aliases.get(text, text or "related_to")


def _deduplicate_edges(edges: List[JSON]) -> List[JSON]:
    result: List[JSON] = []
    seen = set()
    for edge in edges:
        key = (
            edge.get("source_node_id"),
            edge.get("target_node_id"),
            edge.get("relationship_type"),
            edge.get("source"),
        )
        if key not in seen:
            result.append(edge)
            seen.add(key)
    return result


def _operation_cache_key(operation: str, args: Tuple[Any, ...], kwargs: JSON) -> str:
    serialized = json.dumps([operation, args, kwargs], sort_keys=True, default=str)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _redacted_parameters(args: Tuple[Any, ...], kwargs: JSON) -> JSON:
    def safe(value: Any, key: str = "") -> Any:
        if any(token in key.casefold() for token in ("secret", "password", "token", "credential")):
            return "<redacted>"
        if isinstance(value, dict):
            return {str(item): safe(child, str(item)) for item, child in value.items()}
        if isinstance(value, (list, tuple)):
            return [safe(child, key) for child in value]
        return value

    return {"args": safe(args), "kwargs": safe(kwargs)}


def _public_resume_arguments(arguments: JSON) -> JSON:
    return {
        key: deepcopy(value)
        for key, value in arguments.items()
        if not key.startswith("_")
        and key
        not in {
            "focus_resource",
            "focus_service",
            "environment",
            "criticality",
            "owner",
            "data_classification",
            "access_pattern",
            "retention",
            "recovery",
            "traffic",
            "growth",
            "consumers",
            "exposure",
            "compliance",
        }
    }
