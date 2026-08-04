from __future__ import annotations

import json
import re
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

JSON = Dict[str, Any]
PromptRenderer = Callable[[Mapping[str, str]], str]

SUPPORTED_OBJECTIVES = (
    "cost_optimization",
    "security",
    "reliability",
    "operations",
    "performance_efficiency",
    "all",
)
SUPPORTED_SERVICES = (
    "all",
    "iam",
    "cloudtrail",
    "cloudwatch",
    "dynamodb",
    "s3",
    "ec2",
    "rds",
    "lambda",
    "efs",
    "eks",
    "ecs",
    "alb",
    "kms",
    "secrets-manager",
    "sns",
    "sqs",
    "api-gateway",
)
SUPPORTED_REVIEW_OPERATIONS = (
    "create",
    "update",
    "review",
    "delete",
    "troubleshoot",
    "optimize",
)
_REGION_PATTERN = re.compile(r"^[a-z]{2}(?:-gov)?-[a-z0-9-]+-[0-9]+$")


class McpPromptError(ValueError):
    """Invalid MCP prompt name or arguments."""


def _argument(
    name: str,
    title: str,
    description: str,
    *,
    required: bool = False,
) -> JSON:
    return {
        "name": name,
        "title": title,
        "description": description,
        "required": required,
    }


_AWS_SCOPE_ARGUMENTS = (
    _argument(
        "profile",
        "AWS profile",
        "AWS shared-config profile to use. Omit it to have Steward ask the user.",
    ),
    _argument(
        "region",
        "AWS region",
        "AWS region to assess. Omit it to have Steward ask the user.",
    ),
    _argument(
        "service",
        "Service scope",
        "One supported service or 'all'. Defaults to all supported live services.",
    ),
    _argument(
        "max_results",
        "Maximum results",
        "Maximum individual findings to show, from 1 to 100. Defaults to 20.",
    ),
)


def _prompt(
    name: str,
    title: str,
    description: str,
    renderer: PromptRenderer,
    arguments: Sequence[JSON] = (),
) -> JSON:
    return {
        "name": name,
        "title": title,
        "description": description,
        "arguments": tuple(arguments),
        "renderer": renderer,
    }


def _readiness_prompt(_: Mapping[str, str]) -> str:
    return (
        "Check BlueArch AWS Steward readiness first. Ask me to choose the AWS profile and "
        "region if they are ambiguous. Show the complete catalog count, automated rule count, "
        "unevaluated rule count, supported live services, provider readiness, and caller identity. "
        "Do not scan or change AWS yet."
    )


def _assessment_prompt(arguments: Mapping[str, str]) -> str:
    profile_region = _profile_region_instruction(arguments)
    service = arguments.get("service", "all")
    objective = arguments.get("objective", "all")
    limit = arguments.get("max_results", "20")
    return (
        "Perform a read-only BlueArch AWS Steward assessment. "
        f"{profile_region} Use objective {_quoted(objective)} and service scope {_quoted(service)}. "
        "Show only resources caught by native BlueArch rules, prioritize high-severity findings, "
        "group results by service and rule, include observed evidence and service errors, and "
        f"return at most {limit} individual findings. Report detection coverage, including automated, "
        "evaluated, and unevaluated catalog rules. Do not describe the account as fully clean when "
        "complete_catalog_evaluation is false. Do not change AWS."
    )


def _architectural_review_prompt(arguments: Mapping[str, str]) -> str:
    profile_region = _profile_region_instruction(arguments)
    resource = arguments.get("resource")
    operation = arguments.get("operation", "review")
    workspace_root = arguments.get("workspace_root")
    iac_path = arguments.get("iac_path")
    focus_instruction = (
        f"Use exact focus resource {_quoted(resource)}. "
        if resource
        else "Ask me to select one exact resource; never guess among resources. "
    )
    iac_instruction = (
        f"Review IaC path {_quoted(iac_path)} under workspace root {_quoted(workspace_root)}. "
        if workspace_root and iac_path
        else ""
    )
    return (
        "Perform a contextual Well-Architected review with BlueArch AWS Steward by calling "
        "bluearch_assess with assessment_mode architectural_review. "
        f"{profile_region} Use operation {_quoted(operation)}. {focus_instruction}{iac_instruction}"
        "Ask only the returned applicability questions, preserve skipped answers as unknown, and do "
        "not broaden this into a service-wide or full-account scan. Report the focus, selected knowledge "
        "pack, observed typed relationships, excluded scope, practice statuses, evidence provenance, "
        "business impact, safe correction, verification, missing context, and high-impact cross-pillar "
        "concerns. Do not modify IaC or AWS."
    )


def _cost_prompt(arguments: Mapping[str, str]) -> str:
    profile_region = _profile_region_instruction(arguments)
    service = arguments.get("service", "all")
    limit = arguments.get("max_results", "10")
    return (
        "Find AWS cost-reduction opportunities with BlueArch AWS Steward. "
        f"{profile_region} Use service scope {_quoted(service)}. Show only resources caught by native "
        f"rules and return at most {limit} individual findings. Rank opportunities by supported savings "
        "evidence, include confidence and assumptions, separate advisory findings that lack sufficient "
        "cost evidence, group results by service and rule, and report detection coverage and service "
        "errors. Keep the assessment read-only and do not apply changes."
    )


def _security_prompt(arguments: Mapping[str, str]) -> str:
    profile_region = _profile_region_instruction(arguments)
    service = arguments.get("service", "all")
    limit = arguments.get("max_results", "20")
    return (
        "Review AWS security risks with BlueArch AWS Steward. "
        f"{profile_region} Use service scope {_quoted(service)}. Show only matched resources, prioritize "
        f"high-severity findings, and return at most {limit} individual findings. Include the observed "
        "evidence, risk, recommended fix, partial-service failures, and detection coverage with "
        "unevaluated catalog rules. Keep the assessment read-only and do not apply changes."
    )


def _catalog_prompt(arguments: Mapping[str, str]) -> str:
    query = arguments["query"]
    service = arguments.get("service", "all")
    limit = arguments.get("max_results", "20")
    return (
        f"Search the complete BlueArch rule catalog for {_quoted(query)} with service scope "
        f"{_quoted(service)}. This is a knowledge search, not an AWS scan. Return at most {limit} rules, "
        "grouped by service and evaluation mode. Separate native automated checks, manual reviews, "
        "metadata-required rules, signal-required rules, and rules that still need detector "
        "specifications. Do not query or change AWS."
    )


def _remediation_prompt(arguments: Mapping[str, str]) -> str:
    profile_region = _profile_region_instruction(arguments)
    reference = arguments["finding_reference"]
    return (
        f"Create a no-write remediation plan for the BlueArch finding reference {_quoted(reference)}. "
        f"{profile_region} Resolve the finding from Steward assessment results and revalidate the live "
        "resource before planning. Show the exact operation, required IAM permissions, before and "
        "after state, impact warnings, rollback guidance, verification method, plan expiry, and whether "
        "apply is supported. Do not call the apply tool and do not change AWS."
    )


def _pdf_report_prompt(arguments: Mapping[str, str]) -> str:
    assessment_id = arguments["assessment_id"]
    output_path = arguments.get(
        "output_path",
        "./reports/bluearch-aws-steward-assessment.pdf",
    )
    return (
        f"Export the completed BlueArch AWS Steward assessment {_quoted(assessment_id)} as a PDF "
        f"to {_quoted(output_path)} using bluearch_export_report with format pdf. Use only the "
        "saved point-in-time assessment result: do not start another assessment, query AWS again, "
        "or apply changes. Include the executive summary, severity and service charts, detection "
        "coverage, and every matched finding with its rule description, matching criteria, observed "
        "evidence, risk, and remediation guidance. Return the local output path and file size."
    )


_PROMPTS: Tuple[JSON, ...] = (
    _prompt(
        "readiness_and_coverage",
        "Readiness and coverage",
        "Inspect Steward, AWS context, and catalog coverage without starting a scan.",
        _readiness_prompt,
    ),
    _prompt(
        "contextual_architecture_review",
        "Contextual architecture review",
        "Review one existing or proposed AWS resource and its bounded architecture neighborhood.",
        _architectural_review_prompt,
        (
            _argument(
                "resource",
                "Focus resource",
                "Exact AWS ARN, resource URI, identifier, or proposed resource address.",
            ),
            _argument(
                "operation",
                "Review operation",
                "create, update, review, delete, troubleshoot, or optimize. Defaults to review.",
            ),
            _argument(
                "workspace_root",
                "IaC workspace root",
                "Declared local workspace root when reviewing Terraform or CloudFormation.",
            ),
            _argument(
                "iac_path",
                "IaC path",
                "Explicit Terraform or CloudFormation file under workspace_root.",
            ),
            _argument(
                "profile",
                "AWS profile",
                "AWS shared-config profile to use. Omit it to have Steward ask the user.",
            ),
            _argument(
                "region",
                "AWS region",
                "AWS region to review. Omit it to have Steward ask the user.",
            ),
        ),
    ),
    _prompt(
        "comprehensive_assessment",
        "Comprehensive assessment",
        "Run a guided, read-only assessment and report matched resources plus coverage limitations.",
        _assessment_prompt,
        (
            _argument(
                "objective",
                "Assessment objective",
                "cost_optimization, security, reliability, operations, or all. Defaults to all.",
            ),
            *_AWS_SCOPE_ARGUMENTS,
        ),
    ),
    _prompt(
        "cost_optimization",
        "Cost optimization",
        "Find ranked AWS cost opportunities while preserving evidence and coverage caveats.",
        _cost_prompt,
        _AWS_SCOPE_ARGUMENTS,
    ),
    _prompt(
        "security_review",
        "Security review",
        "Find AWS security misconfigurations with evidence in a read-only workflow.",
        _security_prompt,
        _AWS_SCOPE_ARGUMENTS,
    ),
    _prompt(
        "catalog_search",
        "Catalog search",
        "Search all BlueArch catalog knowledge without querying AWS.",
        _catalog_prompt,
        (
            _argument(
                "query",
                "Search query",
                "Rule topic, service, risk, control, or keyword to search for.",
                required=True,
            ),
            _argument(
                "service",
                "Service scope",
                "One supported service or 'all'. Defaults to all services.",
            ),
            _argument(
                "max_results",
                "Maximum results",
                "Maximum catalog rules to show, from 1 to 100. Defaults to 20.",
            ),
        ),
    ),
    _prompt(
        "remediation_plan",
        "No-write remediation plan",
        "Revalidate one finding and prepare an approval-ready plan without changing AWS.",
        _remediation_prompt,
        (
            _argument(
                "finding_reference",
                "Finding reference",
                "Assessment finding ID or unambiguous resource and rule reference.",
                required=True,
            ),
            _argument(
                "profile",
                "AWS profile",
                "AWS shared-config profile to use. Omit it to have Steward ask the user.",
            ),
            _argument(
                "region",
                "AWS region",
                "AWS region to use for revalidation. Omit it to have Steward ask the user.",
            ),
        ),
    ),
    _prompt(
        "pdf_assessment_report",
        "PDF assessment report",
        "Export an existing completed assessment as a local PDF without querying or changing AWS.",
        _pdf_report_prompt,
        (
            _argument(
                "assessment_id",
                "Assessment ID",
                "Completed BlueArch AWS Steward assessment to export.",
                required=True,
            ),
            _argument(
                "output_path",
                "PDF output path",
                "Local .pdf path. Defaults to ./reports/bluearch-aws-steward-assessment.pdf.",
            ),
        ),
    ),
)
_PROMPTS_BY_NAME = {prompt["name"]: prompt for prompt in _PROMPTS}


def list_mcp_prompts(cursor: Optional[str] = None) -> List[JSON]:
    if cursor:
        raise McpPromptError("Prompt pagination cursor is invalid; the prompt list has one page.")
    return [
        {
            "name": prompt["name"],
            "title": prompt["title"],
            "description": prompt["description"],
            "arguments": [dict(argument) for argument in prompt["arguments"]],
        }
        for prompt in _PROMPTS
    ]


def get_mcp_prompt(name: str, arguments: Optional[Mapping[str, Any]] = None) -> JSON:
    prompt_name = str(name or "").strip()
    prompt = _PROMPTS_BY_NAME.get(prompt_name)
    if prompt is None:
        raise McpPromptError(f"Unknown MCP prompt: {prompt_name or '<missing>'}")
    normalized = _validate_arguments(prompt, arguments)
    return {
        "description": prompt["description"],
        "messages": [
            {
                "role": "user",
                "content": {
                    "type": "text",
                    "text": prompt["renderer"](normalized),
                },
            }
        ],
    }


def _validate_arguments(prompt: JSON, arguments: Optional[Mapping[str, Any]]) -> Dict[str, str]:
    if arguments is None:
        arguments = {}
    if not isinstance(arguments, Mapping):
        raise McpPromptError("Prompt arguments must be an object with string values.")

    definitions = {argument["name"]: argument for argument in prompt["arguments"]}
    unknown = sorted(set(arguments) - set(definitions))
    if unknown:
        raise McpPromptError(f"Unsupported prompt argument(s): {', '.join(unknown)}")

    normalized: Dict[str, str] = {}
    for name, definition in definitions.items():
        raw_value = arguments.get(name)
        if raw_value is None or raw_value == "":
            if definition.get("required"):
                raise McpPromptError(f"Prompt argument '{name}' is required.")
            continue
        if not isinstance(raw_value, str):
            raise McpPromptError(f"Prompt argument '{name}' must be a string.")
        value = raw_value.strip()
        if not value:
            if definition.get("required"):
                raise McpPromptError(f"Prompt argument '{name}' is required.")
            continue
        normalized[name] = _validate_argument_value(name, value)
    return normalized


def _validate_argument_value(name: str, value: str) -> str:
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise McpPromptError(f"Prompt argument '{name}' contains control characters.")
    if name == "objective" and value not in SUPPORTED_OBJECTIVES:
        raise McpPromptError(
            f"Prompt argument 'objective' must be one of: {', '.join(SUPPORTED_OBJECTIVES)}."
        )
    if name == "service" and value not in SUPPORTED_SERVICES:
        raise McpPromptError(
            f"Prompt argument 'service' must be one of: {', '.join(SUPPORTED_SERVICES)}."
        )
    if name == "operation" and value not in SUPPORTED_REVIEW_OPERATIONS:
        raise McpPromptError(
            f"Prompt argument 'operation' must be one of: {', '.join(SUPPORTED_REVIEW_OPERATIONS)}."
        )
    if name == "region" and not _REGION_PATTERN.fullmatch(value):
        raise McpPromptError("Prompt argument 'region' is not a valid AWS region name.")
    if name == "max_results":
        try:
            number = int(value)
        except ValueError as exc:
            raise McpPromptError("Prompt argument 'max_results' must be an integer.") from exc
        if number < 1 or number > 100:
            raise McpPromptError("Prompt argument 'max_results' must be between 1 and 100.")
        return str(number)

    if name == "output_path" and not value.lower().endswith(".pdf"):
        raise McpPromptError("Prompt argument 'output_path' must end in .pdf.")

    maximum = (
        1024
        if name in {"output_path", "workspace_root", "iac_path"}
        else 512
        if name in {"finding_reference", "resource"}
        else 200
    )
    if len(value) > maximum:
        raise McpPromptError(f"Prompt argument '{name}' exceeds the {maximum}-character limit.")
    return value


def _profile_region_instruction(arguments: Mapping[str, str]) -> str:
    profile = arguments.get("profile")
    region = arguments.get("region")
    if profile and region:
        return f"Use AWS profile {_quoted(profile)} in region {_quoted(region)}."
    if profile:
        return f"Use AWS profile {_quoted(profile)} and ask me to choose the region."
    if region:
        return f"Use AWS region {_quoted(region)} and ask me to choose the profile."
    return "Ask me to choose the AWS profile and region when they are ambiguous."


def _quoted(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)
