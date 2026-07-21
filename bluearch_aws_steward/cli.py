from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

from bluearch_aws_steward import __version__
from bluearch_aws_steward.catalog_registry import search_catalog_rules
from bluearch_aws_steward.catalog_sync import (
    EVALUATION_MODES,
    catalog_matches,
    default_catalog_output_path,
    default_full_catalog_output_path,
    full_catalog_matches,
    write_catalog_from_misconfig_db,
    write_full_catalog_from_misconfig_db,
)
from bluearch_aws_steward.detectors.s3 import iter_s3_scan_events
from bluearch_aws_steward.policy import build_scan_policy
from bluearch_aws_steward.providers.base import AwsProvider, AwsProviderError
from bluearch_aws_steward.providers.factory import (
    DEFAULT_AWS_PROVIDER,
    SUPPORTED_AWS_PROVIDERS,
    create_aws_provider,
    provider_dependency_status,
)
from bluearch_aws_steward.scanner import AWS_SCAN_SERVICE_CHOICES, run_aws_scan
from bluearch_aws_steward.tui import run_scan_dashboard as run_classic_scan_dashboard


def main(argv: List[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        return args.func(args)
    except AwsProviderError as exc:
        print(f"error: {exc}", file=sys.stderr)
        if exc.detail:
            print(exc.detail, file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="bluearch-steward")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(required=True)

    doctor = subparsers.add_parser("doctor", help="Check local prerequisites and AWS connectivity.")
    _add_aws_options(doctor)
    doctor.set_defaults(func=_doctor)

    rules = subparsers.add_parser("rules", help="Search or synchronize bundled BlueArch rules.")
    rules_subparsers = rules.add_subparsers(required=True)
    rules_search = rules_subparsers.add_parser("search", help="Search rules by text.")
    rules_search.add_argument("query", nargs="?", default=None)
    rules_search.add_argument("--service", default=None)
    rules_search.add_argument("--evaluation-mode", choices=EVALUATION_MODES, default=None)
    rules_search.add_argument("--automated-only", action="store_true")
    rules_search.add_argument("--limit", type=int, default=50)
    rules_search.add_argument("--output", choices=["text", "json"], default="text")
    rules_search.set_defaults(func=_rules_search)
    rules_sync = rules_subparsers.add_parser(
        "sync",
        help="Import the full knowledge catalog and executable detector slice from aws-misconfig-db.",
    )
    rules_sync.add_argument(
        "--source",
        default="../aws-misconfig-db",
        help="Path to the aws-misconfig-db repository. Defaults to ../aws-misconfig-db.",
    )
    rules_sync.add_argument(
        "--output",
        default=None,
        help="Executable catalog output path. Defaults to bluearch_aws_steward/catalog/rules.json.",
    )
    rules_sync.add_argument(
        "--full-output",
        default=None,
        help="Full catalog output path. Defaults to bluearch_aws_steward/catalog/full_rules.json.",
    )
    rules_sync.add_argument(
        "--check",
        action="store_true",
        help="Return non-zero if the bundled catalog is out of sync.",
    )
    rules_sync.set_defaults(func=_rules_sync)

    scan = subparsers.add_parser("scan", help="Scan AWS or IaC targets.")
    scan_subparsers = scan.add_subparsers(required=True)
    scan_aws = scan_subparsers.add_parser(
        "aws", help="Scan an AWS account or an explicit local AWS emulator endpoint."
    )
    _add_aws_options(scan_aws)
    scan_aws.add_argument(
        "--service",
        choices=AWS_SCAN_SERVICE_CHOICES,
        default="s3",
        help="AWS service to scan, or all for every executable service. Defaults to s3.",
    )
    scan_aws.add_argument(
        "--bucket-prefix", default=None, help="Limit S3 scans to buckets with this prefix."
    )
    scan_aws.add_argument(
        "--rule-filter",
        default=None,
        help="Limit scans to one or more comma-separated executable rule short IDs.",
    )
    scan_aws.add_argument("--output", choices=["json", "text"], default="text")
    scan_aws.add_argument("--output-file", default=None)
    scan_aws.add_argument(
        "--max-results",
        type=int,
        default=20,
        help="Maximum findings to show in text output. Use 0 to show every finding.",
    )
    scan_aws.add_argument("--fail-on-findings", action="store_true")
    scan_aws.add_argument(
        "--ebs-min-unattached-days",
        type=int,
        default=None,
        help="Override the catalog minimum age for unattached EBS findings.",
    )
    scan_aws.add_argument(
        "--cloudwatch-retention-days",
        type=int,
        default=None,
        help="Override the catalog retention period used in CloudWatch remediation plans.",
    )
    scan_aws.add_argument(
        "--cloudwatch-min-stored-bytes",
        type=int,
        default=None,
        help="Override the minimum stored bytes required for a CloudWatch cost opportunity.",
    )
    scan_aws.add_argument(
        "--exclude-tag",
        action="append",
        default=None,
        metavar="KEY=VALUE",
        help="Exclude resources matching a tag. May be repeated.",
    )
    scan_aws.set_defaults(func=_scan_aws)

    dashboard = subparsers.add_parser("dashboard", help="Open an interactive live scan dashboard.")
    dashboard_subparsers = dashboard.add_subparsers(required=True)
    dashboard_aws = dashboard_subparsers.add_parser("aws", help="Open a live AWS scan dashboard.")
    _add_aws_options(dashboard_aws)
    dashboard_aws.add_argument(
        "--service", choices=["s3"], default="s3", help="AWS service to scan. Defaults to s3."
    )
    dashboard_aws.add_argument(
        "--bucket-prefix", default=None, help="Limit S3 scans to buckets with this prefix."
    )
    dashboard_aws.add_argument(
        "--rule-filter",
        default=None,
        help="Limit S3 scans to one or more comma-separated rule short IDs.",
    )
    dashboard_aws.add_argument(
        "--output-file",
        default=None,
        help="Write the final scan report JSON when the scan completes.",
    )
    dashboard_aws.add_argument(
        "--ui",
        choices=["modern", "classic"],
        default="modern",
        help="Choose the Textual dashboard or the legacy curses dashboard.",
    )
    dashboard_aws.set_defaults(func=_dashboard_aws)

    mcp = subparsers.add_parser("mcp", help="Use the BlueArch Steward MCP server.")
    mcp_subparsers = mcp.add_subparsers(required=True)
    mcp_info = mcp_subparsers.add_parser("info", help="Show human-friendly MCP setup guidance.")
    mcp_info.set_defaults(func=_mcp_info)
    mcp_config = mcp_subparsers.add_parser("config", help="Print MCP client configuration JSON.")
    mcp_config.add_argument(
        "--runtime",
        choices=["auto", "installed", "uvx"],
        default="auto",
        help=(
            "Choose the MCP launch strategy. 'auto' prefers the current checkout, "
            "'installed' uses this Python environment, and 'uvx' uses the exact public package version."
        ),
    )
    mcp_config.set_defaults(func=_mcp_config)
    mcp_install = mcp_subparsers.add_parser(
        "install", help="Register Steward with one or more supported MCP clients."
    )
    mcp_install.add_argument(
        "--client",
        action="append",
        choices=["codex", "cursor", "claude", "all"],
        required=True,
        help="MCP client to configure. Repeat for multiple clients, or use all by itself.",
    )
    mcp_install.add_argument(
        "--runtime",
        choices=["installed", "uvx"],
        default="installed",
        help="Use the installed executable or an exact-version uvx runtime.",
    )
    mcp_install.add_argument(
        "--dry-run", action="store_true", help="Show planned changes without writing configuration."
    )
    mcp_install.add_argument(
        "--yes",
        action="store_true",
        help="Apply configuration without an interactive confirmation.",
    )
    mcp_install.set_defaults(func=_mcp_install)
    mcp_uninstall = mcp_subparsers.add_parser(
        "uninstall", help="Remove Steward from one or more supported MCP clients."
    )
    mcp_uninstall.add_argument(
        "--client",
        action="append",
        choices=["codex", "cursor", "claude", "all"],
        required=True,
        help="MCP client to update. Repeat for multiple clients, or use all by itself.",
    )
    mcp_uninstall.add_argument(
        "--dry-run", action="store_true", help="Show planned changes without writing configuration."
    )
    mcp_uninstall.add_argument(
        "--yes",
        action="store_true",
        help="Apply configuration without an interactive confirmation.",
    )
    mcp_uninstall.set_defaults(func=_mcp_uninstall)
    mcp_tools = mcp_subparsers.add_parser(
        "tools", help="List available BlueArch Steward MCP tools."
    )
    mcp_tools.add_argument("--output", choices=["text", "json"], default="text")
    mcp_tools.set_defaults(func=_mcp_tools)
    mcp_prompts = mcp_subparsers.add_parser(
        "prompts",
        help="List user-controlled BlueArch Steward MCP workflow prompts.",
    )
    mcp_prompts.add_argument("--output", choices=["text", "json"], default="text")
    mcp_prompts.set_defaults(func=_mcp_prompts)
    mcp_smoke = mcp_subparsers.add_parser(
        "smoke", help="Run a local MCP smoke test without AWS credentials."
    )
    mcp_smoke.add_argument("--output", choices=["text", "json"], default="text")
    mcp_smoke.set_defaults(func=_mcp_smoke)
    mcp_serve = mcp_subparsers.add_parser(
        "serve", help="Serve BlueArch Steward tools over MCP stdio."
    )
    mcp_serve.set_defaults(func=_mcp_serve)

    return parser


def _add_aws_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--provider",
        choices=SUPPORTED_AWS_PROVIDERS,
        default=DEFAULT_AWS_PROVIDER,
        help="AWS access provider. Defaults to the bundled AWS SDK.",
    )
    parser.add_argument("--profile", default=None)
    parser.add_argument("--endpoint-url", default=None)
    parser.add_argument("--region", default="us-east-1")


def _doctor(args: argparse.Namespace) -> int:
    dependency = provider_dependency_status(args.provider)
    checks: List[Dict[str, Any]] = [
        {"name": "provider", "ok": True, "detail": args.provider},
        dependency,
    ]

    if dependency["ok"]:
        client = _client_from_args(args)
        try:
            identity = client.caller_identity()
            checks.append(
                {
                    "name": "aws-connectivity",
                    "ok": True,
                    "detail": identity.get("Arn") or identity.get("Account"),
                }
            )
        except AwsProviderError as exc:
            checks.append(
                {"name": "aws-connectivity", "ok": False, "detail": exc.detail or str(exc)}
            )

    for check in checks:
        marker = "ok" if check["ok"] else "fail"
        print(f"{marker:4} {check['name']}: {check['detail']}")

    return 0 if all(check["ok"] for check in checks) else 1


def _rules_search(args: argparse.Namespace) -> int:
    if args.limit < 1 or args.limit > 500:
        raise ValueError("--limit must be between 1 and 500")
    matches = search_catalog_rules(
        service=args.service,
        query=args.query,
        evaluation_mode=args.evaluation_mode,
        automated_only=args.automated_only,
    )
    rules = matches[: args.limit]
    if args.output == "json":
        print(
            json.dumps(
                {
                    "count": len(matches),
                    "returned": len(rules),
                    "truncated": len(rules) < len(matches),
                    "rules": rules,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0

    for rule in rules:
        evaluation = rule.get("evaluation") or {}
        display_id = evaluation.get("short_id") or rule["id"]
        print(
            f"{display_id:40} {rule['service']:20} {evaluation.get('mode', 'unknown'):24} "
            f"{rule['scenario']}"
        )
    if not rules:
        print("No rules found.")
    elif len(rules) < len(matches):
        print(
            f"Showing {len(rules)} of {len(matches)} matching rules. Increase --limit to see more."
        )
    return 0


def _rules_sync(args: argparse.Namespace) -> int:
    source = Path(args.source).resolve()
    source_catalog = source / "data" / "by-service"
    if not source_catalog.is_dir():
        print(
            "Catalog source is unavailable: "
            f"{source_catalog}. Clone bluearchio/aws-misconfig-db or pass --source "
            "with the path to that repository.",
            file=sys.stderr,
        )
        return 2
    output = Path(args.output).resolve() if args.output else default_catalog_output_path()
    full_output = (
        Path(args.full_output).resolve() if args.full_output else default_full_catalog_output_path()
    )
    if args.check:
        executable_matches = catalog_matches(source, output)
        full_matches = full_catalog_matches(source, full_output)
        if executable_matches and full_matches:
            print(f"Executable catalog is in sync: {output}")
            print(f"Full catalog is in sync: {full_output}")
            return 0
        if not executable_matches:
            print(f"Executable catalog is out of sync: {output}", file=sys.stderr)
        if not full_matches:
            print(f"Full catalog is out of sync: {full_output}", file=sys.stderr)
        return 1

    payload = write_catalog_from_misconfig_db(source, output)
    full_payload = write_full_catalog_from_misconfig_db(source, full_output)
    sync = payload["sync"]
    print(f"Wrote {sync['imported_rules']} executable rule(s) to {output}")
    print(f"Wrote {full_payload['sync']['catalog_rules']} catalog rule(s) to {full_output}")
    for service, skipped in sync["skipped_unsupported_rules"].items():
        print(f"Skipped unsupported {service} rule(s): {skipped}")
    return 0


def _scan_aws(args: argparse.Namespace) -> int:
    client = _client_from_args(args)
    policy = build_scan_policy(
        ebs_min_unattached_days=args.ebs_min_unattached_days,
        cloudwatch_retention_days=args.cloudwatch_retention_days,
        cloudwatch_min_stored_bytes=args.cloudwatch_min_stored_bytes,
        exclude_tags=args.exclude_tag,
    )
    result = run_aws_scan(
        client,
        service=args.service,
        profile=args.profile,
        endpoint_url=args.endpoint_url,
        region=args.region,
        provider=args.provider,
        bucket_prefix=args.bucket_prefix,
        rule_filter=args.rule_filter,
        policy=policy,
    )

    payload = result.to_dict()
    if args.output_file:
        output_path = Path(args.output_file)
        output_path.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

    if args.output == "json":
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        _print_scan_text(payload, max_results=args.max_results)
    return 1 if args.fail_on_findings and payload["findings"] else 0


def _dashboard_aws(args: argparse.Namespace) -> int:
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise ValueError(
            "The interactive dashboard requires a TTY. Use 'scan aws --output text' in non-interactive shells."
        )

    client = _client_from_args(args)
    if args.service != "s3":
        raise ValueError(f"Unsupported service: {args.service}")

    def event_factory():
        return iter_s3_scan_events(
            client,
            profile=args.profile,
            endpoint_url=args.endpoint_url,
            region=args.region,
            provider=args.provider,
            bucket_prefix=args.bucket_prefix,
            rule_filter=args.rule_filter,
        )

    dashboard_kwargs = {
        "title": "BlueArch AWS Steward",
        "service": args.service,
        "profile": args.profile,
        "endpoint_url": args.endpoint_url,
        "region": args.region,
        "bucket_prefix": args.bucket_prefix,
        "output_file": args.output_file,
        "event_factory": event_factory,
    }

    if args.ui == "classic":
        run_classic_scan_dashboard(**dashboard_kwargs)
        return 0

    try:
        from bluearch_aws_steward.textual_tui import run_textual_scan_dashboard
    except ModuleNotFoundError as exc:
        if exc.name and exc.name.startswith("textual"):
            raise ValueError(
                "Modern dashboard requires Textual. Install the 'tui' extra or use '--ui classic'."
            ) from exc
        raise

    run_textual_scan_dashboard(
        **dashboard_kwargs,
    )
    return 0


def _mcp_serve(args: argparse.Namespace) -> int:
    from bluearch_aws_steward.mcp_server import run_mcp_stdio_server

    try:
        return run_mcp_stdio_server()
    except KeyboardInterrupt:
        print("BlueArch AWS Steward MCP server stopped.", file=sys.stderr)
        return 130


def _mcp_info(args: argparse.Namespace) -> int:
    print("BlueArch AWS Steward MCP")
    print("=" * 25)
    print("MCP is for Codex, Cursor, Claude Code, VS Code, and other MCP clients.")
    print()
    print("MCP clients launch `bluearch-steward-mcp` automatically.")
    print("It is a stdio server, not an interactive command.")
    print()
    print("Recommended checks:")
    print("  bluearch-steward mcp smoke")
    print("  bluearch-steward mcp tools")
    print("  bluearch-steward mcp prompts")
    print("  bluearch-steward mcp config")
    print("  bluearch-steward mcp install --client codex")
    print()
    print("Client command:")
    print("  bluearch-steward-mcp")
    print()
    print("Try this prompt in your agent after configuring MCP:")
    print("  Find AWS cost opportunities using my AWS profile in us-east-1.")
    return 0


def _mcp_config(args: argparse.Namespace) -> int:
    from bluearch_aws_steward.mcp_server import mcp_client_config

    print(json.dumps(mcp_client_config(runtime=args.runtime), indent=2, sort_keys=True))
    return 0


def _mcp_install(args: argparse.Namespace) -> int:
    from bluearch_aws_steward.mcp_install import install_mcp_clients, resolve_mcp_clients
    from bluearch_aws_steward.mcp_server import mcp_client_config

    clients = resolve_mcp_clients(args.client)
    config = mcp_client_config(runtime=args.runtime)
    if not _confirm_mcp_config_change("install", clients, args):
        print("No MCP client configuration was changed.")
        return 0
    results = install_mcp_clients(clients, config, dry_run=args.dry_run)
    _print_mcp_config_results(results)
    if not args.dry_run:
        print("Restart the configured MCP clients before using Steward.")
    return 0


def _mcp_uninstall(args: argparse.Namespace) -> int:
    from bluearch_aws_steward.mcp_install import resolve_mcp_clients, uninstall_mcp_clients

    clients = resolve_mcp_clients(args.client)
    if not _confirm_mcp_config_change("uninstall", clients, args):
        print("No MCP client configuration was changed.")
        return 0
    results = uninstall_mcp_clients(clients, dry_run=args.dry_run)
    _print_mcp_config_results(results)
    if not args.dry_run:
        print("Restart the configured MCP clients to complete removal.")
    return 0


def _confirm_mcp_config_change(action: str, clients: List[str], args: argparse.Namespace) -> bool:
    verb = "Install into" if action == "install" else "Remove from"
    print(f"{verb}: {', '.join(clients)}")
    if args.dry_run or args.yes:
        return True
    if not sys.stdin.isatty():
        raise ValueError("Interactive confirmation is unavailable. Re-run with --yes or --dry-run.")
    return input("Continue? [y/N] ").strip().lower() in {"y", "yes"}


def _print_mcp_config_results(results: List[Dict[str, Any]]) -> None:
    for result in results:
        print(f"{result['client']:7} {result['status']:13} {result['config_path']}")
        if result.get("command"):
            print(f"        command: {result['command']}")
        if result.get("backup_path"):
            print(f"        backup:  {result['backup_path']}")


def _mcp_tools(args: argparse.Namespace) -> int:
    from bluearch_aws_steward.mcp_server import list_mcp_tools

    tools = list_mcp_tools()
    if args.output == "json":
        print(json.dumps(tools, indent=2, sort_keys=True))
        return 0
    for tool in tools:
        print(f"{tool['name']:34} {tool['description']}")
    return 0


def _mcp_prompts(args: argparse.Namespace) -> int:
    from bluearch_aws_steward.mcp_server import list_mcp_prompts

    prompts = list_mcp_prompts()
    if args.output == "json":
        print(json.dumps(prompts, indent=2, sort_keys=True))
        return 0
    for prompt in prompts:
        arguments = [
            f"{argument['name']}{'*' if argument.get('required') else ''}"
            for argument in prompt.get("arguments", [])
        ]
        suffix = f" ({', '.join(arguments)})" if arguments else ""
        print(f"{prompt['name']:28} {prompt['title']}{suffix}")
        print(f"{'':28} {prompt['description']}")
    print()
    print("* required argument")
    print("Prompt visibility depends on the MCP client interface.")
    return 0


def _mcp_smoke(args: argparse.Namespace) -> int:
    from bluearch_aws_steward.mcp_server import run_mcp_smoke_test

    payload = run_mcp_smoke_test()
    if args.output == "json":
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0
    print("MCP smoke test passed")
    print()
    print("Checks:")
    for check in payload["checks"]:
        print(f"  ok   {check}")
    print()
    print("Next:")
    print("  bluearch-steward mcp install --client codex")
    print("  Or run 'bluearch-steward mcp config' for manual setup.")
    return 0


def _client_from_args(args: argparse.Namespace) -> AwsProvider:
    return create_aws_provider(
        provider=args.provider,
        profile=args.profile,
        endpoint_url=args.endpoint_url,
        region=args.region,
    )


def _print_scan_text(payload: Dict[str, Any], max_results: int = 20) -> None:
    summary = payload["summary"]
    detection_coverage = summary.get("detection_coverage") or {}
    findings = sorted(payload["findings"], key=_finding_sort_key)
    rule_summaries = _scan_rule_summaries(findings)
    matched_resources = len({finding["resource"] for finding in findings})
    print("BlueArch AWS Steward scan")
    print("=" * 24)
    print(f"Service:        {payload['service']}")
    print(f"Provider:       {payload['provider']}")
    print(f"Region:         {payload['region']}")
    print(f"Profile:        {payload['profile'] or 'default/environment'}")
    print(f"Endpoint:       {payload['endpoint_url'] or 'AWS'}")
    if summary.get("bucket_prefix"):
        print(f"Bucket prefix:  {summary['bucket_prefix']}")
    if summary.get("rule_filter"):
        print(f"Rule filter:    {summary['rule_filter']}")
    print(f"Resources:      {summary['resources_scanned']}")
    print(f"Matched:        {matched_resources}")
    print(f"Rules:          {summary['rules_evaluated']}")
    print(f"Findings:       {summary['findings']}")
    if detection_coverage:
        print(
            "Catalog scope:  "
            f"{detection_coverage.get('automated_rules_evaluated', 0)}/"
            f"{detection_coverage.get('catalog_rules_in_scope', 0)} evaluated; "
            f"{detection_coverage.get('unevaluated_catalog_rules', 0)} unevaluated"
        )
    if summary.get("scan_errors"):
        print(f"Scan errors:    {summary['scan_errors']}")
        for error in (summary.get("scan_error_samples") or [])[:3]:
            scope = error.get("service") or error.get("resource") or "unknown scope"
            print(
                f"  - {scope}: {error.get('detail') or error.get('error_type') or 'unknown error'}"
            )

    if not findings:
        print()
        if summary.get("scan_errors"):
            print(
                "No findings returned, but the scan was incomplete. "
                "Resolve the errors above before treating it as clean."
            )
        elif detection_coverage and not detection_coverage.get("complete_catalog_evaluation"):
            print(
                "No findings among the evaluated native rules. "
                f"{detection_coverage.get('unevaluated_catalog_rules', 0)} catalog rule(s) "
                "remain unevaluated."
            )
        else:
            print("No findings detected.")
        return

    print()
    print("Rule matches")
    for rule in rule_summaries:
        print(
            f"- {rule['rule']}: {rule['findings']} findings across "
            f"{rule['resources']} resources ({rule['severity']})"
        )

    result_limit = len(findings) if max_results <= 0 else min(max_results, len(findings))
    print()
    print(f"Top findings ({result_limit} of {len(findings)})")
    for finding in findings[:result_limit]:
        remediation = finding["remediation"]
        print(
            f"- [{finding['severity'].upper()}] {finding['rule_short_id']} "
            f"{finding['resource']} ({finding['finding_id']})"
        )
        print(f"  why: {finding['scenario']}")
        print(f"  fix: {remediation['summary']}")

    if result_limit < len(findings):
        print()
        print(
            "Output truncated. Re-run with --max-results 0 to show all findings, "
            "or narrow with --rule-filter/--bucket-prefix."
        )
    print("Use --output json or --output-file scan.json for full evidence and remediation details.")


def _scan_rule_summaries(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    summaries: Dict[str, Dict[str, Any]] = {}
    resources_by_rule: Dict[str, set[str]] = {}
    for finding in findings:
        rule = finding["rule_short_id"]
        summary = summaries.setdefault(
            rule,
            {
                "rule": rule,
                "findings": 0,
                "resources": 0,
                "severity": finding["severity"],
            },
        )
        summary["findings"] += 1
        summary["severity"] = _higher_severity(summary["severity"], finding["severity"])
        resources_by_rule.setdefault(rule, set()).add(finding["resource"])
    for rule, resources in resources_by_rule.items():
        summaries[rule]["resources"] = len(resources)
    return sorted(
        summaries.values(),
        key=lambda item: (_severity_rank(item["severity"]), -item["findings"], item["rule"]),
    )


def _finding_sort_key(finding: Dict[str, Any]) -> tuple[int, str, str]:
    return (
        _severity_rank(finding.get("severity")),
        str(finding.get("rule_short_id") or ""),
        str(finding.get("resource") or ""),
    )


def _higher_severity(left: str, right: str) -> str:
    return left if _severity_rank(left) <= _severity_rank(right) else right


def _severity_rank(value: Any) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(str(value or "").lower(), 4)


def _format_evidence_value(value: Any) -> str:
    if value is None:
        return "not configured"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, dict):
        if not value:
            return "{}"
        return ", ".join(f"{key}={val}" for key, val in sorted(value.items()))
    if isinstance(value, list):
        return f"{len(value)} item(s)"
    return str(value)


if __name__ == "__main__":
    raise SystemExit(main())
