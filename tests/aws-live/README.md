# AWS Live Fixture Environment

This directory contains a small real-AWS fixture harness for validating the MVP
against an actual AWS account.

The fixture creates empty S3 buckets with a unique `basw-live-*` prefix, runs
the BlueArch AWS Steward scanner only against that prefix, applies
approved low-risk remediation, verifies a clean follow-up scan, and then deletes
the fixture buckets.

AWS may not emit a missing-default-encryption finding for the live fixture. New
S3 buckets can report default SSE-S3 behavior even when the fixture removes
explicit bucket encryption configuration. LocalEmu keeps a deterministic
missing-encryption fixture for exercising that detector path.

## Safety Defaults

- Uses `AWS_PROFILE=default` unless you provide another profile.
- Uses `AWS_REGION=us-east-1` by default.
- Creates empty buckets only.
- Scans only buckets matching the generated fixture prefix.
- Applies remediation only with `--allow-write`.
- Cleans up fixture buckets at the end of `make aws-live-s3`.

## Run

```bash
make aws-live-s3
```

Override profile or region:

```bash
AWS_PROFILE=my-sso AWS_REGION=us-east-1 make aws-live-s3
```

If a run is interrupted, clean up the last generated fixture prefix:

```bash
make aws-live-clean
```

Artifacts are written under `tests/aws-live/.artifacts/` and are git-ignored.

## Read-Only Cost Provider Parity

The CloudWatch retention and unattached EBS checks have a separate harness that
does not create, modify, or delete AWS resources. It validates each provider's
result contract and then compares AWS CLI and AWS SDK resource counts and
finding identities:

```bash
make dev-sync
AWS_PROFILE=my-sso-profile AWS_REGION=us-east-1 make aws-live-cost-parity
```

Run one provider independently with `make aws-live-cost-cli` or
`make aws-live-cost-sdk`.

## Full MCP Read-Only Validation

The release gate uses the actual stdio MCP server to assess all 16 supported
runtime scopes and request the native Steward, Security Hub, Compute Optimizer,
and Cost Optimization Hub sources. It builds the same unified queue exposed to
MCP clients, including deduplication, validation status, source freshness, and
resolved or stale counts. It never calls a planning or write tool, emits only
aggregate counts, and does not print account identifiers or resource names:

```bash
AWS_PROFILE=my-sso-profile AWS_REGION=us-east-1 make aws-live-mcp
```

An AWS recommendation service that is disabled or not permitted is reported in
`incomplete_sources` and `capability_error_details`; results from available
sources are still returned.

### Optional real Prowler correlation

Prowler is an exported JSON source rather than an AWS API. Keep it isolated
from Steward's runtime dependencies, run a focused read-only scan, and pass its
JSON-OCSF report to the same MCP release gate:

```bash
uv tool install prowler==5.34.0
mkdir -p /tmp/bluearch-prowler-validation
prowler aws \
  --profile my-sso-profile \
  --filter-region us-east-1 \
  --checks s3_bucket_object_versioning s3_bucket_default_encryption \
    cloudtrail_log_file_validation_enabled iam_root_mfa_enabled \
  --output-formats json-ocsf \
  --output-directory /tmp/bluearch-prowler-validation \
  --output-filename prowler-steward \
  --no-banner --no-color

.venv/bin/python tests/aws-live/scripts/e2e-mcp-readonly.py \
  --profile my-sso-profile \
  --region us-east-1 \
  --service all \
  --signal-sources native,security-hub,compute-optimizer,cost-optimization-hub \
  --prowler-json-file /tmp/bluearch-prowler-validation/prowler-steward.ocsf.json
```

Prowler exits with code `3` when it successfully finds failed checks. The MCP
gate must then report `prowler_file_imported: true`, include `prowler-json` in
`source_findings`, and consolidate overlapping signals under
`deduplicated_signals`. The LocalEmu MCP E2E remains the deterministic CI-safe
coverage for this flow.

This is a manual validation only. AWS credentials and SSO sessions are never
configured in GitHub Actions.

Steward's current Prowler contract is validated against Prowler `5.34.0`
JSON-OCSF. Upgrade Prowler only together with adapter contract tests and the
compatibility matrix in `docs/source-compatibility.md`.
