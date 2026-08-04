EMULATOR_COMPOSE ?= tests/aws-emulator/docker-compose.yml
EMULATOR_COMPOSE_PROFILE ?=
EMULATOR_SERVICE ?= localemu
EMULATOR_ENDPOINT ?= http://localhost:4566
EMULATOR_REGION ?= us-east-1
EMULATOR_ARTIFACT_DIR ?= tests/aws-emulator/.artifacts
EMULATOR_SCAN_OUTPUT ?= $(EMULATOR_ARTIFACT_DIR)/scan.s3.json
EMULATOR_REMEDIATION_OUTPUT ?= $(EMULATOR_ARTIFACT_DIR)/remediation.s3.json
EMULATOR_VERIFY_OUTPUT ?= $(EMULATOR_ARTIFACT_DIR)/verify.s3.json
EMULATOR_NATIVE_SDK_OUTPUT ?= $(EMULATOR_ARTIFACT_DIR)/scan.native.sdk.json
EMULATOR_NATIVE_CLI_OUTPUT ?= $(EMULATOR_ARTIFACT_DIR)/scan.native.cli.json
EMULATOR_RULE_FILTER ?= s3-public-bucket,s3-no-default-encryption,s3-no-lifecycle,s3-versioning-disabled
EMULATOR_NATIVE_RULE_FILTER ?= $(shell $(PYTHON) -c 'import json; print(",".join(sorted(rule["short_id"] for rule in json.load(open("bluearch_aws_steward/catalog/rules.json"))["rules"] if rule["service"] != "eks")))')
EMULATOR_FIXTURE_ENDPOINT_TOKEN ?= __FIXTURE_ENDPOINT__
CATALOG_SOURCE ?= ../aws-misconfig-db
AWS_PROFILE ?= default
AWS_REGION ?= us-east-1
PYTHON ?= $(shell if [ -x .venv/bin/python ]; then echo .venv/bin/python; else echo python3; fi)
PIP_AUDIT_CACHE_DIR ?= /tmp/bluearch-steward-pip-audit
PACKAGE_VERSION ?= $(shell $(PYTHON) -c 'from bluearch_aws_steward import __version__; print(__version__)')
UV ?= uv
EKS_LAB_ARTIFACT_DIR ?= tests/eks-lab/.artifacts
EKS_AWS_LAB_DIR ?= tests/aws-eks-live
EKS_AWS_LAB_ARTIFACT_DIR ?= $(EKS_AWS_LAB_DIR)/.artifacts
TERRAFORM ?=
KIND_NODE_IMAGE ?= kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5

.PHONY: dev-sync
dev-sync:
	$(UV) sync --extra tui --dev --no-editable --reinstall-package bluearch-aws-steward
	$(MAKE) runtime-info

.PHONY: runtime-info
runtime-info:
	cd /tmp && EXPECTED_VERSION=$(PACKAGE_VERSION) $(CURDIR)/.venv/bin/python -c 'import importlib.metadata as metadata, os; from pathlib import Path; import bluearch_aws_steward as steward; runtime_path = Path(steward.__file__).resolve(); package_version = metadata.version("bluearch-aws-steward"); expected_version = os.environ["EXPECTED_VERSION"]; print("expected_version=" + expected_version); print("runtime_version=" + steward.__version__); print("package_version=" + package_version); print("runtime_path=" + str(runtime_path)); assert steward.__version__ == package_version == expected_version, "checkout and installed package versions differ"; assert "site-packages" in runtime_path.parts, "runtime is not using the installed package"; print("runtime_status=ok")'
	cd /tmp && $(CURDIR)/.venv/bin/bluearch-steward --version

.PHONY: quality
quality:
	$(PYTHON) -m ruff check .
	$(PYTHON) -m ruff format --check .
	$(PYTHON) -m mypy bluearch_aws_steward

.PHONY: security
security:
	$(PYTHON) -m bandit -c pyproject.toml -r bluearch_aws_steward
	$(PYTHON) -m pip_audit --progress-spinner off --cache-dir $(PIP_AUDIT_CACHE_DIR)
	git ls-files --cached --others --exclude-standard -z ':!.secrets.baseline' | xargs -0 $(PYTHON) -m detect_secrets.pre_commit_hook --baseline .secrets.baseline

.PHONY: clean-package
clean-package:
	rm -rf build dist

.PHONY: package
package: clean-package
	$(PYTHON) -m build
	$(PYTHON) -m twine check dist/*
	$(PYTHON) tests/package/smoke-wheel.py dist/bluearch_aws_steward-$(PACKAGE_VERSION)-py3-none-any.whl --expected-version $(PACKAGE_VERSION)

.PHONY: package-install-smoke
package-install-smoke: package
	UV_TOOL_DIR=/tmp/bluearch-steward-uv-tools UV_TOOL_BIN_DIR=/tmp/bluearch-steward-uv-bin $(UV) tool install --force dist/bluearch_aws_steward-$(PACKAGE_VERSION)-py3-none-any.whl
	/tmp/bluearch-steward-uv-bin/bluearch-steward --version
	/tmp/bluearch-steward-uv-bin/bluearch-steward mcp smoke >/dev/null
	/tmp/bluearch-steward-uv-bin/bluearch-steward mcp config --runtime installed >/dev/null
	/tmp/bluearch-steward-uv-bin/bluearch-steward mcp install --client cursor --runtime installed --dry-run >/dev/null
	UV_TOOL_DIR=/tmp/bluearch-steward-uv-tools UV_TOOL_BIN_DIR=/tmp/bluearch-steward-uv-bin $(UV) tool uninstall bluearch-aws-steward

.PHONY: knowledge-check
knowledge-check:
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -c 'from bluearch_aws_steward.knowledge_packs import validate_knowledge_packs; manifest = validate_knowledge_packs(); print("validated_contextual_scopes=" + str(manifest["runtime_scope_count"])); print("validated_native_rules=" + str(manifest["native_rule_count"]))'

.PHONY: contextual-benchmark
contextual-benchmark:
	mkdir -p tests/contextual/.artifacts
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) tests/contextual/run_benchmark.py --output tests/contextual/.artifacts/benchmark.json >/dev/null

.PHONY: test
test: test-mcp knowledge-check contextual-benchmark
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -m unittest discover -s tests -p 'test_*.py'
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -m bluearch_aws_steward.iam_policies --check
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -m bluearch_aws_steward --version
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -m bluearch_aws_steward rules search s3 --service s3 --output json >/dev/null
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -m bluearch_aws_steward rules search retention --service cloudwatch --output json >/dev/null
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -m bluearch_aws_steward rules search unattached --service ec2 --output json >/dev/null
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -m bluearch_aws_steward rules search root --service iam --output json >/dev/null
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -m bluearch_aws_steward rules search trail --service cloudtrail --output json >/dev/null
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -m bluearch_aws_steward rules search storage --service rds --output json >/dev/null
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -m bluearch_aws_steward rules search tracing --service lambda --output json >/dev/null
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -m bluearch_aws_steward rules search encryption --service efs --output json >/dev/null
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -m bluearch_aws_steward rules search task --service ecs --output json >/dev/null
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -m bluearch_aws_steward rules search listener --service alb --output json >/dev/null
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -m bluearch_aws_steward rules search nodegroup --service eks --output json >/dev/null

.PHONY: catalog-check
catalog-check:
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -m bluearch_aws_steward rules sync --source $(CATALOG_SOURCE) --check

.PHONY: test-mcp
test-mcp:
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -m bluearch_aws_steward mcp smoke >/dev/null
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -m bluearch_aws_steward mcp prompts --output json >/dev/null
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) tests/mcp/scripts/smoke-mcp.py
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -m unittest tests.test_mcp_first

.PHONY: emulator-doctor
emulator-doctor:
	tests/aws-emulator/scripts/doctor.sh

.PHONY: emulator-up
emulator-up:
	docker compose -f $(EMULATOR_COMPOSE) $(EMULATOR_COMPOSE_PROFILE) up -d $(EMULATOR_SERVICE)

.PHONY: emulator-down
emulator-down:
	docker compose -f $(EMULATOR_COMPOSE) $(EMULATOR_COMPOSE_PROFILE) down

.PHONY: emulator-clean
emulator-clean:
	docker compose -f $(EMULATOR_COMPOSE) $(EMULATOR_COMPOSE_PROFILE) rm -sfv $(EMULATOR_SERVICE)

.PHONY: emulator-reset
emulator-reset:
	BLUEARCH_STEWARD_TEST_PYTHON=$(PYTHON) tests/aws-emulator/scripts/reset.sh

.PHONY: emulator-seed
emulator-seed:
	BLUEARCH_STEWARD_TEST_PYTHON=$(PYTHON) tests/aws-emulator/scripts/seed.sh

.PHONY: emulator-assert
emulator-assert:
	BLUEARCH_STEWARD_TEST_PYTHON=$(PYTHON) tests/aws-emulator/scripts/assert-fixtures.sh

.PHONY: emulator-recreate
emulator-recreate: emulator-clean emulator-up emulator-reset emulator-seed emulator-assert

.PHONY: emulator-scan
emulator-scan: emulator-recreate
	mkdir -p $(EMULATOR_ARTIFACT_DIR)
	AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_SESSION_TOKEN=test $(PYTHON) -m bluearch_aws_steward.cli scan aws --service s3 --endpoint-url $(EMULATOR_ENDPOINT) --region $(EMULATOR_REGION) --rule-filter $(EMULATOR_RULE_FILTER) --output json --output-file $(EMULATOR_SCAN_OUTPUT)
	$(PYTHON) tests/aws-emulator/scripts/assert-scan.py --actual $(EMULATOR_SCAN_OUTPUT) --expected tests/aws-emulator/expected/findings.s3.json

.PHONY: emulator-coverage
emulator-coverage: emulator-recreate
	mkdir -p $(EMULATOR_ARTIFACT_DIR)
	AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_SESSION_TOKEN=test $(PYTHON) tests/aws-emulator/scripts/fixture_proxy.py --upstream $(EMULATOR_ENDPOINT) -- $(PYTHON) -m bluearch_aws_steward.cli scan aws --provider aws-sdk --service all --endpoint-url $(EMULATOR_FIXTURE_ENDPOINT_TOKEN) --region $(EMULATOR_REGION) --bucket-prefix bluearch-steward- --rule-filter $(EMULATOR_NATIVE_RULE_FILTER) --ebs-min-unattached-days 0 --output json --output-file $(EMULATOR_NATIVE_SDK_OUTPUT) >/dev/null
	$(PYTHON) tests/aws-emulator/scripts/assert-scan.py --actual $(EMULATOR_NATIVE_SDK_OUTPUT) --expected tests/aws-emulator/expected/findings.native.json
	AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_SESSION_TOKEN=test $(PYTHON) tests/aws-emulator/scripts/fixture_proxy.py --upstream $(EMULATOR_ENDPOINT) -- $(PYTHON) -m bluearch_aws_steward.cli scan aws --provider aws-cli --service all --endpoint-url $(EMULATOR_FIXTURE_ENDPOINT_TOKEN) --region $(EMULATOR_REGION) --bucket-prefix bluearch-steward- --rule-filter $(EMULATOR_NATIVE_RULE_FILTER) --ebs-min-unattached-days 0 --output json --output-file $(EMULATOR_NATIVE_CLI_OUTPUT) >/dev/null
	$(PYTHON) tests/aws-emulator/scripts/assert-scan.py --actual $(EMULATOR_NATIVE_CLI_OUTPUT) --expected tests/aws-emulator/expected/findings.native.json
	$(PYTHON) tests/aws-emulator/scripts/e2e-mcp.py --endpoint-url $(EMULATOR_ENDPOINT) --region $(EMULATOR_REGION)

.PHONY: emulator-mcp-e2e
emulator-mcp-e2e: emulator-recreate
	$(PYTHON) tests/aws-emulator/scripts/e2e-mcp.py --endpoint-url $(EMULATOR_ENDPOINT) --region $(EMULATOR_REGION)

.PHONY: emulator-remediate
emulator-remediate: emulator-scan
	AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_SESSION_TOKEN=test $(PYTHON) tests/aws-live/scripts/apply-s3-fixtures-via-mcp.py --scan-file $(EMULATOR_SCAN_OUTPUT) --region $(EMULATOR_REGION) --endpoint-url $(EMULATOR_ENDPOINT) --bucket-prefix bluearch-steward- --output-file $(EMULATOR_REMEDIATION_OUTPUT)
	AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_SESSION_TOKEN=test $(PYTHON) -m bluearch_aws_steward.cli scan aws --service s3 --endpoint-url $(EMULATOR_ENDPOINT) --region $(EMULATOR_REGION) --rule-filter $(EMULATOR_RULE_FILTER) --output json --output-file $(EMULATOR_VERIFY_OUTPUT)
	$(PYTHON) tests/aws-emulator/scripts/assert-scan.py --actual $(EMULATOR_VERIFY_OUTPUT) --expect-no-findings

.PHONY: emulator-mvp
emulator-mvp: emulator-coverage emulator-remediate

.PHONY: emulator-dashboard
emulator-dashboard: emulator-recreate
	mkdir -p $(EMULATOR_ARTIFACT_DIR)
	AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_SESSION_TOKEN=test $(PYTHON) -m bluearch_aws_steward.cli dashboard aws --service s3 --endpoint-url $(EMULATOR_ENDPOINT) --region $(EMULATOR_REGION) --rule-filter $(EMULATOR_RULE_FILTER) --output-file $(EMULATOR_ARTIFACT_DIR)/dashboard.s3.json

.PHONY: emulator-logs
emulator-logs:
	docker compose -f $(EMULATOR_COMPOSE) $(EMULATOR_COMPOSE_PROFILE) logs -f $(EMULATOR_SERVICE)

# Transitional compatibility target. LocalEmu is the default emulator; this
# profile keeps the prior LocalStack image available for parity investigations.
.PHONY: localstack-compat-up localstack-compat-down
localstack-compat-up:
	$(MAKE) emulator-up EMULATOR_SERVICE=localstack EMULATOR_COMPOSE_PROFILE="--profile localstack-compat"

localstack-compat-down:
	$(MAKE) emulator-down EMULATOR_COMPOSE_PROFILE="--profile localstack-compat"

.PHONY: localstack-compat-coverage
localstack-compat-coverage:
	$(MAKE) emulator-coverage EMULATOR_SERVICE=localstack EMULATOR_COMPOSE_PROFILE="--profile localstack-compat"

# Deprecated LocalStack target names continue to select the compatibility
# profile. New development and CI use the emulator-* targets with LocalEmu.
.PHONY: localstack-doctor localstack-up localstack-down localstack-reset localstack-seed localstack-assert localstack-recreate localstack-scan localstack-coverage localstack-mcp-e2e localstack-remediate localstack-mvp localstack-dashboard localstack-logs
localstack-doctor: emulator-doctor
localstack-up: localstack-compat-up
localstack-down: localstack-compat-down
localstack-reset: emulator-reset
localstack-seed: emulator-seed
localstack-assert: emulator-assert
localstack-recreate: localstack-up localstack-reset localstack-seed localstack-assert
localstack-scan:
	$(MAKE) emulator-scan EMULATOR_SERVICE=localstack EMULATOR_COMPOSE_PROFILE="--profile localstack-compat"
localstack-coverage: localstack-compat-coverage
localstack-mcp-e2e:
	$(MAKE) emulator-mcp-e2e EMULATOR_SERVICE=localstack EMULATOR_COMPOSE_PROFILE="--profile localstack-compat"
localstack-remediate:
	$(MAKE) emulator-remediate EMULATOR_SERVICE=localstack EMULATOR_COMPOSE_PROFILE="--profile localstack-compat"
localstack-mvp:
	$(MAKE) emulator-mvp EMULATOR_SERVICE=localstack EMULATOR_COMPOSE_PROFILE="--profile localstack-compat"
localstack-dashboard:
	$(MAKE) emulator-dashboard EMULATOR_SERVICE=localstack EMULATOR_COMPOSE_PROFILE="--profile localstack-compat"
localstack-logs:
	$(MAKE) emulator-logs EMULATOR_SERVICE=localstack EMULATOR_COMPOSE_PROFILE="--profile localstack-compat"

.PHONY: eks-lab-up eks-lab-reset eks-lab-status eks-lab-down
eks-lab-up:
	KIND_NODE_IMAGE=$(KIND_NODE_IMAGE) tests/eks-lab/scripts/up.sh

eks-lab-reset:
	tests/eks-lab/scripts/reset.sh

eks-lab-status:
	tests/eks-lab/scripts/status.sh

eks-lab-down:
	tests/eks-lab/scripts/down.sh

.PHONY: eks-lab-phase-0 eks-lab-phase-1 eks-lab-phase-2 eks-lab-phase-3 eks-lab-phase-4
eks-lab-phase-0:
	$(PYTHON) tests/eks-lab/scripts/phase.py --phase 0 --endpoint-url $(EMULATOR_ENDPOINT) --region $(EMULATOR_REGION) --artifact-dir $(EKS_LAB_ARTIFACT_DIR)

eks-lab-phase-1:
	$(PYTHON) tests/eks-lab/scripts/phase.py --phase 1 --endpoint-url $(EMULATOR_ENDPOINT) --region $(EMULATOR_REGION) --artifact-dir $(EKS_LAB_ARTIFACT_DIR)

eks-lab-phase-2:
	$(PYTHON) tests/eks-lab/scripts/phase.py --phase 2 --endpoint-url $(EMULATOR_ENDPOINT) --region $(EMULATOR_REGION) --artifact-dir $(EKS_LAB_ARTIFACT_DIR)

eks-lab-phase-3:
	$(PYTHON) tests/eks-lab/scripts/phase.py --phase 3 --endpoint-url $(EMULATOR_ENDPOINT) --region $(EMULATOR_REGION) --artifact-dir $(EKS_LAB_ARTIFACT_DIR)

eks-lab-phase-4:
	$(PYTHON) tests/eks-lab/scripts/phase.py --phase 4 --endpoint-url $(EMULATOR_ENDPOINT) --region $(EMULATOR_REGION) --artifact-dir $(EKS_LAB_ARTIFACT_DIR)

.PHONY: eks-lab-full eks-lab-remediation
eks-lab-full: eks-lab-reset
	$(PYTHON) tests/eks-lab/scripts/full.py --endpoint-url $(EMULATOR_ENDPOINT) --region $(EMULATOR_REGION) --artifact-dir $(EKS_LAB_ARTIFACT_DIR)

eks-lab-remediation:
	$(PYTHON) tests/eks-lab/scripts/remediation.py --endpoint-url $(EMULATOR_ENDPOINT) --region $(EMULATOR_REGION) --artifact-dir $(EKS_LAB_ARTIFACT_DIR)

.PHONY: eks-aws-lab-preflight eks-aws-lab-plan eks-aws-lab-up eks-aws-lab-seed
eks-aws-lab-preflight:
	$(PYTHON) $(EKS_AWS_LAB_DIR)/scripts/preflight.py --artifact-dir $(EKS_AWS_LAB_ARTIFACT_DIR)

eks-aws-lab-plan:
	EKS_AWS_LAB_ARTIFACT_DIR=$(EKS_AWS_LAB_ARTIFACT_DIR) TERRAFORM=$(TERRAFORM) $(EKS_AWS_LAB_DIR)/scripts/plan.sh

eks-aws-lab-up:
	EKS_AWS_LAB_ARTIFACT_DIR=$(EKS_AWS_LAB_ARTIFACT_DIR) TERRAFORM=$(TERRAFORM) $(EKS_AWS_LAB_DIR)/scripts/up.sh

eks-aws-lab-seed:
	EKS_AWS_LAB_ARTIFACT_DIR=$(EKS_AWS_LAB_ARTIFACT_DIR) $(EKS_AWS_LAB_DIR)/scripts/seed.sh

.PHONY: eks-aws-lab-validate-connection eks-aws-lab-rules eks-aws-lab-investigate
eks-aws-lab-validate-connection:
	$(PYTHON) $(EKS_AWS_LAB_DIR)/scripts/e2e_mcp.py --stage connection --artifact-dir $(EKS_AWS_LAB_ARTIFACT_DIR)

eks-aws-lab-rules:
	$(PYTHON) $(EKS_AWS_LAB_DIR)/scripts/e2e_mcp.py --stage rules --artifact-dir $(EKS_AWS_LAB_ARTIFACT_DIR)

eks-aws-lab-investigate:
	$(PYTHON) $(EKS_AWS_LAB_DIR)/scripts/e2e_mcp.py --stage investigate --artifact-dir $(EKS_AWS_LAB_ARTIFACT_DIR)


.PHONY: eks-aws-lab-full eks-aws-lab-down eks-aws-lab-verify-clean
eks-aws-lab-full:
	EKS_AWS_LAB_ARTIFACT_DIR=$(EKS_AWS_LAB_ARTIFACT_DIR) TERRAFORM=$(TERRAFORM) $(EKS_AWS_LAB_DIR)/scripts/full.sh

eks-aws-lab-down:
	EKS_AWS_LAB_ARTIFACT_DIR=$(EKS_AWS_LAB_ARTIFACT_DIR) TERRAFORM=$(TERRAFORM) $(EKS_AWS_LAB_DIR)/scripts/down.sh

eks-aws-lab-verify-clean:
	$(PYTHON) $(EKS_AWS_LAB_DIR)/scripts/verify_clean.py --artifact-dir $(EKS_AWS_LAB_ARTIFACT_DIR)

.PHONY: aws-live-s3
aws-live-s3:
	AWS_PROFILE=$(AWS_PROFILE) AWS_REGION=$(AWS_REGION) tests/aws-live/scripts/run-s3-mvp.sh

.PHONY: aws-live-cost-cli
aws-live-cost-cli:
	AWS_PROFILE=$(AWS_PROFILE) AWS_REGION=$(AWS_REGION) AWS_PROVIDER=aws-cli tests/aws-live/scripts/run-cost-readonly.sh

.PHONY: aws-live-cost-sdk
aws-live-cost-sdk:
	AWS_PROFILE=$(AWS_PROFILE) AWS_REGION=$(AWS_REGION) AWS_PROVIDER=aws-sdk tests/aws-live/scripts/run-cost-readonly.sh

.PHONY: aws-live-cost-parity
aws-live-cost-parity: aws-live-cost-cli aws-live-cost-sdk
	$(PYTHON) tests/aws-live/scripts/compare-cost-provider-scans.py --artifact-dir tests/aws-live/.artifacts

.PHONY: aws-live-mcp
aws-live-mcp:
	$(PYTHON) tests/aws-live/scripts/e2e-mcp-readonly.py --profile $(AWS_PROFILE) --region $(AWS_REGION)

.PHONY: aws-live-clean
aws-live-clean:
	AWS_PROFILE=$(AWS_PROFILE) AWS_REGION=$(AWS_REGION) tests/aws-live/scripts/cleanup-s3.sh
