# Triage and Prioritization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make Steward rank findings by actual risk instead of alphabetically within severity, and report them grouped instead of one-by-one, so an account scan produces an actionable summary rather than a 208-page list.

**Architecture:** This is a wiring project, not a construction project. `priority_score()`, `grouped_solutions`, the four report profiles, the "Top priorities" action and the priority-aware sort key all already exist and are disconnected. Exactly one new component is written: a pure `risk_factors` module that raises priority for genuinely dangerous findings. Everything else is connecting existing seams.

**Tech Stack:** Python 3.10-3.13, `unittest` (not pytest), `ruff`, `mypy`, `uv`, `make`.

## Global Constraints

- Tests use `unittest.TestCase`. Run with `python -m unittest`, never `pytest`.
- Run every command from the repository root with `PYTHON=.venv/bin/python` already the Makefile default.
- `severity` is never modified. The risk layer changes `priority` only, so `rules sync` has nothing to overwrite.
- Group priority is the **maximum** of member priorities, never the sum.
- Scoring must be idempotent: re-scoring an already-scored finding yields an identical result.
- Never call AWS. Every test in this plan runs offline.
- `ruff format` line length and style are enforced; run `make quality` before every commit.
- Python 3.10 is the floor. Do not use `match` statements or 3.11+ typing syntax.

## Autonomous Execution Note

This plan is written for uninterrupted execution. Every ambiguity is pre-resolved,
every test is written out, and every step states its expected output. Do not stop
for review between tasks. Task 9 produces the single validation package for the
user at the end.

If a step's expected output does not match reality, stop and report rather than
improvising — that is the one exception.

---

### Task 0: Create the working branch

Every later task commits, so the branch must exist first.

**Files:** none.

**Interfaces:**
- Consumes: nothing.
- Produces: branch `feat/triage-and-prioritization`, which Task 9 pushes.

- [ ] **Step 1: Branch from current main**

```bash
git fetch origin
git switch -c feat/triage-and-prioritization origin/main
```

- [ ] **Step 2: Confirm the environment is usable**

```bash
make dev-sync
.venv/bin/python -m unittest discover -s tests -p 'test_*.py' 2>&1 | tail -3
```
Expected: `OK`, at least 240 tests. This establishes the baseline that Task 9
compares against.

---

### Task 1: Fix the PDF capability-errors crash

`pdf_report.py` calls `len()` on `summary["capability_errors"]`, which arrives as an
`int` on live accounts while the top-level field is a list. Any account with
capability errors — an EKS cluster without kubeconfig is enough — raises
`TypeError` on PDF export. This blocks the acceptance criterion in Task 9, so it
comes first.

**Files:**
- Modify: `bluearch_aws_steward/pdf_report.py:531-533`
- Test: `tests/test_reports.py`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `_count(value: Any) -> int` in `bluearch_aws_steward/pdf_report.py`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_reports.py`:

```python
class PdfCountFieldTests(unittest.TestCase):
    def test_pdf_renders_when_capability_errors_is_an_int(self) -> None:
        from bluearch_aws_steward.pdf_report import render_pdf_report

        model = {
            "generated_at": "2026-08-04T00:00:00Z",
            "provider": "aws-sdk",
            "report_profile": "technical",
            "summary": {
                "resources_scanned": 10,
                "complete_findings": 1,
                "capability_errors": 3,
                "service_errors": 0,
                "rules_skipped": 2,
                "detection_coverage": {},
            },
            "findings": [],
            "severity_counts": {},
            "service_counts": {},
        }
        pdf = render_pdf_report(model)
        self.assertTrue(pdf.startswith(b"%PDF-"))
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m unittest tests.test_reports.PdfCountFieldTests -v`
Expected: FAIL with `TypeError: object of type 'int' has no len()`

- [ ] **Step 3: Write minimal implementation**

Add near the top of `bluearch_aws_steward/pdf_report.py`, after the imports:

```python
def _count(value: Any) -> int:
    """Count entries whether the summary field carries a list or a pre-counted int."""
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return value
    if isinstance(value, (list, tuple, set, dict)):
        return len(value)
    return 0
```

Then replace lines 531-533 with:

```python
        ("Service errors", _count(summary.get("service_errors"))),
        ("Capability errors", _count(summary.get("capability_errors"))),
        ("Rules skipped", _count(summary.get("rules_skipped"))),
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m unittest tests.test_reports.PdfCountFieldTests -v`
Expected: PASS

- [ ] **Step 5: Verify nothing regressed**

Run: `make quality && make test`
Expected: ruff passes, mypy reports no issues, 241 tests OK.

- [ ] **Step 6: Commit**

```bash
git add bluearch_aws_steward/pdf_report.py tests/test_reports.py
git commit -m "fix: render PDF when summary counts are integers"
```

---

### Task 2: Add the contextual risk layer

The only genuinely new component. A pure function with no I/O, no AWS calls and no
dependency on the scan pipeline, so it is testable in isolation.

**Files:**
- Create: `bluearch_aws_steward/risk_factors.py`
- Test: `tests/test_risk_factors.py`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `risk_factors(finding: Dict[str, Any]) -> Dict[str, Any]` returning
  `{"factors": List[Dict[str, Any]], "total": float}`. Each factor is
  `{"id": str, "points": float, "rationale": str}`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_risk_factors.py`:

```python
import unittest

from bluearch_aws_steward.risk_factors import risk_factors


class RiskFactorTests(unittest.TestCase):
    def test_root_credential_scores_highest(self) -> None:
        result = risk_factors({"rule": "iam-root-access-key-present"})
        self.assertEqual(result["total"], 40.0)
        self.assertEqual([factor["id"] for factor in result["factors"]], ["root_credential"])
        self.assertTrue(result["factors"][0]["rationale"])

    def test_publicly_readable_resource(self) -> None:
        result = risk_factors({"rule": "s3-public-bucket"})
        self.assertEqual(result["total"], 30.0)
        self.assertEqual([factor["id"] for factor in result["factors"]], ["publicly_readable"])

    def test_internet_exposed_port(self) -> None:
        result = risk_factors({"rule": "ec2-security-group-ssh-open"})
        self.assertEqual(result["total"], 25.0)

    def test_administrative_privilege(self) -> None:
        result = risk_factors({"rule": "iam-policy-full-admin"})
        self.assertEqual(result["total"], 20.0)

    def test_aged_credential(self) -> None:
        result = risk_factors({"rule": "iam-access-key-older-than-90-days"})
        self.assertEqual(result["total"], 10.0)

    def test_unremarkable_finding_scores_zero(self) -> None:
        result = risk_factors({"rule": "s3-no-lifecycle"})
        self.assertEqual(result["total"], 0.0)
        self.assertEqual(result["factors"], [])

    def test_missing_rule_is_not_an_error(self) -> None:
        self.assertEqual(risk_factors({})["total"], 0.0)

    def test_malformed_input_is_not_an_error(self) -> None:
        self.assertEqual(risk_factors({"rule": None})["total"], 0.0)
        self.assertEqual(risk_factors({"rule": 12345})["total"], 0.0)

    def test_factors_are_sorted_by_points_descending(self) -> None:
        result = risk_factors({"rule": "iam-root-access-key-present"})
        points = [factor["points"] for factor in result["factors"]]
        self.assertEqual(points, sorted(points, reverse=True))


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m unittest tests.test_risk_factors -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'bluearch_aws_steward.risk_factors'`

- [ ] **Step 3: Write minimal implementation**

Create `bluearch_aws_steward/risk_factors.py`:

```python
"""Contextual risk factors that raise the priority of genuinely dangerous findings.

The catalog owns severity. This layer owns context, and contributes additive
points to the priority score without ever modifying severity, so a catalog sync
has nothing to overwrite.

Every factor carries a rationale. A priority number is a claim, and the product
does not ship claims without evidence.
"""

from __future__ import annotations

from typing import Any, Dict, List

JSON = Dict[str, Any]

_ROOT_CREDENTIAL_RULES = {
    "iam-root-access-key-present",
    "iam-root-mfa-disabled",
    "iam-root-hardware-mfa-missing",
}

_PUBLICLY_READABLE_RULES = {
    "s3-public-bucket",
    "s3-policy-all-actions-public",
    "s3-policy-public-delete",
    "rds-publicly-accessible",
    "sns-topic-public-access",
    "sqs-queue-public-access",
}

_INTERNET_EXPOSED_RULES = {
    "ec2-security-group-ssh-open",
    "ec2-security-group-rdp-open",
}

_ADMIN_PRIVILEGE_RULES = {
    "iam-policy-full-admin",
    "lambda-admin-execution-role",
    "iam-role-wildcard-trust",
}

_AGED_CREDENTIAL_RULES = {
    "iam-access-key-older-than-90-days",
}

_FACTOR_DEFINITIONS = (
    (
        "root_credential",
        40.0,
        "Root account credential; a compromise bypasses every IAM control in the account.",
        _ROOT_CREDENTIAL_RULES,
    ),
    (
        "publicly_readable",
        30.0,
        "Resource is reachable by anonymous principals, so exposure needs no prior access.",
        _PUBLICLY_READABLE_RULES,
    ),
    (
        "internet_exposed",
        25.0,
        "Administrative port is open to the internet, giving attackers a direct entry path.",
        _INTERNET_EXPOSED_RULES,
    ),
    (
        "admin_privilege",
        20.0,
        "Grants unrestricted administrative permissions, removing blast-radius containment.",
        _ADMIN_PRIVILEGE_RULES,
    ),
    (
        "aged_credential",
        10.0,
        "Long-lived credential increases the window in which a leak stays usable.",
        _AGED_CREDENTIAL_RULES,
    ),
)


def risk_factors(finding: JSON) -> JSON:
    """Return additive contextual risk for a finding.

    Never raises. A malformed finding yields no factors, so the caller degrades to
    the base score rather than failing an entire scan.
    """
    try:
        rule = finding.get("rule")
    except AttributeError:
        return {"factors": [], "total": 0.0}
    if not isinstance(rule, str):
        return {"factors": [], "total": 0.0}

    factors: List[JSON] = []
    for factor_id, points, rationale, rules in _FACTOR_DEFINITIONS:
        if rule in rules:
            factors.append({"id": factor_id, "points": points, "rationale": rationale})

    factors.sort(key=lambda factor: -float(factor["points"]))
    return {"factors": factors, "total": float(sum(factor["points"] for factor in factors))}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m unittest tests.test_risk_factors -v`
Expected: PASS, 9 tests OK.

- [ ] **Step 5: Verify quality gates**

Run: `make quality`
Expected: ruff passes, `ruff format --check` reports all files formatted, mypy reports no issues.

- [ ] **Step 6: Commit**

```bash
git add bluearch_aws_steward/risk_factors.py tests/test_risk_factors.py
git commit -m "feat: add contextual risk factors"
```

---

### Task 3: Feed contextual risk into priority_score

**Files:**
- Modify: `bluearch_aws_steward/recommendation_queue.py:302-345`
- Test: `tests/test_recommendation_queue.py`

**Interfaces:**
- Consumes: `risk_factors(finding) -> {"factors": [...], "total": float}` from Task 2.
- Produces: `priority_score(finding)` now returns a dict whose `components` includes
  `contextual_risk: float` and whose top level includes `risk_factors: List[JSON]`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_recommendation_queue.py`:

```python
class ContextualRiskPriorityTests(unittest.TestCase):
    def test_root_credential_outranks_a_high_severity_finding(self) -> None:
        from bluearch_aws_steward.recommendation_queue import priority_score

        root_key = priority_score({"rule": "iam-root-access-key-present", "severity": "medium"})
        encryption = priority_score({"rule": "sns-topic-encryption-disabled", "severity": "high"})
        self.assertGreater(root_key["score"], encryption["score"])

    def test_components_expose_contextual_risk(self) -> None:
        from bluearch_aws_steward.recommendation_queue import priority_score

        scored = priority_score({"rule": "iam-root-access-key-present", "severity": "medium"})
        self.assertEqual(scored["components"]["contextual_risk"], 40.0)
        self.assertEqual(
            [factor["id"] for factor in scored["risk_factors"]], ["root_credential"]
        )

    def test_unremarkable_finding_has_zero_contextual_risk(self) -> None:
        from bluearch_aws_steward.recommendation_queue import priority_score

        scored = priority_score({"rule": "s3-no-lifecycle", "severity": "low"})
        self.assertEqual(scored["components"]["contextual_risk"], 0.0)
        self.assertEqual(scored["risk_factors"], [])

    def test_scoring_is_idempotent(self) -> None:
        from bluearch_aws_steward.recommendation_queue import priority_score

        finding = {"rule": "iam-root-access-key-present", "severity": "medium"}
        first = priority_score(finding)
        finding["priority"] = first
        second = priority_score(finding)
        self.assertEqual(first, second)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m unittest tests.test_recommendation_queue.ContextualRiskPriorityTests -v`
Expected: FAIL with `KeyError: 'contextual_risk'`

- [ ] **Step 3: Write minimal implementation**

Add to the imports at the top of `bluearch_aws_steward/recommendation_queue.py`:

```python
from bluearch_aws_steward.risk_factors import risk_factors
```

In `priority_score()`, immediately before the `components = {` literal, add:

```python
    contextual = risk_factors(finding)
```

Add one entry to the `components` dict, after `"implementation_effort"`:

```python
        "contextual_risk": round(float(contextual["total"]), 2),
```

And add `risk_factors` to the returned dict, after `"components": components,`:

```python
        "risk_factors": contextual["factors"],
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m unittest tests.test_recommendation_queue -v`
Expected: PASS, including the four new tests.

- [ ] **Step 5: Verify nothing regressed**

Run: `make quality && make test`
Expected: ruff and mypy clean, all tests OK.

- [ ] **Step 6: Commit**

```bash
git add bluearch_aws_steward/recommendation_queue.py tests/test_recommendation_queue.py
git commit -m "feat: score contextual risk into finding priority"
```

---

### Task 4: Stamp priority on every finding

The single write point. `_opportunity_sort_key` already prefers `priority.score`
when present and falls back to severity-then-alphabetical when absent, so stamping
alone fixes the ordering without touching the sort function.

**Files:**
- Modify: `bluearch_aws_steward/mcp_server.py:5641-5646`
- Test: `tests/test_triage_ordering.py`

**Interfaces:**
- Consumes: `priority_score(finding)` from Task 3.
- Produces: every entry of `opportunities`, `complete_opportunities`,
  `opportunities` (returned slice) and each `solution_cards` entry carries a
  populated `priority` dict.

- [ ] **Step 1: Write the failing test**

Create `tests/test_triage_ordering.py`:

```python
import unittest

from bluearch_aws_steward.mcp_server import StewardMcpServer
from tests.support_triage import call_tool, completed_result, triage_scan_result


class TriageOrderingTests(unittest.TestCase):
    def test_root_access_key_is_ranked_first(self) -> None:
        server = StewardMcpServer()
        submitted = call_tool(
            server,
            1,
            "bluearch_assess",
            {
                "prompt": "Assess this account.",
                "scan_result": triage_scan_result(),
                "objectives": ["all"],
                "services": ["iam"],
            },
        )
        result = completed_result(server, submitted["assessment_id"])
        rules = [item["rule"] for item in result["opportunities"]]
        self.assertIn("iam-root-access-key-present", rules[:5])

    def test_every_opportunity_is_scored(self) -> None:
        server = StewardMcpServer()
        submitted = call_tool(
            server,
            10,
            "bluearch_assess",
            {
                "prompt": "Assess this account.",
                "scan_result": triage_scan_result(),
                "objectives": ["all"],
                "services": ["iam"],
            },
        )
        result = completed_result(server, submitted["assessment_id"])
        for item in result["opportunities"]:
            self.assertIsInstance(item["priority"]["score"], (int, float))


if __name__ == "__main__":
    unittest.main()
```

Create the shared fixture helper `tests/support_triage.py`. It reproduces the exact
pathology observed on a live account — a `medium` root access key competing with
`high` findings whose rules sort earlier alphabetically — without embedding real
account data.

Two things about this file are deliberate. It is named `support_triage.py` rather
than `test_*.py` so `unittest discover` does not try to run it as a test module.
And `from tests.support_triage import ...` resolves even though `tests/` has no
`__init__.py`, because implicit namespace packages make `tests.<module>`
importable from the repository root — the same mechanism `make test-mcp` already
relies on when it runs `python -m unittest tests.test_mcp_first`.

```python
"""Shared fixture for triage tests.

Reproduces the ordering pathology seen on a live account: iam-root-access-key-present
carries severity medium in the catalog while sns-topic-encryption-disabled and
api-gateway-access-logging-disabled carry high, and the latter two sort earlier
alphabetically.
"""

from __future__ import annotations

import json
import time
from typing import Any, Dict

JSON = Dict[str, Any]

_RULES = (
    ("api-gateway-access-logging-disabled", "high", "api-gateway", "apigw://stage/prod"),
    ("sns-topic-encryption-disabled", "high", "sns", "sns://topic/alerts"),
    ("iam-root-access-key-present", "medium", "iam", "iam://account/root"),
    ("s3-no-lifecycle", "low", "s3", "s3://archive-bucket"),
)


def triage_scan_result() -> JSON:
    findings = []
    for index, (rule, severity, service, resource) in enumerate(_RULES):
        findings.append(
            {
                "finding_id": f"triage-{index}",
                "rule_id": f"00000000-0000-0000-0000-00000000000{index}",
                "rule_short_id": rule,
                "service": service,
                "resource": resource,
                "resource_ref": {
                    "provider": "aws",
                    "service": service,
                    "resource_type": f"aws.{service}.resource",
                    "resource_id": resource.rsplit("/", 1)[-1],
                    "region": "us-east-1",
                },
                "severity": severity,
                "risk_detail": "security",
                "scenario": f"Fixture finding for {rule}.",
                "evidence": {"observation": {"source": "aws_control_plane", "confidence": "high"}},
            }
        )
    return {
        "schema_version": "0.2",
        "generated_at": "2026-08-04T00:00:00Z",
        "service": "all",
        "provider": "aws-sdk",
        "profile": None,
        "region": "us-east-1",
        "findings": findings,
        "summary": {
            "resources_scanned": len(findings),
            "rules_evaluated": len(findings),
            "scan_errors": 0,
        },
    }


def call_tool(server: Any, request_id: int, tool: str, arguments: JSON) -> JSON:
    response = server.handle(
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/call",
            "params": {"name": tool, "arguments": arguments},
        }
    )
    if "error" in response:
        raise AssertionError(f"{tool} failed: {response['error']}")
    return json.loads(response["result"]["content"][0]["text"])


def completed_result(server: Any, assessment_id: str) -> JSON:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        status = call_tool(server, 900, "bluearch_get_scan_status", {"assessment_id": assessment_id})
        if status["status"] == "completed":
            break
        time.sleep(0.01)
    else:
        raise AssertionError("assessment did not complete")
    return call_tool(
        server,
        901,
        "bluearch_get_scan_results",
        {"assessment_id": assessment_id, "generate_pdf_report": False},
    )["result"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m unittest tests.test_triage_ordering -v`
Expected: FAIL. `test_every_opportunity_is_scored` fails with `KeyError: 'score'`
because `priority` is `{}`, and `test_root_access_key_is_ranked_first` fails
because the two `high` rules sort ahead of the `medium` root key.

- [ ] **Step 3: Write minimal implementation**

Add to the imports of `bluearch_aws_steward/mcp_server.py`, inside the existing
`from bluearch_aws_steward.recommendation_queue import (` block:

```python
    priority_score,
```

In `_tool_find_opportunities`, replace:

```python
    opportunities.sort(key=_opportunity_sort_key)
```

with:

```python
    for opportunity in opportunities:
        opportunity["priority"] = priority_score(opportunity)
    opportunities.sort(key=_opportunity_sort_key)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m unittest tests.test_triage_ordering -v`
Expected: PASS, 2 tests OK.

- [ ] **Step 5: Verify nothing regressed**

Run: `make quality && make test`
Expected: ruff and mypy clean, all tests OK. The unified-queue path re-scores
during merge, which is safe because Task 3 proved scoring idempotent.

- [ ] **Step 6: Commit**

```bash
git add bluearch_aws_steward/mcp_server.py tests/test_triage_ordering.py tests/support_triage.py
git commit -m "feat: score every finding so results rank by risk"
```

---

### Task 5: Give each group the priority of its worst member

**Files:**
- Modify: `bluearch_aws_steward/mcp_server.py:6349-6380`
- Test: `tests/test_triage_ordering.py`

**Interfaces:**
- Consumes: solution cards carrying `priority` (Task 4).
- Produces: each `grouped_solutions` entry carries `priority_score: float`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_triage_ordering.py`, above the `if __name__` block:

```python
class GroupPriorityTests(unittest.TestCase):
    def test_group_priority_is_the_maximum_not_the_sum(self) -> None:
        from bluearch_aws_steward.mcp_server import _group_solution_cards

        groups = _group_solution_cards(
            [
                {
                    "objective": "all",
                    "rule": "s3-no-lifecycle",
                    "severity": "low",
                    "resource": f"s3://bucket-{index}",
                    "priority": {"score": 12.0},
                }
                for index in range(50)
            ]
        )
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["priority_score"], 12.0)

    def test_single_dangerous_finding_outranks_a_large_low_risk_group(self) -> None:
        from bluearch_aws_steward.mcp_server import _group_solution_cards

        cards = [
            {
                "objective": "all",
                "rule": "s3-no-lifecycle",
                "severity": "low",
                "resource": f"s3://bucket-{index}",
                "priority": {"score": 12.0},
            }
            for index in range(50)
        ]
        cards.append(
            {
                "objective": "all",
                "rule": "iam-root-access-key-present",
                "severity": "medium",
                "resource": "iam://account/root",
                "priority": {"score": 80.0},
            }
        )
        groups = _group_solution_cards(cards)
        ranked = sorted(groups, key=lambda group: -group["priority_score"])
        self.assertEqual(ranked[0]["rule"], "iam-root-access-key-present")

    def test_missing_priority_defaults_to_zero(self) -> None:
        from bluearch_aws_steward.mcp_server import _group_solution_cards

        groups = _group_solution_cards(
            [{"objective": "all", "rule": "s3-no-lifecycle", "resource": "s3://b"}]
        )
        self.assertEqual(groups[0]["priority_score"], 0.0)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m unittest tests.test_triage_ordering.GroupPriorityTests -v`
Expected: FAIL with `KeyError: 'priority_score'`

- [ ] **Step 3: Write minimal implementation**

In `_group_solution_cards`, add `"priority_score": 0.0,` to the `grouped.setdefault`
literal, immediately after `"severity": card.get("severity"),`.

Then, immediately after the existing line

```python
        group["severity"] = _higher_severity(group.get("severity"), card.get("severity"))
```

add:

```python
        card_priority = (card.get("priority") or {}).get("score")
        if isinstance(card_priority, (int, float)):
            group["priority_score"] = max(float(group["priority_score"]), float(card_priority))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m unittest tests.test_triage_ordering -v`
Expected: PASS, 5 tests OK.

- [ ] **Step 5: Verify nothing regressed**

Run: `make quality && make test`
Expected: all clean.

- [ ] **Step 6: Commit**

```bash
git add bluearch_aws_steward/mcp_server.py tests/test_triage_ordering.py
git commit -m "feat: rank solution groups by their worst member"
```

---

### Task 6: Make report profiles change the report

`REPORT_PROFILES` is declared and `report_profile` is stored in the model, but it
has no effect on output. This task gives `executive` behaviour and passes the
existing grouped rollup through to the model.

**Files:**
- Modify: `bluearch_aws_steward/reports.py:27-150`
- Test: `tests/test_reports.py`

**Interfaces:**
- Consumes: `grouped_solutions` entries carrying `priority_score` (Task 5).
- Produces: `build_report_model(result, report_profile=...)` returns a model with
  `grouped_solutions: List[JSON]` and, for `executive`, at most 10 entries in
  `findings`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_reports.py`:

```python
class ReportProfileTests(unittest.TestCase):
    def _result(self) -> dict:
        opportunities = [
            {
                "rule": f"rule-{index:03d}",
                "service": "s3",
                "resource": f"s3://bucket-{index}",
                "severity": "low",
                "priority": {"score": float(index)},
            }
            for index in range(40)
        ]
        return {
            "observed_at": "2026-08-04T00:00:00Z",
            "provider": "aws-sdk",
            "summary": {"resources_scanned": 40},
            "complete_opportunities": opportunities,
            "grouped_solutions": [
                {"rule": "rule-039", "resources": 1, "priority_score": 39.0},
                {"rule": "rule-000", "resources": 39, "priority_score": 0.0},
            ],
        }

    def test_executive_profile_limits_findings_to_ten(self) -> None:
        from bluearch_aws_steward.reports import build_report_model

        model = build_report_model(self._result(), report_profile="executive")
        self.assertEqual(len(model["findings"]), 10)

    def test_executive_profile_keeps_the_highest_priority_findings(self) -> None:
        from bluearch_aws_steward.reports import build_report_model

        model = build_report_model(self._result(), report_profile="executive")
        scores = [item["priority_score"] for item in model["findings"]]
        self.assertEqual(scores, sorted(scores, reverse=True))
        self.assertEqual(scores[0], 39.0)

    def test_technical_profile_keeps_every_finding(self) -> None:
        from bluearch_aws_steward.reports import build_report_model

        model = build_report_model(self._result(), report_profile="technical")
        self.assertEqual(len(model["findings"]), 40)

    def test_grouped_solutions_reach_the_model_already_ranked(self) -> None:
        from bluearch_aws_steward.reports import build_report_model

        model = build_report_model(self._result(), report_profile="executive")
        self.assertEqual(len(model["grouped_solutions"]), 2)
        scores = [group["priority_score"] for group in model["grouped_solutions"]]
        self.assertEqual(scores, sorted(scores, reverse=True))
        self.assertEqual(model["grouped_solutions"][0]["rule"], "rule-039")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m unittest tests.test_reports.ReportProfileTests -v`
Expected: FAIL. `test_executive_profile_limits_findings_to_ten` reports 40, and
`test_grouped_solutions_reach_the_model` raises `KeyError: 'grouped_solutions'`.

- [ ] **Step 3: Write minimal implementation**

Add a module-level constant to `bluearch_aws_steward/reports.py`, next to
`REPORT_FORMATS`:

```python
EXECUTIVE_FINDING_LIMIT = 10
```

In `build_report_model`, after `items` is built and before the model dict is
assembled, add:

```python
    if report_profile == "executive":
        items = sorted(
            items,
            key=lambda item: -float(item.get("priority_score") or 0.0),
        )[:EXECUTIVE_FINDING_LIMIT]
```

Add one entry to the returned model dict, next to `"report_profile": report_profile,`.
The groups are ranked **here, once**, so the three renderers in Task 7 consume
already-ordered data instead of each repeating the same sort:

```python
        "grouped_solutions": sorted(
            deepcopy_json(result.get("grouped_solutions") or []),
            key=lambda group: -float(group.get("priority_score") or 0.0),
        ),
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m unittest tests.test_reports.ReportProfileTests -v`
Expected: PASS, 4 tests OK.

- [ ] **Step 5: Verify nothing regressed**

Run: `make quality && make test`
Expected: all clean.

- [ ] **Step 6: Commit**

```bash
git add bluearch_aws_steward/reports.py tests/test_reports.py
git commit -m "feat: give report profiles real behaviour"
```

---

### Task 7: Render the grouped rollup

**Files:**
- Modify: `bluearch_aws_steward/reports.py` (`_render_markdown`, `_render_html`)
- Modify: `bluearch_aws_steward/pdf_report.py` (`render_pdf_report`)
- Test: `tests/test_reports.py`

**Interfaces:**
- Consumes: `model["grouped_solutions"]` from Task 6.
- Produces: `_grouped_markdown(model) -> List[str]` and `_grouped_html(model) -> str`
  in `reports.py`; `_grouped_summary(model, styles) -> List[Any]` in `pdf_report.py`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_reports.py`, inside `ReportProfileTests`:

```python
    def test_markdown_shows_the_grouped_rollup(self) -> None:
        from bluearch_aws_steward.reports import build_report_model, render_report

        model = build_report_model(self._result(), report_profile="executive")
        rendered = render_report(model, "markdown")
        self.assertIn("Grouped Solutions", rendered)
        self.assertIn("rule-039", rendered)

    def test_html_shows_the_grouped_rollup(self) -> None:
        from bluearch_aws_steward.reports import build_report_model, render_report

        model = build_report_model(self._result(), report_profile="executive")
        rendered = render_report(model, "html")
        self.assertIn("Grouped Solutions", rendered)

    def test_executive_pdf_is_far_smaller_than_technical(self) -> None:
        from bluearch_aws_steward.pdf_report import render_pdf_report
        from bluearch_aws_steward.reports import build_report_model

        executive = render_pdf_report(build_report_model(self._result(), report_profile="executive"))
        technical = render_pdf_report(build_report_model(self._result(), report_profile="technical"))
        self.assertLess(len(executive), len(technical))
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m unittest tests.test_reports.ReportProfileTests -v`
Expected: FAIL with `AssertionError: 'Grouped Solutions' not found`

- [ ] **Step 3: Write minimal implementation**

Add to `bluearch_aws_steward/reports.py`:

`build_report_model` already ranked `grouped_solutions` in Task 6, so none of the
three renderers below sorts again — they iterate in the order they are given.

```python
def _grouped_markdown(model: JSON) -> List[str]:
    groups = model.get("grouped_solutions") or []
    if not groups:
        return []
    lines = ["", "## Grouped Solutions", ""]
    for group in groups:
        resources = group.get("resources") or group.get("solutions") or 0
        lines.append(
            f"- `{group.get('rule')}` — {resources} resource(s), "
            f"priority {group.get('priority_score', 0)}"
        )
        fix = group.get("recommended_fix")
        if fix:
            lines.append(f"  {fix}")
    return lines


def _grouped_html(model: JSON) -> str:
    groups = model.get("grouped_solutions") or []
    if not groups:
        return ""
    rows = "".join(
        "<tr>"
        f"<td>{html.escape(str(group.get('rule')))}</td>"
        f"<td>{html.escape(str(group.get('resources') or group.get('solutions') or 0))}</td>"
        f"<td>{html.escape(str(group.get('priority_score', 0)))}</td>"
        "</tr>"
        for group in groups
    )
    return (
        "<h2>Grouped Solutions</h2>"
        "<table><tr><th>Rule</th><th>Resources</th><th>Priority</th></tr>"
        f"{rows}</table>"
    )
```

In `_render_markdown`, insert the grouped section immediately before the findings
section is appended:

```python
    lines.extend(_grouped_markdown(model))
```

`_render_html` returns a single f-string template with `{contextual_html}`
interpolated into it. Add the grouped section the same way. Immediately after

```python
    contextual_html = _contextual_html(model)
```

add:

```python
    grouped_html = _grouped_html(model)
```

Then, inside the returned f-string, change

```
{contextual_html}<h2>Severity</h2><ul>{severity}</ul><h2>Findings</h2>
```

to

```
{contextual_html}{grouped_html}<h2>Severity</h2><ul>{severity}</ul><h2>Findings</h2>
```

In `bluearch_aws_steward/pdf_report.py`, add:

```python
def _grouped_summary(model: JSON, styles: Dict[str, ParagraphStyle]) -> List[Any]:
    groups = model.get("grouped_solutions") or []
    if not groups:
        return []
    story: List[Any] = [Paragraph("Grouped Solutions", styles["heading"])]
    for group in groups:
        resources = group.get("resources") or group.get("solutions") or 0
        story.append(
            Paragraph(
                _safe(
                    f"{group.get('rule')} — {resources} resource(s), "
                    f"priority {group.get('priority_score', 0)}"
                ),
                styles["small"],
            )
        )
    return story
```

In `render_pdf_report`, add `story.extend(_grouped_summary(model, styles))`
immediately after `story.extend(_coverage(summary, styles))`.

`_styles()` already returns `"heading"` and `"small"` keys, so the code above
needs no adjustment.

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m unittest tests.test_reports -v`
Expected: PASS.

- [ ] **Step 5: Verify nothing regressed**

Run: `make quality && make test`
Expected: all clean.

- [ ] **Step 6: Commit**

```bash
git add bluearch_aws_steward/reports.py bluearch_aws_steward/pdf_report.py tests/test_reports.py
git commit -m "feat: render the grouped rollup in reports"
```

---

### Task 8: Make executive the default profile

**Files:**
- Modify: `bluearch_aws_steward/reports.py:32`
- Modify: `bluearch_aws_steward/mcp_server.py:1795`
- Modify: `CHANGELOG.md`
- Test: `tests/test_reports.py`

**Interfaces:**
- Consumes: executive profile behaviour from Tasks 6 and 7.
- Produces: no new symbols.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_reports.py`, inside `ReportProfileTests`:

```python
    def test_default_profile_is_executive(self) -> None:
        from bluearch_aws_steward.reports import build_report_model

        model = build_report_model(self._result())
        self.assertEqual(model["report_profile"], "executive")
        self.assertEqual(len(model["findings"]), 10)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m unittest tests.test_reports.ReportProfileTests.test_default_profile_is_executive -v`
Expected: FAIL with `AssertionError: 'technical' != 'executive'`

- [ ] **Step 3: Write minimal implementation**

In `bluearch_aws_steward/reports.py`, change the `build_report_model` signature
default from `report_profile: str = "technical"` to `report_profile: str = "executive"`.

In `bluearch_aws_steward/mcp_server.py:1795`, change
`report_profile=str(arguments.get("report_profile") or "technical"),` to
`report_profile=str(arguments.get("report_profile") or "executive"),`.

Add to the top of `CHANGELOG.md`, under a new `## Unreleased` heading if one does
not already exist:

```markdown
### Changed

- Findings are now ranked by contextual risk instead of alphabetically within
  severity. Root credentials, publicly reachable resources and internet-exposed
  administrative ports rank above lower-risk findings that merely carry a higher
  catalog severity. Delivery order changes for every consumer.
- The default report profile is now `executive`, which leads with the ten
  highest-priority findings and the grouped rollup. Request `technical`,
  `remediation` or `complete` for the previous finding-by-finding output.

### Fixed

- PDF export no longer fails with `TypeError` when a summary reports capability
  errors, service errors or skipped rules as counts rather than lists.
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m unittest tests.test_reports -v`
Expected: PASS.

- [ ] **Step 5: Verify nothing regressed**

Run: `make quality && make test`
Expected: all clean.

This was checked before the plan was written: every existing caller of
`build_report_model` without an explicit profile uses a fixture with a single
opportunity, so the ten-finding cap cannot change their results, and
`tests/test_contextual_reviews.py:488` asserts Well-Architected practice text that
is rendered from `well_architected_review` rather than from `findings`. No
existing test should need editing. If one does fail, it is asserting the old
default rather than real behaviour — update it to request `technical` explicitly
and say so in the commit body.

- [ ] **Step 6: Commit**

```bash
git add bluearch_aws_steward/reports.py bluearch_aws_steward/mcp_server.py CHANGELOG.md tests/test_reports.py
git commit -m "feat: default reports to the executive profile"
```

---

### Task 9: Produce the validation package

The single point at which the user reviews. Everything before this runs unattended.

**Files:**
- Create: `/private/tmp/steward-triage-validation/report.md` (scratch, not committed)

**Interfaces:**
- Consumes: everything.
- Produces: a written validation report and a pushed branch.

- [ ] **Step 1: Run the full gate set**

```bash
make quality && make test && make security && make package
```
Expected: all four pass.

- [ ] **Step 2: Confirm acceptance criterion 1**

```bash
.venv/bin/python -m unittest tests.test_triage_ordering -v
```
Expected: PASS. The root access key ranks in the top 5.

- [ ] **Step 3: Confirm acceptance criterion 2**

```bash
.venv/bin/python - <<'PY'
import json, re
from bluearch_aws_steward.reports import build_report_model
from bluearch_aws_steward.pdf_report import render_pdf_report

result = json.load(open("/private/tmp/steward-waf-review/result.json"))
for profile in ("executive", "technical"):
    pdf = render_pdf_report(build_report_model(result, report_profile=profile))
    pages = len(re.findall(rb"/Type\s*/Page[^s]", pdf))
    print(f"{profile:10} {pages:4d} pages  {len(pdf):>9,d} bytes")
PY
```
Expected: `executive` reports 15 pages or fewer. If
`/private/tmp/steward-waf-review/result.json` is absent, skip this step and record
in the report that criterion 2 could not be measured against live data, stating
why.

- [ ] **Step 4: Confirm acceptance criterion 3**

```bash
.venv/bin/python -m unittest discover -s tests -p 'test_*.py' 2>&1 | tail -3
```
Expected: `OK`, with a test count of at least 240.

- [ ] **Step 5: Push the branch and open a pull request**

```bash
git push -u origin feat/triage-and-prioritization
gh pr create --base main --head feat/triage-and-prioritization \
  --title "feat: rank findings by contextual risk" \
  --body-file /private/tmp/steward-triage-validation/report.md
```

- [ ] **Step 6: Wait for CI and write the validation report**

```bash
gh pr checks --watch
```

Write `/private/tmp/steward-triage-validation/report.md` covering, with measured
numbers rather than claims:

- the three acceptance criteria and whether each held;
- the before and after position of `iam-root-access-key-present`;
- executive versus technical PDF page counts;
- the full gate results;
- CI status;
- anything that did not go to plan.

---

## Out of Scope

Tracked in the roadmap section of the design document, not implemented here:
multi-region scanning, workload granularity, EKS rules without kubeconfig, cost
estimates in USD, remediation coverage, relationship graph depth, the guided
questionnaire for non-native catalog rules, and repositioning the product
narrative. The TUI having zero test coverage is also recorded there.
