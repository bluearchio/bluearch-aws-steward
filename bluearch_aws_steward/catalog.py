from __future__ import annotations

import json
from importlib import resources
from typing import Iterable, List

from bluearch_aws_steward.models import Rule


def load_rules() -> List[Rule]:
    with (
        resources.files("bluearch_aws_steward")
        .joinpath("catalog/rules.json")
        .open("r", encoding="utf-8") as handle
    ):
        payload = json.load(handle)
    return [Rule(**rule) for rule in payload["rules"]]


def filter_rules(service: str | None = None, query: str | None = None) -> List[Rule]:
    rules: Iterable[Rule] = load_rules()
    if service:
        rules = [rule for rule in rules if rule.service == service]
    if query:
        needle = query.lower()
        rules = [
            rule
            for rule in rules
            if needle in rule.id.lower()
            or needle in rule.short_id.lower()
            or needle in rule.scenario.lower()
            or needle in rule.risk_detail.lower()
        ]
    return list(rules)
