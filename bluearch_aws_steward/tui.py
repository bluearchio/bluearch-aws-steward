from __future__ import annotations

import curses
import json
import queue
import threading
import time
import traceback
from _curses import window as CursesWindow
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional

from bluearch_aws_steward.models import Finding, ScanEvent, ScanResult


@dataclass
class ResourceRow:
    resource: str
    status: str = "queued"
    findings: List[Finding] = field(default_factory=list)
    last_message: str = ""


@dataclass
class DashboardState:
    title: str
    service: str
    profile: Optional[str]
    endpoint_url: Optional[str]
    region: str
    bucket_prefix: Optional[str]
    resources_total: int = 0
    resources_seen: int = 0
    findings_total: int = 0
    rules_evaluated: int = 0
    selected_index: int = 0
    selected_rule_index: int = 0
    scroll_offset: int = 0
    active_tab: str = "all"
    rule_filter: Optional[str] = None
    detail_mode: bool = False
    running: bool = True
    status: str = "starting"
    error: Optional[str] = None
    final_result: Optional[ScanResult] = None
    resources: Dict[str, ResourceRow] = field(default_factory=dict)
    resource_order: List[str] = field(default_factory=list)


def run_scan_dashboard(
    *,
    title: str,
    service: str,
    profile: Optional[str],
    endpoint_url: Optional[str],
    region: str,
    bucket_prefix: Optional[str],
    event_factory: Callable[[], Iterable[ScanEvent]],
    output_file: Optional[str] = None,
) -> ScanResult:
    state = DashboardState(
        title=title,
        service=service,
        profile=profile,
        endpoint_url=endpoint_url,
        region=region,
        bucket_prefix=bucket_prefix,
    )
    events: "queue.Queue[ScanEvent | BaseException]" = queue.Queue()

    def worker() -> None:
        try:
            for event in event_factory():
                events.put(event)
        except Exception as exc:  # pragma: no cover - hard to exercise in curses tests
            events.put(RuntimeError(f"{exc}\n{traceback.format_exc()}"))

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()

    result = curses.wrapper(_run_curses_app, state, events)
    thread.join(timeout=1)

    if output_file and result:
        Path(output_file).write_text(
            json.dumps(result.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

    if not result:
        raise RuntimeError("Dashboard closed before the scan produced a final result.")
    return result


def _run_curses_app(
    stdscr: CursesWindow,
    state: DashboardState,
    events: "queue.Queue[ScanEvent | BaseException]",
) -> Optional[ScanResult]:
    try:
        curses.curs_set(0)
    except curses.error:
        pass
    stdscr.nodelay(True)
    stdscr.keypad(True)
    _init_colors()

    while True:
        _drain_events(events, state)
        _draw(stdscr, state)

        key = stdscr.getch()
        if key in (ord("q"), ord("Q")):
            if not state.running:
                break
            state.status = "scan still running; press q again after completion"
        elif key in (curses.KEY_DOWN, ord("j")):
            _move_selection(state, 1)
        elif key in (curses.KEY_UP, ord("k")):
            _move_selection(state, -1)
        elif key in (curses.KEY_RIGHT, ord("l")):
            _move_tab(state, 1)
        elif key in (curses.KEY_LEFT, ord("h")):
            _move_tab(state, -1)
        elif key in (curses.KEY_NPAGE,):
            _move_selection(state, 10)
        elif key in (curses.KEY_PPAGE,):
            _move_selection(state, -10)
        elif key in (ord("1"),):
            _set_tab(state, "all")
        elif key in (ord("2"),):
            _set_tab(state, "failed")
        elif key in (ord("3"),):
            _set_tab(state, "passed")
        elif key in (ord("4"),):
            _set_tab(state, "rules")
        elif key in (ord("r"), ord("R")):
            _cycle_rule_filter(state)
        elif key in (ord("c"), ord("C")):
            state.rule_filter = None
            state.selected_index = 0
            state.scroll_offset = 0
        elif key in (ord("\n"), curses.KEY_ENTER, 10, 13):
            if state.active_tab == "rules":
                selected_rule = _selected_rule(state)
                if selected_rule:
                    state.rule_filter = selected_rule
                    _set_tab(state, "failed")
            elif _visible_resources(state):
                state.detail_mode = True
        elif key in (ord("b"), ord("B"), 27):
            state.detail_mode = False
        elif key == curses.KEY_RESIZE:
            pass

        if state.error:
            state.running = False
        if not state.running and key in (ord("q"), ord("Q")):
            break

        time.sleep(0.05)

    return state.final_result


def _drain_events(events: "queue.Queue[ScanEvent | BaseException]", state: DashboardState) -> None:
    while True:
        try:
            event = events.get_nowait()
        except queue.Empty:
            return

        if isinstance(event, BaseException):
            state.error = str(event)
            notes = getattr(event, "__notes__", None)
            if notes:
                state.error = f"{state.error}\n{notes[0]}"
            state.status = "error"
            state.running = False
            continue

        _apply_event(state, event)


def _apply_event(state: DashboardState, event: ScanEvent) -> None:
    if event.type == "scan_started":
        state.status = "scanning"
        state.resources_total = int(event.data.get("resources_total", 0))
        state.rules_evaluated = int(event.data.get("rules_evaluated", 0))
    elif event.type == "resource_started" and event.resource:
        row = state.resources.setdefault(event.resource, ResourceRow(resource=event.resource))
        row.status = "scanning"
        row.last_message = event.message or ""
        if event.resource not in state.resource_order:
            state.resource_order.append(event.resource)
        state.resources_seen = len(state.resource_order)
    elif event.type == "finding" and event.resource and event.finding:
        row = state.resources.setdefault(event.resource, ResourceRow(resource=event.resource))
        row.findings.append(event.finding)
        row.status = "fail"
        row.last_message = event.message or ""
        state.findings_total += 1
    elif event.type == "resource_completed" and event.resource:
        row = state.resources.setdefault(event.resource, ResourceRow(resource=event.resource))
        row.status = str(event.data.get("status", row.status))
        row.last_message = event.message or ""
    elif event.type == "scan_completed":
        state.status = "complete"
        state.running = False
        state.final_result = event.result
        if event.result:
            state.findings_total = len(event.result.findings)


def _draw(stdscr: CursesWindow, state: DashboardState) -> None:
    stdscr.erase()
    height, width = stdscr.getmaxyx()
    if height < 12 or width < 72:
        _safe_addstr(stdscr, 0, 0, "Terminal too small. Resize to at least 72x12.", curses.A_BOLD)
        stdscr.refresh()
        return

    _draw_header(stdscr, state, width)
    if state.detail_mode:
        _draw_detail(stdscr, state, height, width)
    elif state.active_tab == "rules":
        _draw_rule_list(stdscr, state, height, width)
    else:
        _draw_resource_list(stdscr, state, height, width)
    _draw_footer(stdscr, state, height, width)
    stdscr.refresh()


def _draw_header(stdscr: CursesWindow, state: DashboardState, width: int) -> None:
    status_attr = _status_attr(state.status)
    _safe_addstr(stdscr, 0, 0, state.title[: width - 1], curses.A_BOLD)
    _safe_addstr(stdscr, 0, max(0, width - 18), f"{state.status.upper():>16}", status_attr)
    _safe_addstr(
        stdscr,
        1,
        0,
        f"service={state.service} region={state.region} profile={state.profile or 'default'} endpoint={state.endpoint_url or 'AWS'}",
    )
    if state.bucket_prefix:
        _safe_addstr(stdscr, 2, 0, f"bucket-prefix={state.bucket_prefix}")
    _safe_addstr(
        stdscr,
        3,
        0,
        _summary_line(state),
        curses.A_BOLD,
    )
    if state.error:
        _safe_addstr(
            stdscr,
            4,
            0,
            f"error: {state.error}".replace("\n", " ")[: width - 1],
            curses.color_pair(4),
        )
    else:
        _draw_tabs(stdscr, state, 5, width)


def _draw_resource_list(
    stdscr: CursesWindow, state: DashboardState, height: int, width: int
) -> None:
    top = 7
    card_height = 4
    visible_items = max(1, (height - top - 2) // card_height)
    visible_resources = _visible_resources(state)
    _clamp_selection(state, visible_items, visible_resources)

    if not visible_resources:
        _safe_addstr(stdscr, top + 2, 2, "Waiting for resources...")
        return

    for card_number, resource in enumerate(
        visible_resources[state.scroll_offset : state.scroll_offset + visible_items]
    ):
        index = state.scroll_offset + card_number
        y = top + (card_number * card_height)
        row = state.resources[resource]
        selected = index == state.selected_index
        attr = curses.A_REVERSE if selected else curses.A_NORMAL
        status_attr = _status_attr(row.status) | attr
        finding_label = "finding" if len(row.findings) == 1 else "findings"
        rules = _resource_rule_ids(row)
        header = f"{row.status.upper():<8} {resource}  ({len(row.findings)} {finding_label})"
        _safe_addstr(stdscr, y, 0, header[: width - 1], status_attr)
        _safe_addstr(
            stdscr,
            y + 1,
            2,
            f"rules: {', '.join(rules) if rules else 'none'}"[: max(0, width - 3)],
            attr,
        )
        _safe_addstr(
            stdscr, y + 2, 2, f"latest: {row.last_message or '-'}"[: max(0, width - 3)], attr
        )
        _safe_addstr(stdscr, y + 3, 0, "-" * max(8, width - 1), curses.A_DIM)


def _draw_rule_list(stdscr: CursesWindow, state: DashboardState, height: int, width: int) -> None:
    top = 7
    rules = _rule_summaries(state)
    visible_height = max(1, height - top - 2)
    if not rules:
        _safe_addstr(
            stdscr, top + 2, 2, "No findings yet. Rule view will populate as findings arrive."
        )
        return

    state.selected_rule_index = max(0, min(len(rules) - 1, state.selected_rule_index))
    _safe_addstr(stdscr, top, 0, "Rule", curses.A_BOLD)
    _safe_addstr(stdscr, top, 30, "Findings", curses.A_BOLD)
    _safe_addstr(stdscr, top, 42, "Resources", curses.A_BOLD)
    _safe_addstr(stdscr, top, 58, "Severity", curses.A_BOLD)

    for offset, rule in enumerate(rules[:visible_height], start=1):
        selected = offset - 1 == state.selected_rule_index
        attr = curses.A_REVERSE if selected else curses.A_NORMAL
        y = top + offset
        _safe_addstr(stdscr, y, 0, rule["rule"][:28], attr)
        _safe_addstr(stdscr, y, 30, f"{rule['findings']:>8}", attr)
        _safe_addstr(stdscr, y, 42, f"{rule['resources']:>9}", attr)
        _safe_addstr(stdscr, y, 58, rule["severity"][:12], attr | _severity_attr(rule["severity"]))

    _safe_addstr(
        stdscr,
        min(height - 3, top + visible_height + 1),
        0,
        "Press enter on a rule to filter failing resources by that rule.",
        curses.A_DIM,
    )


def _draw_detail(stdscr: CursesWindow, state: DashboardState, height: int, width: int) -> None:
    top = 5
    visible_resources = _visible_resources(state)
    if not visible_resources:
        _safe_addstr(stdscr, top, 0, "No resource selected.")
        return

    resource = visible_resources[state.selected_index]
    row = state.resources[resource]
    _safe_addstr(stdscr, top, 0, resource[: width - 1], curses.A_BOLD)
    _safe_addstr(stdscr, top + 1, 0, f"status={row.status} findings={len(row.findings)}")

    y = top + 3
    if not row.findings:
        _safe_addstr(stdscr, y, 2, "No findings for this resource.")
        return

    detail_findings = _filter_findings_by_rule(row.findings, state.rule_filter)
    for finding in detail_findings:
        if y >= height - 3:
            _safe_addstr(stdscr, y, 2, "...", curses.A_DIM)
            break
        _safe_addstr(
            stdscr,
            y,
            0,
            f"[{finding.severity.upper()}] {finding.rule_short_id}",
            curses.A_BOLD | _status_attr("fail"),
        )
        y += 1
        for line in [
            f"finding: {finding.finding_id}",
            f"rule:    {finding.rule_id}",
            f"risk:    {finding.risk_detail}",
            f"why:     {finding.scenario}",
            f"fix:     {finding.remediation.summary}",
            f"verify:  {finding.remediation.verification}",
        ]:
            if y >= height - 3:
                break
            _safe_addstr(stdscr, y, 2, line[: max(0, width - 3)])
            y += 1
        if y < height - 3:
            _safe_addstr(stdscr, y, 2, "evidence:", curses.A_BOLD)
            y += 1
        for key, value in finding.evidence.items():
            if y >= height - 3:
                break
            _safe_addstr(
                stdscr, y, 4, f"- {key}: {_format_evidence_value(value)}"[: max(0, width - 5)]
            )
            y += 1
        y += 1


def _draw_footer(stdscr: CursesWindow, state: DashboardState, height: int, width: int) -> None:
    if state.detail_mode:
        text = "up/down: select resource | b/esc: back | r: cycle rule filter | q: quit after scan"
    elif state.active_tab == "rules":
        text = "1-4/h/l: tabs | up/down: select rule | enter: filter by rule | c: clear filter | q: quit"
    else:
        text = (
            "1-4/h/l: tabs | up/down: select | enter: inspect | r: rule filter | c: clear | q: quit"
        )
    _safe_addstr(stdscr, height - 1, 0, text[: width - 1], curses.A_REVERSE)


def _move_selection(state: DashboardState, delta: int) -> None:
    if state.active_tab == "rules":
        rules = _rule_summaries(state)
        if not rules:
            return
        state.selected_rule_index = max(0, min(len(rules) - 1, state.selected_rule_index + delta))
        return
    visible_resources = _visible_resources(state)
    if not visible_resources:
        return
    state.selected_index = max(0, min(len(visible_resources) - 1, state.selected_index + delta))


def _clamp_selection(
    state: DashboardState, visible_items: int, visible_resources: List[str]
) -> None:
    if not visible_resources:
        state.selected_index = 0
        state.scroll_offset = 0
        return
    state.selected_index = max(0, min(len(visible_resources) - 1, state.selected_index))
    if state.selected_index < state.scroll_offset:
        state.scroll_offset = state.selected_index
    elif state.selected_index >= state.scroll_offset + visible_items:
        state.scroll_offset = state.selected_index - visible_items + 1


def _init_colors() -> None:
    if not curses.has_colors():
        return
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(1, curses.COLOR_GREEN, -1)
    curses.init_pair(2, curses.COLOR_YELLOW, -1)
    curses.init_pair(3, curses.COLOR_CYAN, -1)
    curses.init_pair(4, curses.COLOR_RED, -1)


def _status_attr(status: str) -> int:
    if not curses.has_colors():
        return curses.A_NORMAL
    if status in {"pass", "complete"}:
        return curses.color_pair(1)
    if status in {"scanning", "starting"}:
        return curses.color_pair(3)
    if status in {"fail", "error"}:
        return curses.color_pair(4)
    return curses.color_pair(2)


def _severity_attr(severity: str) -> int:
    if not curses.has_colors():
        return curses.A_NORMAL
    if severity == "high":
        return curses.color_pair(4)
    if severity == "medium":
        return curses.color_pair(2)
    return curses.color_pair(3)


def _safe_addstr(
    stdscr: CursesWindow, y: int, x: int, text: str, attr: int = curses.A_NORMAL
) -> None:
    height, width = stdscr.getmaxyx()
    if y < 0 or y >= height or x < 0 or x >= width:
        return
    try:
        stdscr.addstr(y, x, text[: max(0, width - x - 1)], attr)
    except curses.error:
        pass


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


def _summary_line(state: DashboardState) -> str:
    counts = _category_counts(state)
    rule_filter = state.rule_filter or "all"
    return (
        f"resources {state.resources_seen}/{state.resources_total} | "
        f"fail {counts['failed']} | pass {counts['passed']} | scanning {counts['scanning']} | "
        f"findings {state.findings_total} | rules {state.rules_evaluated} | rule filter {rule_filter}"
    )


def _draw_tabs(stdscr: CursesWindow, state: DashboardState, y: int, width: int) -> None:
    counts = _category_counts(state)
    tabs = [
        ("1", "all", f"All {len(state.resource_order)}"),
        ("2", "failed", f"Failed {counts['failed']}"),
        ("3", "passed", f"Passed {counts['passed']}"),
        ("4", "rules", f"Rules {len(_rule_summaries(state))}"),
    ]
    x = 0
    for key, tab, label in tabs:
        text = f" {key} {label} "
        attr = curses.A_REVERSE | curses.A_BOLD if state.active_tab == tab else curses.A_BOLD
        _safe_addstr(stdscr, y, x, text[: max(0, width - x - 1)], attr)
        x += len(text) + 1
    hint = "enter=details r=rule-filter c=clear"
    _safe_addstr(stdscr, y, max(0, width - len(hint) - 1), hint, curses.A_DIM)


def _visible_resources(state: DashboardState) -> List[str]:
    resources: List[str] = []
    for resource in state.resource_order:
        row = state.resources[resource]
        if state.active_tab == "failed" and row.status != "fail":
            continue
        if state.active_tab == "passed" and row.status != "pass":
            continue
        if state.rule_filter and state.rule_filter not in _resource_rule_ids(row):
            continue
        resources.append(resource)
    return resources


def _category_counts(state: DashboardState) -> Dict[str, int]:
    counts = {"failed": 0, "passed": 0, "scanning": 0, "queued": 0}
    for row in state.resources.values():
        if row.status == "fail":
            counts["failed"] += 1
        elif row.status == "pass":
            counts["passed"] += 1
        elif row.status == "scanning":
            counts["scanning"] += 1
        else:
            counts["queued"] += 1
    return counts


def _resource_rule_ids(row: ResourceRow) -> List[str]:
    return sorted({finding.rule_short_id for finding in row.findings})


def _rule_summaries(state: DashboardState) -> List[Dict[str, Any]]:
    by_rule: Dict[str, Dict[str, Any]] = {}
    for row in state.resources.values():
        for finding in row.findings:
            summary = by_rule.setdefault(
                finding.rule_short_id,
                {
                    "rule": finding.rule_short_id,
                    "findings": 0,
                    "resources": set(),
                    "severity": finding.severity,
                },
            )
            summary["findings"] += 1
            summary["resources"].add(row.resource)
            if finding.severity == "high":
                summary["severity"] = "high"
    results: List[Dict[str, Any]] = []
    for summary in by_rule.values():
        results.append(
            {
                "rule": summary["rule"],
                "findings": summary["findings"],
                "resources": len(summary["resources"]),
                "severity": summary["severity"],
            }
        )
    return sorted(results, key=lambda item: (-item["findings"], item["rule"]))


def _set_tab(state: DashboardState, tab: str) -> None:
    state.active_tab = tab
    state.detail_mode = False
    state.selected_index = 0
    state.scroll_offset = 0


def _move_tab(state: DashboardState, delta: int) -> None:
    tabs = ["all", "failed", "passed", "rules"]
    current = tabs.index(state.active_tab) if state.active_tab in tabs else 0
    _set_tab(state, tabs[(current + delta) % len(tabs)])


def _cycle_rule_filter(state: DashboardState) -> None:
    rules = [None] + [summary["rule"] for summary in _rule_summaries(state)]
    if not rules:
        return
    current = rules.index(state.rule_filter) if state.rule_filter in rules else 0
    state.rule_filter = rules[(current + 1) % len(rules)]
    state.selected_index = 0
    state.scroll_offset = 0


def _selected_rule(state: DashboardState) -> Optional[str]:
    rules = _rule_summaries(state)
    if not rules:
        return None
    state.selected_rule_index = max(0, min(len(rules) - 1, state.selected_rule_index))
    return str(rules[state.selected_rule_index]["rule"])


def _filter_findings_by_rule(findings: List[Finding], rule_filter: Optional[str]) -> List[Finding]:
    if not rule_filter:
        return findings
    return [finding for finding in findings if finding.rule_short_id == rule_filter]
