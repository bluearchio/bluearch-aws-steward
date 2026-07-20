from __future__ import annotations

import json
import queue
import threading
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, cast

from rich.markup import escape
from textual import on
from textual.app import App, ComposeResult
from textual.containers import Container, Grid, Horizontal, Vertical, VerticalScroll
from textual.css.query import NoMatches
from textual.widgets import Button, Footer, Header, LoadingIndicator, RichLog, Static

from bluearch_aws_steward.models import Finding, ScanEvent, ScanResult


@dataclass
class ResourceRow:
    resource: str
    status: str = "queued"
    findings: List[Finding] = field(default_factory=list)
    last_message: str = ""


@dataclass
class ModernDashboardState:
    title: str
    service: str
    profile: Optional[str]
    endpoint_url: Optional[str]
    region: str
    bucket_prefix: Optional[str]
    output_file: Optional[str]
    resources_total: int = 0
    resources_seen: int = 0
    findings_total: int = 0
    rules_evaluated: int = 0
    rule_filter: Optional[str] = None
    selected_resource: Optional[str] = None
    running: bool = False
    status: str = "idle"
    error: Optional[str] = None
    final_result: Optional[ScanResult] = None
    resources: Dict[str, ResourceRow] = field(default_factory=dict)
    resource_order: List[str] = field(default_factory=list)

    def reset_for_scan(self) -> None:
        self.resources_total = 0
        self.resources_seen = 0
        self.findings_total = 0
        self.rules_evaluated = 0
        self.rule_filter = None
        self.selected_resource = None
        self.running = True
        self.status = "starting"
        self.error = None
        self.final_result = None
        self.resources.clear()
        self.resource_order.clear()


class MetricCard(Static):
    can_focus = True

    def __init__(self, action_name: str, **kwargs: Any) -> None:
        self.action_name = action_name
        super().__init__("", classes=f"metric metric-{action_name}", **kwargs)

    def on_click(self) -> None:
        cast("StewardDashboardApp", self.app).handle_metric_action(self.action_name)


class ResourceCard(Static):
    can_focus = True

    def __init__(self, resource: str, row: ResourceRow, selected: bool) -> None:
        self.resource = resource
        classes = f"resource-card {row.status}"
        if selected:
            classes += " selected"
        super().__init__(_render_resource_card(resource, row), classes=classes)

    def on_click(self) -> None:
        cast("StewardDashboardApp", self.app).select_resource(self.resource)

    def on_focus(self) -> None:
        cast("StewardDashboardApp", self.app).select_resource(self.resource)


class StewardDashboardApp(App[Optional[ScanResult]]):
    TITLE = "BlueArch AWS Steward"

    CSS = """
    Screen {
        background: #05070d;
        color: #d7e3f4;
    }

    Header {
        background: #07111d;
        color: #d7e3f4;
    }

    #shell {
        height: 100%;
        layout: vertical;
    }

    #topbar {
        height: 7;
        padding: 1 2;
        background: #07111d;
        border-bottom: heavy #0b63f6;
    }

    #brand {
        width: 1fr;
        height: 5;
    }

    #title {
        height: 1;
        color: #edf5ff;
        text-style: bold;
    }

    #context {
        height: 1;
        color: #89a4bf;
    }

    #pipeline {
        height: 1;
        color: #6a8299;
    }

    #scan-monitor {
        width: 42;
        height: 5;
        padding: 0 1;
        border: round #20344a;
        background: #09131f;
    }

    #scan-monitor.scanning {
        border: heavy #17c9ff;
    }

    #scan-monitor.complete {
        border: heavy #20c7a9;
    }

    #scan-monitor.error {
        border: heavy #ff6b6b;
    }

    #scan-spinner {
        width: 4;
        height: 3;
        margin-right: 1;
        color: #17c9ff;
    }

    #scan-state {
        width: 1fr;
        height: 3;
    }

    #update-button {
        height: 3;
        margin-top: 0;
        border: tall #0b63f6;
        background: #0b1d36;
        color: #edf5ff;
    }

    #metrics {
        height: 5;
        padding: 1 2 0 2;
        background: #05070d;
    }

    .metric {
        width: 1fr;
        height: 3;
        margin-right: 1;
        padding: 0 1;
        border: round #20344a;
        background: #09131f;
        color: #d7e3f4;
    }

    .metric:hover,
    .metric:focus {
        border: heavy #0b63f6;
        background: #0b1d36;
    }

    .metric-findings {
        border: round #ff6b6b;
    }

    .metric-filter {
        border: round #17c9ff;
    }

    #filter-bar {
        height: 4;
        padding: 0 2 1 2;
        background: #05070d;
    }

    .rule-chip {
        min-width: 16;
        height: 3;
        margin-right: 1;
        border: tall #20344a;
        background: #09131f;
        color: #9fb6cc;
    }

    .rule-chip.active {
        border: tall #17c9ff;
        background: #0b1d36;
        color: #edf5ff;
        text-style: bold;
    }

    #matched-only-label {
        width: 27;
        height: 3;
        padding: 1 1 0 1;
        color: #89a4bf;
        text-style: bold;
    }

    #rule-filters {
        width: 1fr;
        height: 3;
        overflow-x: auto;
    }

    #workspace {
        height: 1fr;
        padding: 0 2 1 2;
    }

    #left-pane {
        width: 2fr;
        min-width: 74;
        margin-right: 1;
    }

    #right-pane {
        width: 1fr;
        min-width: 42;
    }

    .pane-title {
        height: 1;
        color: #89a4bf;
        text-style: bold;
    }

    #resource-scroll {
        height: 1fr;
        background: #05070d;
    }

    #resource-grid {
        layout: grid;
        grid-size: 2;
        grid-columns: 1fr 1fr;
        grid-gutter: 1 1;
        padding: 0 1 1 0;
    }

    .resource-card {
        height: 7;
        padding: 0 1;
        border: round #20344a;
        background: #09131f;
    }

    .resource-card.fail {
        border: round #ff6b6b;
    }

    .resource-card.pass {
        border: round #20c7a9;
    }

    .resource-card.scanning {
        border: round #17c9ff;
    }

    .resource-card.selected {
        background: #10283a;
        border: heavy #17c9ff;
    }

    #detail {
        height: 1fr;
        padding: 1;
        border: round #20344a;
        background: #09131f;
    }

    #detail-actions {
        height: 4;
        padding-top: 1;
    }

    #copy-remediation,
    #detail-refresh {
        height: 3;
        margin-right: 1;
        border: tall #20344a;
        background: #09131f;
        color: #d7e3f4;
    }

    #copy-remediation:hover,
    #detail-refresh:hover {
        border: tall #0b63f6;
        background: #0b1d36;
    }

    #activity {
        height: 8;
        margin-top: 1;
        padding: 0 1;
        border: round #20344a;
        background: #07111d;
    }

    Footer {
        background: #07111d;
        color: #9fb6cc;
    }
    """

    BINDINGS = [
        ("q", "request_quit", "Quit"),
        ("u", "refresh_scan", "Update"),
        ("r", "next_rule", "Next rule"),
        ("c", "clear_filters", "Clear filters"),
        ("up", "move_selection('up')", "Up"),
        ("down", "move_selection('down')", "Down"),
        ("left", "move_selection('left')", "Left"),
        ("right", "move_selection('right')", "Right"),
        ("k", "move_selection('up')", "Up"),
        ("j", "move_selection('down')", "Down"),
        ("l", "move_selection('right')", "Right"),
        ("enter", "copy_remediation", "Copy fix"),
    ]

    GRID_COLUMNS = 2

    def __init__(
        self,
        state: ModernDashboardState,
        event_factory: Callable[[], Iterable[ScanEvent]],
    ) -> None:
        super().__init__()
        self.state_model = state
        self.event_factory = event_factory
        self.events: "queue.Queue[ScanEvent | BaseException]" = queue.Queue()
        self._rule_chip_ids: List[str] = []
        self._scan_thread: Optional[threading.Thread] = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Container(id="shell"):
            with Horizontal(id="topbar"):
                with Vertical(id="brand"):
                    yield Static(self.state_model.title, id="title")
                    yield Static("", id="context")
                    yield Static(
                        "scan event stream -> AWS provider adapter -> current account state",
                        id="pipeline",
                    )
                with Vertical(id="scan-monitor"):
                    with Horizontal():
                        yield LoadingIndicator(id="scan-spinner")
                        yield Static("", id="scan-state")
                    yield Button("Update scan", id="update-button")
            with Horizontal(id="metrics"):
                yield MetricCard("resources", id="metric-resources")
                yield MetricCard("findings", id="metric-findings")
                yield MetricCard("rules", id="metric-rules")
                yield MetricCard("filter", id="metric-filter")
            with Horizontal(id="filter-bar"):
                with Horizontal(id="view-filters"):
                    yield Static("Matched resources only", id="matched-only-label")
                with Horizontal(id="rule-filters"):
                    pass
            with Horizontal(id="workspace"):
                with Vertical(id="left-pane"):
                    yield Static("Resources", classes="pane-title")
                    with VerticalScroll(id="resource-scroll"):
                        yield Grid(id="resource-grid")
                with Vertical(id="right-pane"):
                    yield Static(
                        "Select a resource to inspect evidence and remediation.", id="detail"
                    )
                    with Horizontal(id="detail-actions"):
                        yield Button("Copy fix command", id="copy-remediation")
                        yield Button("Update scan", id="detail-refresh")
                    yield RichLog(id="activity", highlight=False, wrap=True, max_lines=200)
        yield Footer()

    def on_mount(self) -> None:
        self.set_interval(0.08, self._drain_events)
        self._start_scan()

    @on(Button.Pressed, "#update-button")
    @on(Button.Pressed, "#detail-refresh")
    def on_update_pressed(self) -> None:
        self.action_refresh_scan()

    @on(Button.Pressed, "#copy-remediation")
    def on_copy_remediation_pressed(self) -> None:
        self.action_copy_remediation()

    @on(Button.Pressed, ".rule-chip")
    def on_rule_chip_pressed(self, event: Button.Pressed) -> None:
        self._set_rule_filter(event.button.name or "__all__")

    def handle_metric_action(self, action_name: str) -> None:
        if action_name == "resources":
            self.action_clear_filters()
        elif action_name == "findings":
            self.action_clear_filters()
        elif action_name == "rules":
            self.action_next_rule()
        elif action_name == "filter":
            if self.state_model.rule_filter:
                self._set_rule_filter("__all__")
            else:
                self.action_next_rule()

    def select_resource(self, resource: str) -> None:
        self.state_model.selected_resource = resource
        self._refresh_resource_grid()
        self._refresh_detail()

    def action_next_rule(self) -> None:
        rules = [None] + [summary["rule"] for summary in _rule_summaries(self.state_model)]
        if len(rules) <= 1:
            self._write_log("[yellow]No rules discovered yet.[/]")
            return
        current = (
            rules.index(self.state_model.rule_filter)
            if self.state_model.rule_filter in rules
            else 0
        )
        self._set_rule_filter(rules[(current + 1) % len(rules)] or "__all__")

    def action_clear_filters(self) -> None:
        self.state_model.rule_filter = None
        self._select_first_visible_if_needed(force=True)
        self._refresh_ui()

    def action_move_selection(self, direction: str) -> None:
        resources = _visible_resources(self.state_model)
        if not resources:
            return
        current = self.state_model.selected_resource
        current_index = resources.index(current) if current in resources else 0
        if direction == "left":
            next_index = current_index - 1
        elif direction == "right":
            next_index = current_index + 1
        elif direction == "up":
            next_index = current_index - self.GRID_COLUMNS
        elif direction == "down":
            next_index = current_index + self.GRID_COLUMNS
        else:
            next_index = current_index
        next_index = max(0, min(len(resources) - 1, next_index))
        self.select_resource(resources[next_index])

    def action_copy_remediation(self) -> None:
        finding = _selected_finding(self.state_model)
        if not finding:
            self._write_log(
                "[yellow]No remediation command available for the current selection.[/]"
            )
            return
        command = _remediation_command(self.state_model, finding)
        self.copy_to_clipboard(command)
        self._write_log(f"[green]copied remediation command[/] {escape(finding.finding_id)}")

    def action_refresh_scan(self) -> None:
        if self.state_model.running:
            self._write_log("[yellow]Scan is already running.[/]")
            return
        self._start_scan()

    def action_request_quit(self) -> None:
        if self.state_model.running:
            self._write_log("[yellow]Scan is still running. Press q after completion to quit.[/]")
            return
        self.exit(self.state_model.final_result)

    def _start_scan(self) -> None:
        self.events = queue.Queue()
        self.state_model.reset_for_scan()
        self._rule_chip_ids = []
        self.query_one("#activity", RichLog).clear()
        self._refresh_ui()

        def worker() -> None:
            try:
                for event in self.event_factory():
                    self.events.put(event)
            except Exception as exc:  # pragma: no cover - hard to exercise in TUI tests
                self.events.put(RuntimeError(f"{exc}\n{traceback.format_exc()}"))

        self._scan_thread = threading.Thread(target=worker, daemon=True)
        self._scan_thread.start()
        self._write_log("[cyan]scan requested[/]")

    def _set_rule_filter(self, rule_id: str) -> None:
        self.state_model.rule_filter = None if rule_id == "__all__" else rule_id
        self._select_first_visible_if_needed(force=True)
        self._refresh_ui()

    def _drain_events(self) -> None:
        changed = False
        while True:
            try:
                event = self.events.get_nowait()
            except queue.Empty:
                break

            if isinstance(event, BaseException):
                self.state_model.error = str(event)
                notes = getattr(event, "__notes__", None)
                if notes:
                    self.state_model.error = f"{self.state_model.error}\n{notes[0]}"
                self.state_model.status = "error"
                self.state_model.running = False
                self._write_log(f"[red]error:[/] {escape(self.state_model.error)}")
                changed = True
                continue

            self._apply_event(event)
            changed = True

        if changed:
            self._select_first_visible_if_needed()
            self._refresh_ui()

    def _apply_event(self, event: ScanEvent) -> None:
        state = self.state_model
        if event.type == "scan_started":
            state.status = "scanning"
            state.resources_total = int(event.data.get("resources_total", 0))
            state.rules_evaluated = int(event.data.get("rules_evaluated", 0))
            self._write_log("[cyan]scan started[/]")
        elif event.type == "resource_started" and event.resource:
            row = state.resources.setdefault(event.resource, ResourceRow(resource=event.resource))
            row.status = "scanning"
            row.last_message = event.message or ""
            if event.resource not in state.resource_order:
                state.resource_order.append(event.resource)
            state.resources_seen = len(state.resource_order)
            self._write_log(f"[blue]scanning[/] {escape(event.resource)}")
        elif event.type == "finding" and event.resource and event.finding:
            row = state.resources.setdefault(event.resource, ResourceRow(resource=event.resource))
            row.findings.append(event.finding)
            row.status = "fail"
            row.last_message = event.message or ""
            state.findings_total += 1
            self._write_log(
                f"[red]{escape(event.finding.rule_short_id)}[/] {escape(event.resource)}"
            )
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
                self._write_log("[green]scan complete[/]")

    def _refresh_ui(self) -> None:
        self._refresh_header()
        self._refresh_metrics()
        self._refresh_filters()
        self._refresh_resource_grid()
        self._refresh_detail()

    def _refresh_header(self) -> None:
        state = self.state_model
        endpoint = state.endpoint_url or "AWS"
        prefix = f" bucket-prefix={state.bucket_prefix}" if state.bucket_prefix else ""
        self.query_one("#context", Static).update(
            f"service={escape(state.service)} region={escape(state.region)} "
            f"profile={escape(state.profile or 'default')} endpoint={escape(endpoint)}{escape(prefix)}"
        )
        monitor = self.query_one("#scan-monitor", Vertical)
        monitor.set_class(state.status == "scanning" or state.status == "starting", "scanning")
        monitor.set_class(state.status == "complete", "complete")
        monitor.set_class(state.status == "error", "error")
        self.query_one("#scan-spinner", LoadingIndicator).display = state.running
        status_style = "cyan" if state.running else "green"
        if state.status == "error":
            status_style = "red"
        self.query_one("#scan-state", Static).update(
            f"[dim]SCAN MONITOR[/]\n"
            f"[bold {status_style}]{escape(state.status.upper())}[/] "
            f"{state.resources_seen}/{state.resources_total} resources\n"
            f"[dim]{state.findings_total} findings, {state.rules_evaluated} rules[/]"
        )
        self.query_one("#update-button", Button).disabled = state.running
        self.query_one("#detail-refresh", Button).disabled = state.running

    def _refresh_metrics(self) -> None:
        state = self.state_model
        counts = _category_counts(state)
        matched_resources = counts["failed"]
        self.query_one("#metric-resources", MetricCard).update(
            f"[dim]MATCHED RESOURCES[/]\n[bold red]{matched_resources}[/] with findings\n"
            f"[dim]{state.resources_seen}/{state.resources_total} scanned[/]"
        )
        self.query_one("#metric-findings", MetricCard).update(
            f"[dim]FINDINGS[/]\n[bold red]{state.findings_total}[/] needs action\n"
            f"[dim]click: clear rule filter[/]"
        )
        self.query_one("#metric-rules", MetricCard).update(
            f"[dim]RULE COVERAGE[/]\n[bold]{state.rules_evaluated}[/] evaluated, {len(_rule_summaries(state))} active\n"
            f"[dim]click: next rule[/]"
        )
        self.query_one("#metric-filter", MetricCard).update(
            f"[dim]FILTER[/]\n[bold]{escape(_filter_label(state))}[/]\n[dim]click: change/clear[/]"
        )
        self.query_one("#metric-findings", MetricCard).set_class(
            counts["failed"] > 0, "metric-findings"
        )
        self.query_one("#metric-filter", MetricCard).set_class(
            bool(state.rule_filter), "metric-filter"
        )

    def _refresh_filters(self) -> None:
        rule_ids = [summary["rule"] for summary in _rule_summaries(self.state_model)]
        chip_ids = ["__all__"] + rule_ids
        if chip_ids != self._rule_chip_ids:
            self._rule_chip_ids = chip_ids
            rule_bar = self.query_one("#rule-filters", Horizontal)
            rule_bar.remove_children()
            buttons: List[Button] = [Button("All rules", name="__all__", classes="rule-chip")]
            for rule_id in rule_ids:
                buttons.append(
                    Button(_compact_rule_label(rule_id), name=rule_id, classes="rule-chip")
                )
            rule_bar.mount_all(buttons)

        for button in self.query(".rule-chip").results(Button):
            button.set_class(button.name == (self.state_model.rule_filter or "__all__"), "active")

    def _refresh_resource_grid(self) -> None:
        grid = self.query_one("#resource-grid", Grid)
        resources = _visible_resources(self.state_model)
        grid.remove_children()
        if not resources:
            grid.mount(Static(_empty_message(self.state_model), classes="resource-card"))
            return
        grid.mount_all(
            ResourceCard(
                resource,
                self.state_model.resources[resource],
                selected=resource == self.state_model.selected_resource,
            )
            for resource in resources
        )

    def _refresh_detail(self) -> None:
        state = self.state_model
        detail = self.query_one("#detail", Static)
        if state.error:
            detail.update(f"[bold red]Error[/]\n{escape(state.error)}")
            return
        if state.selected_resource and state.selected_resource in state.resources:
            detail.update(_render_resource_detail(state, state.resources[state.selected_resource]))
            return
        detail.update("Select a resource card to inspect evidence and remediation actions.")

    def _select_first_visible_if_needed(self, force: bool = False) -> None:
        resources = _visible_resources(self.state_model)
        if force or self.state_model.selected_resource not in resources:
            self.state_model.selected_resource = resources[0] if resources else None

    def _write_log(self, message: str) -> None:
        try:
            self.query_one("#activity", RichLog).write(message)
        except NoMatches:
            return


def run_textual_scan_dashboard(
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
    state = ModernDashboardState(
        title=title,
        service=service,
        profile=profile,
        endpoint_url=endpoint_url,
        region=region,
        bucket_prefix=bucket_prefix,
        output_file=output_file,
    )
    app = StewardDashboardApp(state, event_factory)
    result = app.run()

    final_result = result or state.final_result
    if output_file and final_result:
        Path(output_file).write_text(
            json.dumps(final_result.to_dict(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    if not final_result:
        raise RuntimeError("Dashboard closed before the scan produced a final result.")
    return final_result


def _visible_resources(state: ModernDashboardState) -> List[str]:
    resources: List[str] = []
    for resource in state.resource_order:
        row = state.resources[resource]
        if not row.findings:
            continue
        if state.rule_filter and state.rule_filter not in _resource_rule_ids(row):
            continue
        resources.append(resource)
    return resources


def _category_counts(state: ModernDashboardState) -> Dict[str, int]:
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


def _rule_summaries(state: ModernDashboardState) -> List[Dict[str, Any]]:
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
                    "risk_detail": finding.risk_detail,
                    "scenario": finding.scenario,
                },
            )
            summary["findings"] += 1
            summary["resources"].add(row.resource)
            if finding.severity == "high":
                summary["severity"] = "high"
    return sorted(
        [
            {
                "rule": summary["rule"],
                "findings": summary["findings"],
                "resources": len(summary["resources"]),
                "severity": summary["severity"],
                "risk_detail": summary["risk_detail"],
                "scenario": summary["scenario"],
            }
            for summary in by_rule.values()
        ],
        key=lambda item: (-item["findings"], item["rule"]),
    )


def _render_resource_card(resource: str, row: ResourceRow) -> str:
    rules = _resource_rule_ids(row)
    rule_line = ", ".join(rules) if rules else "none"
    severity = _highest_severity(row.findings)
    color = _status_color(row.status)
    short_resource = _short_resource_name(resource)
    return (
        f"[bold {color}]{escape(row.status.upper())}[/] [bold]{escape(short_resource)}[/]\n"
        f"[dim]{escape(resource)}[/]\n"
        f"[dim]findings[/] {len(row.findings)}   [dim]severity[/] {escape(severity)}\n"
        f"[dim]rules[/] {escape(rule_line)}\n"
        f"[dim]latest[/] {escape(row.last_message or '-')}"
    )


def _render_resource_detail(state: ModernDashboardState, row: ResourceRow) -> str:
    findings = _filter_findings_by_rule(row.findings, state.rule_filter)
    lines = [
        f"[bold]{escape(row.resource)}[/]",
        f"[dim]status[/] [bold {_status_color(row.status)}]{escape(row.status)}[/]   "
        f"[dim]findings[/] {len(findings)}",
        "",
    ]
    if not findings:
        lines.append("No findings match the current filter.")
        return "\n".join(lines)

    for finding in findings:
        lines.extend(
            [
                f"[bold {_severity_color(finding.severity)}]{escape(finding.rule_short_id)}[/]",
                f"[dim]risk[/] {escape(finding.risk_detail)}",
                f"[dim]why[/] {escape(finding.scenario)}",
                "",
                "[bold]Remediation actions[/]",
                f"summary: {escape(finding.remediation.summary)}",
            ]
        )
        for index, action in enumerate(finding.remediation.actions, start=1):
            lines.append(f"{index}. {escape(action)}")
        lines.extend(
            [
                f"approval: {'required' if finding.remediation.requires_approval else 'not required'}",
                f"safety: {escape(finding.remediation.safety_level)}",
                f"verify: {escape(finding.remediation.verification)}",
                "",
                "[bold]Command[/]",
                escape(_remediation_command(state, finding)),
                "",
                "[bold]Evidence[/]",
            ]
        )
        for key, value in finding.evidence.items():
            lines.append(f"- {escape(str(key))}: {escape(_format_evidence_value(value))}")
        lines.append("")
    return "\n".join(lines).rstrip()


def _selected_finding(state: ModernDashboardState) -> Optional[Finding]:
    if not state.selected_resource:
        return None
    row = state.resources.get(state.selected_resource)
    if not row:
        return None
    findings = _filter_findings_by_rule(row.findings, state.rule_filter)
    return findings[0] if findings else None


def _remediation_command(state: ModernDashboardState, finding: Finding) -> str:
    scan_file = state.output_file or "<scan-output.json>"
    parts = [
        "bluearch-steward",
        "remediate",
        "--scan-file",
        scan_file,
        "--finding-id",
        finding.finding_id,
        "--allow-write",
    ]
    if state.profile:
        parts.extend(["--profile", state.profile])
    if state.endpoint_url:
        parts.extend(["--endpoint-url", state.endpoint_url])
    if state.region:
        parts.extend(["--region", state.region])
    if state.bucket_prefix:
        parts.extend(["--bucket-prefix", state.bucket_prefix])
    return " ".join(parts)


def _filter_findings_by_rule(findings: List[Finding], rule_filter: Optional[str]) -> List[Finding]:
    if not rule_filter:
        return findings
    return [finding for finding in findings if finding.rule_short_id == rule_filter]


def _highest_severity(findings: List[Finding]) -> str:
    if any(finding.severity == "high" for finding in findings):
        return "high"
    if any(finding.severity == "medium" for finding in findings):
        return "medium"
    if findings:
        return findings[0].severity
    return "none"


def _status_color(status: str) -> str:
    if status == "pass":
        return "green"
    if status == "fail":
        return "red"
    if status == "scanning":
        return "cyan"
    return "yellow"


def _severity_color(severity: str) -> str:
    if severity == "high":
        return "red"
    if severity == "medium":
        return "yellow"
    return "cyan"


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


def _compact_rule_label(rule_id: str) -> str:
    return rule_id.replace("s3-", "")


def _short_resource_name(resource: str) -> str:
    if resource.startswith("s3://"):
        return resource.removeprefix("s3://")
    return resource


def _filter_label(state: ModernDashboardState) -> str:
    if state.rule_filter:
        return state.rule_filter
    return "all matched"


def _empty_message(state: ModernDashboardState) -> str:
    if state.rule_filter:
        return f"No rule-matched resources for {state.rule_filter}."
    return "No rule-matched resources yet."
