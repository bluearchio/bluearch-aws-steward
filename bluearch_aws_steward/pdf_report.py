"""Polished local PDF renderer for completed Steward assessments."""

from __future__ import annotations

import html
import io
from typing import Any, Callable, Dict, Iterable, List, Tuple

from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.lib import colors
from reportlab.lib.colors import Color, HexColor
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfgen.canvas import Canvas
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    LongTable,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from bluearch_aws_steward.reports import group_label, group_member_count, group_priority

JSON = Dict[str, Any]

BLUE = HexColor("#1F6FEB")
CYAN = HexColor("#00A6C7")
INK = HexColor("#172033")
MUTED = HexColor("#536174")
PALE = HexColor("#EDF4FF")
BORDER = HexColor("#D8E1EC")
CRITICAL = HexColor("#8B1E3F")
HIGH = HexColor("#D64545")
MEDIUM = HexColor("#D98B1F")
LOW = HexColor("#267A5E")
UNKNOWN = HexColor("#667085")
SEVERITY_COLORS = {
    "critical": CRITICAL,
    "high": HIGH,
    "medium": MEDIUM,
    "low": LOW,
    "unknown": UNKNOWN,
}
PageCallback = Callable[[Canvas, SimpleDocTemplate], None]


def _count(value: Any) -> int:
    """Count entries whether the summary field carries a list or a pre-counted int."""
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return value
    if isinstance(value, (list, tuple, set, dict)):
        return len(value)
    return 0


class _AssessmentDocTemplate(SimpleDocTemplate):
    def __init__(self, *args: Any, page_callback: PageCallback, **kwargs: Any) -> None:
        self._page_callback = page_callback
        super().__init__(*args, **kwargs)

    def afterPage(self) -> None:
        self._page_callback(self.canv, self)


def render_pdf_report(model: JSON) -> bytes:
    buffer = io.BytesIO()
    document = _AssessmentDocTemplate(
        buffer,
        page_callback=_page_callback(model),
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=24 * mm,
        bottomMargin=20 * mm,
        title="BlueArch AWS Steward Assessment",
        author="BlueArch",
        subject="Point-in-time AWS misconfiguration assessment",
    )
    styles = _styles()
    story: List[Any] = []
    summary = dict(model.get("summary") or {})
    report_profile = str(model.get("report_profile") or "technical")

    story.extend(_cover(model, summary, styles))
    if model.get("assessment_mode") == "architectural_review":
        story.extend(_contextual_review(model, styles))
    story.extend(_risk_overview(summary, styles))
    story.extend(_coverage(summary, styles))
    story.extend(_grouped_summary(model, styles))
    if report_profile == "executive":
        executive_model = {**model, "findings": list(model.get("findings") or [])[:25]}
        story.extend(_findings_summary(executive_model, styles))
    elif report_profile == "remediation":
        story.extend(_finding_details(model, styles))
    else:
        story.extend(_findings_summary(model, styles))
        story.extend(_finding_details(model, styles))
    story.extend(_limitations(model, styles))

    document.build(story)
    return buffer.getvalue()


def _styles() -> Dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "BlueArchTitle",
            parent=base["Title"],
            fontName="Helvetica-Bold",
            fontSize=23,
            leading=28,
            textColor=INK,
            alignment=TA_LEFT,
            spaceAfter=5 * mm,
        ),
        "subtitle": ParagraphStyle(
            "BlueArchSubtitle",
            parent=base["BodyText"],
            fontName="Helvetica",
            fontSize=9,
            leading=13,
            textColor=MUTED,
            spaceAfter=5 * mm,
        ),
        "heading": ParagraphStyle(
            "BlueArchHeading",
            parent=base["Heading1"],
            fontName="Helvetica-Bold",
            fontSize=15,
            leading=19,
            textColor=INK,
            spaceBefore=5 * mm,
            spaceAfter=3 * mm,
        ),
        "subheading": ParagraphStyle(
            "BlueArchSubheading",
            parent=base["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=10,
            leading=13,
            textColor=INK,
            spaceBefore=3 * mm,
            spaceAfter=1.5 * mm,
            keepWithNext=True,
        ),
        "body": ParagraphStyle(
            "BlueArchBody",
            parent=base["BodyText"],
            fontName="Helvetica",
            fontSize=8.5,
            leading=12,
            textColor=INK,
            splitLongWords=True,
        ),
        "small": ParagraphStyle(
            "BlueArchSmall",
            parent=base["BodyText"],
            fontName="Helvetica",
            fontSize=7,
            leading=9,
            textColor=MUTED,
            splitLongWords=True,
        ),
        "code": ParagraphStyle(
            "BlueArchCode",
            parent=base["BodyText"],
            fontName="Helvetica",
            fontSize=7,
            leading=9,
            textColor=INK,
            backColor=PALE,
            borderColor=BORDER,
            borderWidth=0.5,
            borderPadding=4,
            wordWrap="CJK",
            splitLongWords=True,
        ),
        "table_header": ParagraphStyle(
            "BlueArchTableHeader",
            parent=base["BodyText"],
            fontName="Helvetica-Bold",
            fontSize=7,
            leading=8,
            textColor=colors.white,
        ),
        "table_cell": ParagraphStyle(
            "BlueArchTableCell",
            parent=base["BodyText"],
            fontName="Helvetica",
            fontSize=6.5,
            leading=8,
            textColor=INK,
            wordWrap="CJK",
            splitLongWords=True,
        ),
    }


def _cover(model: JSON, summary: JSON, styles: Dict[str, ParagraphStyle]) -> List[Any]:
    generated = model.get("generated_at") or "unknown"
    elements: List[Any] = [
        Spacer(1, 5 * mm),
        Paragraph("BlueArch AWS Steward", styles["subtitle"]),
        Paragraph("AWS Assessment Report", styles["title"]),
        Paragraph(
            "Point-in-time, read-only analysis of resources matched by evaluated BlueArch rules.",
            styles["subtitle"],
        ),
    ]
    metadata = [
        ["Generated", generated, "Account", model.get("account_id") or "not reported"],
        [
            "Region",
            model.get("region") or "not reported",
            "Provider",
            model.get("provider") or "not reported",
        ],
        [
            "Scope",
            model.get("service") or "all",
            "Profile",
            model.get("report_profile") or "technical",
        ],
        ["AWS writes", "None", "Findings", summary.get("findings", 0)],
        [
            "Est. monthly savings",
            f"USD {float(summary.get('estimated_monthly_savings_usd') or 0):.2f}",
            "Cost estimates",
            f"{summary.get('cost_estimates_available', 0)}/{summary.get('findings', 0)} available",
        ],
    ]
    table = Table(
        [
            [
                Paragraph(f"<b>{_safe(row[0])}</b>", styles["small"]),
                Paragraph(_safe(row[1]), styles["small"]),
                Paragraph(f"<b>{_safe(row[2])}</b>", styles["small"]),
                Paragraph(_safe(row[3]), styles["small"]),
            ]
            for row in metadata
        ],
        colWidths=[23 * mm, 61 * mm, 23 * mm, 67 * mm],
    )
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), PALE),
                ("BOX", (0, 0), (-1, -1), 0.6, BORDER),
                ("INNERGRID", (0, 0), (-1, -1), 0.3, BORDER),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    elements.extend([table, Spacer(1, 6 * mm), Paragraph("Executive summary", styles["heading"])])

    metrics = [
        ("Findings", summary.get("findings", 0)),
        ("Matched resources", summary.get("resources", 0)),
        ("Resources scanned", summary.get("resources_scanned", 0)),
        ("Rules evaluated", summary.get("rules_evaluated", 0)),
        ("Scan errors", summary.get("scan_errors", 0)),
    ]
    metric_table = Table(
        [[_metric(label, value, styles) for label, value in metrics]],
        colWidths=[34.8 * mm] * 5,
    )
    metric_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.white),
                ("BOX", (0, 0), (-1, -1), 0.6, BORDER),
                ("INNERGRID", (0, 0), (-1, -1), 0.3, BORDER),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )
    elements.extend([metric_table, Spacer(1, 2 * mm)])
    return elements


def _metric(label: str, value: Any, styles: Dict[str, ParagraphStyle]) -> Paragraph:
    return Paragraph(
        f'<font color="#1F6FEB" size="16"><b>{_safe(value)}</b></font><br/>'
        f'<font color="#536174" size="6.5">{_safe(label).upper()}</font>',
        styles["body"],
    )


def _risk_overview(summary: JSON, styles: Dict[str, ParagraphStyle]) -> List[Any]:
    severity_order = ("critical", "high", "medium", "low", "unknown")
    by_severity = dict(summary.get("by_severity") or {})
    severity_data = [(key.title(), int(by_severity.get(key) or 0)) for key in severity_order]
    severity_data = [(key, value) for key, value in severity_data if value]
    by_service = sorted(
        ((str(key), int(value)) for key, value in dict(summary.get("by_service") or {}).items()),
        key=lambda item: (-item[1], item[0]),
    )
    return [
        Paragraph("Risk overview", styles["heading"]),
        _bar_chart("Findings by severity", severity_data, severity=True),
        Spacer(1, 3 * mm),
        _bar_chart("Findings by service", by_service[:15]),
    ]


def _contextual_review(model: JSON, styles: Dict[str, ParagraphStyle]) -> List[Any]:
    focus = (model.get("focus") or {}).get("resources") or []
    selected_knowledge = (model.get("focus") or {}).get("selected_knowledge") or []
    graph = model.get("architecture_neighborhood") or {}
    review = model.get("well_architected_review") or {}
    ledger = model.get("evidence_ledger") or {}
    excluded = model.get("excluded_scope") or {}
    unknowns = (model.get("context_questions") or {}).get("unknown_facts") or []
    elements: List[Any] = [
        Paragraph("Contextual architecture review", styles["heading"]),
        _labelled(
            "Assessment mode",
            model.get("assessment_mode") or "architectural_review",
            styles["body"],
        ),
        _labelled("Operation", model.get("operation") or "review", styles["body"]),
    ]
    for resource in focus:
        elements.append(
            _labelled(
                "Focus",
                f"{resource.get('arn') or resource.get('resource_id') or 'unknown'} "
                f"({resource.get('service') or 'unknown'})",
                styles["body"],
            )
        )
    elements.extend(
        [
            _labelled(
                "Observed neighborhood",
                f"{len(graph.get('nodes') or [])} nodes, {len(graph.get('edges') or [])} relationships",
                styles["body"],
            ),
            _labelled(
                "Read ledger",
                f"{ledger.get('operation_count', 0)} of {ledger.get('operation_budget', 0)} operations",
                styles["body"],
            ),
            _labelled(
                "Selected knowledge",
                ", ".join(str(item.get("service")) for item in selected_knowledge) or "none",
                styles["body"],
            ),
            _labelled(
                "Excluded services",
                ", ".join(str(item) for item in excluded.get("services") or []) or "none",
                styles["body"],
            ),
            _labelled(
                "Unknown context",
                ", ".join(str(item) for item in unknowns) or "none",
                styles["body"],
            ),
            Paragraph(
                "An unobserved relationship is not proof that no dependency exists.",
                styles["small"],
            ),
            Spacer(1, 2 * mm),
        ]
    )
    rows = [["Pillar", "Risk", "Aligned", "Needs input", "Unknown", "Not evaluated"]]
    for pillar in review.get("pillars") or []:
        counts = pillar.get("status_counts") or {}
        rows.append(
            [
                str(pillar.get("pillar") or "unknown").replace("_", " ").title(),
                counts.get("risk", 0),
                counts.get("aligned", 0),
                counts.get("requires_input", 0),
                counts.get("unknown", 0),
                counts.get("not_evaluated", 0),
            ]
        )
    table = Table(rows, colWidths=[45 * mm, 18 * mm, 20 * mm, 25 * mm, 20 * mm, 27 * mm])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), PALE),
                ("BOX", (0, 0), (-1, -1), 0.6, BORDER),
                ("INNERGRID", (0, 0), (-1, -1), 0.3, BORDER),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 7),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    elements.extend([table, Spacer(1, 3 * mm)])

    practice_rows: List[List[Any]] = [
        [
            Paragraph("Practice", styles["table_header"]),
            Paragraph("Pillar", styles["table_header"]),
            Paragraph("Status", styles["table_header"]),
            Paragraph("Evidence", styles["table_header"]),
        ]
    ]
    for pillar in review.get("pillars") or []:
        for practice in pillar.get("practices") or []:
            practice_rows.append(
                [
                    Paragraph(
                        f"<b>{_safe(practice.get('practice_id') or 'unknown')}</b><br/>"
                        f"{_safe(_short(practice.get('title') or '', 55))}",
                        styles["table_cell"],
                    ),
                    Paragraph(
                        _safe(str(pillar.get("pillar") or "unknown").replace("_", " ").title()),
                        styles["table_cell"],
                    ),
                    Paragraph(_safe(practice.get("status") or "unknown"), styles["table_cell"]),
                    Paragraph(
                        _safe(
                            ", ".join(practice.get("matched_native_rules") or [])
                            or "Manual or unavailable evidence"
                        ),
                        styles["table_cell"],
                    ),
                ]
            )
    if len(practice_rows) > 1:
        practice_table = LongTable(
            practice_rows,
            colWidths=[62 * mm, 34 * mm, 23 * mm, 56 * mm],
            repeatRows=1,
        )
        practice_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), BLUE),
                    ("BOX", (0, 0), (-1, -1), 0.5, BORDER),
                    ("INNERGRID", (0, 0), (-1, -1), 0.25, BORDER),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 4),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ]
            )
        )
        elements.extend(
            [
                Paragraph("Well-Architected practice ledger", styles["subheading"]),
                practice_table,
                Spacer(1, 3 * mm),
            ]
        )
    concerns = model.get("hidden_relevant_concerns") or []
    if concerns:
        elements.append(Paragraph("High-impact cross-pillar concerns", styles["subheading"]))
        for concern in concerns:
            elements.append(
                Paragraph(
                    f"<b>{_safe(concern.get('severity') or 'unknown')}</b> "
                    f"{_safe(concern.get('rule') or 'unknown')} on "
                    f"{_safe(concern.get('resource') or 'unknown')}",
                    styles["body"],
                )
            )
    return elements


def _bar_chart(
    title: str,
    values: Iterable[Tuple[str, int]],
    *,
    severity: bool = False,
) -> Drawing:
    rows = list(values) or [("None", 0)]
    width = 174 * mm
    row_height = 13
    height = 28 + len(rows) * row_height
    chart = Drawing(width, height)
    chart.add(String(0, height - 11, title, fontName="Helvetica-Bold", fontSize=9, fillColor=INK))
    maximum = max((value for _, value in rows), default=1) or 1
    bar_x = 102
    available = width - bar_x - 30
    for index, (label, value) in enumerate(rows):
        y = height - 28 - index * row_height
        chart.add(
            String(0, y, _short(label, 22), fontName="Helvetica", fontSize=7, fillColor=MUTED)
        )
        chart.add(Rect(bar_x, y - 1, available, 7, fillColor=PALE, strokeColor=None))
        color = SEVERITY_COLORS.get(label.lower(), BLUE) if severity else CYAN
        chart.add(
            Rect(
                bar_x,
                y - 1,
                available * (value / maximum),
                7,
                fillColor=color,
                strokeColor=None,
            )
        )
        chart.add(
            String(
                bar_x + available + 5,
                y,
                str(value),
                fontName="Helvetica-Bold",
                fontSize=7,
                fillColor=INK,
            )
        )
    return chart


def _coverage(summary: JSON, styles: Dict[str, ParagraphStyle]) -> List[Any]:
    coverage = dict(summary.get("detection_coverage") or {})
    rows = [
        ("Catalog rules in scope", coverage.get("catalog_rules_in_scope", 0)),
        ("Automated rules available", coverage.get("automated_rules_available", 0)),
        ("Automated rules evaluated", coverage.get("automated_rules_evaluated", 0)),
        ("Unevaluated rules", coverage.get("unevaluated_catalog_rules", 0)),
        ("Evaluation percentage", f"{coverage.get('catalog_evaluation_percentage', 0)}%"),
        (
            "Complete scoped evaluation",
            "Yes" if coverage.get("complete_catalog_evaluation") else "No",
        ),
        ("Service errors", _count(summary.get("service_errors"))),
        ("Capability errors", _count(summary.get("capability_errors"))),
        ("Rules skipped", _count(summary.get("rules_skipped"))),
    ]
    table = Table(
        [
            [
                Paragraph(f"<b>{_safe(label)}</b>", styles["small"]),
                Paragraph(_safe(value), styles["small"]),
            ]
            for label, value in rows
        ],
        colWidths=[80 * mm, 94 * mm],
    )
    table.setStyle(
        TableStyle(
            [
                ("BOX", (0, 0), (-1, -1), 0.5, BORDER),
                ("INNERGRID", (0, 0), (-1, -1), 0.25, BORDER),
                ("BACKGROUND", (0, 0), (0, -1), PALE),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    return [PageBreak(), Paragraph("Detection coverage", styles["heading"]), table]


def _grouped_summary(model: JSON, styles: Dict[str, ParagraphStyle]) -> List[Any]:
    groups = model.get("grouped_solutions") or []
    if not groups:
        return []
    story: List[Any] = [PageBreak(), Paragraph("Grouped Solutions", styles["heading"])]
    for group in groups:
        priority = group_priority(group)
        text = f"{group_label(group)} — {group_member_count(group)} resource(s)"
        if priority is not None:
            text += f", priority {priority}"
        story.append(Paragraph(_safe(text), styles["small"]))
    return story


def _findings_summary(model: JSON, styles: Dict[str, ParagraphStyle]) -> List[Any]:
    rows: List[List[Any]] = [
        [
            Paragraph("#", styles["table_header"]),
            Paragraph("Severity", styles["table_header"]),
            Paragraph("Service", styles["table_header"]),
            Paragraph("Rule", styles["table_header"]),
            Paragraph("Resource", styles["table_header"]),
            Paragraph("Savings", styles["table_header"]),
        ]
    ]
    for index, item in enumerate(model.get("findings") or [], start=1):
        rows.append(
            [
                Paragraph(str(index), styles["table_cell"]),
                Paragraph(
                    _safe(str(item.get("severity") or "unknown").upper()), styles["table_cell"]
                ),
                Paragraph(_safe(item.get("service") or "unknown"), styles["table_cell"]),
                Paragraph(
                    _safe(item.get("rule") or item.get("rule_id") or "unknown"),
                    styles["table_cell"],
                ),
                Paragraph(_safe(item.get("resource") or "unknown"), styles["table_cell"]),
                Paragraph(_safe(_cost_display(item)), styles["table_cell"]),
            ]
        )
    table = LongTable(
        rows,
        repeatRows=1,
        colWidths=[7 * mm, 16 * mm, 20 * mm, 42 * mm, 62 * mm, 27 * mm],
    )
    commands: List[Tuple[Any, ...]] = [
        ("BACKGROUND", (0, 0), (-1, 0), INK),
        ("BOX", (0, 0), (-1, -1), 0.5, BORDER),
        ("INNERGRID", (0, 0), (-1, -1), 0.2, BORDER),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 3),
        ("RIGHTPADDING", (0, 0), (-1, -1), 3),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]
    for row_number in range(2, len(rows), 2):
        commands.append(("BACKGROUND", (0, row_number), (-1, row_number), HexColor("#F8FAFC")))
    table.setStyle(TableStyle(commands))
    return [Paragraph("Findings summary", styles["heading"]), table]


def _finding_details(model: JSON, styles: Dict[str, ParagraphStyle]) -> List[Any]:
    elements: List[Any] = [PageBreak(), Paragraph("Finding details", styles["heading"])]
    findings = list(model.get("findings") or [])
    if not findings:
        elements.append(Paragraph("No resources matched the evaluated rules.", styles["body"]))
        return elements

    for index, item in enumerate(findings, start=1):
        severity = str(item.get("severity") or "unknown").lower()
        severity_color = _color_hex(SEVERITY_COLORS.get(severity, UNKNOWN))
        rule = item.get("rule") or item.get("rule_id") or "unknown"
        heading = Paragraph(
            f'{index}. <font color="{severity_color}">[{_safe(severity.upper())}]</font> {_safe(rule)}',
            styles["subheading"],
        )
        resource_ref = (
            item.get("resource_ref") if isinstance(item.get("resource_ref"), dict) else {}
        )
        remediation = item.get("remediation") if isinstance(item.get("remediation"), dict) else {}
        apply = item.get("apply") if isinstance(item.get("apply"), dict) else {}
        context_rows = [
            ("Service", item.get("service") or "unknown"),
            ("Resource", item.get("resource") or "unknown"),
            ("Resource type", resource_ref.get("resource_type") or "not reported"),
            ("ARN", resource_ref.get("arn") or "not reported"),
            ("Observed", item.get("evidence_observed_at") or "not reported"),
            ("Evidence confidence", item.get("evidence_confidence") or "not_available"),
            ("Estimated monthly savings", _cost_display(item)),
            ("Cost confidence", item.get("cost_confidence") or "not_available"),
        ]
        context_table = Table(
            [
                [
                    Paragraph(f"<b>{_safe(label)}</b>", styles["small"]),
                    Paragraph(_safe(value), styles["small"]),
                ]
                for label, value in context_rows
            ],
            colWidths=[28 * mm, 146 * mm],
        )
        context_table.setStyle(
            TableStyle(
                [
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("BACKGROUND", (0, 0), (0, -1), PALE),
                    ("BOX", (0, 0), (-1, -1), 0.4, BORDER),
                    ("INNERGRID", (0, 0), (-1, -1), 0.2, BORDER),
                    ("LEFTPADDING", (0, 0), (-1, -1), 5),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                    ("TOPPADDING", (0, 0), (-1, -1), 3),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ]
            )
        )
        elements.append(
            KeepTogether(
                [
                    heading,
                    context_table,
                    Spacer(1, 1.5 * mm),
                    _labelled("Rule description", item.get("rule_description"), styles["body"]),
                    _labelled("Why matched", item.get("matching_criteria"), styles["body"]),
                    _labelled("Observed evidence", item.get("observed_evidence"), styles["code"]),
                    _labelled("Risk", item.get("risk_detail"), styles["body"]),
                    _labelled(
                        "Cost estimate basis", item.get("cost_estimate_basis"), styles["body"]
                    ),
                    _labelled("Value", item.get("value"), styles["body"]),
                    _labelled("Recommended fix", remediation.get("summary"), styles["body"]),
                    _labelled(
                        "Actions",
                        " | ".join(str(action) for action in remediation.get("actions") or []),
                        styles["body"],
                    ),
                    _labelled("Verification", remediation.get("verification"), styles["body"]),
                    _labelled(
                        "Safety",
                        f"level={remediation.get('safety_level') or 'not reported'}; "
                        f"approval_required={str(bool(remediation.get('requires_approval'))).lower()}; "
                        f"apply_supported={str(bool(apply.get('supported'))).lower()}",
                        styles["body"],
                    ),
                    Spacer(1, 2 * mm),
                    HRFlowable(width="100%", thickness=0.4, color=BORDER),
                    Spacer(1, 2 * mm),
                ]
            )
        )
    return elements


def _cost_display(item: JSON) -> str:
    savings = item.get("estimated_monthly_savings_usd")
    confidence = item.get("cost_confidence") or "not_available"
    if savings is None:
        return f"not estimated ({confidence})"
    return f"USD {float(savings):.2f} ({confidence})"


def _labelled(label: str, value: Any, style: ParagraphStyle) -> Paragraph:
    return Paragraph(f"<b>{_safe(label)}:</b> {_safe(value or 'not reported')}", style)


def _limitations(model: JSON, styles: Dict[str, ParagraphStyle]) -> List[Any]:
    elements: List[Any] = [Paragraph("Limitations", styles["heading"])]
    for limitation in model.get("limitations") or []:
        if isinstance(limitation, dict):
            limitation = limitation.get("message") or limitation.get("detail") or limitation
        elements.append(Paragraph(f"- {_safe(limitation)}", styles["body"]))
    return elements


def _page_callback(model: JSON):
    generated = str(model.get("generated_at") or "unknown")

    def draw(canvas: Canvas, document: SimpleDocTemplate) -> None:
        canvas.saveState()
        width, height = A4
        canvas.setTitle("BlueArch AWS Steward Assessment")
        canvas.setAuthor("BlueArch")
        canvas.setStrokeColor(BORDER)
        canvas.setLineWidth(0.5)
        canvas.line(
            document.leftMargin, height - 15 * mm, width - document.rightMargin, height - 15 * mm
        )
        canvas.setFont("Helvetica-Bold", 8)
        canvas.setFillColor(INK)
        canvas.drawString(document.leftMargin, height - 11.5 * mm, "BlueArch AWS Steward")
        canvas.setFont("Helvetica", 6.5)
        canvas.setFillColor(MUTED)
        canvas.drawRightString(width - document.rightMargin, height - 11.5 * mm, generated)
        canvas.line(document.leftMargin, 13 * mm, width - document.rightMargin, 13 * mm)
        canvas.drawString(document.leftMargin, 8.5 * mm, "Point-in-time read-only assessment")
        canvas.drawRightString(width - document.rightMargin, 8.5 * mm, f"Page {document.page}")
        canvas.restoreState()

    return draw


def _safe(value: Any) -> str:
    return html.escape(str(value), quote=True).replace("\n", "<br/>")


def _short(value: str, limit: int) -> str:
    return value if len(value) <= limit else value[: limit - 3] + "..."


def _color_hex(color: Color) -> str:
    return "#%02X%02X%02X" % (
        round(color.red * 255),
        round(color.green * 255),
        round(color.blue * 255),
    )
