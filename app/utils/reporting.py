from __future__ import annotations

from datetime import datetime
from html import escape
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

from app.config import get_settings
from app.models import Assessment, Evidence, Finding, Mitigation
from app.utils.jsonx import from_json


EXPORT_DIR = get_settings().runtime_dir / "exports"
EXPORT_DIR.mkdir(parents=True, exist_ok=True)


def _kpi_rows(evidences: list[Evidence], findings: list[Finding], mitigations: list[Mitigation]) -> list[list[str]]:
    pivot_count = len([f for f in findings if f.type == "pivot"])
    high_findings = len([f for f in findings if f.severity >= 4])
    return [
        ["KPI", "Value"],
        ["Evidence Collected", str(len(evidences))],
        ["Findings", str(len(findings))],
        ["High Severity (4-5)", str(high_findings)],
        ["Risk to Clients via Impersonation", str(pivot_count)],
        ["Risk Reduction Actions", str(len(mitigations))],
    ]


def _normalize_refs(raw_json: str) -> list[int]:
    refs: list[int] = []
    for item in from_json(raw_json, []):
        if str(item).isdigit():
            refs.append(int(item))
            continue
        if isinstance(item, dict):
            cand = item.get("evidence_id") or item.get("id")
            if str(cand).isdigit():
                refs.append(int(cand))
    seen: set[int] = set()
    ordered: list[int] = []
    for value in refs:
        if value not in seen:
            seen.add(value)
            ordered.append(value)
    return ordered


def _chain_template(finding_type: str) -> dict[str, str]:
    key = (finding_type or "").strip().lower()
    if key == "exposure":
        return {
            "inference": "Public organizational cues can be assembled into targeted reconnaissance.",
            "risk": "Higher success probability for social-engineering pretexts.",
            "boundary": "Exposure conditions observed; no active exploitation confirmed above threshold.",
        }
    if key == "mention":
        return {
            "inference": "Narrative alignment allows attackers to mimic trusted language and timing.",
            "risk": "Increased credibility of malicious outreach.",
            "boundary": "Narrative pressure detected; no coordinated campaign attribution performed.",
        }
    if key == "touchpoint":
        return {
            "inference": "Multiple contact paths create official-channel ambiguity.",
            "risk": "Conversation insertion into support, billing, or onboarding workflows.",
            "boundary": "Trust-friction weakness observed; no direct compromise telemetry in scope.",
        }
    if key == "pivot":
        return {
            "inference": "Trust in brand/channel can be leveraged to target third parties.",
            "risk": "Client/partner impersonation with potential downstream process abuse.",
            "boundary": "Assessment identifies preconditions and blast radius, not victim confirmation.",
        }
    return {
        "inference": "Independent signals converge on a plausible abuse pattern.",
        "risk": "Trust-heavy workflows may be exploitable without added controls.",
        "boundary": "Open-source signal assessment only; internal telemetry not included.",
    }


def _is_web_url(value: str | None) -> bool:
    if not value:
        return False
    try:
        parsed = urlparse(value)
        return parsed.scheme in {"http", "https"} and bool(parsed.netloc)
    except Exception:
        return False


def _compact(text: str, limit: int = 120) -> str:
    raw = " ".join((text or "").strip().split())
    if len(raw) <= limit:
        return raw
    return f"{raw[: max(0, limit - 3)]}..."


def _what_we_saw_line(finding: Finding, evidence_rows: list[Evidence]) -> str:
    count = len(evidence_rows)
    if not evidence_rows:
        return f"{finding.title}: no linked evidence rows were attached to this finding."
    connectors = sorted({str(e.connector or "").strip() for e in evidence_rows if str(e.connector or "").strip()})
    connector_label = ", ".join(connectors[:3]) if connectors else "mixed connectors"
    snippets = [_compact(e.snippet or e.title, 90) for e in evidence_rows[:2] if (e.snippet or e.title)]
    if snippets:
        sample = " | ".join(snippets)
        return f"{count} linked evidence items from {connector_label}. Sample signals: {sample}"
    return f"{count} linked evidence items from {connector_label}."


def _severity_why_line(finding: Finding, evidence_count: int) -> str:
    sev = max(1, min(5, int(finding.severity or 3)))
    conf = max(1, min(100, int(finding.confidence or 0)))
    if sev >= 4:
        impact = "material operational/trust impact if exploited"
    elif sev == 3:
        impact = "meaningful but bounded business impact"
    else:
        impact = "contained impact unless combined with additional signals"
    if conf >= 75:
        likelihood = "high"
    elif conf >= 50:
        likelihood = "medium"
    else:
        likelihood = "low-to-medium"
    return (
        f"S{sev}: likelihood {likelihood} ({conf}% confidence, {evidence_count} corroborating references) + {impact}."
    )


def _effort_window(effort: str) -> str:
    key = (effort or "").strip().upper()
    if key == "S":
        return "execution target: 1-2 weeks"
    if key == "M":
        return "execution target: 2-6 weeks"
    if key == "L":
        return "execution target: 6+ weeks"
    return "execution target: planned sprint cadence"


def render_assessment_pdf(
    assessment: Assessment,
    evidences: list[Evidence],
    findings: list[Finding],
    mitigations: list[Mitigation],
) -> Path:
    stamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    pdf_path = EXPORT_DIR / f"assessment_{assessment.id}_{stamp}.pdf"

    doc = SimpleDocTemplate(str(pdf_path), pagesize=A4, leftMargin=28, rightMargin=28, topMargin=24)
    styles = getSampleStyleSheet()

    story = []
    story.append(Paragraph(f"ExposureMapper TI Report - {assessment.company_name}", styles["Title"]))
    story.append(Paragraph(f"Domain: {assessment.domain} | Sector: {assessment.sector}", styles["Normal"]))
    story.append(Paragraph(f"Generated: {datetime.utcnow().isoformat()} UTC", styles["Normal"]))
    story.append(Spacer(1, 10))

    kpi_table = Table(_kpi_rows(evidences, findings, mitigations), hAlign="LEFT")
    kpi_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111827")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#F8FAFC")),
            ]
        )
    )
    story.append(kpi_table)
    story.append(Spacer(1, 10))

    evidence_map = {e.id: e for e in evidences}
    sorted_findings = sorted(findings, key=lambda x: (x.severity, x.confidence), reverse=True)[:5]

    story.append(Paragraph("Top Findings (Evidence -> Inference -> Risk)", styles["Heading2"]))
    for f in sorted_findings:
        refs = _normalize_refs(f.evidence_refs_json)
        linked_evidence = [evidence_map[ev_id] for ev_id in refs if ev_id in evidence_map][:8]
        chain = _chain_template(f.type)

        story.append(Paragraph(f"[S{f.severity}] {f.title} (confidence {f.confidence}%)", styles["Heading3"]))
        story.append(Paragraph(f"<b>What we saw:</b> {_what_we_saw_line(f, linked_evidence)}", styles["BodyText"]))
        story.append(Paragraph(f"<b>Why it matters:</b> {chain['risk']}", styles["BodyText"]))
        story.append(Paragraph(f"<b>Why S{f.severity}:</b> {_severity_why_line(f, len(refs))}", styles["BodyText"]))
        story.append(Paragraph(f"<b>Scope boundary:</b> {chain['boundary']}", styles["BodyText"]))

        table = Table(
            [
                ["Evidence", "Inference", "Risk conclusion"],
                [
                    _what_we_saw_line(f, linked_evidence),
                    chain["inference"],
                    f.title,
                ],
            ],
            hAlign="LEFT",
            colWidths=[165, 165, 165],
        )
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1F2937")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#F8FAFC")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        story.append(table)

        citations = []
        for ev in linked_evidence[:3]:
            source = ev.source_url if _is_web_url(ev.source_url) else ""
            if not source:
                continue
            citations.append(f"{ev.title} ({source})")
        if citations:
            story.append(Paragraph(f"<b>Linked sources:</b> {'; '.join(citations)}", styles["BodyText"]))
        story.append(Spacer(1, 8))

    story.append(Spacer(1, 4))
    story.append(Paragraph("Risk Reduction Actions (Top 5)", styles["Heading2"]))
    finding_map = {f.id: f for f in findings}
    for m in sorted(mitigations, key=lambda x: x.priority)[:5]:
        linked_ids = [x for x in from_json(m.linked_findings_json, []) if str(x).isdigit()]
        linked_titles = [finding_map[int(fid)].title for fid in linked_ids if int(fid) in finding_map]
        story.append(
            Paragraph(
                f"[P{m.priority}/{m.effort}] {m.owner}: {m.description}",
                styles["BodyText"],
            )
        )
        if linked_titles:
            story.append(Paragraph(f"Linked findings: {', '.join(linked_titles[:3])}", styles["BodyText"]))
        story.append(Paragraph(_effort_window(m.effort), styles["BodyText"]))
        story.append(Spacer(1, 4))

    pivots = [f for f in findings if f.type == "pivot"]
    story.append(Spacer(1, 8))
    story.append(Paragraph("Risk to Clients via Impersonation Highlight", styles["Heading2"]))
    if pivots:
        for p in pivots[:3]:
            story.append(Paragraph(f"- {p.title} (confidence {p.confidence}%)", styles["BodyText"]))
    else:
        story.append(Paragraph("No direct client impersonation-risk signal above threshold.", styles["BodyText"]))

    story.append(Spacer(1, 10))
    story.append(Paragraph("Annex: Evidence (max 20)", styles["Heading2"]))
    for ev in evidences[:20]:
        story.append(
            Paragraph(
                f"[{ev.connector}] {ev.title} | confidence {ev.confidence}% | {ev.source_url}",
                styles["BodyText"],
            )
        )

    assumptions = from_json(assessment.assumptions_json, [])
    story.append(Spacer(1, 10))
    story.append(Paragraph("Assumptions", styles["Heading2"]))
    for item in assumptions:
        story.append(Paragraph(f"- {item}", styles["BodyText"]))

    story.append(Spacer(1, 8))
    story.append(Paragraph("Assessment Boundaries", styles["Heading2"]))
    story.append(
        Paragraph(
            "- This report describes exposure and abuse preconditions from public evidence, not confirmed incidents.",
            styles["BodyText"],
        )
    )
    story.append(
        Paragraph(
            "- Internal controls, ticketing data, and SOC telemetry are outside current collection scope unless provided.",
            styles["BodyText"],
        )
    )

    doc.build(story)
    return pdf_path


def _pdf_text(value: Any) -> str:
    return escape(" ".join(str(value or "").split()).strip())


def _ev_source_for_pdf(ev: dict[str, Any]) -> str:
    url = str(ev.get("url", "") or "").strip()
    if _is_web_url(url):
        return url
    doc_id = ev.get("doc_id")
    if str(doc_id).isdigit():
        return f"/documents/{int(doc_id)}"
    return ""


def _story_column_html(
    cards: list[dict[str, Any]],
    *,
    evidence_sets: dict[str, list[dict[str, Any]]],
) -> str:
    if not cards:
        return "No items."
    chunks: list[str] = []
    for idx, card in enumerate(cards, start=1):
        title = _pdf_text(card.get("title", ""))
        detail = _pdf_text(card.get("detail", ""))
        chunks.append(f"<b>{idx}. {title}</b><br/>{detail}")
        ref_items = list(card.get("evidence_refs") or [])
        for ref in ref_items:
            code = _pdf_text(ref.get("code", ""))
            text = _pdf_text(ref.get("text", ""))
            if code and text:
                chunks.append(f"&nbsp;&nbsp;- {code} {text}")
        set_id = str(card.get("evidence_set_id", "") or "")
        ev_rows = list(evidence_sets.get(set_id, []) or [])
        for ev in ev_rows:
            snippet = _pdf_text(_compact(str(ev.get("snippet", "") or ""), limit=120))
            src = _pdf_text(_ev_source_for_pdf(ev))
            if src:
                chunks.append(f"&nbsp;&nbsp;- Evidence: {snippet} | {src}")
            elif snippet:
                chunks.append(f"&nbsp;&nbsp;- Evidence: {snippet}")
    return "<br/><br/>".join(chunks)


def _append_story_map_column(
    story: list[Any],
    *,
    heading: str,
    cards: list[dict[str, Any]],
    evidence_sets: dict[str, list[dict[str, Any]]],
    h3_style: ParagraphStyle,
    body_style: ParagraphStyle,
) -> None:
    story.append(Paragraph(heading, h3_style))
    if not cards:
        story.append(Paragraph("No items.", body_style))
        story.append(Spacer(1, 4))
        return
    for idx, card in enumerate(cards, start=1):
        title = _pdf_text(card.get("title", ""))
        detail = _pdf_text(card.get("detail", ""))
        story.append(Paragraph(f"<b>{idx}. {title}</b>", body_style))
        if detail:
            story.append(Paragraph(detail, body_style))
        ref_items = list(card.get("evidence_refs") or [])
        for ref in ref_items:
            code = _pdf_text(ref.get("code", ""))
            text = _pdf_text(ref.get("text", ""))
            if code and text:
                story.append(Paragraph(f"&nbsp;&nbsp;- {code} {text}", body_style))
        set_id = str(card.get("evidence_set_id", "") or "")
        ev_rows = list(evidence_sets.get(set_id, []) or [])
        for ev in ev_rows:
            snippet = _pdf_text(_compact(str(ev.get("snippet", "") or ""), limit=130))
            src = _pdf_text(_ev_source_for_pdf(ev))
            if src:
                story.append(Paragraph(f"&nbsp;&nbsp;- Evidence: {snippet} | {src}", body_style))
            elif snippet:
                story.append(Paragraph(f"&nbsp;&nbsp;- Evidence: {snippet}", body_style))
        story.append(Spacer(1, 4))


def render_risk_pdf(
    assessment: Assessment,
    vm: dict[str, Any],
) -> Path:
    risk = dict(vm.get("risk") or {})
    details = dict(vm.get("details") or {})
    story_map = dict(vm.get("story_map") or {})
    recipe_bundles = list(vm.get("recipe_bundles") or [])
    evidence_sets = dict(vm.get("evidenceSets") or {})

    risk_id = int(risk.get("id", 0) or 0)
    stamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    pdf_path = EXPORT_DIR / f"risk_{assessment.id}_{risk_id}_{stamp}.pdf"

    doc = SimpleDocTemplate(str(pdf_path), pagesize=A4, leftMargin=28, rightMargin=28, topMargin=24, bottomMargin=24)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "RiskTitle",
        parent=styles["Title"],
        textColor=colors.black,
        fontSize=18,
        leading=22,
        spaceAfter=8,
    )
    h2_style = ParagraphStyle(
        "RiskH2",
        parent=styles["Heading2"],
        textColor=colors.black,
        fontSize=13,
        leading=16,
        spaceAfter=6,
        spaceBefore=8,
    )
    h3_style = ParagraphStyle(
        "RiskH3",
        parent=styles["Heading3"],
        textColor=colors.black,
        fontSize=11,
        leading=14,
        spaceAfter=4,
    )
    body_style = ParagraphStyle(
        "RiskBody",
        parent=styles["BodyText"],
        textColor=colors.black,
        fontSize=9.5,
        leading=13,
    )

    story: list[Any] = []

    primary_label = _pdf_text(risk.get("primary_risk_type") or risk.get("title") or "Risk")
    vector_line = _pdf_text(
        (risk.get("risk_vector_summary") or f"Risk: {risk.get('title') or 'Unknown risk'}")
    ).replace("Top risk:", "Risk:")
    story.append(Paragraph(vector_line, title_style))
    story.append(Paragraph(f"<b>Primary risk type:</b> {primary_label}", body_style))
    story.append(
        Paragraph(
            f"<b>Assessment:</b> {_pdf_text(assessment.company_name)} | "
            f"<b>Domain:</b> {_pdf_text(assessment.domain)} | "
            f"<b>Generated:</b> {_pdf_text(datetime.utcnow().isoformat() + ' UTC')}",
            body_style,
        )
    )
    story.append(Spacer(1, 10))

    reasoning = dict(risk.get("reasoning") or {})
    story.append(Paragraph("Risk reasoning", h2_style))
    if str(reasoning.get("what_we_saw", "")).strip():
        story.append(Paragraph(f"<b>What we saw:</b> {_pdf_text(reasoning.get('what_we_saw'))}", body_style))
    if str(reasoning.get("why_it_matters", "")).strip():
        story.append(Paragraph(f"<b>Why it matters:</b> {_pdf_text(reasoning.get('why_it_matters'))}", body_style))
    if str(reasoning.get("why_severity", "")).strip():
        story.append(Paragraph(f"<b>Why severity:</b> {_pdf_text(reasoning.get('why_severity'))}", body_style))
    if str(reasoning.get("scope_boundary", "")).strip():
        story.append(Paragraph(f"<b>Scope boundary:</b> {_pdf_text(reasoning.get('scope_boundary'))}", body_style))
    if str(reasoning.get("how", "")).strip():
        story.append(Paragraph(f"<b>How:</b> {_pdf_text(reasoning.get('how'))}", body_style))
    story.append(Spacer(1, 8))

    story.append(Paragraph("Risk context", h2_style))
    context_rows = [
        ["Likelihood", _pdf_text(str(risk.get("likelihood", "")).upper())],
        ["Impact", _pdf_text(risk.get("impact_band", ""))],
        ["Evidence strength", _pdf_text(risk.get("evidence_strength", ""))],
        ["Signal coverage", _pdf_text(risk.get("signal_coverage", 0))],
    ]
    campaign = [str(x).strip() for x in list(risk.get("campaign_chips") or []) if str(x).strip()]
    if campaign:
        context_rows.append(["Campaign chips", _pdf_text(" | ".join(campaign[:8]))])
    context_table = Table(context_rows, colWidths=[130, 370], hAlign="LEFT")
    context_table.setStyle(
        TableStyle(
            [
                ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F1F5F9")),
                ("TEXTCOLOR", (0, 0), (-1, -1), colors.black),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    story.append(context_table)
    story.append(Spacer(1, 8))

    story.append(Paragraph("Risk recipe", h2_style))
    if recipe_bundles:
        for b in recipe_bundles:
            story.append(
                Paragraph(
                    f"- {_pdf_text(b.get('title', ''))} ({int(b.get('item_count', 0) or 0)} items)",
                    body_style,
                )
            )
        story.append(Paragraph(f"<b>Outcome:</b> {primary_label}", body_style))
    else:
        story.append(Paragraph("No recipe bundles available.", body_style))
    story.append(Spacer(1, 8))

    story.append(Paragraph("Abuse path", h2_style))
    abuse_cards = list(story_map.get("abuse_path") or [])
    _append_story_map_column(
        story,
        heading="Timeline",
        cards=abuse_cards,
        evidence_sets=evidence_sets,
        h3_style=h3_style,
        body_style=body_style,
    )
    story.append(Spacer(1, 8))

    story.append(Paragraph("Business impact", h2_style))
    business_impact = _pdf_text(details.get("business_impact", ""))
    if business_impact:
        story.append(Paragraph(business_impact, body_style))
    else:
        story.append(Paragraph("Business impact narrative not available.", body_style))
    impacted_roles = [str(x).strip() for x in list(details.get("impacted_roles") or []) if str(x).strip()]
    if impacted_roles:
        story.append(Paragraph(f"<b>Impacted roles:</b> {', '.join(_pdf_text(x) for x in impacted_roles[:8])}", body_style))
    story.append(Paragraph("What would confirm", h3_style))
    confirm_points = list(details.get("confirm_points") or [])
    for x in confirm_points:
        story.append(Paragraph(f"- {_pdf_text(x)}", body_style))
    if not confirm_points:
        story.append(Paragraph("No confirm criteria available.", body_style))
    story.append(Spacer(1, 8))

    story.append(Paragraph("What would deny", h3_style))
    deny_points = list(details.get("deny_points") or [])
    if deny_points:
        for x in deny_points:
            story.append(Paragraph(f"- {_pdf_text(x)}", body_style))
    else:
        story.append(Paragraph("No deny criteria available.", body_style))

    story.append(Paragraph("Recommended actions", h3_style))
    cps = list(details.get("control_points") or [])
    if cps:
        for cp in cps:
            title = _pdf_text(cp.get("title", ""))
            effort = _pdf_text(cp.get("effort", ""))
            red = _pdf_text(cp.get("expected_reduction", ""))
            story.append(Paragraph(f"- <b>{title}</b>", body_style))
            story.append(Paragraph(f"&nbsp;&nbsp;Effort: {effort} | Expected reduction: {red}", body_style))
    else:
        story.append(Paragraph("No recommended actions available yet.", body_style))
    story.append(Spacer(1, 8))

    story.append(Paragraph("Top evidence", h2_style))
    top_evidence = list(details.get("evidence") or [])
    if top_evidence:
        for ev in top_evidence:
            snippet = _pdf_text(ev.get("snippet", ""))
            signal = _pdf_text(ev.get("signal_type", ""))
            conf = int(ev.get("confidence", 0) or 0)
            src = _pdf_text(_ev_source_for_pdf(ev))
            story.append(Paragraph(f"- {snippet}", body_style))
            line = f"&nbsp;&nbsp;Signal: {signal} | Confidence: {conf}%"
            if src:
                line += f" | Source: {src}"
            story.append(Paragraph(line, body_style))
    else:
        story.append(Paragraph("Insufficient evidence.", body_style))
    story.append(Spacer(1, 8))

    story.append(Paragraph("MITRE ATT&CK categories", h2_style))
    mitre = [str(x).strip() for x in list(risk.get("mitre_chips") or []) if str(x).strip()]
    if mitre:
        story.append(Paragraph(_pdf_text(" | ".join(mitre[:20])), body_style))
    else:
        story.append(Paragraph("No MITRE ATT&CK categories mapped.", body_style))

    doc.build(story)
    return pdf_path
