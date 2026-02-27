from __future__ import annotations

from collections import defaultdict
from datetime import datetime
import csv
import io
import logging
from pathlib import Path
import hashlib

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.connectors import connector_map, connector_registry
from app.connectors.base import ConnectorTarget, EvidencePayload
from app.models import (
    Assessment,
    ConnectorSetting,
    CrossSignalCorrelation,
    Document,
    Edge,
    Evidence,
    ExaminationLog,
    Finding,
    Mitigation,
    Node,
    Report,
)
from app.security import deobfuscate_secret, obfuscate_secret
from app.services.cross_signal import build_cross_signal_correlations
from app.services.collector_v2 import collect_documents
from app.services.evidence_quality_classifier import classify_evidence
from app.services.progress_tracker import finish_progress, start_progress, update_progress
from app.utils.demo_seed import generate_demo_documents, generate_demo_evidence
from app.utils.graphing import build_edges_for_persisted_nodes, rebuild_graph
from app.utils.jsonx import from_json, to_json
from app.utils.reporting import render_assessment_pdf
from app.utils.scoring import build_assumptions, finding_severity
from src.rag.index import build_index as build_rag_index
from src.rag.index import run_query_plan
from src.reasoner.hypotheses import generate_hypotheses


DEFAULT_SOURCES = [
    "website_analyzer",
    "official_channel_enumerator",
    "public_role_extractor",
    "email_posture_analyzer",
    "dns_footprint",
    "subdomain_discovery",
    "brand_impersonation_monitor",
    "gdelt_news",
    "media_trend",
    "social_mock",
    "job_postings_live",
    "vendor_js_detection",
    "procurement_documents",
    "public_docs_pdf",
    "shodan",
    "hibp_breach_domain",
]
LLM_MODEL_OPTIONS = {"gpt-4.1", "gpt-4.1o", "LOCAL"}
LLM_API_SETTING_NAME = "__llm_reasoner_api__"
LLM_MODEL_SETTING_NAME = "__llm_reasoner_model__"
RAG_TOP_K_SETTING_NAME = "__rag_top_k__"
RAG_MIN_RATIO_SETTING_NAME = "__rag_min_ratio__"
logger = logging.getLogger(__name__)


def _finding_chain_template(finding_type: str) -> dict[str, str]:
    key = (finding_type or "").strip().lower()
    if key == "exposure":
        return {
            "what": "Public pages expose reusable organizational details, contacts, and role cues",
            "inference": "Attackers can assemble realistic reconnaissance packages with low effort",
            "why": "Recon material improves pretext quality and lowers social-engineering friction",
            "boundary": "This indicates exposure conditions, not confirmed active exploitation",
        }
    if key == "mention":
        return {
            "what": "External narratives and mentions mirror internal processes or trust language",
            "inference": "Fraud pretexts can borrow familiar wording and timing",
            "why": "Narrative alignment increases plausibility of malicious outreach",
            "boundary": "No coordinated disinformation campaign was confirmed in this run",
        }
    if key == "touchpoint":
        return {
            "what": "Public support, billing, and contact channels are discoverable across sources",
            "inference": "Official-channel ambiguity can enable conversation insertion",
            "why": "Channel ambiguity increases risk of unauthorized process requests",
            "boundary": "This reflects channel friction and trust weakness, not proven compromise",
        }
    if key == "pivot":
        return {
            "what": "Signals suggest brand trust could be leveraged against clients or partners",
            "inference": "Impersonation attempts can pivot from public channels to downstream workflows",
            "why": "Abuse of trusted identity can expand impact beyond internal perimeter",
            "boundary": "No direct victim telemetry was observed above threshold",
        }
    return {
        "what": "Multiple public indicators align around a potential trust-abuse condition",
        "inference": "Evidence supports a plausible attack path hypothesis",
        "why": "Without controls, trust-heavy workflows remain exposed to misuse",
        "boundary": "Assessment captures externally visible signals only",
    }


def _severity_why_line(severity: int, confidence: int, evidence_count: int) -> str:
    sev = max(1, min(5, int(severity or 3)))
    conf = max(1, min(100, int(confidence or 0)))
    count = max(1, int(evidence_count or 1))
    if sev >= 4:
        impact = "material operational/trust disruption if abused"
    elif sev == 3:
        impact = "meaningful disruption requiring defensive prioritization"
    else:
        impact = "contained impact unless combined with additional signals"
    if conf >= 75:
        likelihood = "high"
    elif conf >= 50:
        likelihood = "medium"
    else:
        likelihood = "low-to-medium"
    return f"Likelihood {likelihood} from {count} corroborating signals (confidence {conf}%) with {impact}."


def _mitigation_playbook(finding_type: str) -> str:
    key = (finding_type or "").strip().lower()
    if key == "touchpoint":
        return (
            "Consolidate one public channel registry, enforce callback verification for support/billing changes, "
            "and require secondary approval for high-impact requests."
        )
    if key == "pivot":
        return (
            "Publish anti-impersonation guidance for customers/partners, deploy signed outbound communication patterns, "
            "and activate rapid abuse-report triage."
        )
    if key == "mention":
        return (
            "Monitor recurring external narratives, standardize trusted wording for sensitive workflows, "
            "and route suspicious references to joint Comms/Security review."
        )
    return (
        "Reduce unnecessary public operational detail, harden identity checks in trust-heavy workflows, "
        "and document escalation criteria for suspicious requests."
    )


def _normalize_finding_refs(raw_json: str) -> list[int]:
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


def infer_source_type(url: str, connector_name: str = "") -> str:
    value = (url or "").lower()
    if value.startswith("dns://"):
        return "dns"
    if value.endswith(".pdf") or "/pdf" in value:
        return "pdf"
    if "rss" in value or value.endswith(".xml"):
        return "rss"
    if "gdelt" in value or connector_name == "gdelt_news":
        return "news"
    if value.startswith("http://") or value.startswith("https://"):
        return "html"
    return "manual"


def _hash_text(value: str) -> str:
    return hashlib.sha256((value or "").encode("utf-8")).hexdigest()[:32] if value else ""


def _classify_payload(item: EvidencePayload) -> dict:
    source_type = infer_source_type(item.source_url, item.connector)
    q = classify_evidence(
        url=item.source_url,
        title=item.title,
        snippet=item.snippet,
        source_type=source_type,
        connector=item.connector,
        mime_type=str((item.raw or {}).get("mime_type", "")),
        raw=(item.raw or {}),
        anchor_text=str((item.raw or {}).get("anchor_text", "")),
    )
    return {
        "source_type": source_type,
        "evidence_kind": q.evidence_kind,
        "quality_tier": q.quality_tier,
        "quality_weight": float(q.quality_weight),
        "is_boilerplate": bool(q.is_boilerplate),
        "rationale": q.rationale,
    }


def log_examination_event(
    db: Session,
    assessment_id: int,
    *,
    url: str,
    source_type: str,
    status: str,
    discovered_from: str = "",
    http_status: int | None = None,
    content_hash: str = "",
    bytes_size: int | None = None,
    parse_summary: str = "",
    error_message: str = "",
    fetched_at: datetime | None = None,
    was_rendered: bool | None = None,
    extracted_chars: int | None = None,
    pdf_pages: int | None = None,
    pdf_text_chars: int | None = None,
) -> None:
    row = ExaminationLog(
        assessment_id=assessment_id,
        url=(url or "")[:1024],
        source_type=(source_type or "manual")[:32],
        status=(status or "fetched")[:32],
        http_status=http_status,
        content_hash=(content_hash or "")[:128],
        bytes=bytes_size,
        discovered_from=(discovered_from or "")[:128],
        fetched_at=fetched_at,
        was_rendered=was_rendered,
        extracted_chars=extracted_chars,
        pdf_pages=pdf_pages,
        pdf_text_chars=pdf_text_chars,
        parse_summary=parse_summary or "",
        error_message=error_message or "",
    )
    db.add(row)
    db.commit()


def list_connector_states(db: Session) -> list[dict]:
    settings = {item.name: item for item in db.execute(select(ConnectorSetting)).scalars().all()}
    data = []
    for connector in connector_registry():
        row = settings.get(connector.name)
        data.append(
            {
                "name": connector.name,
                "description": connector.description,
                "requires_api_key": connector.requires_api_key,
                "enabled": True if row is None else row.enabled,
                "has_api_key": bool(row and row.api_key_obfuscated),
            }
        )
    return data


def get_connector_setting(db: Session, name: str) -> ConnectorSetting | None:
    # Historical DBs might contain duplicates because the unique constraint is not retroactive.
    # Always pick the most recently updated row.
    return (
        db.execute(
            select(ConnectorSetting)
            .where(ConnectorSetting.name == name)
            .order_by(ConnectorSetting.updated_at.desc(), ConnectorSetting.id.desc())
            .limit(1)
        )
        .scalars()
        .first()
    )


def save_connector_setting(db: Session, name: str, enabled: bool, api_key: str | None = None) -> None:
    # Dedupe any legacy duplicates first.
    rows = (
        db.execute(select(ConnectorSetting).where(ConnectorSetting.name == name).order_by(ConnectorSetting.id.desc()))
        .scalars()
        .all()
    )
    row = rows[0] if rows else None
    if rows and len(rows) > 1:
        for extra in rows[1:]:
            db.delete(extra)
        db.flush()
    if not row:
        row = ConnectorSetting(name=name, enabled=enabled)
        db.add(row)

    row.enabled = enabled
    if api_key is not None:
        row.api_key_obfuscated = obfuscate_secret(api_key.strip()) if api_key.strip() else ""
    db.commit()


def test_connector(db: Session, connector_name: str) -> tuple[bool, str]:
    cmap = connector_map()
    connector = cmap.get(connector_name)
    if not connector:
        return False, "Unknown connector"
    row = get_connector_setting(db, connector_name)
    api_key = deobfuscate_secret(row.api_key_obfuscated) if row else None
    return connector.ping(api_key=api_key)


def get_llm_state(db: Session) -> dict:
    settings = get_settings()
    env_api_key = (settings.openai_api_key or "").strip()
    model_row = get_connector_setting(db, LLM_MODEL_SETTING_NAME)
    api_row = get_connector_setting(db, LLM_API_SETTING_NAME)
    if not model_row:
        return {
            "model": "gpt-4.1",
            "has_api_key": bool((api_row and api_row.api_key_obfuscated) or env_api_key),
        }
    decoded = deobfuscate_secret(model_row.api_key_obfuscated) if model_row.api_key_obfuscated else None
    model = decoded if decoded in LLM_MODEL_OPTIONS else "gpt-4.1"
    return {
        "model": model,
        "has_api_key": bool((api_row and api_row.api_key_obfuscated) or env_api_key),
    }


def save_llm_setting(db: Session, model: str, api_key: str | None = None, clear_api_key: bool = False) -> None:
    chosen = (model or "").strip()
    if chosen not in LLM_MODEL_OPTIONS:
        chosen = "gpt-4.1"

    model_row = get_connector_setting(db, LLM_MODEL_SETTING_NAME)
    if not model_row:
        model_row = ConnectorSetting(name=LLM_MODEL_SETTING_NAME, enabled=True)
        db.add(model_row)
    model_row.enabled = True
    model_row.api_key_obfuscated = obfuscate_secret(chosen)

    api_row = get_connector_setting(db, LLM_API_SETTING_NAME)
    if not api_row:
        api_row = ConnectorSetting(name=LLM_API_SETTING_NAME, enabled=True)
        db.add(api_row)
    api_row.enabled = True

    if clear_api_key:
        api_row.api_key_obfuscated = ""
    elif api_key is not None and api_key.strip():
        api_row.api_key_obfuscated = obfuscate_secret(api_key.strip())

    db.commit()


def get_llm_runtime_config(db: Session) -> dict:
    settings = get_settings()
    env_model = (settings.openai_reasoner_model or "gpt-4.1").strip()
    env_api_key = (settings.openai_api_key or "").strip() or None
    model_row = get_connector_setting(db, LLM_MODEL_SETTING_NAME)
    api_row = get_connector_setting(db, LLM_API_SETTING_NAME)
    if not model_row:
        return {
            "model": env_model or "gpt-4.1",
            "api_key": deobfuscate_secret(api_row.api_key_obfuscated)
            if (api_row and api_row.api_key_obfuscated)
            else env_api_key,
        }
    decoded_model = deobfuscate_secret(model_row.api_key_obfuscated) if model_row.api_key_obfuscated else None
    model = decoded_model if decoded_model in LLM_MODEL_OPTIONS else (env_model or "gpt-4.1")
    api_key = (
        deobfuscate_secret(api_row.api_key_obfuscated) if (api_row and api_row.api_key_obfuscated) else env_api_key
    )
    return {
        "model": model,
        "api_key": api_key,
    }


def get_rag_advanced_state(db: Session) -> dict:
    topk_row = get_connector_setting(db, RAG_TOP_K_SETTING_NAME)
    ratio_row = get_connector_setting(db, RAG_MIN_RATIO_SETTING_NAME)

    top_k = 4
    if topk_row and topk_row.api_key_obfuscated:
        raw = deobfuscate_secret(topk_row.api_key_obfuscated) or ""
        if str(raw).strip().isdigit():
            top_k = int(str(raw).strip())

    min_ratio = 0.70
    if ratio_row and ratio_row.api_key_obfuscated:
        raw = deobfuscate_secret(ratio_row.api_key_obfuscated) or ""
        try:
            min_ratio = float(str(raw).strip())
        except Exception:
            min_ratio = 0.70

    top_k = max(1, min(12, int(top_k)))
    min_ratio = max(0.10, min(0.95, float(min_ratio)))
    return {"top_k": top_k, "min_ratio": round(min_ratio, 2)}


def save_rag_advanced_settings(db: Session, *, top_k: int, min_ratio: float) -> None:
    top_k = max(1, min(12, int(top_k)))
    min_ratio = max(0.10, min(0.95, float(min_ratio)))

    topk_row = get_connector_setting(db, RAG_TOP_K_SETTING_NAME)
    if not topk_row:
        topk_row = ConnectorSetting(name=RAG_TOP_K_SETTING_NAME, enabled=True)
        db.add(topk_row)
    topk_row.enabled = True
    topk_row.api_key_obfuscated = obfuscate_secret(str(top_k))

    ratio_row = get_connector_setting(db, RAG_MIN_RATIO_SETTING_NAME)
    if not ratio_row:
        ratio_row = ConnectorSetting(name=RAG_MIN_RATIO_SETTING_NAME, enabled=True)
        db.add(ratio_row)
    ratio_row.enabled = True
    ratio_row.api_key_obfuscated = obfuscate_secret(f"{min_ratio:.2f}")

    db.commit()


def _selected_connectors(assessment: Assessment) -> list[str]:
    selected = from_json(assessment.selected_sources_json, [])
    if not selected:
        return DEFAULT_SOURCES
    return selected


def _get_api_key(db: Session, connector_name: str) -> str | None:
    setting = get_connector_setting(db, connector_name)
    if not setting or not setting.enabled:
        return None
    return deobfuscate_secret(setting.api_key_obfuscated)


def run_collection(db: Session, assessment: Assessment) -> list[str]:
    start_progress(assessment.id, "collect", "Initializing collection workspace...")
    cmap = connector_map()

    def examination_logger(**kwargs):
        log_examination_event(db, assessment.id, **kwargs)

    target = ConnectorTarget(
        company_name=assessment.company_name,
        domain=assessment.domain,
        sector=assessment.sector,
        regions=assessment.regions,
        demo_mode=assessment.demo_mode,
        assessment_id=assessment.id,
        examination_logger=examination_logger,
    )
    logs: list[str] = []
    selected = _selected_connectors(assessment)

    document_based_connectors = {
        "website_analyzer",
        "official_channel_enumerator",
        "public_role_extractor",
        "public_docs_pdf",
        "vendor_js_detection",
        "procurement_documents",
        "job_postings_live",
    }
    if any(name in selected for name in document_based_connectors):
        update_progress(assessment.id, "collect", "Crawling and parsing public documents...")
        docs = collect_documents(assessment.id, db=db)
        logs.append(f"collector_v2: created/updated {len(docs)} documents")
        log_examination_event(
            db,
            assessment.id,
            url=f"collector://assessment/{assessment.id}",
            source_type="manual",
            status="parsed",
            discovered_from="run_collection",
            parse_summary=f"collector_v2 documents={len(docs)}",
            fetched_at=datetime.utcnow(),
        )
        try:
            update_progress(assessment.id, "collect", "Building retrieval index from collected documents...")
            rag_meta = build_rag_index(assessment.id)
            logs.append(
                f"rag_index: documents={rag_meta.get('num_documents', 0)} passages={rag_meta.get('num_passages', 0)}"
            )
            log_examination_event(
                db,
                assessment.id,
                url=f"rag://assessment/{assessment.id}",
                source_type="manual",
                status="parsed",
                discovered_from="run_collection",
                parse_summary=f"rag index passages={rag_meta.get('num_passages', 0)}",
                fetched_at=datetime.utcnow(),
            )
        except Exception as exc:
            logger.exception("RAG index build failed for assessment %s", assessment.id)
            logs.append(f"rag_index: error ({exc.__class__.__name__})")
            log_examination_event(
                db,
                assessment.id,
                url=f"rag://assessment/{assessment.id}",
                source_type="manual",
                status="failed",
                discovered_from="run_collection",
                error_message=f"{exc.__class__.__name__}: {exc}",
                fetched_at=datetime.utcnow(),
            )

    # Clear previous collection for idempotent step rerun
    update_progress(assessment.id, "collect", "Refreshing normalized evidence store...")
    db.execute(delete(Evidence).where(Evidence.assessment_id == assessment.id))
    db.commit()

    for name in selected:
        update_progress(assessment.id, "collect", f"Running connector: {name}...")
        connector = cmap.get(name)
        if not connector:
            logs.append(f"{name}: skipped (not registered)")
            log_examination_event(
                db,
                assessment.id,
                url=f"connector://{name}",
                source_type="manual",
                status="blocked",
                discovered_from="connector registry",
                error_message="connector not registered",
            )
            continue

        setting = get_connector_setting(db, name)
        enabled = True if setting is None else setting.enabled
        if not enabled:
            logs.append(f"{name}: skipped (disabled in settings)")
            log_examination_event(
                db,
                assessment.id,
                url=f"connector://{name}",
                source_type="manual",
                status="skipped",
                discovered_from="settings/connectors",
                parse_summary="connector disabled",
            )
            continue

        api_key = _get_api_key(db, name)
        if connector.requires_api_key and not api_key:
            logs.append(f"{name}: missing API key, using fallback/skip")
            log_examination_event(
                db,
                assessment.id,
                url=f"connector://{name}",
                source_type="manual",
                status="skipped",
                discovered_from="settings/connectors",
                parse_summary="missing api key",
            )

        try:
            payloads = connector.run(target=target, api_key=api_key)
        except Exception as exc:
            logs.append(f"{name}: error ({exc.__class__.__name__}), skipped")
            log_examination_event(
                db,
                assessment.id,
                url=f"connector://{name}",
                source_type="manual",
                status="failed",
                discovered_from="connector-run",
                error_message=f"{exc.__class__.__name__}: {exc}",
            )
            logger.exception("Connector %s failed for assessment %s", name, assessment.id)
            continue

        if not payloads:
            logs.append(f"{name}: no evidence")
            log_examination_event(
                db,
                assessment.id,
                url=f"connector://{name}",
                source_type="manual",
                status="parsed",
                discovered_from="connector-run",
                parse_summary="no evidence returned",
            )
            continue

        for item in payloads:
            qmeta = _classify_payload(item)
            db.add(
                Evidence(
                    assessment_id=assessment.id,
                    connector=item.connector,
                    category=item.category,
                    title=item.title[:255],
                    snippet=item.snippet,
                    source_url=item.source_url[:512],
                    observed_at=item.observed_at,
                    confidence=max(1, min(100, int(item.confidence))),
                    evidence_kind=qmeta["evidence_kind"],
                    quality_tier=qmeta["quality_tier"],
                    quality_weight=float(qmeta["quality_weight"]),
                    is_boilerplate=bool(qmeta["is_boilerplate"]),
                    rationale=str(qmeta["rationale"])[:255],
                    raw_json=to_json(item.raw),
                )
            )
            log_examination_event(
                db,
                assessment.id,
                url=item.source_url or f"connector://{name}",
                source_type=qmeta["source_type"],
                status="parsed",
                discovered_from=f"{name} evidence",
                content_hash=_hash_text(item.snippet or item.title),
                bytes_size=len((item.snippet or "").encode("utf-8")),
                parse_summary=(f"{item.title[:160]} | {qmeta['evidence_kind']}:{qmeta['quality_tier']}"),
                fetched_at=item.observed_at,
            )

        db.commit()
        logs.append(f"{name}: collected {len(payloads)} evidence items")
        logger.info(
            "Connector %s collected %s evidences for assessment %s",
            name,
            len(payloads),
            assessment.id,
        )

    update_progress(assessment.id, "collect", "Correlating cross-signal findings...")
    correlation_count = build_cross_signal_correlations(db, assessment)
    logs.append(f"cross_signal_correlation: generated {correlation_count} correlations")
    log_examination_event(
        db,
        assessment.id,
        url=f"correlation://assessment/{assessment.id}",
        source_type="manual",
        status="parsed",
        discovered_from="run_collection",
        parse_summary=f"cross-signal correlations={correlation_count}",
        fetched_at=datetime.utcnow(),
    )

    assessment.status = "collected"
    assessment.wizard_step = max(assessment.wizard_step, 4)
    assessment.collect_log_json = to_json(logs)
    assessment.updated_at = datetime.utcnow()
    db.commit()
    finish_progress(assessment.id, "collect", "Collection complete.")

    return logs


def _build_findings_from_evidence(assessment: Assessment, evidences: list[Evidence]) -> list[Finding]:
    grouped: dict[str, list[Evidence]] = defaultdict(list)
    for ev in evidences:
        grouped[ev.category].append(ev)

    findings: list[Finding] = []
    for ftype in ["exposure", "mention", "touchpoint", "pivot"]:
        items = grouped.get(ftype, [])
        if not items:
            continue

        evidence_count = len(items)
        has_critical_touchpoint = any(
            "billing" in ev.snippet.lower() or "support" in ev.snippet.lower() for ev in items
        )
        downstream = ftype == "pivot" or any("imperson" in ev.snippet.lower() for ev in items)
        sev = finding_severity(ftype, evidence_count, has_critical_touchpoint, downstream)
        conf = int(sum(i.confidence for i in items) / evidence_count)

        title_map = {
            "exposure": "Public Information Exposure Enables Reconnaissance",
            "mention": "Narrative Pressure and Brand Mention Volatility",
            "touchpoint": "External Contact Channels with Trust Friction",
            "pivot": "Risk to Clients via Impersonation",
        }
        type_label_map = {
            "exposure": "public information exposure",
            "mention": "narrative mention volatility",
            "touchpoint": "external contact channel",
            "pivot": "risk to clients via impersonation",
        }

        chain = _finding_chain_template(ftype)
        desc = (
            f"What we saw: {chain['what']} ({evidence_count} corroborating signals for {type_label_map.get(ftype, ftype)}). "
            f"Why it matters: {chain['why']}. "
            f"Why S{sev}: {_severity_why_line(sev, conf, evidence_count)} "
            f"Scope boundary: {chain['boundary']}."
        )

        refs = [e.id for e in sorted(items, key=lambda x: x.confidence, reverse=True)[:8]]
        findings.append(
            Finding(
                assessment_id=assessment.id,
                type=ftype,
                severity=sev,
                title=title_map.get(ftype, ftype.title()),
                description=desc,
                confidence=conf,
                evidence_refs_json=to_json(refs),
            )
        )

    # Extra pivot finding when downstream language appears in non-pivot categories
    downstream_refs = [
        e.id
        for e in evidences
        if "onboarding" in e.snippet.lower() or "invoice" in e.snippet.lower() or "donation" in e.snippet.lower()
    ][:8]
    if downstream_refs:
        findings.append(
            Finding(
                assessment_id=assessment.id,
                type="pivot",
                severity=4,
                title="Client/Partner Safety Risk Requires Control Layer",
                description=(
                    "What we saw: Observed external contact and narrative signals indicate downstream trust exposure. "
                    "Why it matters: conversation insertion in onboarding/invoice/donation workflows can trigger partner/client harm. "
                    f"Why S4: {_severity_why_line(4, 72, len(downstream_refs))} "
                    "Scope boundary: This captures abuse preconditions, not confirmed incidents."
                ),
                confidence=72,
                evidence_refs_json=to_json(downstream_refs),
            )
        )

    return findings


def build_model(db: Session, assessment: Assessment) -> dict:
    start_progress(assessment.id, "model", "Loading evidence for graph modeling...")
    evidences = (
        db.execute(select(Evidence).where(Evidence.assessment_id == assessment.id).order_by(Evidence.confidence.desc()))
        .scalars()
        .all()
    )

    db.execute(delete(Node).where(Node.assessment_id == assessment.id))
    db.execute(delete(Edge).where(Edge.assessment_id == assessment.id))
    db.execute(delete(Finding).where(Finding.assessment_id == assessment.id))
    db.commit()

    update_progress(assessment.id, "model", "Rebuilding relationship graph...")
    draft_nodes, _ = rebuild_graph(assessment, evidences)
    db.add_all(draft_nodes)
    db.commit()

    nodes = db.execute(select(Node).where(Node.assessment_id == assessment.id)).scalars().all()
    edges = build_edges_for_persisted_nodes(assessment.id, nodes)
    db.add_all(edges)

    update_progress(assessment.id, "model", "Deriving prioritized findings...")
    findings = _build_findings_from_evidence(assessment, evidences)
    db.add_all(findings)

    assessment.assumptions_json = to_json(build_assumptions(evidences))
    assessment.status = "modeled"
    assessment.wizard_step = max(assessment.wizard_step, 5)
    assessment.updated_at = datetime.utcnow()
    db.commit()
    finish_progress(assessment.id, "model", "Risk model complete.")
    logger.info(
        "Model built for assessment %s: nodes=%s edges=%s findings=%s",
        assessment.id,
        len(nodes),
        len(edges),
        len(findings),
    )

    return {
        "nodes": len(nodes),
        "edges": len(edges),
        "findings": len(findings),
    }


def build_mitigations(db: Session, assessment: Assessment) -> int:
    findings = (
        db.execute(select(Finding).where(Finding.assessment_id == assessment.id).order_by(Finding.severity.desc()))
        .scalars()
        .all()
    )

    db.execute(delete(Mitigation).where(Mitigation.assessment_id == assessment.id))
    db.commit()

    mitigations: list[Mitigation] = []

    for finding in findings:
        owner = "Security Engineering"
        effort = "M"
        if finding.type == "mention":
            owner = "Comms"
            effort = "S"
        elif finding.type == "touchpoint":
            owner = "Operations"
        elif finding.type == "pivot":
            owner = "Customer Trust"
            effort = "L"

        mitigations.append(
            Mitigation(
                assessment_id=assessment.id,
                priority=max(1, min(5, 6 - finding.severity)),
                effort=effort,
                owner=owner,
                description=f"{finding.title}: {_mitigation_playbook(finding.type)}",
                linked_findings_json=to_json([finding.id]),
            )
        )

    # Customer safety controls when pivot risk exists
    if any(f.type == "pivot" for f in findings):
        mitigations.extend(
            [
                Mitigation(
                    assessment_id=assessment.id,
                    priority=1,
                    effort="M",
                    owner="Customer Trust",
                    description=(
                        "Publish client safety controls: verified callback numbers, signed notices, and "
                        "anti-impersonation awareness messaging."
                    ),
                    linked_findings_json=to_json([f.id for f in findings if f.type == "pivot"][:5]),
                ),
                Mitigation(
                    assessment_id=assessment.id,
                    priority=2,
                    effort="M",
                    owner="Support",
                    description=(
                        "Deploy script for support agents to never request credentials; use challenge phrases and "
                        "sanitized templates for outbound communications."
                    ),
                    linked_findings_json=to_json([f.id for f in findings if f.type == "pivot"][:5]),
                ),
            ]
        )

    db.add_all(mitigations)
    assessment.status = "reduced"
    assessment.wizard_step = max(assessment.wizard_step, 6)
    assessment.updated_at = datetime.utcnow()
    db.commit()
    logger.info("Mitigations generated for assessment %s: %s", assessment.id, len(mitigations))

    return len(mitigations)


def export_report(db: Session, assessment: Assessment) -> Report:
    start_progress(assessment.id, "report", "Collecting report inputs...")
    evidences = db.execute(select(Evidence).where(Evidence.assessment_id == assessment.id)).scalars().all()
    findings = db.execute(select(Finding).where(Finding.assessment_id == assessment.id)).scalars().all()
    mitigations = db.execute(select(Mitigation).where(Mitigation.assessment_id == assessment.id)).scalars().all()
    correlations = (
        db.execute(select(CrossSignalCorrelation).where(CrossSignalCorrelation.assessment_id == assessment.id))
        .scalars()
        .all()
    )

    update_progress(assessment.id, "report", "Rendering PDF report...")
    pdf_path = render_assessment_pdf(assessment, evidences, findings, mitigations)

    stamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    export_dir = get_settings().runtime_dir / "exports"
    export_dir.mkdir(parents=True, exist_ok=True)
    json_path = export_dir / f"assessment_{assessment.id}_{stamp}.json"
    evidence_map = {e.id: e for e in evidences}
    finding_payload: list[dict] = []
    for f in findings:
        refs = _normalize_finding_refs(f.evidence_refs_json)
        linked = [evidence_map[ref] for ref in refs if ref in evidence_map]
        chain = _finding_chain_template(f.type)
        samples = [" ".join((e.snippet or e.title).strip().split())[:160] for e in linked[:2] if (e.snippet or e.title)]
        finding_payload.append(
            {
                "id": f.id,
                "type": f.type,
                "severity": f.severity,
                "title": f.title,
                "description": f.description,
                "confidence": f.confidence,
                "evidence_refs": refs,
                "analysis": {
                    "what_we_saw": (
                        f"{len(refs)} corroborating references"
                        + (f"; signal samples: {' | '.join(samples)}" if samples else "")
                    ),
                    "inference": chain["inference"],
                    "why_it_matters": chain["why"],
                    "why_severity": _severity_why_line(f.severity, f.confidence, len(refs)),
                    "scope_boundary": chain["boundary"],
                },
            }
        )

    export_json = {
        "assessment": {
            "id": assessment.id,
            "company_name": assessment.company_name,
            "domain": assessment.domain,
            "sector": assessment.sector,
            "regions": assessment.regions,
            "status": assessment.status,
            "assumptions": from_json(assessment.assumptions_json, []),
        },
        "findings": finding_payload,
        "mitigations": [
            {
                "id": m.id,
                "priority": m.priority,
                "effort": m.effort,
                "owner": m.owner,
                "description": m.description,
                "linked_findings": from_json(m.linked_findings_json, []),
            }
            for m in mitigations
        ],
        "evidence": [
            {
                "id": e.id,
                "connector": e.connector,
                "category": e.category,
                "title": e.title,
                "snippet": e.snippet,
                "source_url": e.source_url,
                "confidence": e.confidence,
                "evidence_kind": e.evidence_kind,
                "quality_tier": e.quality_tier,
                "quality_weight": e.quality_weight,
                "is_boilerplate": bool(e.is_boilerplate),
                "rationale": e.rationale,
            }
            for e in evidences[:200]
        ],
        "cross_signal_correlations": [
            {
                "id": c.id,
                "title": c.title,
                "summary": c.summary,
                "risk_level": c.risk_level,
                "signals": from_json(c.signals_json, []),
                "evidence_refs": from_json(c.evidence_refs_json, []),
            }
            for c in correlations
        ],
    }
    update_progress(assessment.id, "report", "Writing JSON export package...")
    Path(json_path).write_text(to_json(export_json), encoding="utf-8")

    report = Report(assessment_id=assessment.id, pdf_path=str(pdf_path), json_path=str(json_path))
    db.add(report)

    assessment.status = "reported"
    assessment.wizard_step = max(assessment.wizard_step, 7)
    assessment.updated_at = datetime.utcnow()
    db.commit()
    finish_progress(assessment.id, "report", "Report package ready.")
    db.refresh(report)
    logger.info("Report exported for assessment %s: %s", assessment.id, report.pdf_path)
    return report


def create_assessment(
    db: Session,
    company_name: str,
    domain: str,
    sector: str,
    regions: str,
    demo_mode: bool,
) -> Assessment:
    assessment = Assessment(
        company_name=company_name.strip(),
        domain=domain.strip().lower(),
        sector=sector.strip() or "Unknown",
        regions=regions.strip(),
        demo_mode=demo_mode,
        status="draft",
        # Target fields are provided at creation time, so next expected step is source selection.
        wizard_step=2,
        selected_sources_json=to_json(DEFAULT_SOURCES),
    )
    db.add(assessment)
    db.commit()
    db.refresh(assessment)
    return assessment


def update_assessment_target(
    db: Session,
    assessment: Assessment,
    company_name: str,
    domain: str,
    sector: str,
    regions: str,
    demo_mode: bool,
) -> Assessment:
    assessment.company_name = company_name.strip()
    assessment.domain = domain.strip().lower()
    assessment.sector = sector.strip() or "Unknown"
    assessment.regions = regions.strip()
    assessment.demo_mode = demo_mode
    assessment.wizard_step = max(assessment.wizard_step, 2)
    assessment.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(assessment)
    return assessment


def save_selected_sources(db: Session, assessment: Assessment, sources: list[str]) -> Assessment:
    assessment.selected_sources_json = to_json(sources)
    assessment.wizard_step = max(assessment.wizard_step, 3)
    assessment.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(assessment)
    return assessment


def get_assessment(db: Session, assessment_id: int) -> Assessment | None:
    return db.get(Assessment, assessment_id)


def list_examination_logs(
    db: Session,
    assessment_id: int,
    *,
    status: str = "",
    source_type: str = "",
    q: str = "",
    limit: int = 500,
) -> list[ExaminationLog]:
    stmt = select(ExaminationLog).where(ExaminationLog.assessment_id == assessment_id)
    if status.strip():
        stmt = stmt.where(ExaminationLog.status == status.strip())
    if source_type.strip():
        stmt = stmt.where(ExaminationLog.source_type == source_type.strip())
    if q.strip():
        like = f"%{q.strip()}%"
        stmt = stmt.where(
            ExaminationLog.url.ilike(like)
            | ExaminationLog.parse_summary.ilike(like)
            | ExaminationLog.discovered_from.ilike(like)
            | ExaminationLog.error_message.ilike(like)
        )

    stmt = stmt.order_by(ExaminationLog.discovered_at.desc()).limit(max(1, min(5000, limit)))
    return db.execute(stmt).scalars().all()


def examination_log_csv(rows: list[ExaminationLog]) -> str:
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(
        [
            "id",
            "assessment_id",
            "url",
            "source_type",
            "status",
            "http_status",
            "content_hash",
            "bytes",
            "discovered_from",
            "discovered_at",
            "fetched_at",
            "was_rendered",
            "extracted_chars",
            "pdf_pages",
            "pdf_text_chars",
            "parse_summary",
            "error_message",
        ]
    )
    for r in rows:
        writer.writerow(
            [
                r.id,
                r.assessment_id,
                r.url,
                r.source_type,
                r.status,
                r.http_status if r.http_status is not None else "",
                r.content_hash,
                r.bytes if r.bytes is not None else "",
                r.discovered_from,
                r.discovered_at.isoformat() if r.discovered_at else "",
                r.fetched_at.isoformat() if r.fetched_at else "",
                "true" if r.was_rendered else "false" if r.was_rendered is not None else "",
                r.extracted_chars if r.extracted_chars is not None else "",
                r.pdf_pages if r.pdf_pages is not None else "",
                r.pdf_text_chars if r.pdf_text_chars is not None else "",
                r.parse_summary,
                r.error_message,
            ]
        )
    return out.getvalue()


def create_demo_scenario(db: Session, scenario_name: str) -> Assessment:
    scenarios = {
        "RiadGroup Hospitality": {
            "domain": "riadgroup-demo.local",
            "sector": "Hospitality",
            "regions": "GCC, North Africa",
            "seed": 11,
        },
        "DesertAid NGO": {
            "domain": "desertaid-demo.local",
            "sector": "NGO",
            "regions": "MENA, East Africa",
            "seed": 29,
        },
    }
    meta = scenarios.get(scenario_name, scenarios["RiadGroup Hospitality"])

    assessment = create_assessment(
        db=db,
        company_name=scenario_name,
        domain=meta["domain"],
        sector=meta["sector"],
        regions=meta["regions"],
        demo_mode=True,
    )
    save_selected_sources(db, assessment, DEFAULT_SOURCES)

    demo_documents = generate_demo_documents(
        company_name=scenario_name,
        domain=meta["domain"],
    )
    for item in demo_documents:
        content_hash = _hash_text(f"{item.title}|{item.url}|{item.extracted_text}")
        db.add(
            Document(
                assessment_id=assessment.id,
                url=item.url,
                doc_type=item.doc_type,
                title=item.title[:255],
                extracted_text=item.extracted_text,
                language=item.language,
                content_hash=content_hash,
            )
        )
        log_examination_event(
            db,
            assessment.id,
            url=item.url,
            source_type=item.source_type,
            status="parsed",
            discovered_from=item.discovered_from,
            content_hash=content_hash,
            bytes_size=len(item.extracted_text.encode("utf-8")),
            parse_summary=f"demo document {item.doc_type}",
            fetched_at=datetime.utcnow(),
        )
    db.commit()

    # Build document-derived evidence using current connectors.
    document_target = ConnectorTarget(
        company_name=assessment.company_name,
        domain=assessment.domain,
        sector=assessment.sector,
        regions=assessment.regions,
        demo_mode=True,
        assessment_id=assessment.id,
        examination_logger=lambda **kwargs: log_examination_event(db, assessment.id, **kwargs),
    )
    cmap = connector_map()
    evidences: list[EvidencePayload] = []
    for name in ("website_analyzer", "public_docs_pdf"):
        connector = cmap.get(name)
        if not connector:
            continue
        try:
            evidences.extend(connector.run(target=document_target, api_key=None))
        except Exception as exc:
            logger.exception("Demo connector %s failed", name)
            log_examination_event(
                db,
                assessment.id,
                url=f"connector://{name}",
                source_type="manual",
                status="failed",
                discovered_from="demo connector run",
                error_message=f"{exc.__class__.__name__}: {exc}",
                fetched_at=datetime.utcnow(),
            )

    # Add narrative and pivot evidence for richer downstream risk context.
    evidences.extend(
        generate_demo_evidence(
            company_name=scenario_name,
            domain=meta["domain"],
            seed=meta["seed"],
        )
    )

    # Dedupe by connector/category/title/url to keep consistency.
    deduped: list[EvidencePayload] = []
    seen_keys: set[str] = set()
    for item in evidences:
        key = f"{item.connector}|{item.category}|{item.title}|{item.source_url}"
        if key in seen_keys:
            continue
        seen_keys.add(key)
        deduped.append(item)
    evidences = deduped

    for item in evidences:
        qmeta = _classify_payload(item)
        db.add(
            Evidence(
                assessment_id=assessment.id,
                connector=item.connector,
                category=item.category,
                title=item.title,
                snippet=item.snippet,
                source_url=item.source_url,
                confidence=item.confidence,
                evidence_kind=qmeta["evidence_kind"],
                quality_tier=qmeta["quality_tier"],
                quality_weight=float(qmeta["quality_weight"]),
                is_boilerplate=bool(qmeta["is_boilerplate"]),
                rationale=str(qmeta["rationale"])[:255],
                raw_json=to_json(item.raw),
            )
        )
        log_examination_event(
            db,
            assessment.id,
            url=item.source_url or "demo://seed",
            source_type=qmeta["source_type"],
            status="parsed",
            discovered_from="demo seed",
            content_hash=_hash_text(item.snippet or item.title),
            bytes_size=len((item.snippet or "").encode("utf-8")),
            parse_summary=(f"{item.title[:160]} | {qmeta['evidence_kind']}:{qmeta['quality_tier']}"),
            fetched_at=item.observed_at,
        )
    db.commit()

    rag_cfg = get_rag_advanced_state(db)
    rag_top_k = int(rag_cfg.get("top_k", 4))
    rag_min_ratio = float(rag_cfg.get("min_ratio", 0.70))
    rag_meta = build_rag_index(assessment.id)
    rag_plan = run_query_plan(assessment.id, top_k=rag_top_k, min_ratio=rag_min_ratio)
    hypothesis_cards = generate_hypotheses(assessment.id, rag_plan, allow_local_fallback=False)
    correlation_count = build_cross_signal_correlations(db, assessment)

    assessment.collect_log_json = to_json(
        [
            f"demo_seed: generated {len(demo_documents)} documents",
            f"demo_seed: generated {len(evidences)} evidence items",
            f"demo_seed: rag passages {rag_meta.get('num_passages', 0)}",
            f"demo_seed: risk scenarios {len(hypothesis_cards)}",
            f"demo_seed: cross-signal correlations {correlation_count}",
        ]
    )
    assessment.status = "collected"
    assessment.wizard_step = 4
    db.commit()

    build_model(db, assessment)
    build_mitigations(db, assessment)
    export_report(db, assessment)
    db.refresh(assessment)
    return assessment
