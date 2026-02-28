from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request
from fastapi.responses import FileResponse, RedirectResponse, Response
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse
import logging
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session
import statistics

from app.config import get_settings
from app.db import get_db
from app.dependencies import get_current_user
from app.models import (
    Assessment,
    CrossSignalCorrelation,
    Document,
    Evidence,
    ExaminationLog,
    Finding,
    Hypothesis,
    Mitigation,
    Report,
    RiskBrief,
    WorkflowNode,
)
from app.services.assessment_service import (
    build_mitigations,
    build_model,
    create_assessment,
    create_demo_scenario,
    examination_log_csv,
    export_report,
    get_assessment,
    list_examination_logs,
    list_connector_states,
    get_rag_advanced_state,
    run_collection,
    save_selected_sources,
    update_assessment_target,
)
from app.services.progress_tracker import fail_progress, finish_progress, get_progress, start_progress, update_progress
from app.utils.jsonx import from_json
from app.services.risk_brief_service import BriefInput, get_or_generate_brief
from app.services.risk_story import get_ranked_risks
from src.rag.index import build_index as build_rag_index
from src.rag.index import debug_query_plan as rag_debug_query_plan
from src.rag.index import run_query_plan as run_rag_query_plan
from src.rag.index import search as rag_search
from src.reasoner.hypotheses import generate_hypotheses

router = APIRouter(prefix="/assessments", tags=["assessments"])
logger = logging.getLogger(__name__)


def _assessment_group_key(company_name: str, domain: str) -> str:
    company = " ".join(str(company_name or "").split()).strip().lower()
    if company:
        return company
    return " ".join(str(domain or "").split()).strip().lower() or "__unknown__"


def _assessment_display_name(company_name: str, domain: str) -> str:
    company = " ".join(str(company_name or "").split()).strip()
    if company:
        return company
    domain_clean = " ".join(str(domain or "").split()).strip()
    return domain_clean or "Unnamed target"


def _risk_posture_score(row: dict) -> int:
    status = str(row.get("status", "WATCHLIST")).strip().upper()
    impact_band = str(row.get("impact_band", "MED")).strip().upper()
    plausibility = int(row.get("plausibility_score", 0) or 0)
    confidence = int(row.get("confidence", 0) or 0)
    impact_score = {"HIGH": 3, "MED": 2, "LOW": 1}
    impact_norm = int(round((impact_score.get(impact_band, 2) / 3.0) * 100))

    base = (0.45 * impact_norm) + (0.35 * plausibility) + (0.20 * confidence)
    status_factor = 1.0
    if status == "WATCHLIST":
        status_factor = 0.7
    elif status == "BASELINE":
        status_factor = 0.35
    return int(max(0, min(100, round(base * status_factor))))


def _overall_risk_score(rows: list[dict]) -> int:
    if not rows:
        return 0
    valid_rows = [r for r in rows if isinstance(r, dict)]
    if not valid_rows:
        return 0
    status_weight = {"ELEVATED": 1.0, "WATCHLIST": 0.6, "BASELINE": 0.3}
    impact_weight = {"HIGH": 1.25, "MED": 1.0, "LOW": 0.75}
    weighted_sum = 0.0
    weight_total = 0.0
    for row in valid_rows:
        score = float(_risk_posture_score(row))
        status = str(row.get("status", "WATCHLIST")).strip().upper()
        impact_band = str(row.get("impact_band", "MED")).strip().upper()
        w = float(status_weight.get(status, 0.6)) * float(impact_weight.get(impact_band, 1.0))
        w = max(0.1, w)
        weighted_sum += score * w
        weight_total += w
    if weight_total <= 0:
        return 0
    return int(max(0, min(100, round(weighted_sum / weight_total))))


def _assessment_context(assessment: Assessment) -> dict:
    return {
        "id": assessment.id,
        "company_name": assessment.company_name,
    }


def _latest_assessment_id(db: Session) -> int | None:
    latest = db.execute(select(Assessment.id).order_by(Assessment.updated_at.desc()).limit(1)).scalar_one_or_none()
    return int(latest) if latest is not None else None


def _log_confidence(status: str) -> int:
    mapping = {
        "parsed": 88,
        "fetched": 72,
        "pdf_needs_ocr_candidate": 45,
        "skipped_external": 28,
        "skipped": 35,
        "failed": 18,
        "blocked": 12,
    }
    return mapping.get((status or "").strip().lower(), 50)


def _severity_label(severity: int) -> tuple[str, str]:
    value = int(severity or 0)
    if value >= 5:
        return "critical", "High"
    if value >= 4:
        return "high", "High"
    if value == 3:
        return "med", "Med"
    return "low", "Low"


def _confidence_label(confidence: int) -> str:
    value = int(confidence or 0)
    if value >= 75:
        return "high"
    if value >= 50:
        return "med"
    return "low"


def _likelihood_label(value: str | None, severity: int, confidence: int) -> tuple[str, str]:
    if value in {"low", "med", "high"}:
        return value, value.upper()
    if severity >= 4 and confidence >= 70:
        return "high", "HIGH"
    if severity >= 3:
        return "med", "MED"
    return "low", "LOW"


def _risk_type_label(value: str) -> str:
    key = (value or "").strip().lower()
    mapping = {
        "exposure": "Public Information Exposure",
        "mention": "Mentions",
        "touchpoint": "External Contact Channels",
        "pivot": "Risk to Clients via Impersonation",
        "downstream_pivot": "Risk to Clients via Impersonation",
        "impersonation": "Impersonation",
        "brand_abuse": "Brand Abuse",
        "fraud_process": "Fraud Process",
        "credential_theft_risk": "Credential Theft Risk",
        "social_engineering_risk": "Social Engineering Risk",
        "other": "Other",
        "correlation": "Cross-Signal Correlation",
    }
    return mapping.get(key, key.replace("_", " ").title() or "Risk")


def _risk_title_exec(value: str) -> str:
    """
    Executive-friendly short titles for the Overview page.
    Keep them generic and non-technical.
    """
    key = (value or "").strip().lower()
    mapping = {
        "exposure": "Reconnaissance risk",
        "mention": "Public narrative risk",
        "touchpoint": "External channel abuse risk",
        "pivot": "Client impersonation risk",
        "downstream_pivot": "Client impersonation risk",
        "impersonation": "Impersonation risk",
        "brand_abuse": "Brand abuse risk",
        "fraud_process": "Process fraud risk",
        "credential_theft_risk": "Credential theft risk",
        "social_engineering_risk": "Social engineering risk",
        "correlation": "Correlated signal risk",
        "other": "Risk scenario",
    }
    return mapping.get(key, "Risk scenario")


def _domain_for_url(value: str) -> str:
    raw = (value or "").strip()
    if not raw:
        return "unknown"
    if raw.startswith("dns://"):
        return "dns"
    try:
        host = urlparse(raw).netloc.lower().split(":")[0]
        return host or "source"
    except Exception:
        return "source"


def _bucket_key_for_url(url: str, *, connector: str = "", doc_type: str = "") -> str:
    low = (url or "").lower()
    conn = (connector or "").lower()
    dt = (doc_type or "").lower()
    path = ""
    try:
        path = (urlparse(low).path or "").lower()
    except Exception:
        path = ""

    if low.startswith("dns://") or conn in {"dns_footprint", "subdomain_discovery", "shodan"}:
        return "dns"
    if dt == "pdf" or low.endswith(".pdf") or conn in {"public_docs_pdf"}:
        return "pdf"
    if (
        conn in {"job_postings_live"}
        or any(tok in low for tok in ["greenhouse.io", "lever.co", "indeed."])
        or any(tok in path for tok in ["/careers", "/jobs"])
    ):
        return "jobs"
    if conn in {"gdelt_news", "media_trend"} or any(tok in path for tok in ["/news", "/press"]):
        return "news"
    if conn in {"social_mock"} or any(tok in low for tok in ["community", "forum", "reddit", "whatsapp"]):
        return "social"
    return "website"


def _bucket_label(bucket_key: str) -> str:
    mapping = {
        "website": "Website",
        "pdf": "PDF",
        "jobs": "Jobs",
        "news": "News",
        "social": "Social",
        "dns": "DNS",
    }
    return mapping.get(bucket_key, bucket_key.title())


def _coverage_label(distinct_buckets: int, total_refs: int) -> str:
    if distinct_buckets >= 3 and total_refs >= 4:
        return "STRONG"
    if distinct_buckets == 2 and total_refs >= 2:
        return "OK"
    return "WEAK"


def _impact_strip_for_risk(*, risk_type: str, severity: int, impact: str = "", text: str = "") -> list[dict]:
    low = (text or "").lower()
    rt = (risk_type or "").lower()
    sev = max(1, min(5, int(severity or 3)))

    financial = 20 + (sev * 10)
    operational = 25 + (sev * 10)
    client_trust = 25 + (sev * 10)

    if impact == "financial" or any(
        k in low for k in ["billing", "invoice", "payment", "refund", "procurement", "supplier"]
    ):
        financial += 35
    if impact == "ops" or any(k in low for k in ["onboarding", "helpdesk", "support", "portal", "account"]):
        operational += 25
    if impact in {"reputation", "safety"} or rt in {"downstream_pivot", "impersonation", "brand_abuse", "pivot"}:
        client_trust += 35

    if rt in {"exposure"}:
        client_trust += 10

    financial = max(0, min(100, financial))
    operational = max(0, min(100, operational))
    client_trust = max(0, min(100, client_trust))

    return [
        {"label": "Financial", "value": financial},
        {"label": "Operational", "value": operational},
        {"label": "Client Trust", "value": client_trust},
    ]


def _radar_aggregate(risk_cards: list[dict]) -> dict:
    labels = ["Financial", "Operational", "Reputation", "Client Trust", "External Exploitability"]
    explanations = {
        "Financial": "Derived from billing/procurement cues and financial impact markers.",
        "Operational": "Derived from support/onboarding workflows and process friction risk.",
        "Reputation": "Derived from brand/narrative exposure and mention pressure.",
        "Client Trust": "Derived from impersonation/pivot likelihood and trust-channel reuse.",
        "External Exploitability": "Derived from public reachability and multi-source convergence.",
    }

    if not risk_cards:
        return {"labels": labels, "values": [0, 0, 0, 0, 0], "explanations": explanations}

    totals = {k: 0.0 for k in labels}
    weight_sum = 0.0
    for card in risk_cards[:10]:
        sev = float(card.get("severity", 3) or 3)
        w = max(1.0, min(5.0, sev))
        impact_strip = card.get("impact_strip_values") or {}
        buckets = int(card.get("convergence", {}).get("distinct_buckets", 0) or 0)
        refs = int(card.get("convergence", {}).get("total_refs", 0) or 0)

        financial = float(impact_strip.get("Financial", 0))
        operational = float(impact_strip.get("Operational", 0))
        client_trust = float(impact_strip.get("Client Trust", 0))
        reputation = float(card.get("reputation_score", client_trust * 0.7))
        external = float(min(100, (buckets * 18) + (10 if refs >= 2 else 0) + (10 if buckets >= 2 else 0)))

        totals["Financial"] += financial * w
        totals["Operational"] += operational * w
        totals["Client Trust"] += client_trust * w
        totals["Reputation"] += reputation * w
        totals["External Exploitability"] += external * w
        weight_sum += w

    values = [int(max(0, min(100, totals[k] / weight_sum))) if weight_sum else 0 for k in labels]
    return {"labels": labels, "values": values, "explanations": explanations}


@router.get("")
def assessments_list(
    request: Request,
    q: str = Query(default=""),
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    stmt = select(Assessment).order_by(Assessment.updated_at.desc())
    if q.strip():
        like = f"%{q.strip()}%"
        stmt = stmt.where(Assessment.company_name.ilike(like) | Assessment.domain.ilike(like))

    rows = db.execute(stmt).scalars().all()
    assessment_metrics: dict[int, dict[str, int]] = {}
    for a in rows:
        aid = int(a.id)
        ranked = get_ranked_risks(
            db,
            a,
            include_baseline=False,
            risk_type="",
            impact="",
            q="",
        )
        all_ranked_rows = list(ranked.get("all_ranked") or [])
        total_score = int(_overall_risk_score(all_ranked_rows))
        counts = dict(ranked.get("status_counts") or {"ELEVATED": 0, "WATCHLIST": 0, "BASELINE": 0})
        assessment_metrics[aid] = {
            "total_score": int(max(0, min(100, total_score))),
            "elevated": int(counts.get("ELEVATED", 0) or 0),
            "watchlist": int(counts.get("WATCHLIST", 0) or 0),
            "baseline": int(counts.get("BASELINE", 0) or 0),
        }

    grouped_rows: dict[str, dict] = {}
    for row in rows:
        key = _assessment_group_key(row.company_name, row.domain)
        group = grouped_rows.setdefault(
            key,
            {
                "company_name": _assessment_display_name(row.company_name, row.domain),
                "items": [],
            },
        )
        group["items"].append(row)

    company_groups: list[dict] = []
    for group in grouped_rows.values():
        history = sorted(
            list(group.get("items") or []),
            key=lambda a: (a.created_at or a.updated_at or datetime.min, int(a.id or 0)),
        )
        history_rows: list[dict] = []
        prev_score: int | None = None
        for idx, a in enumerate(history, start=1):
            metric = assessment_metrics.get(int(a.id), {"total_score": 0, "elevated": 0, "watchlist": 0, "baseline": 0})
            total_score = int(metric.get("total_score", 0) or 0)
            delta = None if prev_score is None else int(total_score - prev_score)
            assessment_date = a.created_at or a.updated_at
            date_label = assessment_date.strftime("%Y-%m-%d") if assessment_date else "undated"
            trend = "initial"
            if delta is not None:
                if delta > 0:
                    trend = "worse"
                elif delta < 0:
                    trend = "improved"
                else:
                    trend = "stable"
            history_rows.append(
                {
                    "id": int(a.id),
                    "name": f"Assessment {idx} ({date_label})",
                    "company_name": str(a.company_name or ""),
                    "domain": str(a.domain or ""),
                    "status": str(a.status or ""),
                    "created_at": a.created_at,
                    "updated_at": a.updated_at,
                    "total_score": total_score,
                    "delta_score": delta,
                    "delta_trend": trend,
                    "elevated": int(metric.get("elevated", 0) or 0),
                    "watchlist": int(metric.get("watchlist", 0) or 0),
                    "baseline": int(metric.get("baseline", 0) or 0),
                }
            )
            prev_score = total_score
        latest_updated = max((row["updated_at"] for row in history_rows if row.get("updated_at")), default=datetime.min)
        company_groups.append(
            {
                "company_name": str(group.get("company_name") or "Unnamed target"),
                "history": history_rows,
                "latest_updated": latest_updated,
                "prefill_assessment_id": int(history[-1].id) if history else None,
            }
        )
    company_groups.sort(key=lambda g: g.get("latest_updated") or datetime.min, reverse=True)

    return request.app.state.templates.TemplateResponse(
        "assessments_list.html",
        {
            "request": request,
            "user": user,
            "active": "assessments",
            "company_groups": company_groups,
            "q": q,
        },
    )


@router.get("/{assessment_id}/progress")
def assessment_progress(
    assessment_id: int,
    mode: str = Query(default=""),
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    assessment = get_assessment(db, assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")

    mode_key = (mode or "").strip().lower() or "default"
    payload = get_progress(assessment.id, mode_key)
    if not str(payload.get("message", "")).strip():
        defaults = {
            "collect": "Collection is preparing...",
            "model": "Modeling is preparing...",
            "assess": "Risk generation is preparing...",
            "report": "Report generation is preparing...",
            "default": "Working...",
        }
        payload["message"] = defaults.get(mode_key, "Working...")
    return payload


@router.post("/{assessment_id}/delete")
def delete_assessment(
    assessment_id: int,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    assessment = get_assessment(db, assessment_id)
    if not assessment:
        return RedirectResponse(url="/assessments", status_code=302)

    # Collect file paths before DB deletion (Report rows will be deleted by cascade).
    report_rows = db.execute(select(Report).where(Report.assessment_id == assessment_id)).scalars().all()
    report_paths: list[Path] = []
    for r in report_rows:
        for raw in [r.pdf_path, getattr(r, "json_path", "")]:
            p = Path(str(raw or "").strip())
            if p:
                report_paths.append(p)

    rag_index_path = get_settings().runtime_dir / "exports" / "rag_indexes" / f"assessment_{assessment_id}.json"

    # Historical DBs might contain duplicates or tables not wired into ORM cascades.
    # Ensure we remove dependent rows that reference assessment_id.
    db.execute(delete(RiskBrief).where(RiskBrief.assessment_id == assessment_id))

    try:
        db.delete(assessment)
        db.commit()
    except Exception:
        db.rollback()
        raise

    # Best-effort file cleanup (do not fail the delete if files are locked/missing).
    for p in report_paths:
        try:
            if p.exists():
                p.unlink(missing_ok=True)
        except Exception:
            logger.warning("Failed to delete report artifact: %s", p, exc_info=True)
    try:
        if rag_index_path.exists():
            rag_index_path.unlink(missing_ok=True)
    except Exception:
        logger.warning("Failed to delete rag index: %s", rag_index_path, exc_info=True)

    return RedirectResponse(url="/assessments", status_code=302)


@router.get("/new")
def new_assessment_wizard(
    request: Request,
    assessment_id: int | None = Query(default=None),
    prefill_assessment_id: int | None = Query(default=None),
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    assessment = get_assessment(db, assessment_id) if assessment_id else None
    prefill: dict[str, str | bool] = {
        "company_name": "",
        "domain": "",
        "sector": "",
        "regions": "",
        "demo_mode": False,
    }
    if not assessment and prefill_assessment_id:
        seed = get_assessment(db, prefill_assessment_id)
        if seed:
            prefill = {
                "company_name": str(seed.company_name or "").strip(),
                "domain": str(seed.domain or "").strip(),
                "sector": str(seed.sector or "").strip(),
                "regions": str(seed.regions or "").strip(),
                "demo_mode": bool(seed.demo_mode),
            }
    connector_states = list_connector_states(db)
    display_step = 1

    if assessment:
        evid_count = db.execute(select(Evidence).where(Evidence.assessment_id == assessment.id)).scalars().all()
        finding_count = db.execute(select(Finding).where(Finding.assessment_id == assessment.id)).scalars().all()
        hypothesis_count = (
            db.execute(select(Hypothesis).where(Hypothesis.assessment_id == assessment.id)).scalars().all()
        )
        mitigation_count = (
            db.execute(select(Mitigation).where(Mitigation.assessment_id == assessment.id)).scalars().all()
        )
        report_count = db.execute(select(Report).where(Report.assessment_id == assessment.id)).scalars().all()
        exam_count = (
            db.execute(select(ExaminationLog).where(ExaminationLog.assessment_id == assessment.id)).scalars().all()
        )

        inferred_step = assessment.wizard_step
        if assessment.status == "collected":
            inferred_step = max(inferred_step, 4)
        elif assessment.status == "modeled":
            inferred_step = max(inferred_step, 5)
        elif assessment.status == "reduced":
            inferred_step = max(inferred_step, 6)
        elif assessment.status == "reported":
            inferred_step = max(inferred_step, 7)

        if evid_count:
            inferred_step = max(inferred_step, 4)
        if finding_count:
            inferred_step = max(inferred_step, 5)
        if hypothesis_count or mitigation_count:
            inferred_step = max(inferred_step, 6)
        if report_count:
            inferred_step = max(inferred_step, 7)

        if inferred_step != assessment.wizard_step:
            assessment.wizard_step = inferred_step
            db.commit()
            db.refresh(assessment)
        display_step = inferred_step
    else:
        evid_count = []
        finding_count = []
        hypothesis_count = []
        mitigation_count = []
        report_count = []
        exam_count = []
        display_step = 1

    return request.app.state.templates.TemplateResponse(
        "assessment_wizard.html",
        {
            "request": request,
            "user": user,
            "active": "new_assessment",
            "assessment": assessment,
            "assessment_context": _assessment_context(assessment) if assessment else None,
            "section_title": "New Assessment",
            "step": display_step,
            "prefill": prefill,
            "connector_states": connector_states,
            "selected_sources": from_json(assessment.selected_sources_json, []) if assessment else [],
            "collect_logs": from_json(assessment.collect_log_json, []) if assessment else [],
            "stats": {
                "evidence": len(evid_count),
                "examined": len(exam_count),
                "findings": len(finding_count),
                "scenarios": len(hypothesis_count),
                "mitigations": len(mitigation_count),
                "reports": len(report_count),
            },
        },
    )


@router.get("/examination-log")
def examination_log_legacy_redirect(
    assessment_id: int | None = Query(default=None),
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    target_id = assessment_id or _latest_assessment_id(db)
    if not target_id:
        return RedirectResponse(url="/assessments", status_code=302)
    return RedirectResponse(url=f"/assessments/{target_id}/evidence", status_code=302)


@router.get("/examination-log.csv")
def examination_log_legacy_export_csv(
    assessment_id: int,
    status: str = Query(default=""),
    source_type: str = Query(default=""),
    q: str = Query(default=""),
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    return RedirectResponse(url=f"/assessments/{assessment_id}/evidence", status_code=302)


@router.get("/{assessment_id}")
def assessment_context_root(
    assessment_id: int,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    assessment = get_assessment(db, assessment_id)
    if not assessment:
        return RedirectResponse(url="/assessments", status_code=302)
    return RedirectResponse(url=f"/assessments/{assessment_id}/overview", status_code=302)


@router.get("/{assessment_id}/overview")
def assessment_overview(
    request: Request,
    assessment_id: int,
    include_baseline: bool = Query(default=False),
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    assessment = get_assessment(db, assessment_id)
    if not assessment:
        return RedirectResponse(url="/assessments", status_code=302)
    from app.services.risk_story import build_overview_viewmodel

    overview = build_overview_viewmodel(
        db,
        assessment,
        include_weak=False,
        include_baseline=bool(include_baseline),
        generate_brief=False,
    )

    return request.app.state.templates.TemplateResponse(
        "assessment_overview.html",
        {
            "request": request,
            "user": user,
            "active": "assessment_overview",
            "assessment": assessment,
            "assessment_context": _assessment_context(assessment),
            "section_title": "Assessment snapshot",
            "hide_section_title": True,
            "overview": overview,
        },
    )


@router.post("/{assessment_id}/collect")
def collect_from_overview(
    assessment_id: int,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    assessment = get_assessment(db, assessment_id)
    if not assessment:
        return RedirectResponse(url="/assessments", status_code=302)
    try:
        run_collection(db, assessment)
    except Exception as exc:
        fail_progress(assessment.id, "collect", f"{exc.__class__.__name__}: {exc}")
        raise
    return RedirectResponse(url=f"/assessments/{assessment_id}/overview", status_code=302)


@router.post("/{assessment_id}/export-pdf")
def export_pdf_from_overview(
    assessment_id: int,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    assessment = get_assessment(db, assessment_id)
    if not assessment:
        return RedirectResponse(url="/assessments", status_code=302)
    try:
        report = export_report(db, assessment)
    except Exception as exc:
        fail_progress(assessment.id, "report", f"{exc.__class__.__name__}: {exc}")
        raise
    path = Path(report.pdf_path)
    if path.exists():
        return FileResponse(path, media_type="application/pdf", filename=path.name)
    return RedirectResponse(url=f"/assessments/{assessment_id}/report", status_code=302)


@router.get("/{assessment_id}/examination-log")
def examination_log_page(
    request: Request,
    assessment_id: int,
    status: str = Query(default=""),
    source_type: str = Query(default=""),
    q: str = Query(default=""),
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    # Legacy endpoint: redirect to the new risk-first Evidence Log.
    qs = []
    if q:
        qs.append(f"q={q}")
    return RedirectResponse(
        url=f"/assessments/{assessment_id}/evidence" + (("?" + "&".join(qs)) if qs else ""),
        status_code=302,
    )


@router.get("/{assessment_id}/rag-debug")
def rag_debug_page(
    request: Request,
    assessment_id: int,
    top_k: int = Query(default=5, ge=1, le=10),
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    assessment = db.get(Assessment, assessment_id)
    if not assessment:
        return RedirectResponse(url="/assessments", status_code=302)

    debug_payload = rag_debug_query_plan(assessment_id, top_k=top_k)
    return request.app.state.templates.TemplateResponse(
        "rag_debug.html",
        {
            "request": request,
            "user": user,
            "active": "assessment_rag_debug",
            "assessment": assessment,
            "assessment_context": _assessment_context(assessment),
            "section_title": "RAG Debug",
            "section_subtitle": "Per-query retrieval diagnostics for index coverage and passage relevance.",
            "debug_payload": debug_payload,
            "top_k": top_k,
        },
    )


@router.get("/{assessment_id}/collector-stats")
def collector_stats_page(
    request: Request,
    assessment_id: int,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    assessment = db.get(Assessment, assessment_id)
    if not assessment:
        return RedirectResponse(url="/assessments", status_code=302)

    rows = (
        db.execute(
            select(ExaminationLog)
            .where(ExaminationLog.assessment_id == assessment_id)
            .order_by(ExaminationLog.discovered_at.desc())
        )
        .scalars()
        .all()
    )
    documents = db.execute(select(Document).where(Document.assessment_id == assessment_id)).scalars().all()

    status_counts: dict[str, int] = {}
    source_counts: dict[str, int] = {}
    for row in rows:
        status_counts[row.status] = status_counts.get(row.status, 0) + 1
        source_counts[row.source_type] = source_counts.get(row.source_type, 0) + 1

    extracted_chars = [
        int(r.extracted_chars) for r in rows if r.extracted_chars is not None and int(r.extracted_chars) > 0
    ]
    median_chars = int(statistics.median(extracted_chars)) if extracted_chars else 0
    pdf_rows = [r for r in rows if r.source_type == "pdf"]
    parsed_pdf_rows = [r for r in pdf_rows if r.status in {"parsed", "pdf_needs_ocr_candidate"}]
    ocr_candidates = [r for r in pdf_rows if r.status == "pdf_needs_ocr_candidate"]

    doc_type_counts: dict[str, int] = {}
    doc_text_sizes = []
    for doc in documents:
        doc_type_counts[doc.doc_type] = doc_type_counts.get(doc.doc_type, 0) + 1
        doc_text_sizes.append(len(doc.extracted_text or ""))

    return request.app.state.templates.TemplateResponse(
        "collector_stats.html",
        {
            "request": request,
            "user": user,
            "active": "assessment_collector_stats",
            "assessment": assessment,
            "assessment_context": _assessment_context(assessment),
            "section_title": "Collector Stats",
            "section_subtitle": "Collection quality and parsing health metrics for this assessment run history.",
            "status_counts": dict(sorted(status_counts.items(), key=lambda x: x[0])),
            "source_counts": dict(sorted(source_counts.items(), key=lambda x: x[0])),
            "doc_type_counts": dict(sorted(doc_type_counts.items(), key=lambda x: x[0])),
            "kpis": {
                "total_log_rows": len(rows),
                "fetched_count": status_counts.get("fetched", 0),
                "parsed_count": status_counts.get("parsed", 0) + status_counts.get("pdf_needs_ocr_candidate", 0),
                "failed_count": status_counts.get("failed", 0),
                "median_text_chars": median_chars,
                "pdf_total": len(pdf_rows),
                "pdf_parsed": len(parsed_pdf_rows),
                "pdf_ocr_candidates": len(ocr_candidates),
                "documents_total": len(documents),
            },
            "recent_rows": rows[:20],
            "doc_text_median": int(statistics.median(doc_text_sizes)) if doc_text_sizes else 0,
        },
    )


@router.get("/{assessment_id}/examination-log.csv")
def examination_log_export_csv(
    assessment_id: int,
    status: str = Query(default=""),
    source_type: str = Query(default=""),
    q: str = Query(default=""),
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    return RedirectResponse(url=f"/assessments/{assessment_id}/evidence", status_code=302)


@router.get("/{assessment_id}/evidence")
def evidence_log_page(
    request: Request,
    assessment_id: int,
    q: str = Query(default=""),
    signal: str = Query(default=""),
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    assessment = db.get(Assessment, assessment_id)
    if not assessment:
        return RedirectResponse(url="/assessments", status_code=302)
    from app.services.evidence_log import build_evidence_log_viewmodel

    vm = build_evidence_log_viewmodel(db, assessment, q=q, signal_type=signal)
    return request.app.state.templates.TemplateResponse(
        "evidence_log.html",
        {
            "request": request,
            "user": user,
            "active": "assessment_evidence",
            "assessment": assessment,
            "assessment_context": _assessment_context(assessment),
            "section_title": "Evidence Log",
            "vm": vm,
        },
    )


@router.get("/{assessment_id}/collect-log-fragment")
def collect_log_fragment(
    assessment_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    assessment = get_assessment(db, assessment_id)
    collect_logs = from_json(assessment.collect_log_json, []) if assessment else []
    return request.app.state.templates.TemplateResponse(
        "partials/collect_logs.html",
        {"request": request, "collect_logs": collect_logs},
    )


@router.post("/{assessment_id}/rag/build")
def rag_build_index(
    assessment_id: int,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    assessment = get_assessment(db, assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return build_rag_index(assessment_id)


@router.get("/{assessment_id}/rag/query-plan")
def rag_query_plan(
    assessment_id: int,
    top_k: int = Query(default=4, ge=1, le=30),
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    assessment = get_assessment(db, assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return run_rag_query_plan(assessment_id, top_k=top_k, min_ratio=0.70)


@router.get("/{assessment_id}/rag/search")
def rag_search_passages(
    assessment_id: int,
    query: str = Query(..., min_length=2),
    top_k: int = Query(default=4, ge=1, le=50),
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    assessment = get_assessment(db, assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return {
        "assessment_id": assessment_id,
        "query": query,
        "results": rag_search(assessment_id, query, top_k=top_k),
    }


@router.post("/wizard/step1")
def wizard_step1(
    company_name: str = Form(...),
    domain: str = Form(...),
    sector: str = Form(""),
    regions: str = Form(""),
    demo_mode: bool = Form(False),
    assessment_id: int | None = Form(default=None),
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    if assessment_id:
        assessment = get_assessment(db, assessment_id)
        if not assessment:
            return RedirectResponse(url="/assessments/new", status_code=302)
        assessment = update_assessment_target(db, assessment, company_name, domain, sector, regions, demo_mode)
    else:
        assessment = create_assessment(db, company_name, domain, sector, regions, demo_mode)

    return RedirectResponse(url=f"/assessments/new?assessment_id={assessment.id}", status_code=302)


@router.post("/wizard/step2")
def wizard_step2(
    assessment_id: int = Form(...),
    sources: list[str] = Form(default=[]),
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    assessment = get_assessment(db, assessment_id)
    if not assessment:
        return RedirectResponse(url="/assessments/new", status_code=302)

    save_selected_sources(db, assessment, sources)
    return RedirectResponse(url=f"/assessments/new?assessment_id={assessment.id}", status_code=302)


@router.post("/wizard/step3")
def wizard_step3(
    assessment_id: int = Form(...),
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    assessment = get_assessment(db, assessment_id)
    if not assessment:
        return RedirectResponse(url="/assessments/new", status_code=302)

    try:
        run_collection(db, assessment)
    except Exception as exc:
        fail_progress(assessment.id, "collect", f"{exc.__class__.__name__}: {exc}")
        raise
    return RedirectResponse(url=f"/assessments/new?assessment_id={assessment.id}", status_code=302)


@router.post("/wizard/step4")
def wizard_step4(
    assessment_id: int = Form(...),
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    assessment = get_assessment(db, assessment_id)
    if not assessment:
        return RedirectResponse(url="/assessments/new", status_code=302)

    try:
        build_model(db, assessment)
    except Exception as exc:
        fail_progress(assessment.id, "model", f"{exc.__class__.__name__}: {exc}")
        raise
    return RedirectResponse(url=f"/assessments/new?assessment_id={assessment.id}", status_code=302)


@router.post("/wizard/step5")
def wizard_step5(
    assessment_id: int = Form(...),
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    assessment = get_assessment(db, assessment_id)
    if not assessment:
        return RedirectResponse(url="/assessments/new", status_code=302)

    start_progress(assessment.id, "assess", "Preparing risk assessment pipeline...")
    try:
        # Risk scenarios: rebuild local index, run fixed query plan (K=4, relative threshold),
        # then generate evidence-first scenarios (defensive-only) and refresh mitigation backlog.
        update_progress(assessment.id, "assess", "Refreshing retrieval index...")
        build_rag_index(assessment.id)
        rag_cfg = get_rag_advanced_state(db)
        update_progress(assessment.id, "assess", "Selecting top evidence passages...")
        plan = run_rag_query_plan(
            assessment.id, top_k=int(rag_cfg.get("top_k", 4)), min_ratio=float(rag_cfg.get("min_ratio", 0.70))
        )
        update_progress(assessment.id, "assess", "Generating evidence-first risk scenarios...")
        generate_hypotheses(assessment.id, plan, allow_local_fallback=False)
        # Process-based trust workflow map (phase 1): derives workflow nodes and trust friction scoring.
        try:
            from app.services.trust_workflows import generate_trust_workflow_map

            update_progress(assessment.id, "assess", "Building workflow trust map...")
            generate_trust_workflow_map(
                db,
                assessment.id,
                top_k=int(rag_cfg.get("top_k", 4)),
                min_ratio=float(rag_cfg.get("min_ratio", 0.70)),
            )
        except Exception:
            # Never break the wizard due to workflow mapping; log in server logs.
            import logging

            logging.getLogger(__name__).exception("Trust workflow map generation failed for assessment %s", assessment.id)
        from app.services.risk_story import precompute_risk_texts_for_assessment

        update_progress(assessment.id, "assess", "Precomputing risk narratives...")
        precompute_stats = precompute_risk_texts_for_assessment(
            db,
            assessment,
            include_baseline=True,
        )
        update_progress(
            assessment.id,
            "assess",
            f"Risk narratives ready ({int(precompute_stats.get('warmed', 0))}/{int(precompute_stats.get('total', 0))}).",
        )
        update_progress(assessment.id, "assess", "Generating mitigations...")
        build_mitigations(db, assessment)
        finish_progress(assessment.id, "assess", "Risk assessment complete.")
    except Exception as exc:
        fail_progress(assessment.id, "assess", f"{exc.__class__.__name__}: {exc}")
        raise
    return RedirectResponse(url=f"/assessments/new?assessment_id={assessment.id}", status_code=302)


@router.post("/wizard/step6")
def wizard_step6(
    assessment_id: int = Form(...),
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    assessment = get_assessment(db, assessment_id)
    if not assessment:
        return RedirectResponse(url="/assessments/new", status_code=302)

    try:
        export_report(db, assessment)
    except Exception as exc:
        fail_progress(assessment.id, "report", f"{exc.__class__.__name__}: {exc}")
        raise
    return RedirectResponse(url=f"/assessments/new?assessment_id={assessment.id}", status_code=302)


@router.post("/demo/load")
def load_demo(
    scenario: str = Form(...),
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    assessment = create_demo_scenario(db, scenario)
    return RedirectResponse(url=f"/assessments/{assessment.id}/overview", status_code=302)
