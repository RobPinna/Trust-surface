from __future__ import annotations

import logging
import math
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from urllib.parse import urlparse, urlunparse

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import Assessment, Document, Evidence, Hypothesis, WorkflowNode
from app.services.risk_brief_service import BriefInput, get_or_generate_brief, get_or_generate_how_text
from app.services.evidence_quality_classifier import classify_evidence
from app.services.signal_model import (
    SIGNAL_ICONS,
    SIGNAL_LABELS,
    SIGNAL_TYPES,
    compute_hypothesis_confidence,
    coverage_label_from_signals,
    infer_signal_type,
    timeline_for_risk,
)
from app.utils.jsonx import from_json
from config.signal_display_map import map_bundle_display

logger = logging.getLogger(__name__)


LIKELIHOOD_SCORE = {"low": 1, "med": 2, "high": 3}
IMPACT_SCORE = {"LOW": 1, "MED": 2, "HIGH": 3}
EVIDENCE_STRENGTH_SCORE = {"WEAK": 1, "OK": 2, "STRONG": 3}
RISK_STATUS_VALUES = ("ELEVATED", "WATCHLIST", "BASELINE")
MIN_SIGNAL_COVERAGE_ELEVATED = 2
MIN_EVIDENCE_REFS_ELEVATED = 2
MIN_EVIDENCE_STRENGTH_ELEVATED = 60

CONNECTOR_HUMAN_LABELS = {
    "website_analyzer": "Public website content",
    "official_channel_enumerator": "Official contact channels on website",
    "public_role_extractor": "Public roles found in website",
    "email_posture_analyzer": "Email security posture signals",
    "dns_footprint": "DNS records and domain footprint",
    "subdomain_discovery": "Public subdomain exposure",
    "gdelt_news": "News and media mentions",
    "media_trend": "External narrative trend signals",
    "social_mock": "Public social channel signals",
    "job_postings_live": "Public job posting signals",
    "vendor_js_detection": "Third-party vendor technologies on web pages",
    "procurement_documents": "Public procurement/workflow documents",
    "public_docs_pdf": "Public PDF documents",
}
CONNECTOR_PRIORITY = {
    "website_analyzer": 0,
    "official_channel_enumerator": 1,
    "public_role_extractor": 2,
    "dns_footprint": 3,
    "subdomain_discovery": 4,
    "public_docs_pdf": 5,
    "procurement_documents": 6,
    "job_postings_live": 7,
    "vendor_js_detection": 8,
    "social_mock": 9,
    "gdelt_news": 10,
    "media_trend": 11,
}
EMAIL_PATTERN = re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b")
PHONE_PATTERN = re.compile(r"\+?\d[\d\s().\-]{7,}\d")
ROLE_HINTS = (
    "finance",
    "billing",
    "procurement",
    "support",
    "customer care",
    "helpdesk",
    "privacy",
    "dpo",
    "security",
    "it",
    "hr",
    "executive",
    "director",
    "manager",
)


def _connector_human_label(connector_name: str) -> str:
    key = str(connector_name or "").strip().lower()
    if not key:
        return ""
    return CONNECTOR_HUMAN_LABELS.get(key, key.replace("_", " ").strip())


def _connector_sort_key(connector_name: str) -> tuple[int, str]:
    key = str(connector_name or "").strip().lower()
    return (int(CONNECTOR_PRIORITY.get(key, 99)), key)


def _vendor_cues_from_evidence(evidence: list[dict[str, Any]]) -> list[str]:
    cues: list[str] = []
    for e in evidence or []:
        if str(e.get("signal_type", "")).strip().upper() != "VENDOR_CUE":
            continue
        if str(e.get("evidence_kind", "UNKNOWN")).strip().upper() != "WORKFLOW_VENDOR":
            continue
        if bool(e.get("is_boilerplate", False)) or float(e.get("weight", 1.0) or 1.0) < 0.5:
            continue
        snippet = " ".join(str(e.get("snippet", "")).split()).strip()
        title = " ".join(str(e.get("title", "")).split()).strip()
        doc_title = " ".join(str(e.get("doc_title", "")).split()).strip()
        url = " ".join(str(e.get("url", "")).split()).strip()
        blob = f"{title} {doc_title} {snippet} {url}".strip()
        for name in (
            "Zendesk",
            "Freshdesk",
            "Intercom",
            "Salesforce",
            "HubSpot",
            "Stripe",
            "Adyen",
            "PayPal",
            "Cloudflare",
            "Akamai",
            "Okta",
            "Auth0",
            "reCAPTCHA",
            "Google Tag Manager",
        ):
            if name.lower() in blob.lower():
                cues.append(name)
    # Also include explicit vendor hits stored in meta (if present).
    for e in evidence or []:
        raw = e.get("raw_json")
        if isinstance(raw, dict):
            v = raw.get("vendor")
            if v and str(v).strip():
                cues.append(str(v).strip())
    seen = set()
    out = []
    for c in cues:
        k = c.strip().lower()
        if not k or k in seen:
            continue
        seen.add(k)
        out.append(c.strip())
    return out[:10]


def _channel_cues_from_evidence(evidence: list[dict[str, Any]]) -> list[str]:
    cues: list[str] = []
    for e in evidence or []:
        st = str(e.get("signal_type", "")).strip().upper()
        url = str(e.get("url", "")).strip().lower()
        snippet = str(e.get("snippet", "")).lower()
        if st in {"CONTACT_CHANNEL"}:
            cues.append("Public contact channels")
        if st in {"SOCIAL_TRUST_NODE"}:
            cues.append("Official social channel touchpoints")
        if st in {"INFRA_CUE"}:
            cues.append("Support/portal subdomain surface")
        if "/contact" in url:
            cues.append("Contact page")
        if any(x in snippet for x in ("support", "helpdesk", "ticket", "portal", "live chat", "chat")):
            cues.append("Support interaction cues")
    seen = set()
    out = []
    for c in cues:
        k = c.strip().lower()
        if not k or k in seen:
            continue
        seen.add(k)
        out.append(c.strip())
    return out[:10]


def _impact_targets_from_band(impact_band: str, risk_type: str) -> list[str]:
    band = (impact_band or "MED").upper()
    rt = (risk_type or "").strip().lower()
    out = ["Operational"]
    if band == "HIGH":
        out = ["Financial", "Client Trust", "Operational"]
    if rt in {"downstream_pivot", "impersonation", "brand_abuse", "social_trust_surface_exposure"}:
        if "Client Trust" not in out:
            out.insert(0, "Client Trust")
    return out[:3]


def _sentence_case(value: str) -> str:
    s = " ".join(str(value or "").split()).strip()
    if not s:
        return s
    return s[:1].upper() + s[1:].lower()


def _risk_display_name(*, primary_risk_type: str, fallback_outcome: str) -> str:
    """
    Stakeholder-friendly canonical naming used across Overview/Risks/Detail.
    """
    raw = " ".join(str(primary_risk_type or "").split()).strip()
    if not raw:
        raw = " ".join(str(fallback_outcome or "").split()).strip()
    key = raw.lower()
    mapping = {
        "social engineering": "Social manipulation risk",
        "payment fraud": "Payment fraud risk",
        "vendor trust abuse": "Third-party trust abuse risk",
        "account takeover vector": "Account takeover risk",
        "supply chain dependency risk": "Supplier dependency risk",
        "booking fraud": "Booking fraud risk",
        "donation fraud": "Donation fraud risk",
        "partner impersonation": "Partner impersonation risk",
        "data handling abuse": "Data handling risk",
        "channel ambiguity exploitation": "Channel confusion risk",
    }
    if key in mapping:
        return mapping[key]
    return _sentence_case(raw) if raw else "Risk"


def _single_risk_headline(
    *,
    primary_risk_type: str,
    title: str,
    risk_vector_summary: str,
) -> str:
    primary = " ".join(str(primary_risk_type or "").split()).strip()
    if primary:
        return _sentence_case(primary)

    t = " ".join(str(title or "").split()).strip()
    if t:
        t = re.sub(r"^\s*top\s*risk\s*[:\-]\s*", "", t, flags=re.IGNORECASE).strip()
        if t:
            return _sentence_case(t)

    vector = " ".join(str(risk_vector_summary or "").split()).strip()
    if vector:
        vector = re.sub(r"^\s*top\s*risk\s*[:\-]\s*", "", vector, flags=re.IGNORECASE).strip()
        low = vector.lower()
        for sep in (" leading to ", " enabled by ", " from ", " via ", " due to "):
            if sep in low:
                idx = low.find(sep)
                candidate = vector[:idx].strip(" .,:;-")
                if candidate:
                    return _sentence_case(candidate)
        if vector:
            return _sentence_case(vector.strip(" .,:;-"))
    return "Risk"


def _first_sentence(value: str, max_chars: int = 180) -> str:
    text = " ".join(str(value or "").split()).strip()
    if not text:
        return ""
    parts = re.split(r"(?<=[.!?])\s+", text)
    out = (parts[0] if parts else text).strip()
    return out[:max_chars]


def _truncate_words(value: str, max_chars: int = 140) -> str:
    text = " ".join(str(value or "").split()).strip()
    if not text:
        return ""
    if len(text) <= max_chars:
        return text
    chunk = text[: max_chars + 1]
    if " " in chunk:
        chunk = chunk.rsplit(" ", 1)[0]
    chunk = chunk.rstrip(" ,;:-")
    return f"{chunk}..."


def _signal_excerpt(ev: dict[str, Any]) -> str:
    title = _truncate_words(str(ev.get("title", "")), max_chars=120)
    snippet = _truncate_words(_first_sentence(str(ev.get("snippet", "")), max_chars=220), max_chars=140)
    low_title = title.lower()
    if title and low_title not in {"limited evidence", "no excerpt captured."} and len(title) >= 10:
        return title
    if snippet and snippet.lower() != "no excerpt captured.":
        return snippet
    return ""


def _extract_indicator_candidates(title: str, snippet: str) -> list[str]:
    blob = " ".join(f"{title} {snippet}".split()).strip()
    if not blob:
        return []
    out: list[str] = []
    seen: set[str] = set()

    for em in EMAIL_PATTERN.findall(blob):
        key = f"email:{em.lower()}"
        if key in seen:
            continue
        seen.add(key)
        out.append(f"Found public email: {em}")
        if len(out) >= 6:
            return out

    for ph in PHONE_PATTERN.findall(blob):
        normalized = " ".join(str(ph).split())
        key = f"phone:{normalized}"
        if key in seen:
            continue
        seen.add(key)
        out.append(f"Found public phone/contact number: {normalized}")
        if len(out) >= 6:
            return out

    low_blob = blob.lower()
    for role in ROLE_HINTS:
        if role in low_blob:
            key = f"role:{role}"
            if key in seen:
                continue
            seen.add(key)
            out.append(f"Found publicly targetable role cue: {role}")
            if len(out) >= 6:
                return out
    return out


def _is_generic_why_text(value: str) -> bool:
    low = " ".join(str(value or "").split()).strip().lower()
    if not low:
        return True
    generic_markers = (
        "potential effects include",
        "open for evidence and defensive controls",
        "this condition can increase",
        "risk patterns",
        "assessment uses probabilistic",
    )
    return any(marker in low for marker in generic_markers)


def _why_it_matters_cti(
    *,
    risk: dict[str, Any],
    evidence: list[dict[str, Any]],
    fallback_context: str = "",
) -> str:
    signal_types = {str(ev.get("signal_type", "")).strip().upper() for ev in (evidence or []) if ev}
    risk_type = str(risk.get("risk_type", "")).strip().lower()
    impact_band = str(risk.get("impact_band", "MED") or "MED").strip().upper()

    has_contact = "CONTACT_CHANNEL" in signal_types
    has_org = "ORG_CUE" in signal_types
    has_process = "PROCESS_CUE" in signal_types
    has_vendor = "VENDOR_CUE" in signal_types
    has_social = "SOCIAL_TRUST_NODE" in signal_types

    if risk_type in {"downstream_pivot", "impersonation", "brand_abuse", "social_trust_surface_exposure"}:
        actor_line = "A malicious actor could impersonate official channels and insert pretexts into client/partner interactions."
    elif risk_type in {"fraud_process"} or has_process:
        actor_line = (
            "A malicious actor could time fraudulent requests against visible workflow steps to bypass routine checks."
        )
    elif risk_type in {"credential_theft_risk"}:
        actor_line = "A malicious actor could exploit publicly visible account-handling cues to increase account takeover attempts."
    elif has_contact and has_org:
        actor_line = "A malicious actor could combine public contact paths with staff-role cues to craft believable social-engineering pretexts."
    elif has_contact:
        actor_line = "A malicious actor could abuse public contact entrypoints to route deceptive requests through trusted channels."
    elif has_social:
        actor_line = "A malicious actor could exploit social trust surfaces to make malicious outreach appear operationally legitimate."
    else:
        actor_line = "A malicious actor could combine public signals to build convincing pretexts for targeted social engineering."

    if impact_band == "HIGH":
        impact_line = (
            "This raises the success probability of social-engineering pretexts and can cause material trust, operational, "
            "or financial disruption before escalation."
        )
    elif impact_band == "MED":
        impact_line = "This increases the success probability of social-engineering pretexts and can drive avoidable operational friction and trust erosion."
    else:
        impact_line = "This can still improve pretext credibility and should be controlled before it compounds with additional signals."

    if has_vendor:
        impact_line += " Third-party workflow cues can further strengthen attacker plausibility."

    return f"{actor_line} {impact_line}"


def _sample_signal_lines(evidence: list[dict[str, Any]], *, max_items: int = 3) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for ev in evidence or []:
        if len(out) >= max_items:
            break
        hints = ev.get("indicator_hints")
        if isinstance(hints, list):
            for hint in hints:
                line = " ".join(str(hint or "").split()).strip()
                if not line:
                    continue
                key = f"hint:{re.sub(r'[^a-z0-9]+', ' ', line.lower()).strip()[:120]}"
                if key in seen:
                    continue
                seen.add(key)
                out.append(line)
                if len(out) >= max_items:
                    break
        if len(out) >= max_items:
            break

        title = " ".join(str(ev.get("title", "")).split()).strip()
        snippet = " ".join(str(ev.get("snippet", "")).split()).strip()
        blob = f"{title} {snippet}".strip()

        # 1) Prefer concrete indicators (emails/phones/roles/contact channels).
        emails = EMAIL_PATTERN.findall(blob)
        for em in emails:
            key = f"email:{em.lower()}"
            if key in seen:
                continue
            seen.add(key)
            out.append(f"Found public email: {em}")
            if len(out) >= max_items:
                break
        if len(out) >= max_items:
            break

        phones = PHONE_PATTERN.findall(blob)
        for ph in phones:
            normalized = " ".join(str(ph).split())
            key = f"phone:{normalized}"
            if key in seen:
                continue
            seen.add(key)
            out.append(f"Found public phone/contact number: {normalized}")
            if len(out) >= max_items:
                break
        if len(out) >= max_items:
            break

        low_blob = blob.lower()
        role_match = next((role for role in ROLE_HINTS if role in low_blob), "")
        if role_match:
            key = f"role:{role_match}"
            if key not in seen:
                seen.add(key)
                out.append(f"Found publicly targetable role cue: {role_match}")
                if len(out) >= max_items:
                    break

        url = str(ev.get("url", "")).strip()
        if url:
            try:
                parsed = urlparse(url)
                host = (parsed.netloc or "").lower().split(":")[0]
                path = parsed.path or "/"
                if host:
                    key = f"url:{host}{path[:40]}"
                    if key not in seen:
                        seen.add(key)
                        out.append(f"Found public contact/workflow page: {host}{path[:40]}")
                        if len(out) >= max_items:
                            break
            except Exception:
                pass

        # 2) Fallback to concise excerpt.
        txt = _signal_excerpt(ev)
        if txt:
            key = f"txt:{re.sub(r'[^a-z0-9]+', ' ', txt.lower()).strip()[:100]}"
            if key not in seen:
                seen.add(key)
                out.append(txt)
    return out[:max_items]


def _hint_priority(value: str) -> int:
    low = " ".join(str(value or "").split()).strip().lower()
    if not low:
        return 99
    if re.match(r"^e-\d{2,3}\b", low):
        return -1
    if low.startswith("found public email:"):
        return 0
    if low.startswith("found public phone/contact number:"):
        return 1
    if "contact/workflow page" in low:
        return 2
    if low.startswith("found publicly targetable role cue:"):
        return 3
    return 4


_REF_KEYWORD_STOPWORDS = {
    "public",
    "official",
    "exposed",
    "multiple",
    "channel",
    "channels",
    "entrypoints",
    "entrypoint",
    "signal",
    "signals",
    "workflow",
    "cues",
}


def _add_signal_ref(
    refs: list[dict[str, Any]],
    *,
    seen: set[str],
    text: str,
    tags: list[str],
    max_items: int,
    code: str = "",
) -> None:
    if len(refs) >= max_items:
        return
    clean = " ".join(str(text or "").split()).strip()
    if not clean:
        return
    key = re.sub(r"[^a-z0-9]+", " ", clean.lower()).strip()
    if not key or key in seen:
        return
    seen.add(key)
    uniq_tags: list[str] = []
    for tag in tags:
        t = str(tag or "").strip().lower()
        if t and t not in uniq_tags:
            uniq_tags.append(t)
    c = " ".join(str(code or "").split()).strip().upper()
    if not re.match(r"^E-\d{2,3}$", c):
        c = f"E-{len(refs) + 1:02d}"
    refs.append({"code": c, "text": clean, "tags": uniq_tags})


def _evidence_identity_key(ev: dict[str, Any]) -> str:
    u = str(ev.get("canonical_url") or ev.get("url") or "").strip()
    u = _canonical_url(u)
    st = str(ev.get("signal_type") or "OTHER").strip().upper() or "OTHER"
    did = str(ev.get("doc_id") or "").strip()
    return f"{u}|{st}|{did}"


def _evidence_code_for_index(idx: int) -> str:
    n = max(1, int(idx))
    if n <= 99:
        return f"E-{n:02d}"
    return f"E-{n:03d}"


def _artifact_code_key(value: str) -> str:
    return " ".join(str(value or "").split()).strip().lower()


def _artifact_tokens_for_evidence(ev: dict[str, Any]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()

    def _push(value: str) -> None:
        clean = " ".join(str(value or "").split()).strip()
        key = _artifact_code_key(clean)
        if not key or key in seen:
            return
        seen.add(key)
        out.append(clean)

    hints = ev.get("indicator_hints")
    hint_lines = [str(x or "") for x in hints] if isinstance(hints, list) else []
    for line in hint_lines:
        clean = " ".join(str(line or "").split()).strip()
        if not clean:
            continue
        low = clean.lower()
        if low.startswith("found public email:"):
            _push(clean.split(":", 1)[1].strip())
            continue
        if low.startswith("found public phone/contact number:"):
            _push(clean.split(":", 1)[1].strip())
            continue
        if low.startswith("found publicly targetable role cue:"):
            role = clean.split(":", 1)[1].strip()
            _push(f"role: {role}")
            continue
        em = EMAIL_PATTERN.search(clean)
        if em:
            _push(em.group(0).lower())
        ph = PHONE_PATTERN.search(clean)
        if ph:
            _push(" ".join(str(ph.group(0)).split()))
        for role in ROLE_HINTS:
            if role in low:
                _push(f"role: {role}")
                break

    blob = " ".join(
        [
            str(ev.get("title", "") or ""),
            str(ev.get("snippet", "") or ""),
            str(ev.get("url", "") or ""),
            " ".join(hint_lines),
        ]
    )
    for em in EMAIL_PATTERN.findall(blob):
        _push(em.lower())
    for ph in PHONE_PATTERN.findall(blob):
        _push(" ".join(str(ph).split()))
    low_blob = blob.lower()
    for role in ROLE_HINTS:
        if role in low_blob:
            _push(f"role: {role}")

    url_art = _artifact_from_url(str(ev.get("url", "") or ""))
    if url_art:
        _push(url_art)

    return out[:16]


def _artifact_tokens_from_hint_line(value: str) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()

    def _push(raw: str) -> None:
        clean = " ".join(str(raw or "").split()).strip()
        key = _artifact_code_key(clean)
        if not key or key in seen:
            return
        seen.add(key)
        out.append(clean)

    line = " ".join(str(value or "").split()).strip()
    if not line:
        return out
    low = line.lower()
    if low.startswith("found public email:"):
        _push(line.split(":", 1)[1].strip())
    elif low.startswith("found public phone/contact number:"):
        _push(line.split(":", 1)[1].strip())
    elif low.startswith("found publicly targetable role cue:"):
        _push(f"role: {line.split(':', 1)[1].strip()}")

    for em in EMAIL_PATTERN.findall(line):
        _push(em.lower())
    for ph in PHONE_PATTERN.findall(line):
        _push(" ".join(str(ph).split()))
    for role in ROLE_HINTS:
        if role in low:
            _push(f"role: {role}")
    if "http" in low or "/" in low:
        _push(_artifact_from_url(line))
    return out[:8]


def build_assessment_evidence_code_map(
    db: Session,
    assessment: Assessment,
    *,
    ranked_snapshot: dict[str, Any] | None = None,
) -> dict[str, str]:
    ranked = ranked_snapshot if isinstance(ranked_snapshot, dict) else get_ranked_risks(db, assessment)
    evidence_sets = dict(ranked.get("evidence_sets") or {})
    hypotheses = list(ranked.get("hypotheses") or [])
    workflow_nodes = list(ranked.get("workflow_nodes") or [])

    unique_rows: dict[str, dict[str, Any]] = {}
    for h in hypotheses:
        hid = int(getattr(h, "id", 0) or 0)
        if hid <= 0:
            continue
        for ev in list(evidence_sets.get(f"risk:{hid}", []) or []):
            if not isinstance(ev, dict):
                continue
            k = _evidence_identity_key(ev)
            if not k.strip("|") or k in unique_rows:
                continue
            unique_rows[k] = {
                "canonical_url": str(ev.get("canonical_url") or _canonical_url(str(ev.get("url", "")))),
                "url": str(ev.get("url", "")),
                "signal_type": str(ev.get("signal_type", "OTHER") or "OTHER"),
                "doc_id": ev.get("doc_id"),
            }

    for n in workflow_nodes:
        evs = from_json(getattr(n, "evidence_refs_json", "") or "[]", [])
        if not isinstance(evs, list):
            continue
        for ev in evs:
            if not isinstance(ev, dict):
                continue
            raw_url = str(ev.get("url", "")).strip()
            if not raw_url:
                continue
            tmp = {
                "canonical_url": _canonical_url(raw_url),
                "url": raw_url,
                "signal_type": str(ev.get("signal_type", "") or "OTHER"),
                "doc_id": ev.get("doc_id"),
            }
            k = _evidence_identity_key(tmp)
            if not k.strip("|") or k in unique_rows:
                continue
            unique_rows[k] = tmp

    rows = sorted(
        list(unique_rows.values()),
        key=lambda r: (
            str(r.get("canonical_url", "")).lower(),
            str(r.get("signal_type", "")).upper(),
            str(r.get("doc_id") or ""),
        ),
    )
    out: dict[str, str] = {}
    for idx, row in enumerate(rows, start=1):
        out[_evidence_identity_key(row)] = _evidence_code_for_index(idx)
    return out


def build_assessment_artifact_code_map(
    db: Session,
    assessment: Assessment,
    *,
    ranked_snapshot: dict[str, Any] | None = None,
    evidence_code_map: dict[str, str] | None = None,
) -> dict[str, str]:
    ranked = ranked_snapshot if isinstance(ranked_snapshot, dict) else get_ranked_risks(db, assessment)
    code_map = (
        dict(evidence_code_map)
        if isinstance(evidence_code_map, dict)
        else build_assessment_evidence_code_map(db, assessment, ranked_snapshot=ranked)
    )
    evidence_sets = dict(ranked.get("evidence_sets") or {})
    indicator_hints_by_url = dict(ranked.get("indicator_hints_by_url") or {})
    workflow_nodes = list(ranked.get("workflow_nodes") or [])
    out: dict[str, str] = {}
    for key, rows in evidence_sets.items():
        if not str(key).startswith("risk:"):
            continue
        for ev in rows or []:
            if not isinstance(ev, dict):
                continue
            code = code_map.get(_evidence_identity_key(ev), "")
            if not code:
                continue
            for token in _artifact_tokens_for_evidence(ev):
                k = _artifact_code_key(token)
                if k and k not in out:
                    out[k] = code
            canonical = str(ev.get("canonical_url") or _canonical_url(str(ev.get("url", "")))).strip()
            for hint in indicator_hints_by_url.get(canonical, []):
                for token in _artifact_tokens_from_hint_line(str(hint or "")):
                    k = _artifact_code_key(token)
                    if k and k not in out:
                        out[k] = code
    for node in workflow_nodes:
        evs = from_json(getattr(node, "evidence_refs_json", "") or "[]", [])
        if not isinstance(evs, list):
            continue
        for raw in evs:
            if not isinstance(raw, dict):
                continue
            raw_url = str(raw.get("url", "")).strip()
            if not raw_url:
                continue
            tmp = {
                "canonical_url": _canonical_url(raw_url),
                "url": raw_url,
                "title": str(raw.get("title", "")),
                "snippet": str(raw.get("snippet", "")),
                "signal_type": str(raw.get("signal_type", "") or "OTHER"),
                "doc_id": raw.get("doc_id"),
                "indicator_hints": [],
            }
            code = code_map.get(_evidence_identity_key(tmp), "")
            if not code:
                continue
            for token in _artifact_tokens_for_evidence(tmp):
                k = _artifact_code_key(token)
                if k and k not in out:
                    out[k] = code
            for hint in indicator_hints_by_url.get(str(tmp.get("canonical_url", "")), []):
                for token in _artifact_tokens_from_hint_line(str(hint or "")):
                    k = _artifact_code_key(token)
                    if k and k not in out:
                        out[k] = code
    return out


def build_assessment_code_document_map(
    db: Session,
    assessment: Assessment,
    *,
    ranked_snapshot: dict[str, Any] | None = None,
    evidence_code_map: dict[str, str] | None = None,
) -> dict[str, int]:
    ranked = ranked_snapshot if isinstance(ranked_snapshot, dict) else get_ranked_risks(db, assessment)
    code_map = (
        dict(evidence_code_map)
        if isinstance(evidence_code_map, dict)
        else build_assessment_evidence_code_map(db, assessment, ranked_snapshot=ranked)
    )
    evidence_sets = dict(ranked.get("evidence_sets") or {})
    workflow_nodes = list(ranked.get("workflow_nodes") or [])
    out: dict[str, int] = {}

    for rows in evidence_sets.values():
        for ev in rows or []:
            if not isinstance(ev, dict):
                continue
            code = str(code_map.get(_evidence_identity_key(ev), "")).strip().upper()
            did = ev.get("doc_id")
            if code and str(did).isdigit() and code not in out:
                out[code] = int(did)

    for node in workflow_nodes:
        evs = from_json(getattr(node, "evidence_refs_json", "") or "[]", [])
        if not isinstance(evs, list):
            continue
        for raw in evs:
            if not isinstance(raw, dict):
                continue
            did = raw.get("doc_id")
            raw_url = str(raw.get("url", "")).strip()
            if not str(did).isdigit() or not raw_url:
                continue
            tmp = {
                "canonical_url": _canonical_url(raw_url),
                "url": raw_url,
                "signal_type": str(raw.get("signal_type", "") or "OTHER"),
                "doc_id": did,
            }
            code = str(code_map.get(_evidence_identity_key(tmp), "")).strip().upper()
            if code and code not in out:
                out[code] = int(did)
    return out


def _clip_artifact(value: str, *, max_chars: int = 90) -> str:
    value = " ".join(str(value or "").split()).strip()
    if len(value) <= max_chars:
        return value
    return f"{value[: max(8, max_chars - 3)]}..."


def _artifact_from_url(url: str) -> str:
    raw = " ".join(str(url or "").split()).strip()
    if not raw:
        return ""
    if raw.lower().startswith("mailto:"):
        return _clip_artifact(raw.split(":", 1)[1].strip(), max_chars=80)
    try:
        u = urlparse(raw)
        host = (u.netloc or "").lower().split(":")[0]
        path = (u.path or "").strip()
        if host and path and path != "/":
            return _clip_artifact(f"{host}{path}", max_chars=80)
        if host:
            return _clip_artifact(host, max_chars=80)
    except Exception:
        return _clip_artifact(raw, max_chars=80)
    return _clip_artifact(raw, max_chars=80)


def _with_artifact(base: str, artifact: str = "") -> str:
    label = " ".join(str(base or "").split()).strip()
    art = " ".join(str(artifact or "").split()).strip()
    if label and art:
        return f"{label} ({art})"
    return label


def _build_coded_signal_refs(
    evidence: list[dict[str, Any]],
    *,
    extra_hints: list[str] | None = None,
    evidence_code_map: dict[str, str] | None = None,
    artifact_code_map: dict[str, str] | None = None,
    max_items: int = 8,
) -> list[dict[str, Any]]:
    refs: list[dict[str, Any]] = []
    seen: set[str] = set()
    rows = [ev for ev in (evidence or []) if isinstance(ev, dict)]
    hint_lines: list[str] = []
    for hint in extra_hints or []:
        line = " ".join(str(hint or "").split()).strip()
        if line and line not in hint_lines:
            hint_lines.append(line)
    if not rows and not hint_lines:
        return refs

    blobs: list[str] = []
    emails: list[str] = []
    phones: list[str] = []
    page_artifacts: list[str] = []
    privacy_artifacts: list[str] = []
    workflow_artifacts: list[str] = []
    vendor_artifacts: list[str] = []
    role_hits: list[str] = []
    email_codes: dict[str, str] = {}
    phone_codes: dict[str, str] = {}
    role_codes: dict[str, str] = {}
    page_codes: dict[str, str] = {}
    privacy_codes: list[str] = []
    signal_type_codes: dict[str, str] = {}
    contact_like_codes: list[str] = []
    code_map = dict(evidence_code_map or {})
    artifact_map = {str(k).lower(): str(v).strip().upper() for k, v in dict(artifact_code_map or {}).items()}

    def _code_from_artifact(value: str) -> str:
        key = _artifact_code_key(value)
        return str(artifact_map.get(key, "")).strip().upper()

    def _first_valid_code(values: list[str]) -> str:
        for val in values:
            c = " ".join(str(val or "").split()).strip().upper()
            if re.match(r"^E-\d{2,3}$", c):
                return c
        return ""

    for ev in rows:
        row_code = ""
        if code_map:
            row_code = str(code_map.get(_evidence_identity_key(ev), "")).strip().upper()
        hints = ev.get("indicator_hints")
        hint_blob = " ".join(str(x or "") for x in hints) if isinstance(hints, list) else ""
        blob = " ".join(
            [
                str(ev.get("title", "") or ""),
                str(ev.get("snippet", "") or ""),
                str(ev.get("url", "") or ""),
                str(ev.get("doc_title", "") or ""),
                hint_blob,
            ]
        )
        blobs.append(
            " ".join(
                [
                    blob,
                    str(ev.get("signal_type", "") or ""),
                    str(ev.get("evidence_kind", "") or ""),
                ]
            )
        )
        for em in EMAIL_PATTERN.findall(blob):
            low = em.lower()
            if low not in emails:
                emails.append(low)
            if row_code and low not in email_codes:
                email_codes[low] = row_code
            if low not in email_codes:
                mapped = _code_from_artifact(low)
                if mapped:
                    email_codes[low] = mapped
        raw_url = str(ev.get("url", "") or "").strip()
        if raw_url.lower().startswith("mailto:"):
            candidate = raw_url.split(":", 1)[1].strip().lower()
            if candidate and candidate not in emails:
                emails.append(candidate)
            if candidate and row_code and candidate not in email_codes:
                email_codes[candidate] = row_code
        for ph in PHONE_PATTERN.findall(blob):
            normalized = " ".join(str(ph).split())
            if normalized and normalized not in phones:
                phones.append(normalized)
            if normalized and row_code and normalized not in phone_codes:
                phone_codes[normalized] = row_code
            if normalized and normalized not in phone_codes:
                mapped = _code_from_artifact(normalized)
                if mapped:
                    phone_codes[normalized] = mapped
        url_art = _artifact_from_url(raw_url)
        if url_art and url_art not in page_artifacts:
            page_artifacts.append(url_art)
        if url_art and row_code and url_art not in page_codes:
            page_codes[url_art] = row_code
        if url_art and url_art not in page_codes:
            mapped = _code_from_artifact(url_art)
            if mapped:
                page_codes[url_art] = mapped

        st = str(ev.get("signal_type", "")).strip().upper()
        if row_code and st and st not in signal_type_codes:
            signal_type_codes[st] = row_code

        low_blob = blob.lower()
        if any(k in low_blob for k in ("privacy", "legal", "gdpr", "dpo", "data protection", "/privacy", "/legal")):
            if url_art and url_art not in privacy_artifacts:
                privacy_artifacts.append(url_art)
            if row_code and row_code not in privacy_codes:
                privacy_codes.append(row_code)
        if any(
            k in low_blob
            for k in ("workflow", "booking", "payment", "billing", "account", "refund", "invoice", "support flow")
        ):
            if url_art and url_art not in workflow_artifacts:
                workflow_artifacts.append(url_art)
        if str(ev.get("signal_type", "")).strip().upper() == "VENDOR_CUE":
            vendor_art = _clip_artifact(str(ev.get("title", "") or str(ev.get("domain", "") or "")).strip(), max_chars=80)
            if vendor_art and vendor_art not in vendor_artifacts:
                vendor_artifacts.append(vendor_art)
        for role in ("finance", "it", "privacy", "security", "support", "billing", "procurement"):
            if role in low_blob and role not in role_hits:
                role_hits.append(role)
            if role in low_blob and role not in role_codes:
                role_code = row_code or _code_from_artifact(f"role: {role}")
                if role_code:
                    role_codes[role] = role_code

    for line in hint_lines:
        blobs.append(line)
        low_line = line.lower()
        for em in EMAIL_PATTERN.findall(line):
            low = em.lower()
            if low and low not in emails:
                emails.append(low)
            if low and low not in email_codes:
                mapped = _code_from_artifact(low)
                if mapped:
                    email_codes[low] = mapped
        for ph in PHONE_PATTERN.findall(line):
            normalized = " ".join(str(ph).split())
            if normalized and normalized not in phones:
                phones.append(normalized)
            if normalized and normalized not in phone_codes:
                mapped = _code_from_artifact(normalized)
                if mapped:
                    phone_codes[normalized] = mapped
        for role in ROLE_HINTS:
            if role in low_line and role not in role_hits:
                role_hits.append(role)
            if role in low_line and role not in role_codes:
                mapped = _code_from_artifact(f"role: {role}")
                if mapped:
                    role_codes[role] = mapped
        if "http" in low_line or "/" in low_line:
            art = _artifact_from_url(line.split(" ", 1)[-1])
            if art and art not in page_artifacts:
                page_artifacts.append(art)
            if art and art not in page_codes:
                mapped = _code_from_artifact(art)
                if mapped:
                    page_codes[art] = mapped
        if any(k in low_line for k in ("privacy", "legal", "gdpr", "dpo", "data protection")):
            candidate = ""
            if page_artifacts:
                candidate = page_artifacts[0]
            elif emails:
                candidate = next((x for x in emails if any(t in x for t in ("privacy", "legal", "dpo"))), "")
            if candidate and candidate not in privacy_artifacts:
                privacy_artifacts.append(candidate)
            mapped = _code_from_artifact(candidate)
            if mapped and mapped not in privacy_codes:
                privacy_codes.append(mapped)
    all_blob = " ".join(blobs).lower()

    if emails:
        email_artifact = _clip_artifact(emails[0], max_chars=80)
        email_code = _first_valid_code([email_codes.get(emails[0], ""), _code_from_artifact(email_artifact)])
        _add_signal_ref(
            refs,
            seen=seen,
            text=_with_artifact("Public contact email exposed", email_artifact),
            tags=["contact", "email", "identity"],
            max_items=max_items,
            code=email_code,
        )

    if any(k in all_blob for k in ("privacy", "legal", "gdpr", "dpo", "data protection")):
        privacy_artifact = ""
        if privacy_artifacts:
            privacy_artifact = privacy_artifacts[0]
        elif emails:
            em = next((x for x in emails if any(t in x for t in ("privacy", "legal", "dpo"))), "")
            privacy_artifact = em or ""
        privacy_code = _first_valid_code(
            [
                _code_from_artifact(privacy_artifact),
                privacy_codes[0] if privacy_codes else "",
                email_codes.get(privacy_artifact.lower(), ""),
            ]
        )
        _add_signal_ref(
            refs,
            seen=seen,
            text=_with_artifact("Public privacy/legal channel exposed", privacy_artifact),
            tags=["privacy", "legal", "identity", "contact"],
            max_items=max_items,
            code=privacy_code,
        )

    contact_like_urls: set[str] = set()
    for ev in rows:
        st = str(ev.get("signal_type", "")).strip().upper()
        ek = str(ev.get("evidence_kind", "")).strip().upper()
        blob = " ".join([str(ev.get("title", "") or ""), str(ev.get("snippet", "") or ""), str(ev.get("url", "") or "")]).lower()
        if st == "CONTACT_CHANNEL" or ek == "CONTACT_CHANNEL" or any(
            tok in blob for tok in ("contact", "support", "help", "form", "privacy", "legal", "policy")
        ):
            cu = str(ev.get("canonical_url", "") or "").strip() or str(ev.get("url", "") or "").strip()
            if cu:
                contact_like_urls.add(cu[:220])
            row_code = str(code_map.get(_evidence_identity_key(ev), "")).strip().upper()
            if row_code and row_code not in contact_like_codes:
                contact_like_codes.append(row_code)
    for line in hint_lines:
        low = line.lower()
        if any(tok in low for tok in ("contact", "support", "help", "form", "privacy", "legal", "policy", "channel")):
            contact_like_urls.add(low[:220])
            for em in EMAIL_PATTERN.findall(line):
                mapped = _code_from_artifact(em.lower())
                if mapped and mapped not in contact_like_codes:
                    contact_like_codes.append(mapped)
    if len(contact_like_urls) >= 2:
        entry_artifacts: list[str] = []
        if page_artifacts:
            entry_artifacts.append(page_artifacts[0])
        if emails:
            entry_artifacts.append(emails[0])
        elif phones:
            entry_artifacts.append(phones[0])
        entry_code = _first_valid_code(
            [
                contact_like_codes[0] if contact_like_codes else "",
                page_codes.get(entry_artifacts[0], "") if entry_artifacts else "",
                email_codes.get(emails[0], "") if emails else "",
            ]
        )
        _add_signal_ref(
            refs,
            seen=seen,
            text=_with_artifact("Multiple official entrypoints", " + ".join(entry_artifacts[:2]) or "form + email + page"),
            tags=["entrypoint", "channel", "contact", "ambiguity"],
            max_items=max_items,
            code=entry_code,
        )

    if role_hits:
        role_code = ""
        for role in role_hits:
            rc = role_codes.get(role, "")
            if rc:
                role_code = rc
                break
        _add_signal_ref(
            refs,
            seen=seen,
            text=_with_artifact("Public role cues", "/".join(role_hits[:3])),
            tags=["role", "staff", "identity"] + role_hits[:3],
            max_items=max_items,
            code=role_code,
        )

    signal_set = {str(ev.get("signal_type", "")).strip().upper() for ev in rows if str(ev.get("signal_type", "")).strip()}
    if "PROCESS_CUE" in signal_set:
        wf_artifact = workflow_artifacts[0] if workflow_artifacts else (page_artifacts[0] if page_artifacts else "")
        _add_signal_ref(
            refs,
            seen=seen,
            text=_with_artifact("Public workflow handling cues exposed", wf_artifact),
            tags=["workflow", "process", "request"],
            max_items=max_items,
            code=_first_valid_code([signal_type_codes.get("PROCESS_CUE", ""), _code_from_artifact(wf_artifact)]),
        )
    if "VENDOR_CUE" in signal_set:
        vendor_artifact = vendor_artifacts[0] if vendor_artifacts else ""
        _add_signal_ref(
            refs,
            seen=seen,
            text=_with_artifact("Public vendor/platform cues exposed", vendor_artifact),
            tags=["vendor", "platform", "third-party"],
            max_items=max_items,
            code=_first_valid_code([signal_type_codes.get("VENDOR_CUE", ""), _code_from_artifact(vendor_artifact)]),
        )
    if "INFRA_CUE" in signal_set:
        infra_artifact = page_artifacts[0] if page_artifacts else ""
        _add_signal_ref(
            refs,
            seen=seen,
            text=_with_artifact("Public support/portal endpoints exposed", infra_artifact),
            tags=["infra", "portal", "endpoint", "page"],
            max_items=max_items,
            code=_first_valid_code([signal_type_codes.get("INFRA_CUE", ""), _code_from_artifact(infra_artifact)]),
        )

    if not refs:
        for line in _sample_signal_lines(rows, max_items=min(4, max_items)):
            hint_code = ""
            em = EMAIL_PATTERN.search(line)
            if em:
                hint_code = _code_from_artifact(em.group(0).lower())
            if not hint_code:
                for role in ROLE_HINTS:
                    if role in line.lower():
                        hint_code = _code_from_artifact(f"role: {role}")
                        if hint_code:
                            break
            _add_signal_ref(
                refs,
                seen=seen,
                text=line,
                tags=["signal"],
                max_items=max_items,
                code=hint_code,
            )
    # Final fallback: surface concrete correlated hints (emails/phones/roles/pages) if still not present.
    if len(refs) < max_items:
        for line in hint_lines:
            clean = " ".join(str(line or "").split()).strip()
            if not clean:
                continue
            low = clean.lower()
            tags: list[str] = ["signal"]
            hint_code = ""
            if EMAIL_PATTERN.search(clean):
                tags += ["email", "contact", "identity"]
                email_match = EMAIL_PATTERN.search(clean)
                if email_match:
                    email_artifact = _clip_artifact(email_match.group(0), max_chars=80)
                    clean = _with_artifact("Public contact email exposed", email_artifact)
                    hint_code = _first_valid_code(
                        [email_codes.get(email_match.group(0).lower(), ""), _code_from_artifact(email_artifact)]
                    )
            elif PHONE_PATTERN.search(clean):
                tags += ["contact", "phone", "identity"]
                phone_match = PHONE_PATTERN.search(clean)
                if phone_match:
                    hint_code = _first_valid_code(
                        [phone_codes.get(" ".join(str(phone_match.group(0)).split()), ""), _code_from_artifact(phone_match.group(0))]
                    )
            elif any(k in low for k in ("privacy", "legal", "dpo", "gdpr")):
                tags += ["privacy", "legal", "identity"]
                hint_code = _first_valid_code([privacy_codes[0] if privacy_codes else "", _code_from_artifact(clean)])
            elif any(k in low for k in ROLE_HINTS):
                tags += ["role", "staff", "identity"]
                for role in ROLE_HINTS:
                    if role in low:
                        hint_code = _first_valid_code([role_codes.get(role, ""), _code_from_artifact(f"role: {role}")])
                        if hint_code:
                            break
            elif "http" in low or "/" in low:
                tags += ["entrypoint", "page", "channel"]
                hint_code = _code_from_artifact(_artifact_from_url(clean))
            _add_signal_ref(refs, seen=seen, text=clean, tags=tags, max_items=max_items, code=hint_code)
            if len(refs) >= max_items:
                break
    return refs[:max_items]


def _refs_for_bundle(
    bundle: dict[str, Any],
    refs: list[dict[str, Any]],
    *,
    bundle_evidence: list[dict[str, Any]] | None = None,
    evidence_code_map: dict[str, str] | None = None,
    artifact_code_map: dict[str, str] | None = None,
    max_items: int = 10,
) -> list[dict[str, str]]:
    if not refs and not bundle_evidence:
        return []
    btype = str(bundle.get("bundle_type", "")).strip().upper()
    wanted_map = {
        "IDENTITY_SIGNALS": {"contact", "email", "privacy", "legal", "role", "identity", "staff"},
        "CHANNEL_AMBIGUITY": {"entrypoint", "ambiguity", "contact", "channel", "page", "form"},
        "INFORMAL_WORKFLOW": {"workflow", "process", "request"},
        "VENDOR_DEPENDENCY": {"vendor", "platform", "third-party"},
        "INFRA_ENDPOINTS": {"infra", "portal", "endpoint", "page"},
        "EXTERNAL_VISIBILITY": {"visibility", "external", "news"},
    }
    wanted = wanted_map.get(btype, set())
    selected: list[dict[str, str]] = []
    selected_keys: set[str] = set()
    for ref in refs:
        tags = {str(x).strip().lower() for x in (ref.get("tags") or []) if str(x).strip()}
        if wanted and tags and not tags.intersection(wanted):
            continue
        text = " ".join(str(ref.get("text", "")).split()).strip()
        code = " ".join(str(ref.get("code", "")).split()).strip()
        if not text:
            continue
        key = re.sub(r"[^a-z0-9]+", " ", text.lower()).strip()[:180]
        if not key or key in selected_keys:
            continue
        selected_keys.add(key)
        selected.append({"code": code, "text": text})
        if len(selected) >= max_items:
            break
    if not selected and bundle_evidence:
        local = _build_coded_signal_refs(
            list(bundle_evidence or []),
            evidence_code_map=evidence_code_map,
            artifact_code_map=artifact_code_map,
            max_items=max_items,
        )
        if local:
            return [
                {"code": str(x.get("code", "")), "text": str(x.get("text", ""))}
                for x in local[:max_items]
                if str(x.get("code", "")).strip() and str(x.get("text", "")).strip()
            ]
    if not selected and refs:
        text = " ".join(str(refs[0].get("text", "")).split()).strip()
        code = " ".join(str(refs[0].get("code", "")).split()).strip()
        if text:
            selected.append({"code": code, "text": text})
    return selected[:max_items]


def _ref_keywords(ref: dict[str, Any]) -> set[str]:
    out: set[str] = set()
    for tag in ref.get("tags") or []:
        t = str(tag or "").strip().lower()
        if t:
            out.add(t)
    for tok in re.findall(r"[a-z0-9]{3,}", str(ref.get("text", "")).lower()):
        if tok in _REF_KEYWORD_STOPWORDS:
            continue
        out.add(tok)
    return out


def _inject_evidence_codes_in_how(text: str, refs: list[dict[str, Any]]) -> str:
    raw = " ".join(str(text or "").split()).strip()
    if not raw or not refs:
        return raw
    parts = [p for p in re.split(r"(?<=[.!?])\s+", raw) if p.strip()]
    if not parts:
        return raw
    meta = [(str(r.get("code", "")).strip(), _ref_keywords(r)) for r in refs if str(r.get("code", "")).strip()]
    if not meta:
        return raw

    out: list[str] = []
    for idx, sentence in enumerate(parts):
        s = sentence.strip()
        if not s:
            continue
        existing = set(re.findall(r"E-\d{2,3}", s))
        matched: list[str] = sorted(existing) if existing else []
        if not matched:
            low = s.lower()
            for code, kws in meta:
                if not kws:
                    continue
                if any(k in low for k in kws):
                    matched.append(code)
            dedup_codes: list[str] = []
            for code in matched:
                if code not in dedup_codes:
                    dedup_codes.append(code)
            matched = dedup_codes[:3]
        if idx == 0 and not matched:
            matched = [meta[0][0]]
        if matched and not existing:
            tail = ""
            core = s
            if core[-1] in ".!?":
                tail = core[-1]
                core = core[:-1].rstrip()
            s = f"{core} [{', '.join(matched)}]{tail}"
        out.append(s)
    return " ".join(out).strip()


def _signal_type_from_evidence_row(*, url: str, title: str, snippet: str, evidence_kind: str, category: str) -> str:
    kind = str(evidence_kind or "").strip().upper()
    cat = str(category or "").strip().lower()
    if kind == "WORKFLOW_VENDOR":
        return "VENDOR_CUE"
    if kind == "CONTACT_CHANNEL" or cat == "touchpoint":
        return "CONTACT_CHANNEL"
    if kind == "NEWS_MENTION" or cat == "mention":
        return "EXTERNAL_ATTENTION"
    if kind == "ORG_ROLE":
        return "ORG_CUE"
    if kind == "PROCUREMENT":
        return "PROCESS_CUE"
    if cat == "pivot":
        return "PROCESS_CUE"
    return infer_signal_type(url, snippet, query_id="EV")


def _evidence_context_maps_for_assessment(
    db: Session, assessment_id: int
) -> tuple[dict[str, set[str]], dict[str, list[str]], dict[str, list[str]], dict[str, set[str]]]:
    """
    Build canonical_url -> connector names + indicator hints from normalized evidence rows.
    This lets stakeholder views show concrete data lineage and concrete indicators next to risk evidence.
    """
    connectors_by_url: dict[str, set[str]] = {}
    indicator_hints_by_url: dict[str, list[str]] = {}
    signal_hints_by_type: dict[str, list[str]] = {}
    signal_connectors_by_type: dict[str, set[str]] = {}
    rows = db.execute(
        select(
            Evidence.source_url,
            Evidence.connector,
            Evidence.title,
            Evidence.snippet,
            Evidence.evidence_kind,
            Evidence.category,
        ).where(Evidence.assessment_id == int(assessment_id))
    ).all()
    for raw_url, raw_connector, raw_title, raw_snippet, raw_kind, raw_category in rows:
        url = str(raw_url or "").strip()
        connector = str(raw_connector or "").strip()
        if not url or not connector:
            continue
        key = _canonical_url(url)
        if not key:
            continue
        bucket = connectors_by_url.setdefault(key, set())
        bucket.add(connector)

        hints = _extract_indicator_candidates(str(raw_title or ""), str(raw_snippet or ""))
        if hints:
            dst = indicator_hints_by_url.setdefault(key, [])
            for hint in hints:
                line = " ".join(str(hint or "").split()).strip()
                if not line or line in dst:
                    continue
                dst.append(line)
                if len(dst) >= 8:
                    break
        st = _signal_type_from_evidence_row(
            url=url,
            title=str(raw_title or ""),
            snippet=str(raw_snippet or ""),
            evidence_kind=str(raw_kind or ""),
            category=str(raw_category or ""),
        )
        if st:
            sc = signal_connectors_by_type.setdefault(st, set())
            sc.add(connector)
            sh = signal_hints_by_type.setdefault(st, [])
            for hint in hints:
                line = " ".join(str(hint or "").split()).strip()
                if not line or line in sh:
                    continue
                sh.append(line)
                if len(sh) >= 16:
                    break
    return connectors_by_url, indicator_hints_by_url, signal_hints_by_type, signal_connectors_by_type


def _severity_from_likelihood_impact(likelihood: str, impact_band: str) -> int:
    lik = (likelihood or "med").strip().lower()
    imp = (impact_band or "MED").strip().upper()
    matrix = {
        "LOW": {"low": 1, "med": 2, "high": 3},
        "MED": {"low": 2, "med": 3, "high": 4},
        "HIGH": {"low": 3, "med": 4, "high": 5},
    }
    return int(matrix.get(imp, matrix["MED"]).get(lik, 3))


def _reasoning_block_for_risk(
    *,
    risk: dict[str, Any],
    evidence: list[dict[str, Any]],
    recipe_bundles: list[dict[str, Any]] | None = None,
    risk_vector_summary: str = "",
    supplemental_hints: list[str] | None = None,
    supplemental_connectors: list[str] | None = None,
) -> dict[str, str]:
    signal_types = int(risk.get("signal_diversity_count", 0) or 0)
    refs = int(risk.get("evidence_refs_count", 0) or len(evidence or []))

    bundle_names = [
        str(b.get("title", "")).strip()
        for b in (recipe_bundles or [])
        if isinstance(b, dict) and str(b.get("title", "")).strip()
    ]
    if not bundle_names:
        bundle_names = [
            str(b.get("title", "")).strip()
            for b in (risk.get("recipe_bundles") or [])
            if isinstance(b, dict) and str(b.get("title", "")).strip()
        ]
    bundle_phrase = ", ".join(bundle_names[:2])

    connector_set: set[str] = set()
    for ev in evidence or []:
        raw = ev.get("connectors")
        if isinstance(raw, list):
            for item in raw:
                c = str(item or "").strip()
                if c:
                    connector_set.add(c)
    for conn in supplemental_connectors or []:
        c = str(conn or "").strip()
        if c:
            connector_set.add(c)
    ordered_connector_names = sorted(connector_set, key=_connector_sort_key)
    connector_labels = [
        _connector_human_label(name) for name in ordered_connector_names if _connector_human_label(name)
    ]
    source_label = ", ".join(connector_labels[:3]) if connector_labels else "risk evidence sources"

    merged_candidates: list[str] = []
    merged_candidates.extend(_sample_signal_lines(evidence, max_items=8))
    for hint in supplemental_hints or []:
        line = " ".join(str(hint or "").split()).strip()
        if line:
            merged_candidates.append(line)

    deduped: list[str] = []
    seen_keys: set[str] = set()
    for line in merged_candidates:
        key = re.sub(r"[^a-z0-9]+", " ", line.lower()).strip()[:140]
        if not key or key in seen_keys:
            continue
        seen_keys.add(key)
        deduped.append(line)
    deduped.sort(key=lambda x: (_hint_priority(x), len(x)))
    coded_only = [x for x in deduped if re.match(r"^E-\d{2,3}\b", str(x or "").strip(), flags=re.IGNORECASE)]
    sample_pool = coded_only if coded_only else deduped
    sample_signals = sample_pool[:10] if len(sample_pool) > 10 else sample_pool

    supplemental_indicator_count = min(max(0, len(supplemental_hints or [])), 4)
    display_refs = int(refs) + int(supplemental_indicator_count) if supplemental_indicator_count > 0 else int(refs)
    what_we_saw = f"{display_refs} linked evidence items"
    if supplemental_indicator_count > 0:
        what_we_saw += f" ({int(refs)} risk-linked + {supplemental_indicator_count} correlated indicators)"
    if signal_types > 0:
        what_we_saw += f" across {signal_types} signal types"
    what_we_saw += f" from {source_label}."
    if bundle_phrase:
        what_we_saw += f" Key conditions: {bundle_phrase}."
    if sample_signals:
        what_we_saw += " Sample signals: " + "; ".join(sample_signals)

    why_context = str(risk.get("why_matters", "") or risk_vector_summary or "")
    why_it_matters = _why_it_matters_cti(
        risk=risk,
        evidence=evidence,
        fallback_context=why_context,
    )

    likelihood = str(risk.get("likelihood", "med") or "med").strip().lower()
    impact_band = str(risk.get("impact_band", "MED") or "MED").strip().upper()
    confidence = int(risk.get("confidence", 0) or 0)
    evidence_strength = str(risk.get("evidence_strength", "WEAK") or "WEAK").strip().upper()
    severity = _severity_from_likelihood_impact(likelihood, impact_band)
    why_severity = (
        f"S{severity} from likelihood {likelihood.upper()} + impact {impact_band}; "
        f"evidence strength {evidence_strength} ({confidence}%)."
    )

    scope_boundary = (
        "Defensive hypothesis based on public evidence. It reflects exposure/preconditions, not confirmed exploitation."
    )
    return {
        "what_we_saw": what_we_saw,
        "why_it_matters": why_it_matters,
        "why_severity": why_severity,
        "scope_boundary": scope_boundary,
    }


def _canonical_url(url: str) -> str:
    raw = (url or "").strip()
    if not raw:
        return ""
    if raw.startswith(("dns://", "subdomain://", "shodan://", "virustotal://")):
        return raw.lower()
    try:
        u = urlparse(raw)
        host = (u.netloc or "").lower().split(":")[0]
        path = u.path or "/"
        scheme = u.scheme or "https"
        return urlunparse((scheme, host, path, "", "", ""))
    except Exception:
        return raw


def _domain_for_url(url: str) -> str:
    raw = (url or "").strip()
    if not raw:
        return "unknown"
    if raw.startswith("dns://"):
        return "dns"
    try:
        host = urlparse(raw).netloc.lower().split(":")[0]
        return host or "source"
    except Exception:
        return "source"


def _impact_band_from_severity(severity: int) -> str:
    sev = int(severity or 3)
    if sev >= 4:
        return "HIGH"
    if sev == 3:
        return "MED"
    return "LOW"


def _evidence_strength_tooltip(label: str) -> str:
    l = (label or "WEAK").upper()
    if l == "STRONG":
        return "Strong evidence strength: multiple distinct signal types converge across distinct URLs."
    if l == "OK":
        return "OK evidence strength: at least two distinct signal types support the risk."
    return "Weak evidence strength: evidence is narrow (repetition) or lacks critical process/vendor/org cues."


def _evidence_quality_label(meta: dict) -> str:
    try:
        weighted = int(meta.get("weighted_evidence_count", 0) or 0)
        distinct = int(meta.get("distinct_url_count", 0) or 0)
        diversity = int(meta.get("signal_diversity_count", 0) or 0)
    except Exception:
        return "WEAK"
    if weighted >= 4 and distinct >= 2 and diversity >= 3:
        return "STRONG"
    if weighted >= 3 and distinct >= 2 and diversity >= 2:
        return "OK"
    return "WEAK"


def _risk_outcome_label(risk_type: str, *, sector: str = "", process_flags: dict | None = None) -> str:
    rkey = (risk_type or "other").strip().lower()
    sector_norm = (sector or "").strip().lower()
    sens = (process_flags or {}).get("data_sens_kinds") if isinstance(process_flags, dict) else []
    sens_set = {str(x).upper() for x in (sens or []) if str(x).strip()}
    if "BOOKING_PAYMENT" in sens_set:
        return "Booking and payment workflow exposure"
    if "CREDENTIALS" in sens_set:
        return "Credential and account workflow exposure"
    if rkey in {"social_trust_surface_exposure"}:
        return "Social channel trust surface exposure"
    if rkey in {"downstream_pivot"}:
        return "Risk to clients via impersonation"
    if rkey in {"impersonation", "brand_abuse", "social_engineering_risk"}:
        if any(tok in sector_norm for tok in ("hospital", "hotel", "hospitality")):
            return "Guest-facing impersonation opportunity"
        return "Impersonation opportunity"
    if rkey in {"fraud_process"}:
        return "Process fraud opportunity"
    if rkey in {"privacy_data_risk"}:
        return "Data request handling exposure"
    if rkey in {"credential_theft_risk"}:
        return "Account handling exposure"
    if rkey in {"workflow_trust_exposure"}:
        # Avoid generic labels; keep outcome decision-ready and abuse-oriented.
        return "Channel ambiguity exploitation"
    if rkey in {"exposure"}:
        return "Reconnaissance opportunity"
    return "External trust-channel risk"


def _attack_type_phrase(*, primary_risk_type: str, risk_type: str, process_flags: dict | None = None) -> str:
    rt = str(risk_type or "").strip().lower()
    primary = str(primary_risk_type or "").strip().lower()
    sens = set()
    if isinstance(process_flags, dict):
        sens = {str(x).upper() for x in (process_flags.get("data_sens_kinds") or []) if str(x).strip()}

    if (
        rt in {"fraud_process"}
        or any(k in primary for k in ("payment fraud", "booking fraud", "donation fraud"))
        or "BOOKING_PAYMENT" in sens
    ):
        return "Fraudulent payment or invoice redirection"
    if rt in {"privacy_data_risk"} or any(k in primary for k in ("data handling", "data subject", "privacy")):
        return "Unauthorized personal data disclosure"
    if (
        rt in {"credential_theft_risk"}
        or any(k in primary for k in ("account takeover", "credential"))
        or "CREDENTIALS" in sens
    ):
        return "Account takeover via identity verification abuse"
    if rt in {"impersonation", "downstream_pivot", "brand_abuse", "social_trust_surface_exposure"} or any(
        k in primary for k in ("social engineering", "partner impersonation", "channel confusion")
    ):
        return "Impersonation of official contact channels"
    if any(k in primary for k in ("vendor trust abuse", "supplier dependency")):
        return "Vendor trust abuse in operational communications"
    return "Impersonation of trusted business communications"


def _impact_phrase(*, risk_type: str, process_flags: dict | None = None, primary_risk_type: str = "") -> str:
    rt = str(risk_type or "").strip().lower()
    primary = str(primary_risk_type or "").strip().lower()
    sens = set()
    if isinstance(process_flags, dict):
        sens = {str(x).upper() for x in (process_flags.get("data_sens_kinds") or []) if str(x).strip()}

    if (
        rt in {"fraud_process"}
        or any(k in primary for k in ("payment", "invoice", "booking fraud", "donation fraud"))
        or "BOOKING_PAYMENT" in sens
    ):
        return "fraudulent payments and financial loss"
    if rt in {"privacy_data_risk"} or any(k in primary for k in ("data handling", "privacy")):
        return "data leakage and reputational damage"
    if (
        rt in {"credential_theft_risk"}
        or any(k in primary for k in ("account takeover", "credential"))
        or "CREDENTIALS" in sens
    ):
        return "account takeover and operational disruption"
    if rt in {"downstream_pivot", "impersonation", "brand_abuse", "social_trust_surface_exposure"}:
        return "fraudulent requests and client trust damage"
    return "operational disruption and reputational damage"


def _verdict_line(
    *, primary_risk_type: str, risk_type: str, conditions: list[str], process_flags: dict | None = None
) -> str:
    """
    Concrete structure:
      Top Risk: [Concrete attack type] leading to [specific impact].
    """
    attack = _attack_type_phrase(primary_risk_type=primary_risk_type, risk_type=risk_type, process_flags=process_flags)
    impact = _impact_phrase(risk_type=risk_type, process_flags=process_flags, primary_risk_type=primary_risk_type)
    base = f"Top Risk: {attack} leading to {impact}."
    words = base.split()
    if len(words) > 34:
        base = " ".join(words[:34]).rstrip(".") + "."
    return (base[:157] + "...") if len(base) > 160 else base


def _verdict_conditions(v: str) -> list[str]:
    text = " ".join(str(v or "").split()).strip()
    low = text.lower()
    marker = "enabled by "
    idx = low.find(marker)
    if idx < 0:
        return []
    tail = text[idx + len(marker) :].strip().rstrip(".")
    parts = [p.strip() for p in tail.split("+") if p.strip()]
    return parts[:3]


def _verdict_matches_bundles(verdict: str, bundle_titles: list[str]) -> bool:
    if "leading to" in str(verdict or "").lower():
        # Concretized verdict format does not enumerate bundle labels inline.
        return True
    # Legacy "enabled by ..." format is intentionally considered non-compliant
    # for the operational concretization patch and is regenerated.
    return False


@dataclass(frozen=True)
class _ParsedSignalCounts:
    counts: dict[str, int]
    baseline_exposure: bool
    tags: list[str]
    process_flags: dict[str, Any] | None
    extras: dict[str, Any]


def _parse_signal_counts_blob(blob: str) -> _ParsedSignalCounts:
    raw = from_json(blob or "{}", {})
    if not isinstance(raw, dict):
        raw = {}
    baseline = bool(raw.get("__baseline_exposure__", False))
    tags = raw.get("__tags__", []) if isinstance(raw.get("__tags__", []), list) else []
    process_flags = raw.get("__process_flags__", None) if isinstance(raw.get("__process_flags__", None), dict) else None
    extras: dict[str, Any] = {}
    for k in ("__workflow_node_id__", "__workflow_kind__", "__social_node_id__"):
        if k in raw:
            extras[k] = raw.get(k)

    counts: dict[str, int] = {}
    for k, v in raw.items():
        if str(k).strip().upper() not in SIGNAL_TYPES:
            continue
        try:
            counts[str(k).strip().upper()] = int(v or 0)
        except Exception:
            continue
    return _ParsedSignalCounts(
        counts=counts, baseline_exposure=baseline, tags=tags, process_flags=process_flags, extras=extras
    )


def _normalize_evidence_refs(
    refs: list[Any],
    *,
    docs_by_id: dict[int, Document],
    docs_by_url: dict[str, Document],
    query_id: str,
    connectors_by_url: dict[str, set[str]] | None = None,
    indicator_hints_by_url: dict[str, list[str]] | None = None,
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for item in refs or []:
        if not isinstance(item, dict):
            continue
        url = str(item.get("url", "")).strip()[:1024]
        title = str(item.get("title", "")).strip()[:255]
        snippet = " ".join(str(item.get("snippet", "")).split()).strip()
        snippet = snippet[:1200]
        conf_raw = item.get("confidence", 50)
        try:
            conf = int(conf_raw or 50)
        except Exception:
            conf = 50
        conf = max(1, min(100, conf))

        q = classify_evidence(
            url=url,
            title=title,
            snippet=snippet,
            source_type=("pdf" if url.lower().endswith(".pdf") else "html"),
            connector="risk_refs",
            raw={},
        )
        evidence_kind = str(item.get("evidence_kind", "") or q.evidence_kind).strip().upper() or "UNKNOWN"
        quality_tier = str(item.get("quality_tier", "") or q.quality_tier).strip().upper() or "LOW"
        rationale = str(item.get("rationale", "") or q.rationale).strip()
        is_boilerplate = bool(item.get("is_boilerplate", q.is_boilerplate))
        try:
            weight = float(item.get("weight", q.quality_weight) or q.quality_weight)
        except Exception:
            weight = float(q.quality_weight)
        if quality_tier == "BOILERPLATE" or is_boilerplate:
            is_boilerplate = True
            weight = min(weight, 0.10)

        st = str(item.get("signal_type", "")).strip().upper()
        if not st:
            if evidence_kind == "WORKFLOW_VENDOR":
                st = "VENDOR_CUE"
            elif evidence_kind == "CONTACT_CHANNEL":
                st = "CONTACT_CHANNEL"
            elif evidence_kind == "NEWS_MENTION":
                st = "EXTERNAL_ATTENTION"
            elif evidence_kind == "ORG_ROLE":
                st = "ORG_CUE"
            elif evidence_kind == "PROCUREMENT":
                st = "PROCESS_CUE"
            elif evidence_kind == "GENERIC_WEB":
                st = "UNCLASSIFIED"
            else:
                st = infer_signal_type(url, snippet, query_id=query_id)
        # Vendor cues can come only from workflow-specific vendor evidence.
        if st == "VENDOR_CUE" and evidence_kind != "WORKFLOW_VENDOR":
            st = "UNCLASSIFIED"

        doc_link = url
        doc_title = ""
        doc_type = ""
        doc_id = item.get("doc_id")
        doc: Document | None = None
        if str(doc_id).isdigit():
            doc = docs_by_id.get(int(doc_id))
        if not doc and url:
            doc = docs_by_url.get(url)
        if doc:
            doc_link = f"/documents/{doc.id}"
            doc_title = doc.title or ""
            doc_type = doc.doc_type or ""
            doc_id = int(doc.id)

        canonical = _canonical_url(url)
        connectors: list[str] = []
        if connectors_by_url:
            connectors = sorted(list(connectors_by_url.get(canonical, set())))
        indicator_hints: list[str] = []
        if indicator_hints_by_url:
            indicator_hints = list(indicator_hints_by_url.get(canonical, []))

        out.append(
            {
                "url": url,
                "canonical_url": canonical,
                "domain": _domain_for_url(url),
                "title": title,
                "snippet": snippet or "No excerpt captured.",
                "doc_id": doc_id if str(doc_id).isdigit() else None,
                "doc_link": doc_link,
                "doc_title": doc_title,
                "doc_type": doc_type,
                "confidence": conf,
                "signal_type": st,
                "signal_label": SIGNAL_LABELS.get(st, st.replace("_", " ").title()),
                "signal_icon": SIGNAL_ICONS.get(st, "activity"),
                "is_boilerplate": bool(is_boilerplate),
                "weight": weight,
                "evidence_kind": evidence_kind,
                "quality_tier": quality_tier,
                "rationale": rationale,
                "connectors": connectors,
                "indicator_hints": indicator_hints,
            }
        )
    return out


def _dedupe_evidence(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Dedupe for UI: canonical_url + signal_type. Keep one representative snippet and track occurrences.
    Boilerplate must be filtered out by the caller for story views.
    """
    seen: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for ev in items or []:
        key = f"{ev.get('canonical_url', '')}|{ev.get('signal_type', '')}"
        if not key.strip("|"):
            continue
        if key in seen:
            inc = 1
            try:
                inc = int(ev.get("occurrences", 1) or 1)
            except Exception:
                inc = 1
            seen[key]["occurrences"] = int(seen[key].get("occurrences", 1) or 1) + max(1, inc)
            try:
                if int(ev.get("confidence", 0) or 0) > int(seen[key].get("confidence", 0) or 0):
                    seen[key]["snippet"] = ev.get("snippet", seen[key].get("snippet", ""))
                    seen[key]["confidence"] = int(ev.get("confidence", seen[key].get("confidence", 50)) or 50)
            except Exception:
                pass
            continue
        row = dict(ev)
        try:
            row["occurrences"] = max(1, int(row.get("occurrences", 1) or 1))
        except Exception:
            row["occurrences"] = 1
        seen[key] = row
        order.append(key)
    return [seen[k] for k in order if k in seen]


_FOCUS_STOPWORDS = {
    "the",
    "and",
    "for",
    "with",
    "from",
    "that",
    "this",
    "into",
    "over",
    "through",
    "across",
    "risk",
    "step",
    "path",
    "phase",
    "stage",
    "status",
    "impact",
    "evidence",
    "strength",
    "score",
    "high",
    "med",
    "low",
}


def _focus_terms(*chunks: str, max_terms: int = 12) -> list[str]:
    tokens: list[str] = []
    for chunk in chunks:
        for t in re.findall(r"[a-z0-9]{4,}", str(chunk or "").lower()):
            if t in _FOCUS_STOPWORDS:
                continue
            tokens.append(t)
    out: list[str] = []
    seen: set[str] = set()
    for t in tokens:
        if t in seen:
            continue
        seen.add(t)
        out.append(t)
        if len(out) >= max_terms:
            break
    return out


def _focused_evidence_subset(
    evidence: list[dict[str, Any]],
    *,
    seed_texts: list[str],
    max_items: int = 8,
) -> list[dict[str, Any]]:
    rows = [ev for ev in (evidence or []) if isinstance(ev, dict)]
    if not rows:
        return []
    terms = _focus_terms(*seed_texts, max_terms=14)
    if not terms:
        return rows[:max_items]

    scored: list[tuple[float, dict[str, Any]]] = []
    for ev in rows:
        title = str(ev.get("title", "") or "").lower()
        snippet = str(ev.get("snippet", "") or "").lower()
        signal_label = str(ev.get("signal_label", "") or ev.get("signal_type", "") or "").lower()
        evidence_kind = str(ev.get("evidence_kind", "") or "").lower()
        haystack = f"{title} {snippet} {signal_label} {evidence_kind}"
        match_score = 0.0
        for term in terms:
            if term in title:
                match_score += 3.0
            elif term in snippet:
                match_score += 2.0
            elif term in haystack:
                match_score += 1.0
        conf = float(ev.get("confidence", 50) or 50)
        weight = float(ev.get("weight", 1.0) or 1.0)
        score = match_score + (conf * 0.02) + (weight * 0.35)
        scored.append((score, ev))

    has_match = any(s > 0.0 for s, _ in scored)
    if not has_match:
        return rows[:max_items]
    scored.sort(key=lambda x: x[0], reverse=True)
    return [ev for _, ev in scored[:max_items]]


def _priority_score(
    *,
    impact_band: str,
    likelihood: str,
    evidence_strength: str,
    signal_coverage: int,
    distinct_urls: int,
) -> float:
    """
    Deterministic shared ranking:
      4*Impact + 3*Likelihood + 2*EvidenceStrength + min(3, SignalCoverage) + log(1+DistinctURLs)
    """
    i = IMPACT_SCORE.get((impact_band or "MED").upper(), 2)
    l = LIKELIHOOD_SCORE.get((likelihood or "med").lower(), 2)
    e = EVIDENCE_STRENGTH_SCORE.get((evidence_strength or "WEAK").upper(), 1)
    cov = max(0, min(3, int(signal_coverage or 0)))
    urls = max(0, int(distinct_urls or 0))
    return float((4 * i) + (3 * l) + (2 * e) + cov + math.log1p(urls))


def _sensitivity_value(level: str) -> int:
    lv = str(level or "").strip().upper()
    if lv == "HIGH":
        return 3
    if lv == "MED":
        return 2
    return 1


def _likelihood_from_plausibility(
    plausibility: int, *, signal_coverage: int, distinct_urls: int, evidence_refs_count: int
) -> str:
    p = int(max(0, min(100, plausibility)))
    if p >= 75:
        out = "high"
    elif p >= 55:
        out = "med"
    else:
        out = "low"
    if int(signal_coverage or 0) < 2 or int(distinct_urls or 0) < 2:
        if out == "high":
            out = "med"
    if int(signal_coverage or 0) == 0 or int(evidence_refs_count or 0) == 0:
        out = "low"
    return out


def _impact_from_potential(potential_impact: int, *, linked_workflow_nodes_count: int) -> str:
    p = int(max(0, min(100, potential_impact)))
    if p >= 75:
        out = "HIGH"
    elif p >= 50:
        out = "MED"
    else:
        out = "LOW"
    if int(linked_workflow_nodes_count or 0) <= 0 and out == "HIGH":
        out = "MED"
    return out


def _elevated_score(*, impact_band: str, plausibility_score: int, signal_coverage: int) -> float:
    i = IMPACT_SCORE.get((impact_band or "MED").upper(), 2) * 100.0 / 3.0
    p = float(max(0, min(100, int(plausibility_score or 0))))
    cov = float(max(0, min(3, int(signal_coverage or 0))) * 10)
    return (0.45 * i) + (0.45 * p) + (0.10 * cov)


def _elevated_sort_tuple(item: dict[str, Any]) -> tuple[int, int, int, int, int, int, int]:
    """
    Keep ordering aligned with the primary UI badges:
    Impact -> Likelihood -> Evidence strength (%) -> tie-breakers.
    """
    return (
        IMPACT_SCORE.get(str(item.get("impact_band", "MED")).upper(), 2),
        LIKELIHOOD_SCORE.get(str(item.get("likelihood", "med")).lower(), 2),
        int(item.get("confidence", 0) or 0),
        int(item.get("plausibility_score", 0) or 0),
        int(item.get("signal_coverage", 0) or 0),
        int(item.get("evidence_refs_count", 0) or 0),
        int(item.get("id", 0) or 0),
    )


def _watchlist_score(*, potential_impact_score: int, plausibility_score: int) -> float:
    imp = float(max(0, min(100, int(potential_impact_score or 0))))
    pla = float(max(0, min(100, int(plausibility_score or 0))))
    return (0.60 * imp) + (0.40 * pla)


def _cti_chips_for_risk(
    *,
    risk_type: str,
    signal_counts: dict[str, Any] | None = None,
    signal_coverage: int = 0,
) -> tuple[list[str], list[str]]:
    rt_low = str(risk_type or "").strip().lower()
    counts = signal_counts if isinstance(signal_counts, dict) else {}

    campaign_chips: list[str] = []
    mitre_chips: list[str] = []
    if rt_low in {"impersonation", "brand_abuse", "downstream_pivot", "social_trust_surface_exposure"}:
        campaign_chips.append("Impersonation opportunity")
        mitre_chips.extend(
            ["T1589 Identity Information", "T1591 Victim Org Information", "T1593 Search Open Websites/Domains"]
        )
    if int((counts or {}).get("VENDOR_CUE", 0) or 0) > 0:
        campaign_chips.append("Third-party dependency")
    if int((counts or {}).get("PROCESS_CUE", 0) or 0) > 0:
        campaign_chips.append("Workflow trust dependency")
    if int((counts or {}).get("ORG_CUE", 0) or 0) > 0:
        campaign_chips.append("Role-based trust cues")
    if int((counts or {}).get("INFRA_CUE", 0) or 0) > 0:
        campaign_chips.append("Channel/portal surface")
    if int(signal_coverage or 0) >= 3:
        campaign_chips.append("Multi-signal coverage")

    seen = set()
    campaign_chips = [x for x in campaign_chips if not (x in seen or seen.add(x))]
    seen = set()
    mitre_chips = [x for x in mitre_chips if not (x in seen or seen.add(x))]
    return campaign_chips[:6], mitre_chips[:6]


def _risk_posture_score(summary: dict[str, Any]) -> int:
    status = str(summary.get("status", "WATCHLIST")).strip().upper()
    impact_band = str(summary.get("impact_band", "MED")).strip().upper()
    plausibility = int(summary.get("plausibility_score", 0) or 0)
    confidence = int(summary.get("confidence", 0) or 0)
    impact_norm = int(round((IMPACT_SCORE.get(impact_band, 2) / 3.0) * 100))

    base = (0.45 * impact_norm) + (0.35 * plausibility) + (0.20 * confidence)
    status_factor = 1.0
    if status == "WATCHLIST":
        status_factor = 0.7
    elif status == "BASELINE":
        status_factor = 0.35
    return int(max(0, min(100, round(base * status_factor))))


def _overall_risk_score(rows: list[dict[str, Any]]) -> int:
    if not rows:
        return 0
    valid_rows = [r for r in rows if isinstance(r, dict)]
    if not valid_rows:
        return 0
    status_weight = {
        "ELEVATED": 1.0,
        "WATCHLIST": 0.6,
        "BASELINE": 0.3,
    }
    impact_weight = {
        "HIGH": 1.25,
        "MED": 1.0,
        "LOW": 0.75,
    }
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


def _find_previous_assessment(db: Session, assessment: Assessment) -> Assessment | None:
    current_id = int(assessment.id)
    domain_now = " ".join(str(assessment.domain or "").split()).strip().lower()
    company_now = " ".join(str(assessment.company_name or "").split()).strip().lower()
    if not domain_now and not company_now:
        return None

    candidates = (
        db.execute(select(Assessment).where(Assessment.id != current_id).order_by(Assessment.created_at.desc()))
        .scalars()
        .all()
    )
    for cand in candidates:
        cand_domain = " ".join(str(cand.domain or "").split()).strip().lower()
        cand_company = " ".join(str(cand.company_name or "").split()).strip().lower()
        if (domain_now and cand_domain == domain_now) or (company_now and cand_company == company_now):
            return cand
    return None


def _bundle_tooltip(bundle_type: str) -> str:
    mapping = {
        "IDENTITY_SIGNALS": "Public contact channels and staff/team cues that influence where requests are routed.",
        "INFORMAL_WORKFLOW": "Public workflow language that can make high-impact requests more predictable.",
        "CHANNEL_AMBIGUITY": "Multiple channels (web, social, email) without a single authoritative registry can increase confusion.",
        "VENDOR_DEPENDENCY": "Vendor and platform cues that shape support/billing/onboarding workflows.",
        "INFRA_ENDPOINTS": "Public infra endpoints (support/status/portal) that can be mistaken as official.",
        "EXTERNAL_VISIBILITY": "Press/news visibility that can increase urgency and inbound volume.",
    }
    return mapping.get(bundle_type, "Supporting public signals.")


def _bundle_icon(bundle_type: str) -> str:
    mapping = {
        "IDENTITY_SIGNALS": "id-card",
        "INFORMAL_WORKFLOW": "clipboard-list",
        "CHANNEL_AMBIGUITY": "shuffle",
        "VENDOR_DEPENDENCY": "plug",
        "INFRA_ENDPOINTS": "server",
        "EXTERNAL_VISIBILITY": "newspaper",
    }
    return mapping.get(bundle_type, "sparkles")


def _build_bundles_for_risk(
    *,
    evidence_valid: list[dict[str, Any]],
    counts: dict[str, int],
    process_flags: dict | None,
) -> list[dict[str, Any]]:
    present = {k for k, v in (counts or {}).items() if int(v or 0) > 0}
    by_signal: dict[str, list[dict[str, Any]]] = {}
    for ev in evidence_valid or []:
        st = str(ev.get("signal_type", "")).strip().upper()
        by_signal.setdefault(st, []).append(ev)

    bundles: list[dict[str, Any]] = []

    identity_items = [*by_signal.get("CONTACT_CHANNEL", []), *by_signal.get("ORG_CUE", [])]
    if identity_items:
        title = "Public contact channels"
        if by_signal.get("ORG_CUE"):
            title = "Public staff & contact channels"
        bundles.append(
            {
                "id": "identity",
                "title": title,
                "bundle_type": "IDENTITY_SIGNALS",
                "signal_types": [k for k in ("CONTACT_CHANNEL", "ORG_CUE") if k in present],
                "items": identity_items,
            }
        )

    workflow_items = [*by_signal.get("PROCESS_CUE", [])]
    if workflow_items:
        sens = (process_flags or {}).get("data_sens_kinds") if isinstance(process_flags, dict) else []
        sens_set = {str(x).upper() for x in (sens or [])}
        if "BOOKING_PAYMENT" in sens_set:
            title = "Booking and payment handling cues"
        elif "CREDENTIALS" in sens_set:
            title = "Account and credential handling cues"
        else:
            title = "Workflow handling cues"
        bundles.append(
            {
                "id": "workflow",
                "title": title,
                "bundle_type": "INFORMAL_WORKFLOW",
                "signal_types": ["PROCESS_CUE"] if "PROCESS_CUE" in present else [],
                "items": workflow_items,
            }
        )

    channel_items = [*by_signal.get("SOCIAL_TRUST_NODE", []), *by_signal.get("CONTACT_CHANNEL", [])]
    trust_friction = (
        bool((process_flags or {}).get("trust_friction", False)) if isinstance(process_flags, dict) else False
    )
    if channel_items and (
        "SOCIAL_TRUST_NODE" in present or (counts or {}).get("CONTACT_CHANNEL", 0) >= 2 or trust_friction
    ):
        bundles.append(
            {
                "id": "ambiguity",
                "title": "Channel ambiguity",
                "bundle_type": "CHANNEL_AMBIGUITY",
                "signal_types": [k for k in ("SOCIAL_TRUST_NODE", "CONTACT_CHANNEL") if k in present],
                "items": channel_items,
            }
        )

    vendor_items = [
        ev
        for ev in (evidence_valid or [])
        if isinstance(ev, dict)
        and str(ev.get("signal_type", "")).strip().upper() == "VENDOR_CUE"
        and str(ev.get("evidence_kind", "UNKNOWN")).strip().upper() == "WORKFLOW_VENDOR"
        and (not bool(ev.get("is_boilerplate", False)))
        and float(ev.get("weight", 1.0) or 1.0) >= 0.5
    ]
    if vendor_items:
        bundles.append(
            {
                "id": "vendor",
                "title": "Vendor & platform cues",
                "bundle_type": "VENDOR_DEPENDENCY",
                "signal_types": ["VENDOR_CUE"],
                "items": vendor_items,
            }
        )

    attention_items = [*by_signal.get("EXTERNAL_ATTENTION", [])]
    if attention_items:
        bundles.append(
            {
                "id": "visibility",
                "title": "Public visibility cues",
                "bundle_type": "EXTERNAL_VISIBILITY",
                "signal_types": ["EXTERNAL_ATTENTION"] if "EXTERNAL_ATTENTION" in present else [],
                "items": attention_items,
            }
        )

    if by_signal.get("INFRA_CUE") and not any(b.get("bundle_type") == "VENDOR_DEPENDENCY" for b in bundles):
        infra_items = [*by_signal.get("INFRA_CUE", [])]
        bundles.append(
            {
                "id": "infra",
                "title": "Support/portal endpoints",
                "bundle_type": "INFRA_ENDPOINTS",
                "signal_types": ["INFRA_CUE"] if "INFRA_CUE" in present else [],
                "items": infra_items,
            }
        )

    normalized: list[dict[str, Any]] = []
    for b in bundles:
        deduped = _dedupe_evidence(list(b.get("items") or []))
        total_occ = sum(int(x.get("occurrences", 1) or 1) for x in deduped) or len(deduped)
        bundle_type = str(b.get("bundle_type", ""))
        bundle_title = str(b.get("title", ""))
        display = map_bundle_display(
            bundle_type=bundle_type,
            bundle_title=bundle_title,
            signal_types=list(b.get("signal_types") or []),
        )
        normalized.append(
            {
                "id": str(b.get("id", "")),
                "title": bundle_title,
                "display_name": str(display.get("display_name", "")).strip() or bundle_title,
                "short_label": str(display.get("short_label", "")).strip() or bundle_title,
                "internal_name": bundle_type,
                "bundle_type": bundle_type,
                "icon": _bundle_icon(bundle_type),
                "tooltip": _bundle_tooltip(bundle_type),
                "item_count": int(total_occ),
                "signal_types": list(b.get("signal_types") or []),
                "evidence": deduped[:10],
            }
        )
    return normalized


def _pick_recipe_bundles(bundles: list[dict[str, Any]]) -> list[dict[str, Any]]:
    priority = {
        "INFORMAL_WORKFLOW": 1,
        "VENDOR_DEPENDENCY": 2,
        "CHANNEL_AMBIGUITY": 3,
        "IDENTITY_SIGNALS": 4,
        "INFRA_ENDPOINTS": 5,
        "EXTERNAL_VISIBILITY": 6,
    }
    items = sorted(
        bundles or [],
        key=lambda b: (priority.get(str(b.get("bundle_type", "")), 99), -int(b.get("item_count", 0) or 0)),
    )
    out: list[dict[str, Any]] = []
    seen_types: set[str] = set()
    for b in items:
        btype = str(b.get("bundle_type", ""))
        if not btype or btype in seen_types:
            continue
        if int(b.get("item_count", 0) or 0) <= 0:
            continue
        out.append(b)
        seen_types.add(btype)
        if len(out) >= 3:
            break
    return out


def _confirm_deny_points(*, meta: dict, process_flags: dict | None) -> tuple[list[str], list[str]]:
    counts = meta.get("signal_counts") if isinstance(meta.get("signal_counts"), dict) else {}
    confirm: list[str] = []
    deny: list[str] = []

    trust_friction = bool((process_flags or {}).get("trust_friction", False))
    sens_kinds = process_flags.get("data_sens_kinds", []) if isinstance(process_flags, dict) else []
    has_cred = any(str(x).upper() == "CREDENTIALS" for x in (sens_kinds or []))
    has_booking = any(str(x).upper() == "BOOKING_PAYMENT" for x in (sens_kinds or []))
    has_social = int((counts or {}).get("SOCIAL_TRUST_NODE", 0) or 0) > 0

    social_contact_in_bio = bool((process_flags or {}).get("social_contact_in_bio", False))
    social_dm_workflow = bool((process_flags or {}).get("social_dm_workflow", False))
    social_to_booking = bool((process_flags or {}).get("social_to_booking", False))
    social_verified = bool((process_flags or {}).get("social_verified", False))

    if int((counts or {}).get("CONTACT_CHANNEL", 0) or 0) >= 2:
        confirm.append("Multiple external contact channels are visible in the indexed corpus.")
    if int((counts or {}).get("VENDOR_CUE", 0) or 0) > 0:
        confirm.append("Public artifacts contain third-party vendor/tooling cues tied to external workflows.")
    if int((counts or {}).get("PROCESS_CUE", 0) or 0) > 0 and int((counts or {}).get("CONTACT_CHANNEL", 0) or 0) > 0:
        confirm.append("Workflow language and external channels co-occur (higher chance of trust-channel confusion).")
    if has_social and social_contact_in_bio:
        confirm.append("Contact details are exposed on social profile(s) (email/phone in bio).")
    if has_social and social_dm_workflow:
        confirm.append("A social profile advertises DM-based contact handling.")
    if has_social and social_to_booking:
        confirm.append("Social profiles link into booking/payment flows, increasing reliance on channel verification.")
    if has_cred:
        confirm.append("Credential/account handling is referenced alongside externally accessible support channels.")
    if has_booking:
        confirm.append("Booking/billing/payment workflow references appear alongside externally accessible channels.")
    if trust_friction:
        confirm.append(
            "No clear public official-channel verification or anti-phishing guidance was found in the indexed corpus."
        )

    deny.append("A centralized, signed registry of official contact channels is published and consistently referenced.")
    deny.append(
        "A clear statement exists and is visible: the organization will never request passwords or login details."
    )
    if has_social and (social_dm_workflow or social_to_booking):
        deny.append(
            "Clear guidance exists: sensitive actions are never handled via DM; booking/payment changes require verified channels."
        )
    if has_social and social_verified:
        deny.append("Verified social accounts are used as trust anchors and consistently linked from official pages.")
    if has_booking or int((counts or {}).get("PROCESS_CUE", 0) or 0) > 0:
        deny.append("Sensitive booking/payment/billing changes require out-of-band verification and approvals.")
    if has_cred:
        deny.append("Credential and account recovery actions are restricted to secure portals (not email/chat).")

    return [x for x in confirm if x][:4], [x for x in deny if x][:4]


def _control_points_from_actions(actions: list[str]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for idx, action in enumerate([a for a in (actions or []) if str(a or "").strip()][:8]):
        text = " ".join(str(action).split()).strip()
        if not text:
            continue

        lowered = text.lower()
        effort = "MED"
        reduction = "MED"
        reason = "This control reduces ambiguity and increases verification in high-impact workflows."

        if any(k in lowered for k in ("publish", "registry", "official-channel")):
            effort = "LOW"
            reduction = "HIGH"
            reason = "Breaks channel confusion by making official channels explicit and easy to verify."
        if any(k in lowered for k in ("out-of-band", "verification", "approvals", "approve")):
            effort = "MED"
            reduction = "HIGH"
            reason = "Interrupts sensitive changes by requiring a known-good verification step."
        if any(k in lowered for k in ("secure portal", "portal", "prefer secure")):
            effort = "HIGH"
            reduction = "HIGH"
            reason = "Moves sensitive requests away from external channels into controlled flows."
        if any(k in lowered for k in ("never request passwords", "never ask", "password")):
            effort = "LOW"
            reduction = "MED"
            reason = "Reduces credential-handling confusion by setting clear expectations."

        out.append(
            {
                "id": f"cp-{idx + 1}",
                "title": text[:220],
                "effort": effort,
                "expected_reduction": reduction,
                "tooltip_reason": reason,
            }
        )
        if len(out) >= 5:
            break
    return out


def _evidence_strength_label(coverage: str) -> str:
    key = (coverage or "WEAK").upper()
    if key == "STRONG":
        return "STRONG"
    if key == "OK":
        return "OK"
    return "WEAK"


def _limited_evidence_placeholder() -> list[dict[str, Any]]:
    return [
        {
            "url": "",
            "canonical_url": "",
            "domain": "",
            "title": "Limited evidence",
            "snippet": "No non-boilerplate evidence passed quality filtering for this view.",
            "doc_id": None,
            "doc_link": "",
            "doc_title": "",
            "doc_type": "",
            "confidence": 0,
            "signal_type": "UNCLASSIFIED",
            "signal_label": "Unclassified",
            "signal_icon": "alert-circle",
            "is_boilerplate": False,
            "weight": 0.0,
            "evidence_kind": "UNKNOWN",
            "quality_tier": "LOW",
            "rationale": "No evidence met quality thresholds",
        }
    ]


def get_ranked_risks(
    db: Session,
    assessment: Assessment,
    *,
    status: str = "ELEVATED",
    include_baseline: bool = False,
    risk_type: str = "",
    impact: str = "",
    q: str = "",
) -> dict[str, Any]:
    """
    Shared source of truth for risk ordering used by both Overview and Risks page.
    """
    assessment_id = int(assessment.id)
    hypotheses = (
        db.execute(
            select(Hypothesis)
            .where(Hypothesis.assessment_id == assessment_id)
            .order_by(Hypothesis.severity.desc(), Hypothesis.created_at.desc(), Hypothesis.id.desc())
        )
        .scalars()
        .all()
    )

    doc_ids: set[int] = set()
    doc_urls: set[str] = set()
    for h in hypotheses:
        refs = from_json(h.evidence_refs_json or "[]", [])
        if not isinstance(refs, list):
            continue
        for ref in refs:
            if not isinstance(ref, dict):
                continue
            did = ref.get("doc_id")
            if str(did).isdigit():
                doc_ids.add(int(did))
            u = str(ref.get("url", "")).strip()
            if u:
                doc_urls.add(u)

    docs_by_id: dict[int, Document] = {}
    docs_by_url: dict[str, Document] = {}
    (
        connectors_by_url,
        indicator_hints_by_url,
        signal_hints_by_type,
        signal_connectors_by_type,
    ) = _evidence_context_maps_for_assessment(db, assessment_id)
    if doc_ids:
        for d in db.execute(select(Document).where(Document.id.in_(list(doc_ids)))).scalars().all():
            docs_by_id[int(d.id)] = d
    if doc_urls:
        for d in (
            db.execute(
                select(Document).where(Document.assessment_id == assessment_id, Document.url.in_(list(doc_urls)))
            )
            .scalars()
            .all()
        ):
            docs_by_url[str(d.url)] = d

    workflow_nodes = (
        db.execute(
            select(WorkflowNode)
            .where(WorkflowNode.assessment_id == assessment_id)
            .order_by(WorkflowNode.trust_friction_score.desc(), WorkflowNode.created_at.desc(), WorkflowNode.id.desc())
        )
        .scalars()
        .all()
    )

    evidence_sets: dict[str, list[dict[str, Any]]] = {}
    risk_summaries: list[dict[str, Any]] = []
    hypotheses_by_id: dict[int, Hypothesis] = {}

    for h in hypotheses:
        hypotheses_by_id[int(h.id)] = h

        parsed = _parse_signal_counts_blob(h.signal_counts_json or "{}")
        refs = from_json(h.evidence_refs_json or "[]", [])
        if not isinstance(refs, list):
            refs = []
        evidence_all = _normalize_evidence_refs(
            refs,
            docs_by_id=docs_by_id,
            docs_by_url=docs_by_url,
            query_id=str(h.query_id or "")[:16],
            connectors_by_url=connectors_by_url,
            indicator_hints_by_url=indicator_hints_by_url,
        )

        evidence_valid = [
            ev
            for ev in evidence_all
            if isinstance(ev, dict)
            and (not bool(ev.get("is_boilerplate", False)))
            and float(ev.get("weight", 1.0) or 1.0) >= 0.5
        ]
        risk_ev_dedup = _dedupe_evidence(evidence_valid)[:12]
        evidence_sets[f"risk:{h.id}"] = risk_ev_dedup

        signal_types = {
            str(ev.get("signal_type", "")).strip().upper()
            for ev in (risk_ev_dedup or [])
            if str(ev.get("signal_type", "")).strip()
        }
        distinct_urls = {
            str(ev.get("canonical_url", "")).strip()
            for ev in (risk_ev_dedup or [])
            if str(ev.get("canonical_url", "")).strip()
        }
        signal_coverage = len(signal_types)
        evidence_refs_count = len(distinct_urls)
        if evidence_refs_count > 0 and signal_coverage == 0:
            signal_coverage = 1

        base_avg = 0
        if evidence_all:
            base_avg = int(sum(int(x.get("confidence", 50) or 50) for x in evidence_all) / len(evidence_all))

        ev_items = [
            {
                "url": str(x.get("url", "")),
                "snippet": str(x.get("snippet", "")),
                "confidence": int(x.get("confidence", 50) or 50),
                "signal_type": str(x.get("signal_type", "")),
                "query_id": str(h.query_id or ""),
                "is_boilerplate": bool(x.get("is_boilerplate", False)),
                "weight": float(x.get("weight", 1.0) or 1.0),
                "quality_tier": str(x.get("quality_tier", "LOW")),
                "evidence_kind": str(x.get("evidence_kind", "UNKNOWN")),
            }
            for x in evidence_all
            if isinstance(x, dict)
        ]
        calc_conf, meta = compute_hypothesis_confidence(
            ev_items,
            base_avg=base_avg,
            sector=str(assessment.sector or ""),
            risk_type=str(h.risk_type or ""),
        )
        conf = max(1, min(100, int(calc_conf)))
        evidence_strength_pct = int(conf)

        counts = meta.get("signal_counts") if isinstance(meta.get("signal_counts"), dict) else {}
        if not counts and parsed.counts:
            counts = dict(parsed.counts)
        meta["signal_counts"] = counts or {}
        meta["signal_diversity_count"] = int(signal_coverage)

        if isinstance(parsed.process_flags, dict):
            if "data_sens_kinds" in parsed.process_flags and "data_sens_kinds" not in meta:
                meta["data_sens_kinds"] = parsed.process_flags.get("data_sens_kinds")
            if "trust_friction" in parsed.process_flags and "trust_friction" not in meta:
                meta["trust_friction"] = parsed.process_flags.get("trust_friction")

        coverage = coverage_label_from_signals(meta)
        if parsed.baseline_exposure:
            coverage = "WEAK"
        evidence_strength = _evidence_strength_label(coverage)
        evidence_quality = _evidence_quality_label(meta)

        primary_risk_type = str(getattr(h, "primary_risk_type", "") or "").strip()
        outcome = _risk_outcome_label(
            str(h.risk_type or ""),
            sector=str(assessment.sector or ""),
            process_flags=parsed.process_flags,
        )
        title = _risk_display_name(primary_risk_type=primary_risk_type, fallback_outcome=outcome)

        timeline = from_json(h.timeline_json or "[]", [])
        if not isinstance(timeline, list) or not timeline:
            meta["risk_hint"] = str(h.title or "")
            timeline = timeline_for_risk(str(h.risk_type or ""), meta)

        missing_signals = from_json(h.missing_signals_json or "[]", [])
        if not isinstance(missing_signals, list):
            missing_signals = []
        missing_signal_types_count = len({str(x).strip().lower() for x in missing_signals if str(x).strip()})

        # Repetition/policy checks for plausibility calibration.
        url_counts: dict[str, int] = {}
        for ev in evidence_valid:
            cu = str(ev.get("canonical_url", "")).strip()
            if not cu:
                continue
            url_counts[cu] = int(url_counts.get(cu, 0) or 0) + 1
        total_ev = sum(url_counts.values())
        top_ev = max(url_counts.values()) if url_counts else 0
        repetition_ratio = (float(top_ev) / float(total_ev)) if total_ev > 0 else 0.0
        repetition_penalty = 1 if repetition_ratio > 0.60 else 0

        def _is_policy_like(ev: dict[str, Any]) -> bool:
            u = str(ev.get("url", "")).lower()
            dt = str(ev.get("doc_type", "")).lower()
            t = str(ev.get("title", "")).lower()
            return (
                ("policy" in dt)
                or any(k in u for k in ("/privacy", "/policy", "/terms", "/cookie"))
                or any(k in t for k in ("privacy", "policy", "terms"))
            )

        policy_only_penalty = 1 if evidence_valid and all(_is_policy_like(ev) for ev in evidence_valid) else 0

        # Build bundles for all risks (not just elevated).
        risk_bundles = _build_bundles_for_risk(
            evidence_valid=risk_ev_dedup,
            counts=counts or {},
            process_flags=parsed.process_flags,
        )
        high_conf_bundle = any(
            (
                (len(list(b.get("evidence") or [])) > 0)
                and (
                    sum(int(ev.get("confidence", 50) or 50) for ev in list(b.get("evidence") or []))
                    / max(1, len(list(b.get("evidence") or [])))
                )
                >= 70
            )
            for b in (risk_bundles or [])
        )

        plausibility_score = int(
            max(
                0,
                min(
                    100,
                    round(
                        (0.40 * float(evidence_strength_pct))
                        + (12 * min(3, int(signal_coverage or 0)))
                        + (10 * min(3, int(evidence_refs_count or 0)))
                        - (12 * int(repetition_penalty))
                        - (10 * int(policy_only_penalty))
                        + (8 if high_conf_bundle else 0)
                    ),
                ),
            )
        )

        # Link workflow nodes to risk (explicit link or URL overlap).
        linked_nodes: list[WorkflowNode] = []
        explicit_node_id = (parsed.extras or {}).get("__workflow_node_id__")
        if str(explicit_node_id).isdigit():
            maybe = next((wn for wn in workflow_nodes if int(wn.id) == int(explicit_node_id)), None)
            if maybe:
                linked_nodes.append(maybe)
        if distinct_urls:
            for wn in workflow_nodes:
                if wn in linked_nodes:
                    continue
                wrefs = from_json(wn.evidence_refs_json or "[]", [])
                if not isinstance(wrefs, list):
                    continue
                overlap = False
                for wr in wrefs:
                    if not isinstance(wr, dict):
                        continue
                    wu = _canonical_url(str(wr.get("url", "")))
                    if wu and wu in distinct_urls:
                        overlap = True
                        break
                if overlap:
                    linked_nodes.append(wn)

        max_sens = 1
        max_tf = 0
        avg_tf = 0.0
        if linked_nodes:
            sens_vals = [_sensitivity_value(str(wn.sensitivity_level or "LOW")) for wn in linked_nodes]
            tf_vals = [max(0, min(100, int(wn.trust_friction_score or 0))) for wn in linked_nodes]
            max_sens = max(sens_vals) if sens_vals else 1
            max_tf = max(tf_vals) if tf_vals else 0
            avg_tf = (sum(tf_vals) / len(tf_vals)) if tf_vals else 0.0
        else:
            # Best-effort fallback from process flags when workflow map is sparse.
            pflags = parsed.process_flags if isinstance(parsed.process_flags, dict) else {}
            sens_kinds = {str(x).upper() for x in (pflags.get("data_sens_kinds") or [])}
            if "BOOKING_PAYMENT" in sens_kinds or "CREDENTIALS" in sens_kinds:
                max_sens = 3
            elif sens_kinds:
                max_sens = 2
            max_tf = 45 if bool(pflags.get("trust_friction", False)) else 0
            avg_tf = float(max_tf)

        wf_text = " ".join(
            f"{str(getattr(wn, 'workflow_kind', '') or '')} {str(getattr(wn, 'title', '') or '')}".strip()
            for wn in linked_nodes
        ).lower()
        evidence_workflow_text = " ".join(
            f"{str(ev.get('title', '') or '')} {str(ev.get('snippet', '') or '')} {str(ev.get('url', '') or '')}".strip()
            for ev in (risk_ev_dedup or [])
        ).lower()
        risk_text = " ".join(
            [
                str(getattr(h, "title", "") or ""),
                str(getattr(h, "description", "") or ""),
                str(getattr(h, "impact_rationale", "") or ""),
            ]
        ).lower()
        combined_workflow_text = " ".join([wf_text, evidence_workflow_text, risk_text]).strip()
        pflags = parsed.process_flags if isinstance(parsed.process_flags, dict) else {}
        high_impact_workflow = any(
            k in combined_workflow_text
            for k in (
                "billing",
                "payment",
                "account recovery",
                "password reset",
                "booking change",
                "reservation change",
                "invoice",
                "booking modification",
                "chargeback",
                "refund",
                "account unlock",
                "loyalty account",
                "reservation update",
                "reservation cancellation",
            )
        ) or bool(
            (pflags.get("data_sens_kinds") or [])
            and any(str(x).upper() in {"BOOKING_PAYMENT", "CREDENTIALS"} for x in (pflags.get("data_sens_kinds") or []))
        )
        if high_impact_workflow and max_sens < 2:
            max_sens = 2

        potential_impact_score = int(
            max(
                0,
                min(
                    100,
                    round(
                        (20 * int(max_sens))
                        + (0.6 * float(max_tf if max_tf > 0 else avg_tf))
                        + (10 if high_impact_workflow else 0)
                    ),
                ),
            )
        )

        likelihood = _likelihood_from_plausibility(
            plausibility_score,
            signal_coverage=int(signal_coverage),
            distinct_urls=int(evidence_refs_count),
            evidence_refs_count=int(evidence_refs_count),
        )
        impact_band = _impact_from_potential(
            potential_impact_score,
            linked_workflow_nodes_count=len(linked_nodes),
        )

        only_baseline_signals = bool(signal_types) and signal_types.issubset({"CONTACT_CHANNEL", "EXTERNAL_ATTENTION"})
        generic_contact_policy_only = bool(evidence_valid) and all(
            (_is_policy_like(ev) or str(ev.get("signal_type", "")).strip().upper() == "CONTACT_CHANNEL")
            for ev in evidence_valid
        )
        if (
            bool(getattr(h, "baseline_tag", False))
            or bool(parsed.baseline_exposure)
            or (generic_contact_policy_only and len(linked_nodes) == 0)
            or only_baseline_signals
        ):
            status_value = "BASELINE"
        elif (
            plausibility_score >= 55
            and int(signal_coverage) >= MIN_SIGNAL_COVERAGE_ELEVATED
            and int(evidence_refs_count) >= MIN_EVIDENCE_REFS_ELEVATED
            and int(evidence_strength_pct) >= MIN_EVIDENCE_STRENGTH_ELEVATED
        ):
            status_value = "ELEVATED"
        else:
            status_value = "WATCHLIST"

        missing_gate_reasons: list[str] = []
        if status_value == "WATCHLIST":
            if plausibility_score < 55:
                missing_gate_reasons.append("Low plausibility")
            if signal_coverage < MIN_SIGNAL_COVERAGE_ELEVATED:
                missing_gate_reasons.append("Low coverage")
            if evidence_refs_count < MIN_EVIDENCE_REFS_ELEVATED:
                missing_gate_reasons.append("Few sources")
            if evidence_strength_pct < MIN_EVIDENCE_STRENGTH_ELEVATED:
                missing_gate_reasons.append("Weak evidence")

        primary_low = primary_risk_type.strip().lower()
        impact_value = IMPACT_SCORE.get((impact_band or "MED").upper(), 2)
        likelihood_value = LIKELIHOOD_SCORE.get((likelihood or "med").lower(), 2)
        watch_investigation_bonus = (
            1
            if primary_low
            in {
                "account takeover vector",
                "payment fraud",
                "invoice diversion",
            }
            else 0
        )
        watch_score = float(
            (3 * impact_value)
            + (2 * likelihood_value)
            + (2 * int(missing_signal_types_count))
            + watch_investigation_bonus
        )
        watchlist_rank_score = _watchlist_score(
            potential_impact_score=potential_impact_score,
            plausibility_score=plausibility_score,
        )
        elevated_rank_score = _elevated_score(
            impact_band=impact_band,
            plausibility_score=plausibility_score,
            signal_coverage=int(signal_coverage),
        )

        summary = {
            "id": int(h.id),
            "risk_type": str(h.risk_type or "other"),
            "primary_risk_type": primary_risk_type,
            "risk_vector_summary": str(getattr(h, "risk_vector_summary", "") or "").strip(),
            "baseline_tag": bool(getattr(h, "baseline_tag", False)),
            "status": status_value,
            "title": title,
            "why_matters": _first_sentence(str(h.impact_rationale or h.description or ""), max_chars=180)
            or "Open for evidence and defensive controls.",
            "scenario_url": f"/assessments/{assessment_id}/risks/{h.id}",
            "likelihood": likelihood,
            "impact_band": impact_band,
            "evidence_strength": evidence_strength,
            "evidence_strength_tooltip": _evidence_strength_tooltip(evidence_strength),
            "confidence": int(evidence_strength_pct),
            "plausibility_score": int(plausibility_score),
            "potential_impact_score": int(potential_impact_score),
            "signal_diversity_count": int(signal_coverage),
            "signal_coverage": int(signal_coverage),
            "evidence_refs_count": int(evidence_refs_count),
            "distinct_urls_count": int(evidence_refs_count),
            "baseline_exposure": bool(parsed.baseline_exposure),
            "missing_signal_types_count": int(missing_signal_types_count),
            "missing_gate_reasons": missing_gate_reasons[:3],
            "needs_review": bool(status_value == "WATCHLIST"),
            "linked_workflow_nodes_count": int(len(linked_nodes)),
            "has_high_impact_workflow": bool(high_impact_workflow),
            "priority_score": _priority_score(
                impact_band=impact_band,
                likelihood=likelihood,
                evidence_strength=evidence_strength,
                signal_coverage=int(signal_coverage),
                distinct_urls=int(evidence_refs_count),
            ),
            "score_elevated": float(elevated_rank_score),
            "score_watchlist": float(watchlist_rank_score),
            "watch_score": watch_score,
            "evidence_set_id": f"risk:{h.id}",
            "timeline": timeline[:7] if isinstance(timeline, list) else [],
            "defensive_actions": from_json(h.defensive_actions_json or "[]", []),
            "assumptions": from_json(h.assumptions_json or "[]", []),
            "gaps_to_verify": from_json(h.gaps_to_verify_json or "[]", []),
            "process_flags": parsed.process_flags,
            "recipe_bundles": [
                {
                    "id": str(b.get("id", "")),
                    "title": str(b.get("title", "")),
                    "bundle_type": str(b.get("bundle_type", "")),
                    "item_count": int(b.get("item_count", 0) or 0),
                }
                for b in (risk_bundles or [])
            ],
            "confirm_deny": _confirm_deny_points(
                meta={"signal_counts": dict(counts or {})}, process_flags=parsed.process_flags
            ),
            "meta": {
                "signal_counts": counts,
                "evidence_quality": evidence_quality,
            },
        }
        target_signals = [k for k, v in (counts or {}).items() if int(v or 0) > 0 and k in SIGNAL_TYPES]
        if not target_signals:
            target_signals = list(signal_types)
        supplemental_hints: list[str] = []
        supplemental_connectors_set: set[str] = set()
        for st in target_signals:
            for hint in signal_hints_by_type.get(st, []):
                line = " ".join(str(hint or "").split()).strip()
                if line and line not in supplemental_hints:
                    supplemental_hints.append(line)
            supplemental_connectors_set.update(signal_connectors_by_type.get(st, set()))
        supplemental_hints.sort(key=lambda x: (_hint_priority(x), len(x)))
        summary["reasoning"] = _reasoning_block_for_risk(
            risk=summary,
            evidence=risk_ev_dedup,
            recipe_bundles=risk_bundles,
            risk_vector_summary=str(summary.get("risk_vector_summary", "")),
            supplemental_hints=supplemental_hints[:10],
            supplemental_connectors=sorted(list(supplemental_connectors_set), key=_connector_sort_key)[:5],
        )
        risk_summaries.append(summary)

    by_status: dict[str, list[dict[str, Any]]] = {"ELEVATED": [], "WATCHLIST": [], "BASELINE": []}
    for r in risk_summaries:
        st = str(r.get("status", "WATCHLIST")).upper()
        if st not in by_status:
            st = "WATCHLIST"
        by_status[st].append(r)

    by_status["ELEVATED"].sort(key=_elevated_sort_tuple, reverse=True)
    by_status["WATCHLIST"].sort(
        key=lambda x: (
            float(x.get("score_watchlist", 0.0)),
            int(x.get("confidence", 0) or 0),
            int(x.get("id", 0) or 0),
        ),
        reverse=True,
    )
    by_status["BASELINE"].sort(
        key=lambda x: (
            int(x.get("confidence", 0) or 0),
            int(x.get("signal_coverage", 0) or 0),
            int(x.get("id", 0) or 0),
        ),
        reverse=True,
    )

    # Optional compatibility mode: include baseline alongside elevated in the main tab.
    status_tab = str(status or "ELEVATED").strip().upper()
    if status_tab not in RISK_STATUS_VALUES:
        status_tab = "ELEVATED"
    tab_rows = list(by_status[status_tab])
    if bool(include_baseline) and status_tab == "ELEVATED":
        tab_rows = tab_rows + list(by_status["BASELINE"])

    if risk_type:
        tab_rows = [r for r in tab_rows if str(r.get("risk_type", "")) == str(risk_type)]
    if impact:
        impact_q = str(impact).strip().upper()
        tab_rows = [r for r in tab_rows if str(r.get("impact_band", "MED")).upper() == impact_q]
    if q:
        qq = str(q).strip().lower()
        tab_rows = [
            r
            for r in tab_rows
            if qq in str(r.get("title", "")).lower()
            or qq in str(r.get("why_matters", "")).lower()
            or qq in str(r.get("primary_risk_type", "")).lower()
        ]

    risk_types = sorted({str(r.get("risk_type", "other")) for r in (by_status[status_tab] or [])})

    status_counts = {k: len(v) for k, v in by_status.items()}
    all_ranked = list(by_status["ELEVATED"]) + list(by_status["WATCHLIST"]) + list(by_status["BASELINE"])

    return {
        "assessment_id": assessment_id,
        "ranked": tab_rows,
        "all_ranked": all_ranked,
        "all_unfiltered": risk_summaries,
        "ranked_by_status": by_status,
        "status_counts": status_counts,
        "status_tab": status_tab,
        "top_by_status": {k: (v[0] if v else None) for k, v in by_status.items()},
        "risk_types": risk_types,
        "evidence_sets": evidence_sets,
        "hypotheses": hypotheses,
        "hypotheses_by_id": hypotheses_by_id,
        "docs_by_id": docs_by_id,
        "docs_by_url": docs_by_url,
        "workflow_nodes": workflow_nodes,
        "connectors_by_url": connectors_by_url,
        "indicator_hints_by_url": indicator_hints_by_url,
        "signal_hints_by_type": signal_hints_by_type,
        "signal_connectors_by_type": signal_connectors_by_type,
        "include_baseline": bool(include_baseline),
    }


def get_risks_by_status(
    db: Session,
    assessment: Assessment,
    *,
    status: str = "ELEVATED",
    include_baseline: bool = False,
    risk_type: str = "",
    impact: str = "",
    q: str = "",
    limit: int | None = None,
) -> dict[str, Any]:
    """
    Shared helper used by Risks tabs and Overview previews.
    Guarantees same ranking/filtering semantics for status views.
    """
    ranked = get_ranked_risks(
        db,
        assessment,
        status=status,
        include_baseline=bool(include_baseline),
        risk_type=risk_type,
        impact=impact,
        q=q,
    )
    items = list(ranked.get("ranked") or [])
    if isinstance(limit, int) and limit > 0:
        items = items[: int(limit)]
    return {
        "assessment_id": int(assessment.id),
        "status_tab": str(ranked.get("status_tab") or "ELEVATED"),
        "status_counts": dict(ranked.get("status_counts") or {}),
        "risk_types": list(ranked.get("risk_types") or []),
        "items": items,
        "ranked": ranked,
    }


def build_overview_viewmodel(
    db: Session,
    assessment: Assessment,
    *,
    include_weak: bool = False,
    include_baseline: bool = False,
    generate_brief: bool = True,
) -> dict[str, Any]:
    """
    Build a presentation-focused view model ("Risk Story") without changing engine logic.
    Defensive-only: no offensive guidance is generated here.
    """
    settings = get_settings()
    debug_bundle_names = bool(getattr(settings, "admin_debug_risk", False))
    assessment_id = int(assessment.id)
    ranked = get_ranked_risks(
        db,
        assessment,
        include_baseline=bool(include_baseline),
        risk_type="",
        impact="",
        q="",
    )
    hypotheses = list(ranked.get("hypotheses") or [])
    hypotheses_by_id = dict(ranked.get("hypotheses_by_id") or {})
    docs_by_id = dict(ranked.get("docs_by_id") or {})
    docs_by_url = dict(ranked.get("docs_by_url") or {})
    workflow_nodes = list(ranked.get("workflow_nodes") or [])
    connectors_by_url = dict(ranked.get("connectors_by_url") or {})
    indicator_hints_by_url = dict(ranked.get("indicator_hints_by_url") or {})
    evidence_sets = dict(ranked.get("evidence_sets") or {})
    by_status = dict(ranked.get("ranked_by_status") or {})
    elevated = list(by_status.get("ELEVATED") or [])
    watchlist = list(by_status.get("WATCHLIST") or [])
    baseline = list(by_status.get("BASELINE") or [])
    status_counts = dict(
        ranked.get("status_counts")
        or {"ELEVATED": len(elevated), "WATCHLIST": len(watchlist), "BASELINE": len(baseline)}
    )
    risk_summaries = list(ranked.get("all_ranked") or (elevated + watchlist + baseline))
    top_candidate = elevated[0] if elevated else (risk_summaries[0] if risk_summaries else None)
    top_candidate_id = int(top_candidate.get("id", 0) or 0) if isinstance(top_candidate, dict) else 0

    ordered_risks: list[dict[str, Any]] = []
    mitre_codes_set: set[str] = set()
    for idx, row in enumerate(risk_summaries, start=1):
        if not isinstance(row, dict):
            continue
        counts = {}
        try:
            counts = dict((row.get("meta") or {}).get("signal_counts") or {})
        except Exception:
            counts = {}
        _, row_mitre = _cti_chips_for_risk(
            risk_type=str(row.get("risk_type", "")),
            signal_counts=counts,
            signal_coverage=int(row.get("signal_coverage", 0) or 0),
        )
        for code in row_mitre:
            mitre_codes_set.add(str(code))
        ordered_risks.append(
            {
                "rank": int(idx),
                "id": int(row.get("id", 0) or 0),
                "is_top": bool(int(row.get("id", 0) or 0) == top_candidate_id and top_candidate_id > 0),
                "title": str(row.get("title", "") or "Risk"),
                "primary_risk_type": str(row.get("primary_risk_type", "") or "").strip(),
                "status": str(row.get("status", "WATCHLIST")),
                "likelihood": str(row.get("likelihood", "med")),
                "impact_band": str(row.get("impact_band", "MED")),
                "evidence_strength": str(row.get("evidence_strength", "WEAK")),
                "confidence": int(row.get("confidence", 0) or 0),
                "summary": str(row.get("why_matters", "") or "").strip(),
                "scenario_url": str(row.get("scenario_url", "")),
                "posture_score": int(_risk_posture_score(row)),
            }
        )

    overall_score_current = int(_overall_risk_score(risk_summaries))
    prev_assessment = _find_previous_assessment(db, assessment)
    prev_score: int | None = None
    score_delta: int | None = None
    if prev_assessment is not None:
        prev_ranked = get_ranked_risks(
            db,
            prev_assessment,
            include_baseline=bool(include_baseline),
            risk_type="",
            impact="",
            q="",
        )
        prev_rows = list(prev_ranked.get("all_ranked") or [])
        prev_score = int(_overall_risk_score(prev_rows))
        score_delta = int(overall_score_current - prev_score)

    overview_metrics = {
        "detected_risks": int(len(risk_summaries)),
        "overall_score": int(overall_score_current),
        "delta_vs_previous": score_delta,
        "previous_score": prev_score,
        "previous_assessment_id": int(prev_assessment.id) if prev_assessment is not None else None,
        "previous_assessment_at": (
            prev_assessment.created_at.isoformat() if (prev_assessment is not None and prev_assessment.created_at) else ""
        ),
    }
    mitre_codes = sorted(list(mitre_codes_set))

    watchlist_preview_limit = 3
    watchlist_full = get_risks_by_status(
        db,
        assessment,
        status="WATCHLIST",
        include_baseline=bool(include_baseline),
        risk_type="",
        impact="",
        q="",
        limit=None,
    )
    watchlist_preview_data = get_risks_by_status(
        db,
        assessment,
        status="WATCHLIST",
        include_baseline=bool(include_baseline),
        risk_type="",
        impact="",
        q="",
        limit=watchlist_preview_limit,
    )
    watchlist_total_count = int(len(list(watchlist_full.get("items") or [])))
    watchlist_preview_raw = list(watchlist_preview_data.get("items") or [])
    watchlist_preview: list[dict[str, Any]] = []
    for row in watchlist_preview_raw:
        if not isinstance(row, dict):
            continue
        item = dict(row)
        rid = int(item.get("id", 0) or 0)
        ev = list(evidence_sets.get(f"risk:{rid}", []) or [])
        item["reasoning"] = (
            dict(item.get("reasoning") or {})
            if isinstance(item.get("reasoning"), dict)
            else _reasoning_block_for_risk(
                risk=item,
                evidence=ev,
                recipe_bundles=list(item.get("recipe_bundles") or []),
                risk_vector_summary=str(item.get("risk_vector_summary", "")),
            )
        )
        watchlist_preview.append(item)

    if not risk_summaries:
        return {
            "assessment_id": assessment_id,
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "topRiskVerdict": None,
            "watchlist_preview": [],
            "watchlist_total_count": 0,
            "watchlist_preview_limit": int(watchlist_preview_limit),
            "watchlistPreview": [],
            "bundles": [],
            "recipe_bundles": [],
            "storyMap": {"signals": [], "workflows": [], "scenario_cards": [], "scenario_steps": [], "impacts": []},
            "storyMapAll": {"signals": [], "workflows": [], "scenario_cards": [], "scenario_steps": [], "impacts": []},
            "controlPoints": [],
            "elevatedRisks": [],
            "evidenceSets": {},
            "details": {},
            "include_weak": bool(include_weak),
            "include_baseline": bool(include_baseline),
            "debug_bundle_names": bool(debug_bundle_names),
            "status_counts": status_counts,
            "risk_count": 0,
            "overview_metrics": overview_metrics,
            "ordered_risks": ordered_risks,
            "mitre_codes": mitre_codes,
        }

    top = elevated[0] if elevated else None
    if not top:
        return {
            "assessment_id": assessment_id,
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "topRiskVerdict": None,
            "watchlist_preview": watchlist_preview,
            "watchlist_total_count": int(watchlist_total_count),
            "watchlist_preview_limit": int(watchlist_preview_limit),
            "watchlistPreview": watchlist_preview,
            "bundles": [],
            "recipe_bundles": [],
            "storyMap": {"signals": [], "workflows": [], "scenario_cards": [], "scenario_steps": [], "impacts": []},
            "storyMapAll": {"signals": [], "workflows": [], "scenario_cards": [], "scenario_steps": [], "impacts": []},
            "controlPoints": [],
            "elevatedRisks": [],
            "highTrustFrictionNodes": [],
            "evidenceSets": evidence_sets,
            "details": {},
            "include_weak": bool(include_weak),
            "include_baseline": bool(include_baseline),
            "debug_bundle_names": bool(debug_bundle_names),
            "status_counts": status_counts,
            "risk_count": int(len(elevated)),
            "overview_metrics": overview_metrics,
            "ordered_risks": ordered_risks,
            "mitre_codes": mitre_codes,
        }

    top_id = int(top["id"])
    top_row = hypotheses_by_id.get(top_id) or next((h for h in hypotheses if int(h.id) == top_id), None)

    top_ev_valid = evidence_sets.get(f"risk:{top_id}", [])
    top_process_flags = top.get("process_flags") if isinstance(top.get("process_flags"), dict) else None

    top_counts = {}
    try:
        top_counts = dict((top.get("meta") or {}).get("signal_counts") or {})
    except Exception:
        top_counts = {}

    bundles = _build_bundles_for_risk(evidence_valid=top_ev_valid, counts=top_counts, process_flags=top_process_flags)
    recipe_bundles = _pick_recipe_bundles(bundles)

    for b in bundles:
        evidence_sets[f"bundle:{b.get('id')}"] = list(b.get("evidence") or [])

    ingredient_phrases_display = [
        str(b.get("display_name", "")).strip() or str(b.get("title", "")).strip()
        for b in recipe_bundles
        if (str(b.get("display_name", "")).strip() or str(b.get("title", "")).strip())
    ]
    primary_risk_type = ""
    try:
        primary_risk_type = str(getattr(top_row, "primary_risk_type", "") or "").strip()
    except Exception:
        primary_risk_type = ""
    if not primary_risk_type:
        primary_risk_type = _risk_outcome_label(
            str(top.get("risk_type", "")),
            sector=str(assessment.sector or ""),
            process_flags=top_process_flags,
        )
    primary_risk_type = _risk_display_name(
        primary_risk_type=primary_risk_type,
        fallback_outcome=_risk_outcome_label(
            str(top.get("risk_type", "")),
            sector=str(assessment.sector or ""),
            process_flags=top_process_flags,
        ),
    )
    verdict_line = _verdict_line(
        primary_risk_type=primary_risk_type,
        risk_type=str(top.get("risk_type", "")),
        conditions=ingredient_phrases_display,
        process_flags=top_process_flags,
    )
    if not _verdict_matches_bundles(verdict_line, ingredient_phrases_display):
        verdict_line = _verdict_line(
            primary_risk_type=primary_risk_type,
            risk_type=str(top.get("risk_type", "")),
            conditions=ingredient_phrases_display[:3],
            process_flags=top_process_flags,
        )
    convergence_count = int(top.get("signal_diversity_count", 0) or 0)

    topRiskVerdict = {
        "top_risk_id": top_id,
        "verdict_line": verdict_line,
        "primary_risk_type": primary_risk_type,
        "risk_vector_summary": str(getattr(top_row, "risk_vector_summary", "") or "").strip() if top_row else "",
        "scenario_url": str(top.get("scenario_url", "")),
        "likelihood": str(top.get("likelihood", "med")),
        "impact_band": str(top.get("impact_band", "MED")),
        "evidence_strength": str(top.get("evidence_strength", "WEAK")),
        "confidence": int(top.get("confidence", 0) or 0),
        "convergence_count": convergence_count,
        "reasoning": (
            dict(top.get("reasoning") or {})
            if isinstance(top.get("reasoning"), dict)
            else _reasoning_block_for_risk(
                risk=top,
                evidence=list(top_ev_valid or []),
                recipe_bundles=recipe_bundles,
                risk_vector_summary=str(getattr(top_row, "risk_vector_summary", "") or "").strip() if top_row else "",
            )
        ),
    }

    confirm_points: list[str] = []
    deny_points: list[str] = []
    try:
        confirm_points, deny_points = _confirm_deny_points(
            meta={"signal_counts": dict(top_counts)}, process_flags=top_process_flags
        )
    except Exception:
        confirm_points, deny_points = [], []

    actions = top.get("defensive_actions") if isinstance(top.get("defensive_actions"), list) else []
    control_points = _control_points_from_actions(list(actions or []))

    # Link workflows conservatively: explicit linkage first, otherwise evidence overlap.
    linked_workflows: list[WorkflowNode] = []
    explicit_node_id = None
    try:
        parsed_counts = _parse_signal_counts_blob(top_row.signal_counts_json or "{}") if top_row else None
        explicit_node_id = (parsed_counts.extras or {}).get("__workflow_node_id__") if parsed_counts else None
    except Exception:
        explicit_node_id = None
    if str(explicit_node_id).isdigit():
        for n in workflow_nodes:
            if int(n.id) == int(explicit_node_id):
                linked_workflows.append(n)
                break

    top_urls = {str(ev.get("canonical_url", "")) for ev in (top_ev_valid or []) if str(ev.get("canonical_url", ""))}
    if top_urls:
        for n in workflow_nodes:
            if len(linked_workflows) >= 4:
                break
            evs = from_json(n.evidence_refs_json or "[]", [])
            if not isinstance(evs, list):
                continue
            for ev in evs:
                if not isinstance(ev, dict):
                    continue
                u = _canonical_url(str(ev.get("url", "")))
                if u and u in top_urls:
                    linked_workflows.append(n)
                    break

    for n in linked_workflows[:6]:
        evs = from_json(n.evidence_refs_json or "[]", [])
        if not isinstance(evs, list):
            evs = []
        norm = _normalize_evidence_refs(
            evs,
            docs_by_id=docs_by_id,
            docs_by_url=docs_by_url,
            query_id="WF",
            connectors_by_url=connectors_by_url,
            indicator_hints_by_url=indicator_hints_by_url,
        )
        norm_valid = [
            ev
            for ev in norm
            if isinstance(ev, dict)
            and (not bool(ev.get("is_boilerplate", False)))
            and float(ev.get("weight", 1.0) or 1.0) >= 0.5
        ]
        evidence_sets[f"workflow:{n.id}"] = _dedupe_evidence(norm_valid)[:10]

    # Story map (Top Risk)
    story_signals = [
        {
            "id": f"sig:{b.get('id')}",
            "title": str(b.get("title", "")),
            "detail": f"{int(b.get('item_count', 0) or 0)} items",
            "icon": str(b.get("icon", "sparkles")),
            "evidence_set_id": f"bundle:{b.get('id')}",
            "log_q": _domain_for_url(str((b.get("evidence") or [{}])[0].get("url", ""))),
        }
        for b in bundles[:6]
    ]

    story_workflows = [
        {
            "id": f"wf:{n.id}",
            "title": str(n.title or "Workflow node"),
            "detail": f"Sensitivity {n.sensitivity_level}, Channel {n.channel_type}, Trust friction {int(n.trust_friction_score or 0)}",
            "icon": "git-branch-plus",
            "evidence_set_id": f"workflow:{n.id}",
            "log_q": "workflow",
            "trust_friction_score": int(n.trust_friction_score or 0),
        }
        for n in linked_workflows[:6]
    ]

    story_steps = []
    for step in (top.get("timeline") or [])[:6]:
        if not isinstance(step, dict):
            continue
        story_steps.append(
            {
                "id": f"step:{int(step.get('step_index', 0) or 0)}",
                "title": str(step.get("title", ""))[:80],
                "detail": str(step.get("brief", ""))[:140],
                "icon": "route",
                "evidence_set_id": f"risk:{top_id}",
                "log_q": _domain_for_url(str((top_ev_valid or [{}])[0].get("url", ""))),
                "control_point": bool(step.get("control_point", False)),
                "tooltip": str(step.get("tooltip", ""))[:280],
            }
        )

    impact_cards = [
        {
            "id": "impact:primary",
            "title": "Primary impact",
            "detail": _first_sentence(
                str(top_row.impact_rationale if top_row else top.get("why_matters", "")), max_chars=160
            ),
            "icon": "target",
            "evidence_set_id": f"risk:{top_id}",
            "log_q": _domain_for_url(str((top_ev_valid or [{}])[0].get("url", ""))),
        }
    ]
    if str(top.get("risk_type", "")).strip().lower() in {
        "downstream_pivot",
        "impersonation",
        "brand_abuse",
        "social_trust_surface_exposure",
    }:
        impact_cards.append(
            {
                "id": "impact:trust",
                "title": "Client trust",
                "detail": "Opportunity for confusion-driven requests that can damage trust and response workload.",
                "icon": "shield-alert",
                "evidence_set_id": f"risk:{top_id}",
                "log_q": _domain_for_url(str((top_ev_valid or [{}])[0].get("url", ""))),
            }
        )
    if str(top.get("impact_band")) == "HIGH":
        impact_cards.append(
            {
                "id": "impact:financial",
                "title": "Financial exposure",
                "detail": "Higher-impact workflows increase potential loss if controls fail.",
                "icon": "landmark",
                "evidence_set_id": f"risk:{top_id}",
                "log_q": _domain_for_url(str((top_ev_valid or [{}])[0].get("url", ""))),
            }
        )

    storyMap = {
        "signals": story_signals[:6],
        "workflows": story_workflows[:6],
        "scenario_steps": story_steps[:7],
        "scenario_cards": [],
        "impacts": impact_cards[:6],
    }

    elevated_list = elevated[:8]
    agg_bundle_map: dict[str, dict[str, Any]] = {}
    for r in elevated_list[:5]:
        counts = {}
        try:
            counts = dict((r.get("meta") or {}).get("signal_counts") or {})
        except Exception:
            counts = {}
        pflags = r.get("process_flags") if isinstance(r.get("process_flags"), dict) else None
        ev = evidence_sets.get(f"risk:{int(r.get('id'))}", [])
        bs = _build_bundles_for_risk(evidence_valid=ev, counts=counts, process_flags=pflags)
        for b in bs:
            key = f"{b.get('bundle_type')}|{b.get('title')}"
            existing = agg_bundle_map.get(key)
            if not existing:
                agg_bundle_map[key] = dict(b)
                continue
            merged = list(existing.get("evidence") or []) + list(b.get("evidence") or [])
            merged = _dedupe_evidence(merged)
            existing["evidence"] = merged[:10]
            existing["item_count"] = int(existing.get("item_count", 0) or 0) + int(b.get("item_count", 0) or 0)
            agg_bundle_map[key] = existing

    agg_bundles = list(agg_bundle_map.values())
    agg_bundles.sort(key=lambda b: int(b.get("item_count", 0) or 0), reverse=True)
    for b in agg_bundles[:8]:
        evidence_sets[f"bundle_all:{b.get('id')}:{b.get('bundle_type')}"] = list(b.get("evidence") or [])

    all_signals = [
        {
            "id": f"sigall:{b.get('id')}:{b.get('bundle_type')}",
            "title": str(b.get("title", "")),
            "detail": f"{int(b.get('item_count', 0) or 0)} items",
            "icon": str(b.get("icon", "sparkles")),
            "evidence_set_id": f"bundle_all:{b.get('id')}:{b.get('bundle_type')}",
            "log_q": _domain_for_url(str((b.get("evidence") or [{}])[0].get("url", ""))),
        }
        for b in agg_bundles[:6]
    ]

    all_workflows = []
    for n in workflow_nodes[:6]:
        if int(n.trust_friction_score or 0) < 60:
            continue
        evs = from_json(n.evidence_refs_json or "[]", [])
        if not isinstance(evs, list):
            evs = []
        norm = _normalize_evidence_refs(
            evs,
            docs_by_id=docs_by_id,
            docs_by_url=docs_by_url,
            query_id="WF",
            connectors_by_url=connectors_by_url,
            indicator_hints_by_url=indicator_hints_by_url,
        )
        norm_valid = [
            ev
            for ev in norm
            if isinstance(ev, dict)
            and (not bool(ev.get("is_boilerplate", False)))
            and float(ev.get("weight", 1.0) or 1.0) >= 0.5
        ]
        evidence_sets[f"workflow_all:{n.id}"] = _dedupe_evidence(norm_valid)[:10]
        all_workflows.append(
            {
                "id": f"wfAll:{n.id}",
                "title": str(n.title or "Workflow node"),
                "detail": f"Sensitivity {n.sensitivity_level}, Channel {n.channel_type}, Trust friction {int(n.trust_friction_score or 0)}",
                "icon": "git-branch-plus",
                "evidence_set_id": f"workflow_all:{n.id}",
                "log_q": "workflow",
                "trust_friction_score": int(n.trust_friction_score or 0),
            }
        )
        if len(all_workflows) >= 6:
            break

    all_scenarios = []
    for r in elevated_list[:6]:
        set_id = str(r.get("evidence_set_id", ""))
        evs = evidence_sets.get(set_id, [])
        reasoning = (
            dict(r.get("reasoning") or {})
            if isinstance(r.get("reasoning"), dict)
            else _reasoning_block_for_risk(
                risk=r,
                evidence=list(evs or []),
                recipe_bundles=list(r.get("recipe_bundles") or []),
                risk_vector_summary=str(r.get("risk_vector_summary", "")),
            )
        )
        all_scenarios.append(
            {
                "id": f"sc:{int(r.get('id'))}",
                "title": str(r.get("title", "")),
                "detail": str(r.get("why_matters", ""))[:140],
                "icon": "shield",
                "scenario_url": str(r.get("scenario_url", "")),
                "evidence_set_id": set_id,
                "log_q": _domain_for_url(str((evs or [{}])[0].get("url", ""))),
                "impact_band": str(r.get("impact_band", "MED")),
                "likelihood": str(r.get("likelihood", "med")),
                "evidence_strength": str(r.get("evidence_strength", "WEAK")),
                "reasoning": reasoning,
            }
        )

    storyMapAll = {
        "signals": all_signals[:6],
        "workflows": all_workflows[:6],
        "scenario_cards": all_scenarios[:6],
        "scenario_steps": [],
        "impacts": [],
    }

    exec_brief = ""
    if generate_brief and top_row:
        try:
            prt = (
                str(getattr(top_row, "primary_risk_type", "") or "").strip()
                or str(topRiskVerdict.get("primary_risk_type", "") or "").strip()
            )
            vector = str(getattr(top_row, "risk_vector_summary", "") or "").strip()
            conditions = [str(b.get("title", "")).strip() for b in recipe_bundles if str(b.get("title", "")).strip()][
                :3
            ]
            brief_inp = BriefInput(
                assessment_id=assessment_id,
                risk_kind="scenario",
                risk_id=int(top_row.id),
                title=str(top_row.title or top.get("title", "")),
                risk_type=str(top_row.risk_type or ""),
                primary_risk_type=prt,
                risk_vector_summary=vector,
                conditions=conditions,
                signal_bundles=[
                    {"title": str(b.get("title", "")), "item_count": int(b.get("item_count", 0) or 0)}
                    for b in (bundles or [])[:8]
                ],
                workflow_nodes=[
                    {
                        "title": str(n.title or ""),
                        "channel": str(n.channel_type or ""),
                        "sensitivity": str(n.sensitivity_level or ""),
                        "trust_friction": int(n.trust_friction_score or 0),
                    }
                    for n in linked_workflows[:6]
                ],
                vendor_cues=_vendor_cues_from_evidence(list(evidence_sets.get(f"risk:{top_id}", []))),
                channel_cues=_channel_cues_from_evidence(list(evidence_sets.get(f"risk:{top_id}", []))),
                impact_targets=_impact_targets_from_band(
                    str(top.get("impact_band", "MED")), str(top.get("risk_type", ""))
                ),
                severity=int(top_row.severity or 3),
                likelihood_badge=str(top.get("likelihood", "med")).upper(),
                confidence=int(top.get("confidence", 0) or 0),
                evidence=list(evidence_sets.get(f"risk:{top_id}", [])),
                correlation_hint="",
            )
            exec_brief = get_or_generate_brief(db, brief_inp)
        except Exception:
            logger.exception("Failed to generate risk brief for assessment %s risk %s", assessment_id, top_id)
            exec_brief = ""

    details = {
        "exec_brief": exec_brief,
        "confirm_points": confirm_points,
        "deny_points": deny_points,
        "timeline": story_steps[:7],
        "evidence": (evidence_sets.get(f"risk:{top_id}", [])[:12] or _limited_evidence_placeholder()),
        "linked_workflows": [
            {
                "id": int(n.id),
                "title": str(n.title or ""),
                "trust_friction_score": int(n.trust_friction_score or 0),
                "sensitivity_level": str(n.sensitivity_level or ""),
                "channel_type": str(n.channel_type or ""),
                "evidence_set_id": f"workflow:{n.id}",
            }
            for n in linked_workflows[:6]
        ],
    }

    # High trust friction nodes (overview lens). Link each node to the best-matching risk via evidence overlap.
    risk_urls_by_id: dict[int, set[str]] = {}
    risk_titles_by_id: dict[int, str] = {}
    for r in risk_summaries:
        rid = int(r.get("id") or 0)
        if rid <= 0:
            continue
        evs = evidence_sets.get(f"risk:{rid}", [])
        urls = {str(ev.get("canonical_url", "")) for ev in (evs or []) if str(ev.get("canonical_url", ""))}
        risk_urls_by_id[rid] = urls
        risk_titles_by_id[rid] = str(r.get("title", "")) or f"Risk {rid}"

    high_friction_nodes: list[dict[str, Any]] = []
    for n in workflow_nodes:
        score = int(n.trust_friction_score or 0)
        if score < 70:
            continue
        evs = from_json(n.evidence_refs_json or "[]", [])
        if not isinstance(evs, list):
            evs = []
        norm = _normalize_evidence_refs(
            evs,
            docs_by_id=docs_by_id,
            docs_by_url=docs_by_url,
            query_id="WF",
            connectors_by_url=connectors_by_url,
            indicator_hints_by_url=indicator_hints_by_url,
        )
        node_urls = {str(ev.get("canonical_url", "")) for ev in (norm or []) if str(ev.get("canonical_url", ""))}

        best_rid = top_id
        best_overlap = 0
        # Evaluate against the most relevant risks first to keep this cheap.
        for r in elevated[:15] if elevated else risk_summaries[:15]:
            rid = int(r.get("id") or 0)
            if rid <= 0:
                continue
            overlap = len(node_urls.intersection(risk_urls_by_id.get(rid, set())))
            if overlap > best_overlap:
                best_overlap = overlap
                best_rid = rid
        high_friction_nodes.append(
            {
                "id": int(n.id),
                "title": str(n.title or "Workflow node"),
                "trust_friction_score": score,
                "sensitivity_level": str(n.sensitivity_level or ""),
                "channel_type": str(n.channel_type or ""),
                "linked_risk_id": int(best_rid),
                "linked_risk_title": str(risk_titles_by_id.get(int(best_rid), f"Risk {best_rid}")),
                "linked_risk_url": f"/assessments/{assessment_id}/risks/{int(best_rid)}",
            }
        )
        if len(high_friction_nodes) >= 6:
            break

    elevated_with_reasoning: list[dict[str, Any]] = []
    for r in elevated_list[:10]:
        if not isinstance(r, dict):
            continue
        row = dict(r)
        rid = int(row.get("id", 0) or 0)
        ev = list(evidence_sets.get(f"risk:{rid}", []) or [])
        row["reasoning"] = (
            dict(row.get("reasoning") or {})
            if isinstance(row.get("reasoning"), dict)
            else _reasoning_block_for_risk(
                risk=row,
                evidence=ev,
                recipe_bundles=list(row.get("recipe_bundles") or []),
                risk_vector_summary=str(row.get("risk_vector_summary", "")),
            )
        )
        elevated_with_reasoning.append(row)

    return {
        "assessment_id": assessment_id,
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "topRiskVerdict": topRiskVerdict,
        "watchlist_preview": watchlist_preview,
        "watchlist_total_count": int(watchlist_total_count),
        "watchlist_preview_limit": int(watchlist_preview_limit),
        "watchlistPreview": watchlist_preview,
        "bundles": bundles,
        "recipe_bundles": recipe_bundles,
        "storyMap": storyMap,
        "storyMapAll": storyMapAll,
        "controlPoints": control_points,
        "elevatedRisks": elevated_with_reasoning,
        "highTrustFrictionNodes": high_friction_nodes,
        "evidenceSets": evidence_sets,
        "details": details,
        "include_weak": bool(include_weak),
        "include_baseline": bool(include_baseline),
        "debug_bundle_names": bool(debug_bundle_names),
        "status_counts": status_counts,
        "risk_count": int(len(elevated)),
        "overview_metrics": overview_metrics,
        "ordered_risks": ordered_risks,
        "mitre_codes": mitre_codes,
    }


def build_risk_detail_viewmodel(
    db: Session,
    assessment: Assessment,
    risk_id: int,
    *,
    allow_generated_text: bool = True,
) -> dict[str, Any]:
    """
    Build a risk-first detail view model for a single RiskObject (Hypothesis row).
    Workflow is a lens under the same risk; no new risks are introduced here.
    """
    assessment_id = int(assessment.id)
    rid = int(risk_id)

    row = db.get(Hypothesis, rid)
    if not row or int(row.assessment_id) != assessment_id:
        return {
            "assessment_id": assessment_id,
            "risk": None,
            "evidenceSets": {},
            "recipe_bundles": [],
            "bundles": [],
            "details": {},
        }

    ranked_snapshot = get_ranked_risks(db, assessment)
    evidence_code_map = build_assessment_evidence_code_map(db, assessment, ranked_snapshot=ranked_snapshot)
    artifact_code_map = build_assessment_artifact_code_map(
        db,
        assessment,
        ranked_snapshot=ranked_snapshot,
        evidence_code_map=evidence_code_map,
    )
    code_document_map = build_assessment_code_document_map(
        db,
        assessment,
        ranked_snapshot=ranked_snapshot,
        evidence_code_map=evidence_code_map,
    )
    ranked_all = list(ranked_snapshot.get("all_unfiltered") or [])
    ranked_row = next((item for item in ranked_all if int(item.get("id", 0) or 0) == rid), None)
    connectors_by_url = dict(ranked_snapshot.get("connectors_by_url") or {})
    indicator_hints_by_url = dict(ranked_snapshot.get("indicator_hints_by_url") or {})
    signal_hints_by_type = dict(ranked_snapshot.get("signal_hints_by_type") or {})
    signal_connectors_by_type = dict(ranked_snapshot.get("signal_connectors_by_type") or {})

    # Prefetch documents referenced by this risk and by workflow nodes.
    refs = from_json(row.evidence_refs_json or "[]", [])
    if not isinstance(refs, list):
        refs = []
    doc_ids: set[int] = set()
    doc_urls: set[str] = set()
    for ref in refs:
        if not isinstance(ref, dict):
            continue
        did = ref.get("doc_id")
        if str(did).isdigit():
            doc_ids.add(int(did))
        u = str(ref.get("url", "")).strip()
        if u:
            doc_urls.add(u)

    docs_by_id: dict[int, Document] = {}
    docs_by_url: dict[str, Document] = {}
    if doc_ids:
        for d in db.execute(select(Document).where(Document.id.in_(list(doc_ids)))).scalars().all():
            docs_by_id[int(d.id)] = d
    if doc_urls:
        for d in (
            db.execute(
                select(Document).where(Document.assessment_id == assessment_id, Document.url.in_(list(doc_urls)))
            )
            .scalars()
            .all()
        ):
            docs_by_url[str(d.url)] = d

    evidence_sets: dict[str, list[dict[str, Any]]] = {}
    parsed = _parse_signal_counts_blob(row.signal_counts_json or "{}")
    evidence_all = _normalize_evidence_refs(
        refs,
        docs_by_id=docs_by_id,
        docs_by_url=docs_by_url,
        query_id=str(row.query_id or "")[:16],
        connectors_by_url=connectors_by_url,
        indicator_hints_by_url=indicator_hints_by_url,
    )
    evidence_valid = [
        ev
        for ev in evidence_all
        if isinstance(ev, dict)
        and (not bool(ev.get("is_boilerplate", False)))
        and float(ev.get("weight", 1.0) or 1.0) >= 0.5
    ]
    evidence_sets[f"risk:{rid}"] = _dedupe_evidence(evidence_valid)[:18]

    base_avg = 0
    if evidence_all:
        base_avg = int(sum(int(x.get("confidence", 50) or 50) for x in evidence_all) / len(evidence_all))
    ev_items = [
        {
            "url": str(x.get("url", "")),
            "snippet": str(x.get("snippet", "")),
            "confidence": int(x.get("confidence", 50) or 50),
            "signal_type": str(x.get("signal_type", "")),
            "query_id": str(row.query_id or ""),
            "is_boilerplate": bool(x.get("is_boilerplate", False)),
            "weight": float(x.get("weight", 1.0) or 1.0),
            "quality_tier": str(x.get("quality_tier", "LOW")),
            "evidence_kind": str(x.get("evidence_kind", "UNKNOWN")),
        }
        for x in evidence_all
        if isinstance(x, dict)
    ]
    calc_conf, meta = compute_hypothesis_confidence(
        ev_items, base_avg=base_avg, sector=str(assessment.sector or ""), risk_type=str(row.risk_type or "")
    )
    conf = max(1, min(100, int(calc_conf)))
    counts = meta.get("signal_counts") if isinstance(meta.get("signal_counts"), dict) else {}
    if not counts and parsed.counts:
        counts = dict(parsed.counts)
    diversity = int(
        meta.get("signal_diversity_count", 0) or len([k for k, v in (counts or {}).items() if int(v or 0) > 0])
    )
    meta["signal_counts"] = counts or {}
    meta["signal_diversity_count"] = diversity
    coverage = coverage_label_from_signals(meta)
    if parsed.baseline_exposure:
        coverage = "WEAK"
    evidence_strength = _evidence_strength_label(coverage)
    evidence_quality = _evidence_quality_label(meta)

    impact_band = _impact_band_from_severity(int(row.severity or 3))
    likelihood = (str(row.likelihood or "med").strip().lower() or "med")[:8]
    current_status = str(getattr(row, "status", "") or "WATCHLIST").upper()
    if isinstance(ranked_row, dict):
        conf = max(1, min(100, int(ranked_row.get("confidence", conf) or conf)))
        impact_band = str(ranked_row.get("impact_band", impact_band) or impact_band).upper()
        likelihood = str(ranked_row.get("likelihood", likelihood) or likelihood).strip().lower()[:8] or "med"
        current_status = str(ranked_row.get("status", current_status) or current_status).upper()
    primary_risk_type = str(getattr(row, "primary_risk_type", "") or "").strip()
    outcome = _risk_outcome_label(
        str(row.risk_type or ""), sector=str(assessment.sector or ""), process_flags=parsed.process_flags
    )
    title = _risk_display_name(primary_risk_type=primary_risk_type, fallback_outcome=outcome)
    if not primary_risk_type:
        primary_risk_type = title
    risk_vector_summary = str(getattr(row, "risk_vector_summary", "") or "").strip()

    timeline = from_json(row.timeline_json or "[]", [])
    if not isinstance(timeline, list) or not timeline:
        meta["risk_hint"] = str(row.title or "")
        timeline = timeline_for_risk(str(row.risk_type or ""), meta)
    abuse_path_steps_for_how: list[dict[str, str]] = []
    for idx, step in enumerate((timeline or [])[:6], start=1):
        if not isinstance(step, dict):
            continue
        step_title = " ".join(str(step.get("title", "")).split()).strip()
        step_detail = " ".join(str(step.get("brief", "")).split()).strip()
        if not step_title and not step_detail:
            continue
        abuse_path_steps_for_how.append(
            {
                "step": str(idx),
                "title": step_title,
                "detail": step_detail,
            }
        )

    # Bundles (recipe)
    bundles = _build_bundles_for_risk(
        evidence_valid=evidence_sets.get(f"risk:{rid}", []), counts=counts or {}, process_flags=parsed.process_flags
    )
    recipe_bundles = _pick_recipe_bundles(bundles)
    ingredient_phrases = [str(b.get("title", "")).strip() for b in recipe_bundles if str(b.get("title", "")).strip()]
    if primary_risk_type and (
        not risk_vector_summary or not _verdict_matches_bundles(risk_vector_summary, ingredient_phrases)
    ):
        risk_vector_summary = _verdict_line(
            primary_risk_type=primary_risk_type,
            risk_type=str(row.risk_type or ""),
            conditions=ingredient_phrases[:3],
            process_flags=parsed.process_flags,
        )
    risk_headline = _single_risk_headline(
        primary_risk_type=primary_risk_type,
        title=title,
        risk_vector_summary=risk_vector_summary,
    )
    for b in bundles:
        evidence_sets[f"bundle:{b.get('id')}"] = list(b.get("evidence") or [])
    risk_evidence_pool = list(evidence_sets.get(f"risk:{rid}", []) or [])
    risk_signal_types = {
        str(ev.get("signal_type", "")).strip().upper()
        for ev in (risk_evidence_pool or [])
        if str(ev.get("signal_type", "")).strip()
    }
    target_signals = [k for k, v in (counts or {}).items() if int(v or 0) > 0 and k in SIGNAL_TYPES]
    if not target_signals:
        target_signals = sorted(list(risk_signal_types))
    supplemental_hints: list[str] = []
    supplemental_connectors_set: set[str] = set()
    for st in target_signals:
        for hint in signal_hints_by_type.get(st, []):
            line = " ".join(str(hint or "").split()).strip()
            if line and line not in supplemental_hints:
                supplemental_hints.append(line)
        supplemental_connectors_set.update(signal_connectors_by_type.get(st, set()))
    supplemental_hints.sort(key=lambda x: (_hint_priority(x), len(x)))
    coded_signal_refs = _build_coded_signal_refs(
        risk_evidence_pool,
        extra_hints=supplemental_hints[:12],
        evidence_code_map=evidence_code_map,
        artifact_code_map=artifact_code_map,
        max_items=8,
    )
    coded_signal_lines = [f"{str(x.get('code', ''))} {str(x.get('text', ''))}".strip() for x in coded_signal_refs]

    confirm_points: list[str] = []
    deny_points: list[str] = []
    try:
        confirm_points, deny_points = _confirm_deny_points(
            meta={"signal_counts": dict(counts or {})}, process_flags=parsed.process_flags
        )
    except Exception:
        confirm_points, deny_points = [], []

    # Link workflows conservatively: evidence overlap between workflow nodes and this risk's evidence.
    workflow_nodes = (
        db.execute(
            select(WorkflowNode)
            .where(WorkflowNode.assessment_id == assessment_id)
            .order_by(WorkflowNode.trust_friction_score.desc(), WorkflowNode.created_at.desc(), WorkflowNode.id.desc())
        )
        .scalars()
        .all()
    )
    linked_workflows: list[WorkflowNode] = []
    top_urls = {
        str(ev.get("canonical_url", ""))
        for ev in (evidence_sets.get(f"risk:{rid}", []) or [])
        if str(ev.get("canonical_url", ""))
    }
    if top_urls:
        for n in workflow_nodes:
            if len(linked_workflows) >= 8:
                break
            evs = from_json(n.evidence_refs_json or "[]", [])
            if not isinstance(evs, list):
                continue
            for ev in evs:
                if not isinstance(ev, dict):
                    continue
                u = _canonical_url(str(ev.get("url", "")))
                if u and u in top_urls:
                    linked_workflows.append(n)
                    break
    for n in linked_workflows[:10]:
        evs = from_json(n.evidence_refs_json or "[]", [])
        if not isinstance(evs, list):
            evs = []
        norm = _normalize_evidence_refs(
            evs,
            docs_by_id=docs_by_id,
            docs_by_url=docs_by_url,
            query_id="WF",
            connectors_by_url=connectors_by_url,
            indicator_hints_by_url=indicator_hints_by_url,
        )
        norm_valid = [
            ev
            for ev in norm
            if isinstance(ev, dict)
            and (not bool(ev.get("is_boilerplate", False)))
            and float(ev.get("weight", 1.0) or 1.0) >= 0.5
        ]
        evidence_sets[f"workflow:{n.id}"] = _dedupe_evidence(norm_valid)[:12]

    # Risk brief (LLM optional, defensive-only; cached in DB).
    exec_brief = ""
    if allow_generated_text:
        try:
            conditions = [str(b.get("title", "")).strip() for b in recipe_bundles if str(b.get("title", "")).strip()][:3]
            brief_inp = BriefInput(
                assessment_id=assessment_id,
                risk_kind="scenario",
                risk_id=int(row.id),
                title=str(row.title or title),
                risk_type=str(row.risk_type or ""),
                primary_risk_type=primary_risk_type,
                risk_vector_summary=risk_vector_summary,
                conditions=conditions,
                signal_bundles=[
                    {"title": str(b.get("title", "")), "item_count": int(b.get("item_count", 0) or 0)}
                    for b in (bundles or [])[:8]
                ],
                workflow_nodes=[
                    {
                        "title": str(n.title or ""),
                        "channel": str(n.channel_type or ""),
                        "sensitivity": str(n.sensitivity_level or ""),
                        "trust_friction": int(n.trust_friction_score or 0),
                    }
                    for n in linked_workflows[:6]
                ],
                vendor_cues=_vendor_cues_from_evidence(list(evidence_sets.get(f"risk:{rid}", []))),
                channel_cues=_channel_cues_from_evidence(list(evidence_sets.get(f"risk:{rid}", []))),
                impact_targets=_impact_targets_from_band(str(impact_band), str(row.risk_type or "")),
                severity=int(row.severity or 3),
                likelihood_badge=str(likelihood).upper(),
                confidence=int(conf),
                evidence=list(evidence_sets.get(f"risk:{rid}", [])),
                correlation_hint="",
            )
            exec_brief = get_or_generate_brief(db, brief_inp)
        except Exception:
            logger.exception("Failed to generate risk brief for assessment %s risk %s", assessment_id, rid)
            try:
                db.rollback()
            except Exception:
                pass
            exec_brief = ""

    risk = {
        "id": rid,
        "risk_type": str(row.risk_type or "other"),
        "status": current_status,
        "primary_risk_type": primary_risk_type,
        "headline": risk_headline,
        "risk_vector_summary": risk_vector_summary,
        "baseline_tag": bool(getattr(row, "baseline_tag", False)),
        "title": title,
        "description": str(row.description or "").strip(),
        "scenario_url": f"/assessments/{assessment_id}/risks/{rid}",
        "likelihood": likelihood,
        "impact_band": impact_band,
        "evidence_strength": evidence_strength,
        "evidence_quality": evidence_quality,
        "evidence_strength_tooltip": _evidence_strength_tooltip(evidence_strength),
        "signal_coverage": int(diversity),
        "evidence_strength_score": int(conf),
        "timeline": timeline[:7] if isinstance(timeline, list) else [],
    }
    risk_reasoning = _reasoning_block_for_risk(
        risk=risk,
        evidence=list(evidence_sets.get(f"risk:{rid}", []) or []),
        recipe_bundles=recipe_bundles,
        risk_vector_summary=risk_vector_summary,
        supplemental_hints=coded_signal_lines,
        supplemental_connectors=sorted(list(supplemental_connectors_set), key=_connector_sort_key)[:5],
    )
    signal_links: list[dict[str, Any]] = []
    seen_codes: set[str] = set()
    for ref in coded_signal_refs:
        code = " ".join(str(ref.get("code", "")).split()).strip().upper()
        if not code or code in seen_codes:
            continue
        seen_codes.add(code)
        doc_id = code_document_map.get(code)
        signal_links.append(
            {
                "code": code,
                "doc_id": int(doc_id) if isinstance(doc_id, int) and doc_id > 0 else None,
                "doc_url": f"/documents/{int(doc_id)}" if isinstance(doc_id, int) and doc_id > 0 else "",
            }
        )
    if signal_links:
        risk_reasoning["signal_links"] = signal_links
    if allow_generated_text:
        try:
            how_text = get_or_generate_how_text(
                db,
                assessment_id=assessment_id,
                risk_id=rid,
                primary_risk_type=primary_risk_type,
                risk_type=str(row.risk_type or ""),
                abuse_path=abuse_path_steps_for_how,
                likelihood=str(likelihood).upper(),
                impact_band=str(impact_band).upper(),
                evidence_strength=str(evidence_strength).upper(),
                confidence=int(conf),
            )
            if str(how_text or "").strip():
                risk_reasoning["how"] = _inject_evidence_codes_in_how(str(how_text).strip(), coded_signal_refs)
        except Exception:
            logger.exception("Failed to build risk HOW narrative for assessment %s risk %s", assessment_id, rid)
            try:
                db.rollback()
            except Exception:
                pass
    risk["reasoning"] = risk_reasoning
    business_impact_text = str(row.impact_rationale or "").strip()
    if not business_impact_text:
        business_impact_text = str(risk_reasoning.get("why", "")).strip()
    if not business_impact_text:
        business_impact_text = str(row.description or "").strip()
    business_impact_text = re.sub(r"^\s*context:\s*", "", business_impact_text, flags=re.IGNORECASE).strip()
    business_impact_text = _first_sentence(business_impact_text, max_chars=420)
    if not business_impact_text:
        business_impact_text = "Potential trust, operational, and client confidence impact requires validation with additional evidence."

    # Lightweight CTI tags (heuristic, defensive-only): chips for stakeholders.
    campaign_chips, mitre_chips = _cti_chips_for_risk(
        risk_type=str(row.risk_type or ""),
        signal_counts=counts,
        signal_coverage=int(diversity),
    )
    risk["campaign_chips"] = campaign_chips[:6]
    risk["mitre_chips"] = mitre_chips[:6]

    assumptions = from_json(row.assumptions_json or "[]", [])
    if not isinstance(assumptions, list):
        assumptions = []
    gaps = from_json(row.gaps_to_verify_json or "[]", [])
    if not isinstance(gaps, list):
        gaps = []
    actions = from_json(row.defensive_actions_json or "[]", [])
    if not isinstance(actions, list):
        actions = []

    details = {
        "exec_brief": exec_brief,
        "business_impact": business_impact_text,
        "confirm_points": confirm_points,
        "deny_points": deny_points,
        "control_points": _control_points_from_actions(list(actions or [])),
        "evidence": (evidence_sets.get(f"risk:{rid}", [])[:18] or _limited_evidence_placeholder()),
        "assumptions": list(assumptions or []),
        "gaps": list(gaps or []),
        "actions": list(actions or []),
        "linked_workflows": [
            {
                "id": int(n.id),
                "title": str(n.title or ""),
                "trust_friction_score": int(n.trust_friction_score or 0),
                "sensitivity_level": str(n.sensitivity_level or ""),
                "channel_type": str(n.channel_type or ""),
                "evidence_set_id": f"workflow:{n.id}",
            }
            for n in linked_workflows[:10]
        ],
    }

    story_signals = []
    used_signal_ref_keys: set[str] = set()
    for b in (recipe_bundles or [])[:6]:
        bundle_set_id = f"bundle:{b.get('id')}"
        bundle_evidence = list(evidence_sets.get(bundle_set_id, []) or [])
        refs_for_bundle_raw = _refs_for_bundle(
            b,
            coded_signal_refs,
            bundle_evidence=bundle_evidence,
            evidence_code_map=evidence_code_map,
            artifact_code_map=artifact_code_map,
            max_items=10,
        )
        refs_for_bundle: list[dict[str, str]] = []
        for ref in refs_for_bundle_raw:
            text = " ".join(str(ref.get("text", "")).split()).strip()
            code = " ".join(str(ref.get("code", "")).split()).strip()
            if not text:
                continue
            key = re.sub(r"[^a-z0-9]+", " ", text.lower()).strip()[:180]
            if not key or key in used_signal_ref_keys:
                continue
            used_signal_ref_keys.add(key)
            refs_for_bundle.append({"code": code, "text": text})
            if len(refs_for_bundle) >= 10:
                break
        story_signals.append(
            {
                "id": f"sig:{b.get('id')}",
                "title": str(b.get("title", "")),
                "detail": f"{int(b.get('item_count', 0) or 0)} items",
                "icon": str(b.get("icon", "sparkles")),
                "evidence_set_id": bundle_set_id,
                "evidence_refs": refs_for_bundle,
            }
        )
    story_abuse_path = []
    for idx, step in enumerate((risk.get("timeline") or [])[:6], start=1):
        if not isinstance(step, dict):
            continue
        step_title = str(step.get("title", ""))[:90]
        step_detail = str(step.get("brief", ""))[:180]
        step_set_id = f"step:{rid}:{idx}"
        evidence_sets[step_set_id] = _focused_evidence_subset(
            risk_evidence_pool,
            seed_texts=[step_title, step_detail, str(primary_risk_type or ""), str(row.risk_type or "")],
            max_items=8,
        )
        story_abuse_path.append(
            {
                "id": f"step:{int(step.get('step_index', 0) or 0)}",
                "title": step_title,
                "detail": step_detail,
                "icon": "route",
                "evidence_set_id": step_set_id,
            }
        )
    impact_primary_set_id = f"impact:primary:{rid}"
    evidence_sets[impact_primary_set_id] = _focused_evidence_subset(
        risk_evidence_pool,
        seed_texts=[
            str(row.impact_rationale or ""),
            str(row.description or ""),
            str(primary_risk_type or ""),
            str(row.risk_type or ""),
        ],
        max_items=8,
    )
    impact_score_set_id = f"impact:score:{rid}"
    evidence_sets[impact_score_set_id] = _focused_evidence_subset(
        risk_evidence_pool,
        seed_texts=[
            str(current_status),
            str(impact_band),
            str(likelihood),
            str(evidence_strength),
            str(primary_risk_type or ""),
        ],
        max_items=8,
    )
    story_impacts = [
        {
            "id": "impact:primary",
            "title": "Business impact",
            "detail": _first_sentence(str(row.impact_rationale or row.description or ""), max_chars=360),
            "icon": "target",
            "evidence_set_id": impact_primary_set_id,
        },
        {
            "id": "impact:score",
            "title": "Risk intensity",
            "detail": (
                f"Status {str(current_status)} | Impact {str(impact_band)} | Likelihood {str(likelihood).upper()} | "
                f"Evidence strength {str(evidence_strength)} ({int(conf)}%)."
            ),
            "icon": "bar-chart-3",
            "evidence_set_id": impact_score_set_id,
        },
    ]
    story_map = {
        "signals": story_signals[:6],
        "abuse_path": story_abuse_path[:6],
        "impacts": story_impacts[:4],
    }

    return {
        "assessment_id": assessment_id,
        "risk": risk,
        "bundles": bundles,
        "recipe_bundles": recipe_bundles,
        "evidenceSets": evidence_sets,
        "details": details,
        "story_map": story_map,
    }
