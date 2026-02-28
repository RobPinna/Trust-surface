from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
import hashlib
import json
import logging
import random
import re
import time
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests
from sqlalchemy import delete, select

from app.config import get_settings
from app.db import SessionLocal
from app.models import Assessment, ConnectorSetting, Document, Gap, Hypothesis
from app.security import deobfuscate_secret
from app.utils.jsonx import to_json
from app.services.evidence_quality_classifier import classify_evidence
from operational_leverage_framework.scoring.signal_model import (
    SIGNAL_LABELS,
    VENDOR_KEYWORDS,
    compute_hypothesis_confidence,
    coverage_label_from_signals,
    infer_signal_type,
    safe_json_dumps,
    timeline_for_risk,
)

logger = logging.getLogger(__name__)

SAFE_RISK_TYPES = {
    "impersonation",
    "fraud_process",
    "credential_theft_risk",
    "brand_abuse",
    "downstream_pivot",
    "social_engineering_risk",
    "privacy_data_risk",
    "workflow_trust_exposure",
    "other",
}
SAFE_IMPACT_TYPES = {"ops", "financial", "reputation", "safety"}
SAFE_LIKELIHOOD = {"low", "med", "high"}

# Stakeholder-facing, operational abuse typing (deterministic; NOT decided by LLM).
PRIMARY_RISK_TYPES = (
    "Social engineering",
    "Payment fraud",
    "Vendor trust abuse",
    "Account takeover vector",
    "Supply chain dependency risk",
    "Booking fraud",
    "Donation fraud",
    "Partner impersonation",
    "Data handling abuse",
    "Channel ambiguity exploitation",
)

PRIMARY_RISK_SET = {x.lower(): x for x in PRIMARY_RISK_TYPES}

LLM_MAX_ATTEMPTS = 4
LLM_BACKOFF_BASE_SECONDS = 3.0
LLM_BACKOFF_JITTER_SECONDS = 1.0
LLM_BACKOFF_MAX_SECONDS = 45.0
LLM_QUOTA_COOLDOWN_SECONDS = 900
LLM_STABLE_TEMPERATURE = 0.0
LLM_STABLE_TOP_P = 1.0
REASONER_PROMPT_VERSION = "2026-02-25-stable-v1"
REASONER_ENGINE_VERSION = "stable-by-default-v2"
LLM_MODEL_SETTING_NAME = "__llm_reasoner_model__"
LLM_PROVIDER_SETTING_NAME = "__llm_reasoner_provider__"
LLM_OPENAI_API_SETTING_NAME = "__llm_reasoner_api__"
LLM_ANTHROPIC_API_SETTING_NAME = "__llm_reasoner_anthropic_api__"

_llm_quota_block_until = 0.0
_llm_quota_last_notice = 0.0


def _normalize_provider(value: str) -> str:
    p = " ".join(str(value or "").split()).strip().lower()
    if p in {"anthropic", "claude"}:
        return "anthropic"
    if p in {"local"}:
        return "local"
    return "openai"


def _extract_openai_text(body: dict[str, Any]) -> str:
    return " ".join(
        str(
            (((body or {}).get("choices") or [{}])[0] or {})
            .get("message", {})
            .get("content", "")
            or ""
        ).split()
    ).strip()


def _extract_anthropic_text(body: dict[str, Any]) -> str:
    chunks = (body or {}).get("content", [])
    parts: list[str] = []
    if isinstance(chunks, list):
        for item in chunks:
            if isinstance(item, dict) and str(item.get("type", "")).strip().lower() == "text":
                text = " ".join(str(item.get("text", "")).split()).strip()
                if text:
                    parts.append(text)
    text = " ".join(parts).strip()
    if text:
        return text
    return " ".join(str((body or {}).get("completion", "") or "").split()).strip()


def _parse_json_object_text(raw: str) -> dict[str, Any] | None:
    text = str(raw or "").strip()
    if not text:
        return None

    def _load(candidate: str) -> dict[str, Any] | None:
        try:
            parsed = json.loads(candidate)
        except Exception:
            return None
        return parsed if isinstance(parsed, dict) else None

    parsed = _load(text)
    if parsed is not None:
        return parsed

    if text.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*", "", text, flags=re.IGNORECASE)
        cleaned = re.sub(r"\s*```$", "", cleaned, flags=re.IGNORECASE)
        parsed = _load(cleaned.strip())
        if parsed is not None:
            return parsed

    start = text.find("{")
    end = text.rfind("}")
    if start >= 0 and end > start:
        parsed = _load(text[start : end + 1].strip())
        if parsed is not None:
            return parsed
    return None


def _retry_after_seconds(headers: dict[str, Any] | Any) -> float:
    raw = str((headers or {}).get("Retry-After", "")).strip()
    if not raw:
        return 0.0
    try:
        return max(0.0, float(raw))
    except Exception:
        pass
    try:
        dt = parsedate_to_datetime(raw)
        if dt is None:
            return 0.0
        now = time.time()
        return max(0.0, dt.timestamp() - now)
    except Exception:
        return 0.0


def _is_quota_exhausted_response(res: requests.Response) -> bool:
    if int(res.status_code or 0) != 429:
        return False
    code = ""
    err_type = ""
    msg = ""
    try:
        body = res.json() if res is not None else {}
        err = body.get("error", {}) if isinstance(body, dict) else {}
        code = str(err.get("code", "") or "").strip().lower()
        err_type = str(err.get("type", "") or "").strip().lower()
        msg = str(err.get("message", "") or "").strip().lower()
    except Exception:
        return False
    return (
        code in {"insufficient_quota", "billing_hard_limit_reached"}
        or err_type in {"insufficient_quota"}
        or "exceeded your current quota" in msg
    )


def _quota_block_active() -> bool:
    return time.time() < float(_llm_quota_block_until or 0.0)


def _maybe_log_quota_notice(caller: str) -> None:
    global _llm_quota_last_notice
    now = time.time()
    if (now - float(_llm_quota_last_notice or 0.0)) >= 60.0:
        remaining = int(max(0.0, float(_llm_quota_block_until or 0.0) - now))
        logger.warning(
            "%s LLM quota block active (cooldown %ss). Using local fallback without API retries.",
            caller,
            remaining,
        )
        _llm_quota_last_notice = now


def _post_llm_with_backoff(
    *,
    url: str,
    payload: dict[str, Any],
    headers: dict[str, str],
    timeout_seconds: int,
    caller: str,
) -> requests.Response | None:
    global _llm_quota_block_until
    last_response: requests.Response | None = None
    if _quota_block_active():
        _maybe_log_quota_notice(caller)
        return None
    for attempt in range(LLM_MAX_ATTEMPTS):
        try:
            res = requests.post(url, json=payload, headers=headers, timeout=timeout_seconds)
            last_response = res
            if res.status_code < 400:
                return res
            if _is_quota_exhausted_response(res):
                _llm_quota_block_until = time.time() + float(LLM_QUOTA_COOLDOWN_SECONDS)
                logger.warning(
                    "%s LLM quota exhausted (status=429 insufficient_quota). Blocking API retries for %ss.",
                    caller,
                    int(LLM_QUOTA_COOLDOWN_SECONDS),
                )
                return res
            retriable = res.status_code == 429 or res.status_code >= 500
            is_last = attempt >= (LLM_MAX_ATTEMPTS - 1)
            if not retriable or is_last:
                return res
            retry_after = _retry_after_seconds(res.headers)
            backoff = min(
                LLM_BACKOFF_MAX_SECONDS,
                (LLM_BACKOFF_BASE_SECONDS * (2**attempt)) + random.uniform(0, LLM_BACKOFF_JITTER_SECONDS),
            )
            wait_seconds = max(retry_after, backoff)
            logger.warning(
                "%s LLM transient failure status=%s attempt=%s/%s wait=%.2fs",
                caller,
                res.status_code,
                attempt + 1,
                LLM_MAX_ATTEMPTS,
                wait_seconds,
            )
            time.sleep(wait_seconds)
        except requests.RequestException as exc:
            is_last = attempt >= (LLM_MAX_ATTEMPTS - 1)
            if is_last:
                logger.warning("%s LLM request error after retries: %s", caller, exc)
                return last_response
            backoff = min(
                LLM_BACKOFF_MAX_SECONDS,
                (LLM_BACKOFF_BASE_SECONDS * (2**attempt)) + random.uniform(0, LLM_BACKOFF_JITTER_SECONDS),
            )
            logger.warning(
                "%s LLM transport error attempt=%s/%s wait=%.2fs err=%s",
                caller,
                attempt + 1,
                LLM_MAX_ATTEMPTS,
                backoff,
                exc,
            )
            time.sleep(backoff)
    return last_response


def _canonical_url(url: str) -> str:
    raw = (url or "").strip()
    if not raw:
        return ""
    try:
        u = urlparse(raw)
        host = (u.netloc or "").lower().split(":")[0]
        path = (u.path or "/").strip() or "/"
        scheme = u.scheme or "https"
        return f"{scheme}://{host}{path}"
    except Exception:
        return raw


def _distinct_url_count(evidence_refs: list[EvidenceRef]) -> int:
    urls = set()
    for r in evidence_refs or []:
        if not isinstance(r, EvidenceRef):
            continue
        if r.is_boilerplate or float(r.weight or 1.0) < 0.5:
            continue
        u = _canonical_url(r.url)
        if u:
            urls.add(u)
    return len(urls)


def _extract_vendor_hits(evidence_refs: list[EvidenceRef]) -> list[str]:
    hits: set[str] = set()
    for r in evidence_refs or []:
        if bool(r.is_boilerplate) or float(r.weight or 1.0) < 0.5:
            continue
        if (r.evidence_kind or "UNKNOWN").strip().upper() not in {"WORKFLOW_VENDOR", "UNKNOWN"}:
            continue
        blob = _norm_text(f"{r.title} {r.snippet} {r.url}")
        for kw in VENDOR_KEYWORDS:
            if kw and kw.lower() in blob:
                hits.add(kw.lower())
    # Map to nicer display where possible.
    pretty = {
        "zendesk": "Zendesk",
        "freshdesk": "Freshdesk",
        "intercom": "Intercom",
        "salesforce": "Salesforce",
        "hubspot": "HubSpot",
        "stripe": "Stripe",
        "adyen": "Adyen",
        "paypal": "PayPal",
        "cloudflare": "Cloudflare",
        "akamai": "Akamai",
        "auth0": "Auth0",
        "okta": "Okta",
        "microsoft 365": "Microsoft 365",
        "google tag manager": "Google Tag Manager",
        "recaptcha": "reCAPTCHA",
    }
    out = [pretty.get(x, x) for x in sorted(hits)]
    return out[:8]


def _workflow_flags_from_evidence(evidence_refs: list[EvidenceRef], *, sector: str = "") -> dict[str, bool]:
    valid = [
        r
        for r in (evidence_refs or [])
        if isinstance(r, EvidenceRef) and (not bool(r.is_boilerplate)) and float(r.weight or 1.0) >= 0.5
    ]
    text = _norm_text(" ".join([f"{r.title} {r.snippet} {r.url}" for r in valid[:12]]))
    sector_norm = (sector or "").strip().lower()
    flags = {
        "payment": any(
            x in text for x in ("payment", "billing", "invoice", "refund", "wire", "fattura", "pagamento", "rimborso")
        ),
        "booking": any(
            x in text
            for x in ("booking", "reservation", "reservation change", "modify booking", "prenot", "cambio prenot")
        ),
        "donation": any(
            x in text for x in ("donation", "donate", "beneficiary", "fundraising", "gift aid", "donazione", "donare")
        ),
        "account": any(
            x in text for x in ("password", "login", "credentials", "account", "otp", "reset", "credenzial", "accesso")
        ),
        "partner": any(
            x in text
            for x in (
                "partner",
                "supplier",
                "vendor",
                "provider",
                "procurement",
                "tender",
                "supplier",
                "fornit",
                "bando",
            )
        ),
        "press": any(
            x in text for x in ("press", "media", "newsroom", "press office", "comms", "communications", "stampa")
        ),
        "hospitality": any(k in sector_norm for k in ("hotel", "hospitality", "resort", "travel")),
        "ngo": any(
            k in sector_norm
            for k in ("ngo", "nonprofit", "non-profit", "charity", "aid", "humanitarian", "onlus", "associazione")
        ),
    }
    return flags


def _risk_type_mentions_outside_evidence(text: str, *, wf: dict[str, bool], vendor_hits: list[str]) -> list[str]:
    """Flag narrative mentions that are not supported by evidence-driven workflow/vendor cues."""
    t = _norm_text(text)
    flags: list[str] = []
    # Vendor mentions: only allow if the vendor is actually present in evidence hits.
    for kw in VENDOR_KEYWORDS:
        if kw and kw.lower() in t:
            ok = any(kw.lower() == (v or "").lower() for v in vendor_hits) or any(
                kw.lower() in (v or "").lower() for v in vendor_hits
            )
            if not ok:
                flags.append(f"unreferenced_vendor:{kw.lower()}")
    # Workflow mentions: require the corresponding workflow flag.
    if any(x in t for x in ("payment", "billing", "invoice", "refund", "wire")) and not wf.get("payment", False):
        flags.append("unreferenced_workflow:payment")
    if any(x in t for x in ("booking", "reservation", "concierge")) and not wf.get("booking", False):
        flags.append("unreferenced_workflow:booking")
    if any(x in t for x in ("donation", "donate", "beneficiary", "fundraising")) and not wf.get("donation", False):
        flags.append("unreferenced_workflow:donation")
    if any(x in t for x in ("password", "login", "credentials", "account takeover")) and not wf.get("account", False):
        flags.append("unreferenced_workflow:account")
    return flags[:12]


def _assign_primary_risk_type(
    *,
    signal_counts: dict[str, int],
    evidence_refs: list[EvidenceRef],
    sector: str,
    trust_friction: bool,
    diversity_guard: bool,
) -> tuple[str, bool, str, list[str], dict[str, Any]]:
    """
    Deterministically assign a stakeholder-facing primary risk type and a vector summary.

    Returns: (primary_risk_type, baseline_tag, risk_vector_summary, conditions, meta_flags)
    """
    counts = signal_counts or {}
    present = {k for k, v in counts.items() if isinstance(v, int) and v > 0}
    distinct_urls = _distinct_url_count(evidence_refs)
    vendor_hits = _extract_vendor_hits(evidence_refs)
    wf = _workflow_flags_from_evidence(evidence_refs, sector=sector)

    # Bundle categories (approx): contacts, process, vendor, org, infra, attention, social.
    bundle_kinds = set()
    if int(counts.get("CONTACT_CHANNEL", 0) or 0) > 0:
        bundle_kinds.add("contacts")
    if int(counts.get("SOCIAL_TRUST_NODE", 0) or 0) > 0:
        bundle_kinds.add("social")
    if int(counts.get("PROCESS_CUE", 0) or 0) > 0:
        bundle_kinds.add("process")
    if int(counts.get("VENDOR_CUE", 0) or 0) > 0 or vendor_hits:
        bundle_kinds.add("vendor")
    if int(counts.get("ORG_CUE", 0) or 0) > 0:
        bundle_kinds.add("org")
    if int(counts.get("INFRA_CUE", 0) or 0) > 0:
        bundle_kinds.add("infra")
    if int(counts.get("EXTERNAL_ATTENTION", 0) or 0) > 0:
        bundle_kinds.add("attention")

    signal_diversity = len(
        [
            k
            for k in (
                "CONTACT_CHANNEL",
                "SOCIAL_TRUST_NODE",
                "PROCESS_CUE",
                "VENDOR_CUE",
                "ORG_CUE",
                "EXTERNAL_ATTENTION",
                "INFRA_CUE",
            )
            if k in present
        ]
    )
    req_diversity = 2 + (1 if diversity_guard else 0)

    baseline = False
    if signal_diversity < req_diversity or len(bundle_kinds) < 2 or distinct_urls < 2:
        baseline = True

    # Pattern penalty: emails + policy only should never look elevated.
    policy_only = bool(evidence_refs) and all(_is_policy_url(r.url) for r in evidence_refs if r.url)
    contact_only = (
        signal_diversity <= 1
        and (int(counts.get("CONTACT_CHANNEL", 0) or 0) > 0)
        and int(counts.get("PROCESS_CUE", 0) or 0) == 0
        and int(counts.get("VENDOR_CUE", 0) or 0) == 0
    )
    if policy_only or contact_only:
        baseline = True

    # Deterministic type rules (prioritized).
    primary = "Channel ambiguity exploitation"
    if (
        wf.get("payment")
        and (int(counts.get("VENDOR_CUE", 0) or 0) > 0 or vendor_hits)
        and (int(counts.get("CONTACT_CHANNEL", 0) or 0) > 0 or int(counts.get("INFRA_CUE", 0) or 0) > 0)
    ):
        primary = "Payment fraud"
    elif wf.get("booking") and (
        int(counts.get("CONTACT_CHANNEL", 0) or 0) > 0 or int(counts.get("INFRA_CUE", 0) or 0) > 0
    ):
        primary = "Booking fraud"
    elif wf.get("donation") and (
        int(counts.get("CONTACT_CHANNEL", 0) or 0) > 0 or int(counts.get("SOCIAL_TRUST_NODE", 0) or 0) > 0
    ):
        primary = "Donation fraud"
    elif (
        (int(counts.get("VENDOR_CUE", 0) or 0) > 0 or vendor_hits)
        and (wf.get("payment") or wf.get("booking") or wf.get("account"))
        and int(counts.get("PROCESS_CUE", 0) or 0) > 0
    ):
        primary = "Vendor trust abuse"
    elif wf.get("account") and (
        int(counts.get("CONTACT_CHANNEL", 0) or 0) > 0 or int(counts.get("PROCESS_CUE", 0) or 0) > 0
    ):
        primary = "Account takeover vector"
    elif (int(counts.get("ORG_CUE", 0) or 0) > 0 or int(counts.get("CONTACT_CHANNEL", 0) or 0) > 0) and (
        int(counts.get("PROCESS_CUE", 0) or 0) > 0 or trust_friction
    ):
        primary = "Social engineering"
    elif wf.get("partner") or (wf.get("press") and int(counts.get("CONTACT_CHANNEL", 0) or 0) > 0):
        primary = "Partner impersonation"
    elif policy_only or (
        wf.get("account") and "privacy" in _norm_text(" ".join([r.url for r in evidence_refs[:6] if r.url]))
    ):
        primary = "Data handling abuse"
    elif (int(counts.get("VENDOR_CUE", 0) or 0) > 0 or vendor_hits) and signal_diversity >= 2:
        primary = "Supply chain dependency risk"

    # Conditions map directly to signal bundles / cues.
    conditions: list[str] = []
    if int(counts.get("VENDOR_CUE", 0) or 0) > 0 or vendor_hits:
        if primary in {"Payment fraud", "Booking fraud"} and wf.get("payment"):
            conditions.append("external billing dependency")
        elif primary in {"Vendor trust abuse", "Supply chain dependency risk"}:
            conditions.append("third-party service dependency")
        else:
            conditions.append("vendor/tooling cues")
    if int(counts.get("PROCESS_CUE", 0) or 0) > 0:
        if wf.get("booking"):
            conditions.append("booking or reservation workflow cues")
        elif wf.get("payment"):
            conditions.append("billing or payment workflow cues")
        elif wf.get("donation"):
            conditions.append("donation handling workflow cues")
        elif wf.get("account"):
            conditions.append("account handling workflow cues")
        else:
            conditions.append("operational workflow cues")
    if int(counts.get("CONTACT_CHANNEL", 0) or 0) > 0 or int(counts.get("SOCIAL_TRUST_NODE", 0) or 0) > 0:
        if int(counts.get("ORG_CUE", 0) or 0) > 0:
            conditions.append("public staff contact paths")
        else:
            conditions.append("public contact channels")
    if int(counts.get("INFRA_CUE", 0) or 0) > 0 or trust_friction:
        conditions.append("multi-channel trust ambiguity")
    if wf.get("press"):
        conditions.append("press or external attention cues")

    # Deterministic cap: limit to 3 conditions.
    conditions = list(dict.fromkeys([c for c in conditions if c]))[:3]
    if len(conditions) < 2:
        baseline = True

    # Mandatory verdict structure in stored summary (used by overview/detail).
    cond_phrase = " + ".join(conditions[:3])
    summary = (
        f"Top risk: {primary} enabled by {cond_phrase}."
        if cond_phrase
        else f"Top risk: {primary} enabled by limited public signals."
    )

    flags = {
        "signal_diversity_count": int(signal_diversity),
        "bundle_diversity_count": int(len(bundle_kinds)),
        "distinct_url_count": int(distinct_urls),
        "vendor_hits": vendor_hits,
        "workflow_flags": wf,
        "diversity_guard": bool(diversity_guard),
    }
    return primary, bool(baseline), summary[:280], conditions, flags


PROHIBITED_PATTERN = re.compile(
    r"\b("
    r"email template|subject line|send this email|copy paste message|credential harvesting|"
    r"spear[- ]?phish|phishing email|payload|malware|keylogger|exploit|bypass mfa|"
    r"offensive steps|attack chain instructions"
    r")\b",
    re.IGNORECASE,
)

# High-sensitivity token detection (evidence-first, conservative)
DATA_SENS_HIGH_PATTERNS = (
    "password",
    "login details",
    "account credentials",
    "credentials",
    "booking modification",
    "modify booking",
    "reservation change",
    "payment data",
    "payment details",
    "invoice details",
    "loyalty account",
    "loyalty account management",
    "chat conversation details",
    "chat transcript",
    # Italian-ish variants
    "password",
    "credenzial",
    "dettagli di accesso",
    "modifica prenot",
    "cambio prenot",
    "dati di pagamento",
    "dettagli pagamento",
    "programma fedelt",
    "chat",
)

CHANNEL_HINT_PATTERNS = (
    "contact form",
    "submit a request",
    "submit request",
    "support channel",
    "support",
    "help",
    "helpdesk",
    "ticket",
    "live chat",
    "chat",
    "online request",
    "web form",
    "form",
    # Italian-ish
    "modulo contatti",
    "modulo di contatto",
    "assistenza",
    "supporto",
    "chat",
)

TRUST_GUIDANCE_PATTERNS = (
    "we will never ask for your password",
    "we will never request your password",
    "never ask for your password",
    "do not share your password",
    "official channels",
    "official email",
    "verified domains",
    "anti-phishing",
    "phishing",
    # Italian-ish
    "non ti chiederemo mai la password",
    "non chiederemo mai la password",
    "non condividere la password",
    "canali ufficiali",
    "indirizzi ufficiali",
    "anti-phishing",
    "phishing",
)

BOILERPLATE_NAV_WORDS = (
    "home",
    "about",
    "team",
    "careers",
    "jobs",
    "contact",
    "support",
    "help",
    "privacy",
    "terms",
    "cookies",
    "cookie",
    "sitemap",
    "press",
    "news",
    "linkedin",
    "twitter",
    "facebook",
    "instagram",
)

BOILERPLATE_PATTERNS = (
    "meta:",
    "og:title",
    "og:description",
    "cookie preferences",
    "manage cookies",
    "we use cookies",
    "accept all",
    "reject all",
    "consent",
    "all rights reserved",
    "copyright",
)


def _is_boilerplate(*, url: str, title: str, snippet: str) -> bool:
    """
    Best-effort boilerplate/meta detection to prevent layout blocks and banners from inflating evidence.
    """
    t = _norm_text(f"{title} {snippet}")
    u = (url or "").lower()
    if any(p in t for p in BOILERPLATE_PATTERNS):
        return True
    # Cookie banners often mention cookies + preferences/consent in short blocks.
    if "cookie" in t and any(x in t for x in ("preferences", "consent", "accept", "reject", "manage")):
        return True
    # Footer/navigation blocks: many nav words in a short snippet.
    if len(t) <= 260:
        nav_hits = sum(1 for w in BOILERPLATE_NAV_WORDS if w in t)
        if nav_hits >= 5:
            return True
    # META extraction artifacts.
    if (title or "").strip().lower().startswith("meta:"):
        return True
    # Query-only hints: don't mark full policy pages as boilerplate, but a footer snippet from them can be.
    if any(x in u for x in ("/privacy", "/terms", "/cookie")) and len(t) <= 200:
        nav_hits = sum(1 for w in ("home", "contact", "support", "privacy", "terms") if w in t)
        if nav_hits >= 3:
            return True
    return False


@dataclass(slots=True)
class EvidenceRef:
    url: str
    title: str
    snippet: str
    doc_id: int | None
    confidence: int
    signal_type: str = ""
    score: float = 0.0
    relevance_debug: dict[str, Any] | None = None
    is_boilerplate: bool = False
    weight: float = 1.0
    evidence_kind: str = "UNKNOWN"
    quality_tier: str = "LOW"
    rationale: str = ""


@dataclass(slots=True)
class HypothesisCard:
    id: int
    risk_type: str
    title: str
    description: str
    likelihood: str
    likelihood_rationale: str
    impact: str
    impact_rationale: str
    evidence_refs: list[EvidenceRef] = field(default_factory=list)
    assumptions: list[str] = field(default_factory=list)
    gaps_to_verify: list[str] = field(default_factory=list)
    defensive_actions: list[str] = field(default_factory=list)


def _confidence_from_row(row: dict) -> int:
    raw = row.get("confidence")
    if isinstance(raw, (int, float)):
        return max(1, min(100, int(raw)))
    score = row.get("score")
    if isinstance(score, (int, float)):
        return max(1, min(100, int(float(score) * 100)))
    return 50


def _signal_type_from_quality(
    *,
    url: str,
    snippet: str,
    query_id: str,
    evidence_kind: str,
) -> str:
    kind = (evidence_kind or "UNKNOWN").strip().upper()
    if kind == "WORKFLOW_VENDOR":
        return "VENDOR_CUE"
    if kind == "CONTACT_CHANNEL":
        return "CONTACT_CHANNEL"
    if kind == "NEWS_MENTION":
        return "EXTERNAL_ATTENTION"
    if kind == "ORG_ROLE":
        return "ORG_CUE"
    if kind == "PROCUREMENT":
        return "PROCESS_CUE"
    if kind == "GENERIC_WEB":
        return "UNCLASSIFIED"
    return infer_signal_type(url, snippet, query_id=query_id)


def _normalize_sections(retrieved_passages_by_query: Any) -> list[dict]:
    if isinstance(retrieved_passages_by_query, dict):
        sections = retrieved_passages_by_query.get("sections")
        if isinstance(sections, list):
            return sections
    if isinstance(retrieved_passages_by_query, list):
        return [x for x in retrieved_passages_by_query if isinstance(x, dict)]
    return []


def _stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _normalized_sections_for_fingerprint(sections: list[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized_sections: list[dict[str, Any]] = []
    for section in sections:
        query_id = str(section.get("query_id", "")).strip()
        query_text = str(section.get("query", "")).strip()
        citations: list[dict[str, Any]] = []
        for candidate in section.get("findings_candidates") or []:
            if not isinstance(candidate, dict):
                continue
            for cite in candidate.get("citations") or []:
                if not isinstance(cite, dict):
                    continue
                citations.append(
                    {
                        "doc_id": int(cite["doc_id"]) if str(cite.get("doc_id", "")).isdigit() else None,
                        "url": str(cite.get("url", "")).strip(),
                        "title": str(cite.get("title", "")).strip(),
                        "snippet": str(cite.get("snippet", "")).strip(),
                        "score": round(float(cite.get("score", 0.0) or 0.0), 6),
                    }
                )
        citations.sort(
            key=lambda c: (
                -float(c.get("score", 0.0) or 0.0),
                str(c.get("url", "")),
                str(c.get("title", "")),
                str(c.get("snippet", "")),
                int(c.get("doc_id", 0) or 0),
            )
        )
        normalized_sections.append(
            {
                "query_id": query_id,
                "query": query_text,
                "top1_score": round(float(section.get("top1_score", 0.0) or 0.0), 6),
                "threshold_score": round(float(section.get("threshold_score", 0.0) or 0.0), 6),
                "min_ratio": round(float(section.get("min_ratio", 0.0) or 0.0), 6),
                "information_gaps": sorted([str(x).strip() for x in (section.get("information_gaps") or []) if str(x).strip()]),
                "citations": citations,
            }
        )
    normalized_sections.sort(key=lambda s: (str(s.get("query_id", "")), str(s.get("query", ""))))
    return normalized_sections


def _compute_input_fingerprint(
    *,
    assessment_id: int,
    sections: list[dict[str, Any]],
    provider: str,
    model: str,
    confidence_threshold: int,
    allow_local_fallback: bool,
    force_local_mode: bool,
) -> str:
    payload = {
        "engine_version": REASONER_ENGINE_VERSION,
        "prompt_version": REASONER_PROMPT_VERSION,
        "assessment_id": int(assessment_id),
        "provider": _normalize_provider(provider),
        "model": str(model or ""),
        "confidence_threshold": int(confidence_threshold),
        "temperature": LLM_STABLE_TEMPERATURE,
        "top_p": LLM_STABLE_TOP_P,
        "allow_local_fallback": bool(allow_local_fallback),
        "force_local_mode": bool(force_local_mode),
        "sections": _normalized_sections_for_fingerprint(sections),
    }
    return hashlib.sha256(_stable_json(payload).encode("utf-8", errors="ignore")).hexdigest()


def _snapshot_dir() -> Path:
    path = get_settings().runtime_dir / "exports" / "hypothesis_cache"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _snapshot_path(assessment_id: int, fingerprint: str) -> Path:
    safe_fp = str(fingerprint or "").strip().lower()[:128]
    return _snapshot_dir() / f"assessment_{int(assessment_id)}_{safe_fp}.json"


def _load_snapshot(assessment_id: int, fingerprint: str) -> dict[str, Any] | None:
    path = _snapshot_path(assessment_id, fingerprint)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        logger.exception("Failed to load hypothesis snapshot for assessment %s", assessment_id)
        return None
    if not isinstance(data, dict):
        return None
    if str(data.get("input_fingerprint", "")).strip().lower() != str(fingerprint).strip().lower():
        return None
    return data


def _extract_evidence(section: dict) -> list[EvidenceRef]:
    refs: list[EvidenceRef] = []
    findings_candidates = section.get("findings_candidates") or []
    for candidate in findings_candidates:
        if not isinstance(candidate, dict):
            continue
        citations = candidate.get("citations") or []
        for cite in citations:
            if not isinstance(cite, dict):
                continue
            q = classify_evidence(
                url=str(cite.get("url", "")),
                title=str(cite.get("title", "")),
                snippet=str(cite.get("snippet", "")),
                source_type=("pdf" if str(cite.get("url", "")).lower().endswith(".pdf") else "html"),
                connector="rag_retrieval",
                raw={},
            )
            bp = bool(q.is_boilerplate) or _is_boilerplate(
                url=str(cite.get("url", "")),
                title=str(cite.get("title", "")),
                snippet=str(cite.get("snippet", "")),
            )
            signal_type = _signal_type_from_quality(
                url=str(cite.get("url", "")),
                snippet=str(cite.get("snippet", "")),
                query_id=str(section.get("query_id", ""))[:16],
                evidence_kind=q.evidence_kind,
            )
            refs.append(
                EvidenceRef(
                    url=str(cite.get("url", ""))[:1024],
                    title=str(cite.get("title", ""))[:255],
                    snippet=str(cite.get("snippet", ""))[:1200],
                    doc_id=int(cite["doc_id"]) if str(cite.get("doc_id", "")).isdigit() else None,
                    confidence=_confidence_from_row(cite),
                    signal_type=signal_type,
                    score=float(cite.get("score", 0.0) or 0.0),
                    is_boilerplate=bool(bp),
                    weight=0.1 if bp else float(q.quality_weight),
                    evidence_kind=str(q.evidence_kind),
                    quality_tier=str(q.quality_tier),
                    rationale=str(q.rationale)[:220],
                )
            )

    # Unique by url+snippet preserving order.
    deduped: list[EvidenceRef] = []
    seen: set[str] = set()
    for row in refs:
        key = f"{row.url}|{row.snippet[:200]}"
        if key in seen:
            continue
        seen.add(key)
        deduped.append(row)
    return deduped[:8]


def _avg_confidence(rows: list[EvidenceRef]) -> int:
    if not rows:
        return 0
    return int(sum(r.confidence for r in rows) / len(rows))


def _signal_meta(
    *,
    evidence_refs: list[EvidenceRef],
    query_id: str,
    sector: str,
    risk_type: str = "",
) -> tuple[int, dict[str, Any], list[str]]:
    evidence_items = []
    for r in evidence_refs:
        evidence_items.append(
            {
                "url": r.url,
                "snippet": r.snippet,
                "confidence": r.confidence,
                "signal_type": (r.signal_type or "").strip().upper(),
                "query_id": query_id,
                "is_boilerplate": bool(r.is_boilerplate),
                "weight": float(r.weight or 1.0),
                "quality_tier": str(r.quality_tier or "LOW"),
                "evidence_kind": str(r.evidence_kind or "UNKNOWN"),
            }
        )
    base_avg = _avg_confidence(evidence_refs)
    conf, meta = compute_hypothesis_confidence(
        evidence_items,
        base_avg=base_avg,
        sector=sector or "",
        risk_type=risk_type or "",
    )
    missing = [f"Missing: {name}" for name in (meta.get("missing_signals") or [])]
    return conf, meta, missing


def _severity_from_likelihood_and_impact(likelihood: str, impact: str) -> int:
    lmap = {"low": 2, "med": 3, "high": 4}
    severity = lmap.get(likelihood, 3)
    if impact in {"financial", "safety"}:
        severity += 1
    return max(1, min(5, severity))


def _contains_prohibited_content(values: list[str]) -> bool:
    for value in values:
        if PROHIBITED_PATTERN.search(value or ""):
            return True
    return False


def _safe_lines(value: str, max_lines: int) -> str:
    lines = [line.strip() for line in str(value or "").splitlines() if line.strip()]
    if not lines:
        return ""
    return "\n".join(lines[:max_lines])


def _safe_list(values: Any, max_items: int = 8) -> list[str]:
    if not isinstance(values, list):
        return []
    rows: list[str] = []
    for item in values:
        text = str(item or "").strip()
        if not text:
            continue
        rows.append(text[:300])
        if len(rows) >= max_items:
            break
    return rows


def _contextual_title(risk_type: str, sector: str) -> str:
    rkey = (risk_type or "other").strip().lower()
    sector_norm = (sector or "").strip().lower()

    if "hospital" in sector_norm or "hospitality" in sector_norm or "hotel" in sector_norm:
        mapping = {
            "impersonation": "Brand impersonation risk targeting guests",
            "downstream_pivot": "Client impersonation risk affecting guests/partners",
            "fraud_process": "Reservation change and payment diversion risk",
            "brand_abuse": "Brand abuse risk across public channels",
            "social_engineering_risk": "Role-based social engineering risk (public org cues)",
            "credential_theft_risk": "Account recovery confusion risk via support channels",
            "privacy_data_risk": "Guest data privacy risk (public policy cues)",
        }
        return mapping.get(rkey, "Operational trust-channel abuse risk")

    if "ngo" in sector_norm or "nonprofit" in sector_norm:
        mapping = {
            "impersonation": "Impersonation risk targeting donors/beneficiaries",
            "downstream_pivot": "Client impersonation risk affecting donors/beneficiaries",
            "fraud_process": "Donation verification and payment diversion risk",
            "brand_abuse": "Brand abuse risk across campaign channels",
            "social_engineering_risk": "Role-based social engineering risk (public org cues)",
            "privacy_data_risk": "Beneficiary data privacy risk (public policy cues)",
        }
        return mapping.get(rkey, "Operational trust-channel abuse risk")

    mapping = {
        "impersonation": "Impersonation risk via public channels",
        "downstream_pivot": "Client impersonation risk",
        "fraud_process": "Process fraud risk via external channels",
        "brand_abuse": "Brand abuse risk",
        "credential_theft_risk": "Credential theft confusion risk",
        "social_engineering_risk": "Social engineering opportunity risk",
        "privacy_data_risk": "Customer data privacy risk",
    }
    return mapping.get(rkey, "Risk scenario")


def _norm_text(value: str) -> str:
    return " ".join(str(value or "").split()).strip().lower()


def _url_host_path(url: str) -> tuple[str, str]:
    raw = (url or "").strip()
    try:
        u = urlparse(raw)
        host = (u.netloc or "").lower().split(":")[0]
        path = (u.path or "/").lower()
        return host, path
    except Exception:
        return "", ""


def _anchors_for_risk_type(risk_type: str, *, query_id: str = "", sector: str = "") -> dict[str, list[str]]:
    """
    Claim-anchor sets used to validate that retrieved passages are relevant to the scenario risk type.
    Conservative: lack of anchors -> no claim.
    """
    rt = (risk_type or "other").strip().lower()
    sector_norm = (sector or "").strip().lower()

    hosp = any(k in sector_norm for k in ("hotel", "hospital", "hospitality", "resort", "travel"))
    ngo = any(k in sector_norm for k in ("ngo", "nonprofit", "non-profit", "aid", "charity", "humanitarian"))

    common_contact = [
        "contact",
        "email",
        "phone",
        "telephone",
        "press contact",
        "support",
        "help",
        "ticket",
        "billing",
        "invoice",
        "payment",
        "onboarding",
        "portal",
        "account",
        "concierge",
        "reservation",
        "booking",
        "refund",
        "contatto",
        "telefono",
        "fattura",
        "pagamento",
        "prenot",
        "rimborso",
    ]

    if rt in {"impersonation", "downstream_pivot"}:
        anchors = list(
            dict.fromkeys(
                common_contact
                + (["guest", "guests"] if hosp else [])
                + (["donor", "beneficiary", "beneficiaries"] if ngo else [])
            )
        )
        url_hints = [
            "/contact",
            "/support",
            "/help",
            "/billing",
            "/booking",
            "/reservation",
            "/concierge",
            "/portal",
            "/onboarding",
        ]
        return {"anchors": anchors, "url_hints": url_hints}

    if rt in {"fraud_process"}:
        anchors = [
            "invoice",
            "billing",
            "payment",
            "refund",
            "reservation",
            "booking",
            "verification",
            "confirm",
            "change request",
            "update",
            "purchase order",
            "procurement",
            "supplier",
            "onboarding",
            "escalation",
            "callback",
            "fattura",
            "pagamento",
            "rimborso",
            "prenot",
            "fornitore",
            "ordine d'acquisto",
            "approv",
            "verifica",
        ]
        url_hints = [
            "/billing",
            "/invoice",
            "/refund",
            "/booking",
            "/reservation",
            "/procurement",
            "/suppliers",
            "/terms",
            "/polic",
        ]
        return {"anchors": anchors, "url_hints": url_hints}

    if rt in {"credential_theft_risk"}:
        anchors = [
            "login",
            "sign in",
            "password",
            "reset",
            "account recovery",
            "two factor",
            "mfa",
            "sso",
            "helpdesk",
            "support portal",
            "access",
            "autentic",
            "recuper",
        ]
        url_hints = ["/login", "/signin", "/reset", "/account", "/support", "/help", "/portal"]
        return {"anchors": anchors, "url_hints": url_hints}

    if rt in {"brand_abuse"}:
        anchors = [
            "brand",
            "logo",
            "press kit",
            "media kit",
            "trademark",
            "official",
            "domain",
            "social",
            "press",
            "media",
            "marchio",
        ]
        url_hints = ["/brand", "/press", "/media", "/news", "/downloads", "/assets"]
        return {"anchors": anchors, "url_hints": url_hints}

    if rt in {"social_engineering_risk"}:
        anchors = [
            "director",
            "manager",
            "head of",
            "team",
            "finance",
            "it",
            "hr",
            "procurement",
            "communications",
            "press office",
            "dpo",
            "concierge",
            "reservations",
            "org chart",
            "organigram",
            "direttore",
            "responsabile",
            "ufficio stampa",
            "finanza",
            "risorse umane",
        ]
        url_hints = ["/team", "/about", "/leadership", "/org", "/contact", "/press"]
        return {"anchors": anchors, "url_hints": url_hints}

    if rt in {"privacy_data_risk"} or (str(query_id or "").strip().upper() == "Q6"):
        anchors = [
            "privacy",
            "gdpr",
            "data protection",
            "data subject",
            "rights",
            "request",
            "dpo",
            "personal data",
            "processing",
            "contact privacy",
            "cookie",
            "informativa",
            "protezione dati",
            "diritti",
            "richiesta",
            "dati personali",
        ]
        url_hints = ["/privacy", "/polic", "/terms", "/security", "/compliance"]
        return {"anchors": anchors, "url_hints": url_hints}

    return {"anchors": ["contact", "policy", "support", "billing", "partner", "vendor"], "url_hints": []}


def _anchor_match_info(*, title: str, snippet: str, anchors: list[str]) -> tuple[int, list[str]]:
    text = f"{_norm_text(title)} {_norm_text(snippet)}"
    matched: list[str] = []
    for a in anchors or []:
        aa = _norm_text(a)
        if not aa:
            continue
        if aa in text:
            matched.append(a)
    uniq = list(dict.fromkeys(matched))
    return len(uniq), uniq[:10]


def _url_or_title_hint(*, url: str, title: str, url_hints: list[str], anchors: list[str]) -> bool:
    low_url = (url or "").lower()
    low_title = (title or "").lower()
    if any(h and h in low_url for h in (url_hints or [])):
        return True
    _, path = _url_host_path(url)
    for a in anchors or []:
        aa = _norm_text(a)
        if not aa or len(aa) < 4:
            continue
        if aa in low_title or aa in path:
            return True
    return False


def _filter_evidence_relevance(
    *,
    risk_type: str,
    query_id: str,
    sector: str,
    evidence_refs: list[EvidenceRef],
    section_top1_score: float,
    admin_debug: bool,
) -> tuple[list[EvidenceRef], dict[str, Any] | None]:
    """
    Strict evidence filter:
    - score must be >= 0.75 * top1 (per-query)
    - passage must match claim anchors: >=2 anchor hits OR (>=1 hit + url/title hint)
    """
    cfg = _anchors_for_risk_type(risk_type, query_id=query_id, sector=sector)
    anchors = cfg.get("anchors", [])
    url_hints = cfg.get("url_hints", [])

    top1 = float(section_top1_score or 0.0)
    min_score = (0.75 * top1) if top1 > 0 else 0.0

    accepted: list[EvidenceRef] = []
    rejected_debug: list[dict[str, Any]] = []
    for ev in evidence_refs or []:
        if bool(ev.is_boilerplate) or float(ev.weight or 1.0) < 0.5:
            if admin_debug:
                rejected_debug.append(
                    {
                        "url": ev.url,
                        "title": ev.title,
                        "score": round(float(ev.score or 0.0), 4),
                        "anchor_hits": 0,
                        "anchors_matched": [],
                        "url_title_hint": False,
                        "min_score": round(min_score, 4),
                        "reasons": ["boilerplate_or_low_weight"],
                    }
                )
            continue
        score = float(ev.score or 0.0)
        score_ok = score >= min_score if min_score > 0 else True
        hit_count, matched = _anchor_match_info(title=ev.title, snippet=ev.snippet, anchors=anchors)
        hint_ok = _url_or_title_hint(url=ev.url, title=ev.title, url_hints=url_hints, anchors=anchors)
        anchors_ok = (hit_count >= 2) or (hit_count >= 1 and hint_ok)

        if score_ok and anchors_ok:
            if admin_debug:
                ratio = (score / top1) if top1 > 0 else None
                ev.relevance_debug = {
                    "accepted": True,
                    "score": round(score, 4),
                    "top1_score": round(top1, 4),
                    "score_ratio": round(ratio, 4) if ratio is not None else None,
                    "anchor_hits": int(hit_count),
                    "anchors_matched": matched,
                    "url_title_hint": bool(hint_ok),
                    "min_score": round(min_score, 4),
                }
            accepted.append(ev)
        else:
            if admin_debug:
                reasons: list[str] = []
                if not score_ok:
                    reasons.append("score_below_0.75_top1")
                if not anchors_ok:
                    reasons.append("anchor_mismatch")
                ratio = (score / top1) if top1 > 0 else None
                rejected_debug.append(
                    {
                        "url": ev.url,
                        "title": ev.title,
                        "score": round(score, 4),
                        "top1_score": round(top1, 4),
                        "score_ratio": round(ratio, 4) if ratio is not None else None,
                        "anchor_hits": int(hit_count),
                        "anchors_matched": matched,
                        "url_title_hint": bool(hint_ok),
                        "min_score": round(min_score, 4),
                        "reasons": reasons,
                    }
                )

    # Graceful fallback: if strict anchor/score matching rejects everything,
    # keep the best available items (still bounded) so the risk pipeline can
    # produce watchlist scenarios instead of an empty output.
    if not accepted:
        candidates = [
            ev for ev in (evidence_refs or []) if (not bool(ev.is_boilerplate)) and float(ev.weight or 0.0) >= 0.25
        ]
        if not candidates:
            candidates = [ev for ev in (evidence_refs or []) if not bool(ev.is_boilerplate)]
        if not candidates:
            candidates = list(evidence_refs or [])

        if candidates:
            candidates = sorted(
                candidates,
                key=lambda x: (
                    -float(x.score or 0.0),
                    str(x.url or ""),
                    str(x.title or ""),
                    str(x.snippet or ""),
                    int(x.doc_id or 0),
                ),
            )
            soft_min = (0.50 * top1) if top1 > 0 else 0.0
            soft = [ev for ev in candidates if (float(ev.score or 0.0) >= soft_min if soft_min > 0 else True)]
            chosen = soft if soft else candidates
            accepted = chosen[: max(2, min(8, len(chosen)))]
            if admin_debug:
                for ev in accepted:
                    ev.relevance_debug = {
                        "accepted": True,
                        "mode": "relaxed_fallback",
                        "score": round(float(ev.score or 0.0), 4),
                        "top1_score": round(top1, 4),
                        "min_score_soft": round(soft_min, 4),
                    }

    debug_blob = None
    if admin_debug:
        debug_blob = {
            "risk_type": (risk_type or "other"),
            "query_id": query_id,
            "top1_score": round(top1, 4),
            "min_score": round(min_score, 4),
            "accepted": len(accepted),
            "accepted_mode": "strict_or_relaxed",
            "rejected": rejected_debug[:25],
        }
    return accepted[:8], debug_blob


def _evidence_fingerprint(evidence_refs: list[EvidenceRef]) -> tuple[str, set[str]]:
    keys: list[str] = []
    urlset: set[str] = set()
    for ev in evidence_refs or []:
        if bool(ev.is_boilerplate) or float(ev.weight or 1.0) < 0.5:
            continue
        raw = (ev.url or "").strip().lower()
        if not raw:
            continue
        host, path = _url_host_path(raw)
        base = f"{host}{path}"
        keys.append(base)
        urlset.add(base)
    keys_sorted = sorted(set(keys))
    blob = "|".join(keys_sorted)[:8000]
    return hashlib.sha1(blob.encode("utf-8", errors="ignore")).hexdigest(), urlset


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    inter = len(a.intersection(b))
    union = len(a.union(b))
    return float(inter) / float(union) if union else 0.0


@dataclass(slots=True)
class _ScenarioCandidate:
    query_id: str
    query_text: str
    payload: dict[str, Any]
    evidence_refs: list[EvidenceRef]
    conf_score: int
    meta: dict[str, Any]
    merged_from: int = 1
    merged_query_ids: list[str] = field(default_factory=list)
    relevance_debug: dict[str, Any] | None = None


def _canonical_key(*, payload: dict[str, Any], meta: dict[str, Any]) -> str:
    rt = str(payload.get("risk_type", "other")).strip().lower()
    impact = str(payload.get("impact", "ops")).strip().lower()
    counts = meta.get("signal_counts") if isinstance(meta.get("signal_counts"), dict) else {}
    top = sorted(
        [(k, int(v or 0)) for k, v in (counts or {}).items() if int(v or 0) > 0],
        key=lambda x: (-x[1], x[0]),
    )
    top_keys = [k for k, _ in top[:3]]
    return f"{rt}|{impact}|{','.join(top_keys)}"


def _merge_scenarios(candidates: list[_ScenarioCandidate]) -> list[_ScenarioCandidate]:
    """
    Merge near-duplicate scenarios (same canonical key or similar evidence).
    """
    merged: list[_ScenarioCandidate] = []
    for cand in sorted(
        candidates,
        key=lambda c: (
            -int(c.conf_score or 0),
            -len(c.evidence_refs or []),
            str(c.query_id or ""),
            str(c.payload.get("risk_type", "") if isinstance(c.payload, dict) else ""),
        ),
    ):
        fp, urlset = _evidence_fingerprint(cand.evidence_refs)
        ckey = _canonical_key(payload=cand.payload, meta=cand.meta)

        match_idx: int | None = None
        for idx, existing in enumerate(merged):
            e_fp, e_set = _evidence_fingerprint(existing.evidence_refs)
            ekey = _canonical_key(payload=existing.payload, meta=existing.meta)
            if ckey == ekey:
                match_idx = idx
                break
            if cand.payload.get("risk_type") == existing.payload.get("risk_type") and _jaccard(urlset, e_set) >= 0.6:
                match_idx = idx
                break
            if fp == e_fp and cand.payload.get("risk_type") == existing.payload.get("risk_type"):
                match_idx = idx
                break

        if match_idx is None:
            cand.merged_query_ids = [cand.query_id]
            merged.append(cand)
            continue

        target = merged[match_idx]
        target.merged_from += 1
        if cand.query_id not in target.merged_query_ids:
            target.merged_query_ids.append(cand.query_id)

        combined = list(target.evidence_refs) + list(cand.evidence_refs)
        uniq: list[EvidenceRef] = []
        seen: set[str] = set()
        for ev in combined:
            k = f"{(ev.url or '').strip().lower()}|{(ev.snippet or '')[:160].strip().lower()}"
            if not k or k in seen:
                continue
            seen.add(k)
            uniq.append(ev)
        target.evidence_refs = uniq[:6]

        if cand.conf_score > target.conf_score:
            target.payload = cand.payload
            target.conf_score = cand.conf_score
            target.meta = cand.meta
            if cand.relevance_debug:
                target.relevance_debug = cand.relevance_debug

    return merged


def _is_policy_url(url: str) -> bool:
    low = (url or "").lower()
    return any(x in low for x in ("/privacy", "/terms", "/cookie", "/polic", "/gdpr"))


def _text_has_any(text: str, patterns: tuple[str, ...]) -> bool:
    t = _norm_text(text)
    return any(p for p in patterns if _norm_text(p) and _norm_text(p) in t)


def _data_sensitivity_kinds(evidence_refs: list[EvidenceRef]) -> set[str]:
    kinds: set[str] = set()
    for ev in evidence_refs or []:
        if bool(ev.is_boilerplate) or float(ev.weight or 1.0) < 0.5:
            continue
        blob = f"{ev.title} {ev.snippet}"
        low = _norm_text(blob)
        if any(
            x in low
            for x in (
                "password",
                "credential",
                "credenzial",
                "login details",
                "dettagli di accesso",
                "reset password",
                "account recovery",
            )
        ):
            kinds.add("CREDENTIALS")
        if any(
            x in low
            for x in (
                "booking",
                "reservation",
                "prenot",
                "payment",
                "invoice",
                "billing",
                "fattura",
                "pagamento",
                "refund",
                "rimborso",
            )
        ):
            kinds.add("BOOKING_PAYMENT")
        if any(x in low for x in ("loyalty", "fedelt", "points", "punti")):
            kinds.add("LOYALTY")
        if any(
            x in low
            for x in ("chat conversation", "chat transcript", "conversation details", "dettagli conversazione", "chat")
        ):
            kinds.add("CHAT")
        if _text_has_any(low, DATA_SENS_HIGH_PATTERNS):
            kinds.add("HIGH_SENS_GENERIC")
    # If only a generic hit exists, keep it as "HIGH_SENS" without pretending specificity.
    if kinds and kinds == {"HIGH_SENS_GENERIC"}:
        return {"HIGH_SENS"}
    if "HIGH_SENS_GENERIC" in kinds:
        kinds.remove("HIGH_SENS_GENERIC")
    return kinds


SENSITIVE_ORG_ROLE_HINTS = (
    "finance",
    "billing",
    "invoice",
    "payment",
    "reservations",
    "reservation",
    "booking",
    "procurement",
    "supplier",
    "it ",
    "security",
    "dpo",
    "data protection",
    "account recovery",
    "loyalty",
    "refund",
)


def _org_sensitive_function_present(evidence_refs: list[EvidenceRef]) -> bool:
    for ev in evidence_refs or []:
        if bool(ev.is_boilerplate) or float(ev.weight or 1.0) < 0.5:
            continue
        if (ev.signal_type or "").strip().upper() != "ORG_CUE":
            continue
        low = _norm_text(f"{ev.title} {ev.snippet}")
        if any(h in low for h in SENSITIVE_ORG_ROLE_HINTS):
            return True
    return False


def _has_channel_coupling(evidence_refs: list[EvidenceRef]) -> bool:
    """
    Channel coupling: sensitive tokens + channel mentions in the same document or nearby passage.
    Best-effort approximation using the retrieved passages and doc_id grouping.
    """
    by_doc: dict[int, dict[str, bool]] = {}
    any_sensitive = False
    any_channel = False
    for ev in evidence_refs or []:
        if bool(ev.is_boilerplate) or float(ev.weight or 1.0) < 0.5:
            continue
        blob = f"{ev.title} {ev.snippet}"
        low = _norm_text(blob)
        is_sensitive = _text_has_any(low, DATA_SENS_HIGH_PATTERNS)
        is_channel = (
            _text_has_any(low, CHANNEL_HINT_PATTERNS)
            or bool(re.search(r"@[a-z0-9.-]+\\.[a-z]{2,}", ev.snippet or "", re.IGNORECASE))
            or (ev.signal_type or "").upper() == "CONTACT_CHANNEL"
        )
        any_sensitive = any_sensitive or is_sensitive
        any_channel = any_channel or is_channel

        if ev.doc_id is not None:
            st = by_doc.setdefault(int(ev.doc_id), {"sens": False, "chan": False})
            st["sens"] = st["sens"] or is_sensitive
            st["chan"] = st["chan"] or is_channel

        # "Nearby passage" approximation: in the same snippet, co-occurrence counts.
        if is_sensitive and is_channel:
            return True

    if not (any_sensitive and any_channel):
        return False

    # Same document coupling.
    for st in by_doc.values():
        if st.get("sens") and st.get("chan"):
            return True
    return False


def _trust_friction_for_assessment(assessment_id: int) -> bool:
    """
    TRUST_FRICTION is True when the indexed corpus does NOT contain official channel verification guidance.
    This is a best-effort text scan (no over-claiming): absence in the corpus implies friction.
    """
    with SessionLocal() as db:
        rows = (
            db.execute(
                select(Document.extracted_text).where(
                    Document.assessment_id == assessment_id,
                    Document.extracted_text != "",
                )
            )
            .scalars()
            .all()
        )
    # Keep cost bounded: stop after enough text.
    scanned = 0
    for text in rows[:160]:
        scanned += 1
        if _text_has_any(text, TRUST_GUIDANCE_PATTERNS):
            return False
    _ = scanned
    return True


def _call_reasoner_llm(
    *,
    provider: str,
    api_key: str,
    model: str,
    query_id: str,
    query_text: str,
    evidence_refs: list[EvidenceRef],
    sector: str,
    company_name: str,
) -> dict[str, Any] | None:
    evidence_blob = "\n".join(
        f"- url={r.url}\n  snippet={r.snippet}\n  doc_id={r.doc_id}\n  confidence={r.confidence}\n  signal_type={r.signal_type}"
        for r in evidence_refs
    )
    counts: dict[str, int] = {}
    for r in evidence_refs:
        key = (r.signal_type or "").strip().upper() or "UNKNOWN"
        counts[key] = counts.get(key, 0) + 1
    signal_summary = ", ".join(
        f"{SIGNAL_LABELS.get(k, k)}={v}" for k, v in sorted(counts.items(), key=lambda x: (-x[1], x[0]))
    )
    system_prompt = (
        "You are a senior defensive cyber risk analyst and CTI advisor. "
        "Never produce phishing templates, spearphishing messages, offensive steps, or exploit guidance. "
        "Only synthesize evidence into descriptive risk scenarios, assumptions, verification gaps, and defensive actions."
    )
    user_prompt = (
        "Generate one risk scenario card in JSON only.\n"
        f"Query ID: {query_id}\n"
        f"Query: {query_text}\n"
        f"Target organization: {company_name}\n"
        f"Sector: {sector or 'Unknown'}\n"
        f"Evidence signal mix (heuristic): {signal_summary}\n"
        "Evidence:\n"
        f"{evidence_blob}\n\n"
        "Schema keys required:\n"
        "- risk_type (impersonation/fraud_process/credential_theft_risk/brand_abuse/downstream_pivot/social_engineering_risk/privacy_data_risk/other)\n"
        "- title\n"
        "- description (5-7 lines max, probabilistic language)\n"
        "- likelihood (low/med/high)\n"
        "- likelihood_rationale\n"
        "- impact (ops/financial/reputation/safety)\n"
        "- impact_rationale\n"
        "- assumptions (array)\n"
        "- gaps_to_verify (array)\n"
        "- defensive_actions (array; defensive only)\n"
        "\nStyle guidance:\n"
        "- Keep 'title' short (<= 9 words) and sector-specific.\n"
        "- Be contextual to sector/touchpoints (avoid generic statements like 'public emails exist').\n"
        "- Do NOT claim ongoing malicious activity; describe opportunity and uncertainty.\n"
        "- Keep 'description' concise and defensible.\n"
    )
    provider_norm = _normalize_provider(provider)
    model_name = str(model or "").strip()
    api_key_clean = str(api_key or "").strip()
    if provider_norm == "local" or not model_name or not api_key_clean:
        return None

    try:
        if provider_norm == "anthropic":
            payload = {
                "model": model_name,
                "temperature": LLM_STABLE_TEMPERATURE,
                "max_tokens": 1400,
                "system": system_prompt,
                "messages": [
                    {
                        "role": "user",
                        "content": f"{user_prompt}\n\nReturn valid JSON only.",
                    }
                ],
            }
            headers = {
                "x-api-key": api_key_clean,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            }
            res = _post_llm_with_backoff(
                url="https://api.anthropic.com/v1/messages",
                payload=payload,
                headers=headers,
                timeout_seconds=40,
                caller="Reasoner",
            )
        else:
            payload = {
                "model": model_name,
                "temperature": LLM_STABLE_TEMPERATURE,
                "top_p": LLM_STABLE_TOP_P,
                "response_format": {"type": "json_object"},
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
            }
            headers = {"Authorization": f"Bearer {api_key_clean}", "Content-Type": "application/json"}
            res = _post_llm_with_backoff(
                url="https://api.openai.com/v1/chat/completions",
                payload=payload,
                headers=headers,
                timeout_seconds=30,
                caller="Reasoner",
            )

        if res is None:
            logger.warning("Reasoner LLM request failed after retry attempts without response")
            return None
        if res.status_code >= 400:
            logger.warning("Reasoner LLM request failed: status=%s body=%s", res.status_code, res.text[:400])
            return None
        body = res.json()
        if provider_norm == "anthropic":
            content = _extract_anthropic_text(body)
        else:
            content = _extract_openai_text(body)
        parsed = _parse_json_object_text(content)
        return parsed if isinstance(parsed, dict) else None
    except Exception:
        logger.exception("Reasoner LLM request failed unexpectedly")
        return None


def _local_reasoner_payload(
    *,
    query_id: str,
    query_text: str,
    evidence_refs: list[EvidenceRef],
    avg_conf: int,
    section_gaps: list[str],
    sector: str = "",
) -> dict[str, Any]:
    risk_map = {
        "Q1": "fraud_process",
        "Q2": "brand_abuse",
        "Q3": "social_engineering_risk",
        "Q4": "impersonation",
        "Q5": "downstream_pivot",
        "Q6": "privacy_data_risk",
    }
    impact_map = {
        "Q1": "ops",
        "Q2": "reputation",
        "Q3": "ops",
        "Q4": "reputation",
        "Q5": "safety",
        "Q6": "financial",
    }
    risk_type = risk_map.get(query_id, "other")
    impact = impact_map.get(query_id, "ops")
    likelihood = "high" if avg_conf >= 76 else "med"

    top_sources = ", ".join([r.url for r in evidence_refs[:2] if r.url]) or "public evidence set"
    sector_norm = (sector or "").lower()
    contextual = ""
    if "hospital" in sector_norm or "hospitality" in sector_norm or "hotel" in sector_norm:
        if risk_type in {"impersonation", "downstream_pivot"}:
            contextual = " targeting guests via booking/billing contact paths"
        if risk_type in {"fraud_process"}:
            contextual = " via reservation changes, refunds, or billing clarifications"
    elif "ngo" in sector_norm or "nonprofit" in sector_norm:
        if risk_type in {"impersonation", "downstream_pivot"}:
            contextual = " targeting donors/beneficiaries via campaign channels"
        if risk_type in {"fraud_process"}:
            contextual = " via donation verification and partner coordination"

    title = f"{query_id} - Evidence-backed {risk_type.replace('_', ' ')} risk scenario"
    description_lines = [
        f"Based on current public evidence, there is a probable {risk_type.replace('_', ' ')} pattern{contextual}.",
        "Signals suggest this risk could be exploited through trust-based process confusion.",
        "The observed exposure does not confirm malicious activity, but it raises practical abuse potential.",
        "Likelihood remains probabilistic and depends on adversary capability and channel monitoring quality.",
        f"Current strongest references come from: {top_sources}.",
    ]
    if query_id == "Q5":
        description_lines.append(
            "A risk to clients via impersonation exists where customers/beneficiaries may be targeted through brand abuse."
        )

    assumptions = [
        "Publicly visible workflows are used by real users and partners.",
        "External actors can discover the same channels without privileged access.",
        "Current anti-impersonation controls are not uniformly enforced across all external contact channels.",
    ]
    if section_gaps:
        assumptions.append("Some conclusions are constrained by incomplete evidence coverage in the indexed corpus.")

    defensive_actions = [
        "Publish a clear verification policy for official communications and callback channels.",
        "Standardize sender identity controls across support, billing, and onboarding external contact channels.",
        "Add customer/beneficiary safety banners explaining what your teams will never request.",
        "Run periodic tabletop validation for impersonation-response workflows with operations and comms teams.",
    ]
    if query_id == "Q5":
        defensive_actions.append(
            "Deploy downstream partner alerting for suspicious identity misuse affecting clients or beneficiaries."
        )

    return {
        "risk_type": risk_type,
        "title": title,
        "description": "\n".join(description_lines),
        "likelihood": likelihood,
        "likelihood_rationale": (
            f"Average evidence confidence is {avg_conf}% with consistent references across multiple sources."
        ),
        "impact": impact,
        "impact_rationale": (
            "Potential effects include operational friction, trust loss, and avoidable escalation costs if unmitigated."
        ),
        "assumptions": assumptions,
        "gaps_to_verify": section_gaps[:6],
        "defensive_actions": defensive_actions,
    }


def _save_gap(
    *,
    assessment_id: int,
    query_id: str,
    title: str,
    description: str,
    evidence_count: int,
    avg_confidence: int,
) -> None:
    with SessionLocal() as db:
        db.add(
            Gap(
                assessment_id=assessment_id,
                query_id=query_id,
                title=title[:255],
                description=description,
                evidence_count=max(0, int(evidence_count)),
                avg_confidence=max(0, min(100, int(avg_confidence))),
            )
        )
        db.commit()


def _create_hypothesis_row(
    *,
    assessment_id: int,
    query_id: str,
    payload: dict[str, Any],
    evidence_refs: list[EvidenceRef],
    merged_from: int = 1,
    merged_query_ids: list[str] | None = None,
    relevance_debug: dict[str, Any] | None = None,
    trust_friction: bool | None = None,
    input_fingerprint: str = "",
    provider: str = "openai",
    model: str = "",
) -> Hypothesis | None:
    risk_type = str(payload.get("risk_type", "other")).strip().lower()
    if risk_type not in SAFE_RISK_TYPES:
        risk_type = "other"
    likelihood = str(payload.get("likelihood", "med")).strip().lower()
    if likelihood not in SAFE_LIKELIHOOD:
        likelihood = "med"
    impact = str(payload.get("impact", "ops")).strip().lower()
    if impact not in SAFE_IMPACT_TYPES:
        impact = "ops"

    title = str(payload.get("title", "Evidence-based risk scenario")).strip()[:255]
    description = _safe_lines(str(payload.get("description", "")).strip(), max_lines=7)[:1400]
    likelihood_rationale = str(payload.get("likelihood_rationale", "")).strip()[:1000]
    impact_rationale = str(payload.get("impact_rationale", "")).strip()[:1000]
    assumptions = _safe_list(payload.get("assumptions"), max_items=8)
    gaps_to_verify = _safe_list(payload.get("gaps_to_verify"), max_items=8)
    defensive_actions = _safe_list(payload.get("defensive_actions"), max_items=10)

    if not title or not description:
        return None

    if _contains_prohibited_content(
        [title, description, likelihood_rationale, impact_rationale, *assumptions, *gaps_to_verify, *defensive_actions]
    ):
        return None

    # Prefer contextual titles over generic placeholders.
    if "evidence-backed" in title.lower() or title.lower().startswith(("q1", "q2", "q3", "q4", "q5", "q6")):
        # Sector-aware mapping is applied later once assessment is loaded.
        pass

    severity = _severity_from_likelihood_and_impact(likelihood, impact)
    evidence_payload = [asdict(item) for item in evidence_refs]

    with SessionLocal() as db:
        assessment = db.get(Assessment, assessment_id)
        sector = (assessment.sector if assessment else "") or ""
        company_name = (assessment.company_name if assessment else "") or ""

        if "evidence-backed" in title.lower() or title.lower().startswith(("q1", "q2", "q3", "q4", "q5", "q6")):
            title = _contextual_title(risk_type, sector)[:255]

        computed_conf, meta, missing = _signal_meta(
            evidence_refs=evidence_refs,
            query_id=query_id,
            sector=sector,
            risk_type=risk_type,
        )

        # Process-aware elevation flags (evidence-first; do not over-claim).
        sens_kinds = _data_sensitivity_kinds(evidence_refs)
        data_sens_high = bool(sens_kinds)
        process_exposure_candidate = bool(data_sens_high and _has_channel_coupling(evidence_refs))

        if trust_friction is None:
            trust_friction = _trust_friction_for_assessment(assessment_id)

        # Confidence adjustment based on corpus context.
        policy_only = bool(evidence_refs) and all(_is_policy_url(r.url) for r in evidence_refs if r.url)
        has_policy = any(_is_policy_url(r.url) for r in evidence_refs if r.url)
        has_contact = int((meta.get("signal_counts") or {}).get("CONTACT_CHANNEL", 0) or 0) > 0
        has_process = int((meta.get("signal_counts") or {}).get("PROCESS_CUE", 0) or 0) > 0
        multi_section = bool(has_policy and has_contact and has_process)

        if policy_only:
            computed_conf = min(int(computed_conf), 70)
            meta["confidence_policy_only_cap"] = 70
        elif multi_section:
            computed_conf = min(int(computed_conf), 80)
            meta["confidence_multi_section_cap"] = 80

        # Hospitality baseline normality filter: do not elevate on baseline exposures only.
        sector_norm = (sector or "").strip().lower()
        is_hospitality = any(k in sector_norm for k in ("hotel", "hospital", "hospitality", "resort", "travel"))
        baseline_exposure = False
        if is_hospitality:
            c = meta.get("signal_counts") if isinstance(meta.get("signal_counts"), dict) else {}
            channel_count = int((c or {}).get("CONTACT_CHANNEL", 0) or 0) + int(
                (c or {}).get("SOCIAL_TRUST_NODE", 0) or 0
            )
            has_only_channels = (
                channel_count > 0
                and int((c or {}).get("PROCESS_CUE", 0) or 0) == 0
                and int((c or {}).get("VENDOR_CUE", 0) or 0) == 0
                and int((c or {}).get("EXTERNAL_ATTENTION", 0) or 0) == 0
                and int((c or {}).get("INFRA_CUE", 0) or 0) == 0
                and int((c or {}).get("ORG_CUE", 0) or 0) == 0
            )
            if has_only_channels:
                baseline_exposure = True

        if baseline_exposure:
            meta["baseline_exposure"] = True
            meta["tag"] = "Baseline Exposure"
            computed_conf = min(int(computed_conf), 65)
            # Impact cap = MED (severity 3) and coverage WEAK (handled after severity is computed).

        # Specialized short title for high-sensitivity handling (stakeholder friendly).
        if data_sens_high:
            low_blob = _norm_text(" ".join([f"{r.title} {r.snippet}" for r in evidence_refs[:6]]))
            if "CREDENTIALS" in sens_kinds or any(
                x in low_blob for x in ("password", "credential", "credenzial", "login details")
            ):
                title = "Credential and account handling via external channels"
            elif "BOOKING_PAYMENT" in sens_kinds or any(
                x in low_blob
                for x in ("booking", "reservation", "payment", "invoice", "billing", "prenot", "pagamento", "fattura")
            ):
                title = "Booking and payment workflow exposure"
        else:
            # Policy + DSAR/rights handling specialization
            if risk_type == "privacy_data_risk":
                low_blob = _norm_text(" ".join([f"{r.title} {r.snippet} {r.url}" for r in evidence_refs[:6]]))
                dsar = any(
                    x in low_blob
                    for x in ("data subject", "dsar", "rights request", "access request", "diritti", "richiesta", "dpo")
                )
                if dsar and has_policy:
                    title = "Data subject request handling exposure"

        # Adjust likelihood based on evidence quality rules.
        counts = meta.get("signal_counts") if isinstance(meta.get("signal_counts"), dict) else {}
        mostly_contact = bool(meta.get("mostly_contact_only", False))
        has_process = int((counts or {}).get("PROCESS_CUE", 0) or 0) > 0
        attention_spike = bool(meta.get("attention_spike", False))
        if mostly_contact:
            likelihood = "low" if computed_conf < 50 else "med"
        else:
            # HIGH likelihood is only allowed with a process cue or an external attention spike.
            if computed_conf >= 80 and (has_process or attention_spike):
                likelihood = "high"
            elif computed_conf >= 60:
                likelihood = "med"
            else:
                likelihood = "low"

        # Sector-aware impact bump: hospitality + booking/billing process cues => financial impact.
        sector_norm = sector.lower()
        if "hospital" in sector_norm or "hospitality" in sector_norm or "hotel" in sector_norm:
            if has_process and impact in {"ops", "reputation"}:
                impact = "financial"

        severity = _severity_from_likelihood_and_impact(likelihood, impact)

        # Process-aware impact escalation rule:
        # elevate ONLY when sensitivity + channel coupling + missing trust friction guidance converge.
        if data_sens_high:
            if process_exposure_candidate and bool(trust_friction):
                severity = max(int(severity), 4)
                meta["process_aware_impact"] = "HIGH"
            else:
                severity = 3
                meta["process_aware_impact"] = "MED"
            meta["data_sens_high"] = True
            meta["data_sens_kinds"] = sorted(list(sens_kinds))
            meta["process_exposure_candidate"] = bool(process_exposure_candidate)
            meta["trust_friction"] = bool(trust_friction)

        # Apply baseline caps after all other severity adjustments (baseline scenarios should not be "top elevated").
        if bool(meta.get("baseline_exposure", False)):
            severity = min(int(severity), 3)

        # Add missing signals to gaps (not as facts).
        if missing:
            gaps_to_verify = list(dict.fromkeys([*gaps_to_verify, *missing]))[:8]

        meta["coverage_label"] = coverage_label_from_signals(meta)
        meta["risk_hint"] = str(title)
        meta["merged_from"] = int(merged_from or 1)
        meta["merged_query_ids"] = merged_query_ids or ([query_id] if query_id else [])
        if relevance_debug:
            meta["relevance_debug"] = relevance_debug
        timeline = timeline_for_risk(risk_type, meta)

        signal_counts_for_storage = dict(meta.get("signal_counts", {}) or {})
        signal_counts_for_storage["__merged_from__"] = int(merged_from or 1)
        signal_counts_for_storage["__merged_query_ids__"] = merged_query_ids or ([query_id] if query_id else [])
        signal_counts_for_storage["__input_fingerprint__"] = str(input_fingerprint or "")
        signal_counts_for_storage["__engine_version__"] = REASONER_ENGINE_VERSION
        signal_counts_for_storage["__prompt_version__"] = REASONER_PROMPT_VERSION
        signal_counts_for_storage["__llm_provider__"] = _normalize_provider(provider)
        signal_counts_for_storage["__llm_model__"] = str(model or "")
        if relevance_debug:
            signal_counts_for_storage["__debug__"] = {"relevance": relevance_debug}
        if bool(meta.get("baseline_exposure", False)):
            signal_counts_for_storage["__baseline_exposure__"] = True
            signal_counts_for_storage["__tags__"] = list(
                dict.fromkeys([*(signal_counts_for_storage.get("__tags__", []) or []), "Baseline Exposure"])
            )
        if data_sens_high:
            signal_counts_for_storage["__process_flags__"] = {
                "data_sens_high": True,
                "data_sens_kinds": sorted(list(sens_kinds)),
                "process_exposure_candidate": bool(process_exposure_candidate),
                "trust_friction": bool(trust_friction),
                "process_aware_impact": str(meta.get("process_aware_impact", "")),
            }

        # Risk-first: deterministically assign stakeholder primary risk type + vector summary.
        counts = meta.get("signal_counts") if isinstance(meta.get("signal_counts"), dict) else {}
        # Diversity guard across recent assessments: if last 3 assessments yielded the same top primary type,
        # require one extra signal category to avoid repetitive "same risk every time" output.
        recent_same: str | None = None
        try:
            recent: list[str] = []
            # Collect top risk types per recent assessment (best-effort).
            recent_rows = db.execute(
                select(
                    Hypothesis.assessment_id, Hypothesis.primary_risk_type, Hypothesis.severity, Hypothesis.created_at
                )
                .where(Hypothesis.assessment_id != assessment_id, Hypothesis.primary_risk_type != "")
                .order_by(Hypothesis.created_at.desc(), Hypothesis.severity.desc())
                .limit(60)
            ).all()
            seen_assess = set()
            for aid, prt, sev, created_at in recent_rows:
                if aid in seen_assess:
                    continue
                seen_assess.add(aid)
                if prt:
                    recent.append(str(prt))
                if len(recent) >= 3:
                    break
            if len(recent) >= 3 and len(set([x.strip().lower() for x in recent])) == 1:
                recent_same = recent[0].strip().lower()
        except Exception:
            recent_same = None

        primary_risk_type, baseline_tag, risk_vector_summary, conditions, type_flags = _assign_primary_risk_type(
            signal_counts={str(k): int(v or 0) for k, v in (counts or {}).items() if str(k)},
            evidence_refs=evidence_refs,
            sector=sector,
            trust_friction=bool(trust_friction),
            diversity_guard=False,
        )
        if recent_same and str(primary_risk_type or "").strip().lower() == recent_same:
            primary_risk_type, baseline_tag, risk_vector_summary, conditions, type_flags = _assign_primary_risk_type(
                signal_counts={str(k): int(v or 0) for k, v in (counts or {}).items() if str(k)},
                evidence_refs=evidence_refs,
                sector=sector,
                trust_friction=bool(trust_friction),
                diversity_guard=True,
            )

        # Enforce baseline caps for low-quality evidence patterns (anti-repetition + conservative scoring).
        if baseline_tag or bool(meta.get("baseline_exposure", False)):
            severity = min(int(severity), 3)
            computed_conf = min(int(computed_conf), 65)
            if str(likelihood or "").strip().lower() == "high":
                likelihood = "med"
            meta["coverage_label"] = "WEAK"
            meta["baseline_tag"] = True

        # Force stakeholder title to be concrete and abuse-typed.
        # Keep short and decision-ready: "<Primary risk type> risk".
        if primary_risk_type:
            title = f"{primary_risk_type} risk"
            title = title[:1].upper() + title[1:]

        # Evidence-text integrity check: if narrative mentions concepts not present in evidence,
        # replace with deterministic, evidence-bound summary (do not regenerate scenarios here).
        vendor_hits = list(type_flags.get("vendor_hits") or [])
        wf_flags = dict(type_flags.get("workflow_flags") or {})
        integrity_flags = _risk_type_mentions_outside_evidence(
            " ".join([title, description, likelihood_rationale, impact_rationale]),
            wf=wf_flags,
            vendor_hits=vendor_hits,
        )
        if integrity_flags:
            description = _safe_lines(
                f"This assessment identifies a plausible {primary_risk_type} vector. "
                f"Enabled by {' + '.join(conditions[:3]) if conditions else 'limited public signals'}. "
                f"Evidence is incomplete; treat this as a defensive prioritization hypothesis.",
                max_lines=6,
            )[:1400]
            likelihood_rationale = (
                "Derived from distinct public signals; repetition alone does not increase confidence."
            )
            impact_rationale = (
                "Impact is a conservative estimate based on exposed channels and workflow sensitivity cues."
            )

        row = Hypothesis(
            assessment_id=assessment_id,
            query_id=query_id,
            risk_type=risk_type,
            primary_risk_type=primary_risk_type,
            risk_vector_summary=risk_vector_summary,
            baseline_tag=bool(baseline_tag),
            integrity_flags_json=safe_json_dumps({"flags": integrity_flags, "typing": type_flags}, "{}"),
            severity=severity,
            title=title,
            description=description,
            likelihood=likelihood,
            likelihood_rationale=likelihood_rationale,
            impact=impact,
            impact_rationale=impact_rationale,
            evidence_refs_json=to_json(evidence_payload),
            assumptions_json=to_json(assumptions),
            gaps_to_verify_json=to_json(gaps_to_verify),
            defensive_actions_json=to_json(defensive_actions),
            confidence=int(computed_conf),
            signal_diversity=int(meta.get("signal_diversity_count", 0) or 0),
            signal_counts_json=safe_json_dumps(signal_counts_for_storage, "{}"),
            missing_signals_json=safe_json_dumps(meta.get("missing_signals", []), "[]"),
            timeline_json=safe_json_dumps(timeline, "[]"),
        )
        db.add(row)
        db.commit()
        db.refresh(row)
        return row


def _clear_existing_outputs(assessment_id: int) -> None:
    with SessionLocal() as db:
        db.execute(delete(Hypothesis).where(Hypothesis.assessment_id == assessment_id))
        db.execute(delete(Gap).where(Gap.assessment_id == assessment_id))
        db.commit()


def _cards_from_rows(rows: list[Hypothesis]) -> list[HypothesisCard]:
    cards: list[HypothesisCard] = []
    for row in rows:
        cards.append(
            HypothesisCard(
                id=int(row.id),
                risk_type=str(row.risk_type or "other"),
                title=str(row.title or ""),
                description=str(row.description or ""),
                likelihood=str(row.likelihood or "med"),
                likelihood_rationale=str(row.likelihood_rationale or ""),
                impact=str(row.impact or "ops"),
                impact_rationale=str(row.impact_rationale or ""),
                evidence_refs=[EvidenceRef(**item) for item in json.loads(row.evidence_refs_json or "[]")],
                assumptions=json.loads(row.assumptions_json or "[]"),
                gaps_to_verify=json.loads(row.gaps_to_verify_json or "[]"),
                defensive_actions=json.loads(row.defensive_actions_json or "[]"),
            )
        )
    return cards


def _row_input_fingerprint(row: Hypothesis) -> str:
    try:
        blob = json.loads(row.signal_counts_json or "{}")
    except Exception:
        return ""
    if not isinstance(blob, dict):
        return ""
    return str(blob.get("__input_fingerprint__", "")).strip()


def _persist_snapshot(
    *,
    assessment_id: int,
    input_fingerprint: str,
    provider: str,
    model: str,
) -> None:
    with SessionLocal() as db:
        rows = (
            db.execute(
                select(Hypothesis)
                .where(Hypothesis.assessment_id == assessment_id)
                .order_by(Hypothesis.id.asc())
            )
            .scalars()
            .all()
        )
        gaps = (
            db.execute(select(Gap).where(Gap.assessment_id == assessment_id).order_by(Gap.id.asc()))
            .scalars()
            .all()
        )

    payload = {
        "assessment_id": int(assessment_id),
        "input_fingerprint": str(input_fingerprint or ""),
        "engine_version": REASONER_ENGINE_VERSION,
        "prompt_version": REASONER_PROMPT_VERSION,
        "provider": _normalize_provider(provider),
        "model": str(model or ""),
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "hypotheses": [
            {
                "query_id": str(row.query_id or ""),
                "risk_type": str(row.risk_type or "other"),
                "primary_risk_type": str(row.primary_risk_type or ""),
                "risk_vector_summary": str(row.risk_vector_summary or ""),
                "baseline_tag": bool(row.baseline_tag),
                "status": str(row.status or "WATCHLIST"),
                "plausibility_score": int(row.plausibility_score or 0),
                "potential_impact_score": int(row.potential_impact_score or 0),
                "integrity_flags_json": str(row.integrity_flags_json or "{}"),
                "severity": int(row.severity or 3),
                "title": str(row.title or ""),
                "description": str(row.description or ""),
                "likelihood": str(row.likelihood or "med"),
                "likelihood_rationale": str(row.likelihood_rationale or ""),
                "impact": str(row.impact or "ops"),
                "impact_rationale": str(row.impact_rationale or ""),
                "evidence_refs_json": str(row.evidence_refs_json or "[]"),
                "assumptions_json": str(row.assumptions_json or "[]"),
                "gaps_to_verify_json": str(row.gaps_to_verify_json or "[]"),
                "defensive_actions_json": str(row.defensive_actions_json or "[]"),
                "confidence": int(row.confidence or 0),
                "signal_diversity": int(row.signal_diversity or 0),
                "signal_counts_json": str(row.signal_counts_json or "{}"),
                "missing_signals_json": str(row.missing_signals_json or "[]"),
                "timeline_json": str(row.timeline_json or "[]"),
            }
            for row in rows
        ],
        "gaps": [
            {
                "query_id": str(gap.query_id or ""),
                "title": str(gap.title or ""),
                "description": str(gap.description or ""),
                "evidence_count": int(gap.evidence_count or 0),
                "avg_confidence": int(gap.avg_confidence or 0),
            }
            for gap in gaps
        ],
    }

    path = _snapshot_path(assessment_id, input_fingerprint)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(_stable_json(payload), encoding="utf-8")
    tmp.replace(path)


def _restore_snapshot(assessment_id: int, snapshot: dict[str, Any]) -> list[HypothesisCard]:
    with SessionLocal() as db:
        db.execute(delete(Hypothesis).where(Hypothesis.assessment_id == assessment_id))
        db.execute(delete(Gap).where(Gap.assessment_id == assessment_id))
        db.commit()

        for gap in snapshot.get("gaps") or []:
            if not isinstance(gap, dict):
                continue
            db.add(
                Gap(
                    assessment_id=assessment_id,
                    query_id=str(gap.get("query_id", ""))[:16],
                    title=str(gap.get("title", ""))[:255],
                    description=str(gap.get("description", "")),
                    evidence_count=max(0, int(gap.get("evidence_count", 0) or 0)),
                    avg_confidence=max(0, min(100, int(gap.get("avg_confidence", 0) or 0))),
                )
            )

        for row in snapshot.get("hypotheses") or []:
            if not isinstance(row, dict):
                continue
            db.add(
                Hypothesis(
                    assessment_id=assessment_id,
                    query_id=str(row.get("query_id", ""))[:16],
                    risk_type=str(row.get("risk_type", "other")),
                    primary_risk_type=str(row.get("primary_risk_type", "")),
                    risk_vector_summary=str(row.get("risk_vector_summary", "")),
                    baseline_tag=bool(row.get("baseline_tag", False)),
                    status=str(row.get("status", "WATCHLIST")),
                    plausibility_score=max(0, min(100, int(row.get("plausibility_score", 0) or 0))),
                    potential_impact_score=max(0, min(100, int(row.get("potential_impact_score", 0) or 0))),
                    integrity_flags_json=str(row.get("integrity_flags_json", "{}")),
                    severity=max(1, min(5, int(row.get("severity", 3) or 3))),
                    title=str(row.get("title", ""))[:255],
                    description=str(row.get("description", "")),
                    likelihood=str(row.get("likelihood", "med")),
                    likelihood_rationale=str(row.get("likelihood_rationale", "")),
                    impact=str(row.get("impact", "ops")),
                    impact_rationale=str(row.get("impact_rationale", "")),
                    evidence_refs_json=str(row.get("evidence_refs_json", "[]")),
                    assumptions_json=str(row.get("assumptions_json", "[]")),
                    gaps_to_verify_json=str(row.get("gaps_to_verify_json", "[]")),
                    defensive_actions_json=str(row.get("defensive_actions_json", "[]")),
                    confidence=max(0, min(100, int(row.get("confidence", 0) or 0))),
                    signal_diversity=max(0, int(row.get("signal_diversity", 0) or 0)),
                    signal_counts_json=str(row.get("signal_counts_json", "{}")),
                    missing_signals_json=str(row.get("missing_signals_json", "[]")),
                    timeline_json=str(row.get("timeline_json", "[]")),
                )
            )

        db.commit()
        restored_rows = (
            db.execute(select(Hypothesis).where(Hypothesis.assessment_id == assessment_id).order_by(Hypothesis.id.asc()))
            .scalars()
            .all()
        )
    return _cards_from_rows(restored_rows)


def _load_llm_config() -> tuple[str, str, str | None]:
    """Return selected provider/model/API key from DB settings, with env fallback."""
    with SessionLocal() as db:
        provider_row = (
            db.execute(
                select(ConnectorSetting)
                .where(ConnectorSetting.name == LLM_PROVIDER_SETTING_NAME)
                .order_by(ConnectorSetting.updated_at.desc(), ConnectorSetting.id.desc())
                .limit(1)
            )
            .scalars()
            .first()
        )
        model_row = (
            db.execute(
                select(ConnectorSetting)
                .where(ConnectorSetting.name == LLM_MODEL_SETTING_NAME)
                .order_by(ConnectorSetting.updated_at.desc(), ConnectorSetting.id.desc())
                .limit(1)
            )
            .scalars()
            .first()
        )
        openai_api_row = (
            db.execute(
                select(ConnectorSetting)
                .where(ConnectorSetting.name == LLM_OPENAI_API_SETTING_NAME)
                .order_by(ConnectorSetting.updated_at.desc(), ConnectorSetting.id.desc())
                .limit(1)
            )
            .scalars()
            .first()
        )
        anthropic_api_row = (
            db.execute(
                select(ConnectorSetting)
                .where(ConnectorSetting.name == LLM_ANTHROPIC_API_SETTING_NAME)
                .order_by(ConnectorSetting.updated_at.desc(), ConnectorSetting.id.desc())
                .limit(1)
            )
            .scalars()
            .first()
        )

    settings = get_settings()
    env_provider = _normalize_provider(getattr(settings, "llm_provider", "openai"))
    env_openai_model = (settings.openai_reasoner_model or "gpt-4.1").strip()
    env_anthropic_model = (getattr(settings, "anthropic_reasoner_model", "") or "claude-sonnet-4-6").strip()
    env_openai_api_key = (settings.openai_api_key or "").strip() or None
    env_anthropic_api_key = (getattr(settings, "anthropic_api_key", "") or "").strip() or None

    decoded_provider = (
        deobfuscate_secret(provider_row.api_key_obfuscated) if (provider_row and provider_row.api_key_obfuscated) else None
    )
    decoded_model = deobfuscate_secret(model_row.api_key_obfuscated) if (model_row and model_row.api_key_obfuscated) else None
    decoded_openai_api = (
        deobfuscate_secret(openai_api_row.api_key_obfuscated)
        if (openai_api_row and openai_api_row.api_key_obfuscated)
        else None
    )
    decoded_anthropic_api = (
        deobfuscate_secret(anthropic_api_row.api_key_obfuscated)
        if (anthropic_api_row and anthropic_api_row.api_key_obfuscated)
        else None
    )

    model = str(decoded_model or "").strip()
    provider = _normalize_provider(decoded_provider or "")
    if not decoded_provider:
        if model and model.lower().startswith("claude-"):
            provider = "anthropic"
        elif model.upper() == "LOCAL":
            provider = "local"
        else:
            provider = env_provider

    if not model:
        if provider == "anthropic":
            model = env_anthropic_model or "claude-sonnet-4-6"
        elif provider == "local":
            model = "LOCAL"
        else:
            model = env_openai_model or "gpt-4.1"

    if provider == "anthropic":
        api_key = decoded_anthropic_api or env_anthropic_api_key
    elif provider == "local":
        api_key = None
    else:
        api_key = decoded_openai_api or env_openai_api_key

    return provider, model, api_key


def _resolve_model_selection(provider: str, model: str) -> tuple[str, str, bool]:
    provider_norm = _normalize_provider(provider)
    value = (model or "").strip()
    if provider_norm == "local" or value.upper() == "LOCAL":
        return "local", "LOCAL", True
    if provider_norm == "anthropic":
        return "anthropic", (value or "claude-sonnet-4-6"), False
    if value == "gpt-4.1o":
        return "openai", "gpt-4o", False
    return "openai", (value or "gpt-4.1"), False


def generate_hypotheses(
    assessment_id: int,
    retrieved_passages_by_query: Any,
    *,
    allow_local_fallback: bool = False,
) -> list[HypothesisCard]:
    """Generate evidence-first defensive risk scenarios and persist hypotheses/gaps."""
    sections = _normalize_sections(retrieved_passages_by_query)

    with SessionLocal() as db:
        assessment = db.get(Assessment, assessment_id)
    if not assessment:
        return []
    sector = (assessment.sector or "").strip()
    company_name = (assessment.company_name or "").strip()

    settings = get_settings()
    threshold = max(1, min(100, int(settings.openai_hypothesis_confidence_threshold)))
    configured_provider, configured_model, configured_api_key = _load_llm_config()
    provider, model, force_local_mode = _resolve_model_selection(configured_provider, configured_model)
    api_key = (configured_api_key or "").strip()
    input_fingerprint = _compute_input_fingerprint(
        assessment_id=assessment_id,
        sections=sections,
        provider=provider,
        model=model,
        confidence_threshold=threshold,
        allow_local_fallback=allow_local_fallback,
        force_local_mode=force_local_mode,
    )

    with SessionLocal() as db:
        existing_rows = (
            db.execute(select(Hypothesis).where(Hypothesis.assessment_id == assessment_id).order_by(Hypothesis.id.asc()))
            .scalars()
            .all()
        )
    if existing_rows and all(_row_input_fingerprint(row) == input_fingerprint for row in existing_rows):
        logger.info("Reusing existing stable hypotheses for assessment %s", assessment_id)
        return _cards_from_rows(existing_rows)

    cached_snapshot = _load_snapshot(assessment_id, input_fingerprint)
    if cached_snapshot:
        logger.info("Replaying stable hypothesis snapshot for assessment %s", assessment_id)
        return _restore_snapshot(assessment_id, cached_snapshot)

    _clear_existing_outputs(assessment_id)

    admin_debug = bool(getattr(settings, "admin_debug_risk", False))
    trust_friction = _trust_friction_for_assessment(assessment_id)

    candidates: list[_ScenarioCandidate] = []
    for section in sections:
        query_id = str(section.get("query_id", "Q?"))[:16]
        query_text = str(section.get("query", ""))[:500]
        raw_evidence = _extract_evidence(section)
        section_gaps = [str(x) for x in section.get("information_gaps", []) if str(x).strip()]

        if len(raw_evidence) < 2:
            _save_gap(
                assessment_id=assessment_id,
                query_id=query_id,
                title=f"{query_id} information gap",
                description="Insufficient retrieved passages for scenario generation (need >= 2).",
                evidence_count=len(raw_evidence),
                avg_confidence=_avg_confidence(raw_evidence),
            )
            continue

        if force_local_mode:
            payload = _local_reasoner_payload(
                query_id=query_id,
                query_text=query_text,
                evidence_refs=raw_evidence,
                avg_conf=_avg_confidence(raw_evidence),
                section_gaps=section_gaps,
                sector=sector,
            )
        elif not api_key:
            _save_gap(
                assessment_id=assessment_id,
                query_id=query_id,
                title=f"{query_id} generation degraded",
                description="LLM API key not configured for selected provider/model. Using deterministic local synthesis.",
                evidence_count=len(raw_evidence),
                avg_confidence=_avg_confidence(raw_evidence),
            )
            payload = _local_reasoner_payload(
                query_id=query_id,
                query_text=query_text,
                evidence_refs=raw_evidence,
                avg_conf=_avg_confidence(raw_evidence),
                section_gaps=section_gaps,
                sector=sector,
            )
        else:
            payload = _call_reasoner_llm(
                provider=provider,
                api_key=api_key,
                model=model,
                query_id=query_id,
                query_text=query_text,
                evidence_refs=raw_evidence,
                sector=sector,
                company_name=company_name,
            )
            if not payload:
                _save_gap(
                    assessment_id=assessment_id,
                    query_id=query_id,
                    title=f"{query_id} generation degraded",
                    description="LLM call failed or returned invalid payload. Using deterministic local synthesis.",
                    evidence_count=len(raw_evidence),
                    avg_confidence=_avg_confidence(raw_evidence),
                )
                payload = _local_reasoner_payload(
                    query_id=query_id,
                    query_text=query_text,
                    evidence_refs=raw_evidence,
                    avg_conf=_avg_confidence(raw_evidence),
                    section_gaps=section_gaps,
                    sector=sector,
                )

        if not payload:
            continue

        risk_type = str(payload.get("risk_type", "other")).strip().lower()
        top1_score = float(section.get("top1_score", 0.0) or 0.0)
        if top1_score <= 0.0:
            top1_score = max((float(r.score or 0.0) for r in raw_evidence), default=0.0)

        filtered, rel_debug = _filter_evidence_relevance(
            risk_type=risk_type,
            query_id=query_id,
            sector=sector,
            evidence_refs=raw_evidence,
            section_top1_score=top1_score,
            admin_debug=admin_debug,
        )

        conf_score, meta, _missing = _signal_meta(
            evidence_refs=filtered,
            query_id=query_id,
            sector=sector,
            risk_type=risk_type,
        )

        weighted_count = int(meta.get("weighted_evidence_count", 0) or 0)
        if weighted_count < 2:
            _save_gap(
                assessment_id=assessment_id,
                query_id=query_id,
                title=f"{query_id} insufficient evidence",
                description="Insufficient evidence after relevance validation and boilerplate filtering (need >= 2).",
                evidence_count=int(weighted_count),
                avg_confidence=int(conf_score),
            )
            if filtered:
                # Keep weak scenarios as deterministic watchlist/baseline candidates instead of returning no risks.
                if isinstance(meta, dict):
                    meta["relaxed_gate"] = "weighted_count_lt_2"
                candidates.append(
                    _ScenarioCandidate(
                        query_id=query_id,
                        query_text=query_text,
                        payload=payload,
                        evidence_refs=filtered,
                        conf_score=int(conf_score),
                        meta=meta,
                        relevance_debug=rel_debug,
                    )
                )
            continue
        if conf_score < threshold:
            _save_gap(
                assessment_id=assessment_id,
                query_id=query_id,
                title=f"{query_id} low confidence",
                description=(
                    f"Evidence passed relevance validation but remained below confidence threshold. "
                    f"confidence={conf_score}, threshold={threshold}, signal_diversity={meta.get('signal_diversity_count', 0)}."
                ),
                evidence_count=len(filtered),
                avg_confidence=int(conf_score),
            )
            if filtered:
                if isinstance(meta, dict):
                    meta["relaxed_gate"] = "confidence_below_threshold"
                candidates.append(
                    _ScenarioCandidate(
                        query_id=query_id,
                        query_text=query_text,
                        payload=payload,
                        evidence_refs=filtered,
                        conf_score=int(conf_score),
                        meta=meta,
                        relevance_debug=rel_debug,
                    )
                )
            continue

        candidates.append(
            _ScenarioCandidate(
                query_id=query_id,
                query_text=query_text,
                payload=payload,
                evidence_refs=filtered,
                conf_score=int(conf_score),
                meta=meta,
                relevance_debug=rel_debug,
            )
        )

    merged_candidates = _merge_scenarios(candidates)
    strong_candidates = [c for c in merged_candidates if not str((c.meta or {}).get("relaxed_gate", "")).strip()]
    weak_candidates = [c for c in merged_candidates if str((c.meta or {}).get("relaxed_gate", "")).strip()]
    if strong_candidates:
        # Keep a small deterministic weak tail for context without flooding noisy outputs.
        merged_candidates = strong_candidates + weak_candidates[:2]
    else:
        # For weak-only runs, cap to top 3 stable watchlist/baseline hypotheses.
        merged_candidates = weak_candidates[:3]

    cards: list[HypothesisCard] = []
    for cand in merged_candidates:
        primary_qid = cand.merged_query_ids[0] if cand.merged_query_ids else cand.query_id
        row = _create_hypothesis_row(
            assessment_id=assessment_id,
            query_id=primary_qid,
            payload=cand.payload,
            evidence_refs=cand.evidence_refs,
            merged_from=int(cand.merged_from or 1),
            merged_query_ids=cand.merged_query_ids or [primary_qid],
            relevance_debug=cand.relevance_debug,
            trust_friction=trust_friction,
            input_fingerprint=input_fingerprint,
            provider=provider,
            model=model,
        )
        if not row:
            # If LLM narrative violates safety/field guards, fall back to deterministic local wording
            # while preserving the same evidence set and stable fingerprint.
            local_payload = _local_reasoner_payload(
                query_id=primary_qid,
                query_text=cand.query_text,
                evidence_refs=cand.evidence_refs,
                avg_conf=int(cand.conf_score or 0),
                section_gaps=_safe_list(cand.payload.get("gaps_to_verify"), max_items=8),
                sector=sector,
            )
            row = _create_hypothesis_row(
                assessment_id=assessment_id,
                query_id=primary_qid,
                payload=local_payload,
                evidence_refs=cand.evidence_refs,
                merged_from=int(cand.merged_from or 1),
                merged_query_ids=cand.merged_query_ids or [primary_qid],
                relevance_debug=cand.relevance_debug,
                trust_friction=trust_friction,
                input_fingerprint=input_fingerprint,
                provider=provider,
                model=model,
            )
        if not row:
            _save_gap(
                assessment_id=assessment_id,
                query_id=primary_qid,
                title=f"{primary_qid} blocked by safety guardrail",
                description="Generated content violated defensive-only policy or lacked required fields.",
                evidence_count=len(cand.evidence_refs),
                avg_confidence=int(cand.conf_score),
            )
            continue

        cards.append(
            HypothesisCard(
                id=row.id,
                risk_type=row.risk_type,
                title=row.title,
                description=row.description,
                likelihood=row.likelihood,
                likelihood_rationale=row.likelihood_rationale,
                impact=row.impact,
                impact_rationale=row.impact_rationale,
                evidence_refs=[EvidenceRef(**item) for item in json.loads(row.evidence_refs_json or "[]")],
                assumptions=json.loads(row.assumptions_json or "[]"),
                gaps_to_verify=json.loads(row.gaps_to_verify_json or "[]"),
                defensive_actions=json.loads(row.defensive_actions_json or "[]"),
            )
        )

    try:
        _persist_snapshot(
            assessment_id=assessment_id,
            input_fingerprint=input_fingerprint,
            provider=provider,
            model=model,
        )
    except Exception:
        logger.exception("Failed to persist hypothesis snapshot for assessment %s", assessment_id)

    return cards
