import hashlib
import json
import logging
import os
import random
import re
import time
from dataclasses import dataclass, field
from email.utils import parsedate_to_datetime
from typing import Any

import requests
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import RiskBrief
from app.services.assessment_service import get_llm_runtime_config

logger = logging.getLogger(__name__)

LLM_MAX_ATTEMPTS = 4
LLM_BACKOFF_BASE_SECONDS = 3.0
LLM_BACKOFF_JITTER_SECONDS = 1.0
LLM_BACKOFF_MAX_SECONDS = 45.0
LLM_QUOTA_COOLDOWN_SECONDS = 900

_llm_quota_block_until = 0.0
_llm_quota_last_notice = 0.0

# Defensive-only guard: reject outputs that resemble actionable abuse instructions.
# Note: descriptive CTI terms (e.g., "phishing") are allowed when not instructional.
PROHIBITED_ACTIONABLE_PATTERN = re.compile(
    r"(?i)\b("
    r"click here to|copy and paste|use this script|step[- ]by[- ]step|"
    r"send the code|verify your account|login link|invoice attachment|"
    r"bypass|evade|deploy payload|dropper|malware payload"
    r")\b"
)
PROHIBITED_SOCIAL_ENGINEERING_PROMPT_PATTERN = re.compile(
    r"(?i)\b("
    r"enter your credentials|provide your password|share (the )?(otp|code)|"
    r"reset your password using this link|confirm bank details now"
    r")\b"
)

ABSTRACT_TERMS = (
    "cues",
    "visibility",
    "ambiguity",
    "exposure",
    "enabled by",
    "signal bundle",
    "correlation",
    "vector",
    "surface",
)
ABSTRACT_TERM_PATTERN = re.compile(
    r"(?i)\b(cues|visibility|ambiguity|exposure|signal bundle|correlation|vector|surface)\b|enabled by"
)
ABSTRACT_REWRITE_PATTERNS: list[tuple[str, str]] = [
    (r"(?i)\benabled by\b", "driven by"),
    (r"(?i)\bsignal bundle(s)?\b", "evidence group\\1"),
    (r"(?i)\bcorrelation\b", "combined support"),
    (r"(?i)\bvisibility\b", "publicly available details"),
    (r"(?i)\bambiguity\b", "unclear channel definitions"),
    (r"(?i)\bexposure\b", "publicly available information"),
    (r"(?i)\bcues\b", "indicators"),
    (r"(?i)\bvector\b", "scenario"),
    (r"(?i)\bsurface\b", "entry point"),
]
IMPACT_KEYWORDS = (
    "financial loss",
    "fraudulent payment",
    "data leakage",
    "unauthorized data disclosure",
    "account takeover",
    "operational disruption",
    "reputational damage",
)
RISK_BRIEF_SAFETY_FILTER_ENABLED = os.getenv("RISK_BRIEF_SAFETY_FILTER", "0").strip() == "1"
LLM_HYPOTHESIS_PROMPT_VERSION = "2026-02-27-hypothesis-v2"
LLM_SECTIONS_PROMPT_VERSION = "2026-02-28-sections-v3-conservative"


@dataclass(frozen=True)
class BriefInput:
    assessment_id: int
    risk_kind: str
    risk_id: int
    title: str
    risk_type: str
    severity: int
    likelihood_badge: str
    confidence: int
    evidence: list[dict[str, Any]]
    primary_risk_type: str = ""
    risk_vector_summary: str = ""
    # Evidence-bound context for deterministic/LLM writing.
    conditions: list[str] = field(default_factory=list)
    signal_bundles: list[dict[str, Any]] = field(default_factory=list)
    workflow_nodes: list[dict[str, Any]] = field(default_factory=list)
    vendor_cues: list[str] = field(default_factory=list)
    channel_cues: list[str] = field(default_factory=list)
    impact_targets: list[str] = field(default_factory=list)
    correlation_hint: str = ""


def _hash_input(inp: BriefInput) -> str:
    conditions = [str(x) for x in (inp.conditions or []) if str(x).strip()][:3]
    vendor_cues = [str(x) for x in (inp.vendor_cues or []) if str(x).strip()][:8]
    channel_cues = [str(x) for x in (inp.channel_cues or []) if str(x).strip()][:8]
    impact_targets = [str(x) for x in (inp.impact_targets or []) if str(x).strip()][:5]
    blob = json.dumps(
        {
            "title": inp.title,
            "risk_type": inp.risk_type,
            "primary_risk_type": inp.primary_risk_type,
            "risk_vector_summary": inp.risk_vector_summary,
            "conditions": conditions,
            "vendor_cues": vendor_cues,
            "channel_cues": channel_cues,
            "impact_targets": impact_targets,
            "severity": int(inp.severity),
            "likelihood": inp.likelihood_badge,
            "confidence": int(inp.confidence),
            "correlation_hint": inp.correlation_hint,
            "evidence": [
                {
                    "bucket": e.get("bucket_key", ""),
                    "url": e.get("url", ""),
                    "snippet": (e.get("snippet", "") or "")[:220],
                    "confidence": int(e.get("confidence", 50) or 50),
                }
                for e in (inp.evidence or [])[:12]
            ],
        },
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def _contains_prohibited(text: str) -> bool:
    if not RISK_BRIEF_SAFETY_FILTER_ENABLED:
        return False
    value = str(text or "")
    return bool(
        PROHIBITED_ACTIONABLE_PATTERN.search(value) or PROHIBITED_SOCIAL_ENGINEERING_PROMPT_PATTERN.search(value)
    )


def _avg_conf(evidence: list[dict[str, Any]]) -> int:
    vals = []
    for e in evidence or []:
        try:
            vals.append(int(e.get("confidence", 50) or 50))
        except Exception:
            continue
    if not vals:
        return 0
    return int(sum(vals) / len(vals))


def _bucket_counts(evidence: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for e in evidence or []:
        key = str(e.get("bucket_key", "website") or "website")
        counts[key] = counts.get(key, 0) + 1
    return counts


def _contains_abstract_terms(text: str) -> bool:
    return bool(ABSTRACT_TERM_PATTERN.search(text or ""))


def _rewrite_abstract_terms(text: str) -> str:
    out = str(text or "")
    for patt, repl in ABSTRACT_REWRITE_PATTERNS:
        out = re.sub(patt, repl, out)
    return " ".join(out.split())


def _split_sentences(text: str) -> list[str]:
    parts = [p.strip() for p in re.split(r"(?<=[.!?])\s+", " ".join(str(text or "").split()).strip()) if p.strip()]
    return parts


def _first_paragraph(text: str) -> str:
    sents = _split_sentences(text)
    if not sents:
        return ""
    return " ".join(sents[:2]).strip()


def _has_impact_keyword(text: str) -> bool:
    low = str(text or "").lower()
    return any(k in low for k in IMPACT_KEYWORDS)


def _attack_type_from_input(inp: BriefInput) -> str:
    rt = str(inp.risk_type or "").strip().lower()
    primary = str(inp.primary_risk_type or "").strip().lower()
    blob = " ".join(
        [
            " ".join(_normalize_list(inp.conditions, max_items=5)),
            " ".join(_normalize_list(inp.channel_cues, max_items=10)),
            " ".join(_normalize_list(inp.vendor_cues, max_items=10)),
            " ".join(str(b.get("title", "")) for b in (inp.signal_bundles or []) if isinstance(b, dict)),
            " ".join(str(w.get("title", "")) for w in (inp.workflow_nodes or []) if isinstance(w, dict)),
        ]
    ).lower()

    if (
        any(x in blob for x in ("account recovery", "password", "login", "credential"))
        or rt in {"credential_theft_risk"}
        or "account takeover" in primary
    ):
        return "Account takeover via identity verification abuse"
    if any(
        x in blob for x in ("payment", "billing", "invoice", "checkout", "booking modification", "reservation change")
    ) or rt in {"fraud_process"}:
        return "Fraudulent payment or invoice redirection"
    if any(x in blob for x in ("privacy", "data subject", "gdpr", "cndp", "data protection")) or rt in {
        "privacy_data_risk"
    }:
        return "Unauthorized personal data disclosure"
    if any(x in blob for x in ("dmarc", "spf", "spoof")):
        return "Spoofed email impersonation"
    if any(x in blob for x in ("finance", "procurement", "it support", "dpo", "executive", "role")):
        return "Targeted social engineering against identifiable staff"
    if any(
        x in blob for x in ("contact", "phone", "email", "press contact", "support channel", "official channel")
    ) or rt in {
        "impersonation",
        "brand_abuse",
        "downstream_pivot",
        "social_trust_surface_exposure",
    }:
        return "Impersonation of official contact channels"
    return "Impersonation of official contact channels"


def _impact_from_input(inp: BriefInput) -> str:
    rt = str(inp.risk_type or "").strip().lower()
    primary = str(inp.primary_risk_type or "").strip().lower()
    blob = " ".join(
        [
            " ".join(_normalize_list(inp.conditions, max_items=5)),
            " ".join(_normalize_list(inp.channel_cues, max_items=10)),
            " ".join(_normalize_list(inp.vendor_cues, max_items=10)),
            " ".join(str(w.get("title", "")) for w in (inp.workflow_nodes or []) if isinstance(w, dict)),
            " ".join(str(x) for x in (inp.impact_targets or []) if str(x).strip()),
        ]
    ).lower()

    if any(x in blob for x in ("payment", "billing", "invoice", "checkout", "booking", "reservation")) or rt in {
        "fraud_process"
    }:
        return "fraudulent payments and financial loss"
    if (
        any(x in blob for x in ("privacy", "data subject", "data request", "personal data"))
        or rt in {"privacy_data_risk"}
        or "data handling" in primary
    ):
        return "unauthorized data disclosure and reputational damage"
    if any(x in blob for x in ("password", "login", "account recovery", "credential")) or rt in {
        "credential_theft_risk"
    }:
        return "account takeover and operational disruption"
    if any(x in blob for x in ("partner", "client", "guest")) or rt in {
        "impersonation",
        "downstream_pivot",
        "brand_abuse",
    }:
        return "fraudulent requests, operational disruption, and reputational damage"
    return "operational disruption and reputational damage"


def _mechanism_phrase(inp: BriefInput, *, max_conditions: int = 2) -> str:
    conds = [" ".join(str(x).split()).strip() for x in (inp.conditions or []) if str(x).strip()]
    if len(conds) >= 2:
        return f"{conds[0]} and {conds[1]}"
    if conds:
        return conds[0]
    wf = [
        str(w.get("title", "")).strip()
        for w in (inp.workflow_nodes or [])
        if isinstance(w, dict) and str(w.get("title", "")).strip()
    ]
    if wf:
        return "publicly documented operational workflows"
    return "publicly identifiable communication channels and process details"


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


def _local_brief(inp: BriefInput, *, variant_offset: int = 0) -> str:
    attack = _attack_type_from_input(inp)
    impact = _impact_from_input(inp)
    mechanism = _mechanism_phrase(inp)

    # Deterministic variant selection to reduce repetition while staying evidence-bound.
    seed = int(_hash_input(inp)[:8], 16) + int(variant_offset or 0)
    variant_tail = [
        "Current records suggest this scenario is plausible but still requires validation against official process documentation.",
        "Available records indicate this is plausible, while final confirmation depends on process-level checks.",
        "Collected records support plausibility, but final confidence depends on validating official controls and channel governance.",
    ][seed % 3]

    primary_groups = [str(x) for x in (inp.impact_targets or []) if str(x).strip()]
    impacted = ", ".join(primary_groups[:3]) if primary_groups else "customers, partners, and frontline teams"

    first = f"An external actor could {attack.lower()} by exploiting {mechanism}. If successful, this may result in {impact}."
    lines: list[str] = [
        first,
        variant_tail,
        f"Primary impact zones: {impacted}.",
        "Why it matters: official contact paths and communication methods are publicly identifiable, which can increase the chance of fraudulent or misrouted requests.",
        "Next verification: publish a signed list of official channels and require out-of-band verification for payment, account, or data-change requests.",
    ]
    return _rewrite_abstract_terms(" ".join(lines)[:950])


def _normalize_list(value: Any, *, max_items: int) -> list[str]:
    out: list[str] = []
    for x in (value or [])[:max_items]:
        s = " ".join(str(x or "").split()).strip()
        if s:
            out.append(s)
    return out


def _shingle_similarity(a: str, b: str, *, n: int = 3) -> float:
    def _shingles(s: str) -> set[str]:
        toks = [t for t in re.split(r"[^a-z0-9]+", (s or "").lower()) if t]
        if len(toks) < n:
            return set([" ".join(toks)]) if toks else set()
        return set(" ".join(toks[i : i + n]) for i in range(0, len(toks) - n + 1))

    sa = _shingles(a)
    sb = _shingles(b)
    if not sa or not sb:
        return 0.0
    inter = len(sa.intersection(sb))
    union = len(sa.union(sb))
    return float(inter) / float(union or 1)


def _validate_brief_text(text: str, *, inp: BriefInput, recent_briefs: list[str]) -> tuple[bool, str]:
    t = " ".join(str(text or "").split()).strip()
    if not t:
        return False, "empty"
    first_para = _first_paragraph(t)
    attack = _attack_type_from_input(inp)
    if not first_para:
        return False, "missing_first_paragraph"
    if "an external actor could" not in first_para.lower():
        return False, "missing_first_paragraph_template"
    if "if successful, this may result in" not in first_para.lower():
        return False, "missing_impact_sentence"
    if attack.lower() not in first_para.lower():
        return False, "missing_attack_type"
    if not _has_impact_keyword(first_para):
        return False, "missing_impact_keyword"
    if _contains_abstract_terms(first_para):
        return False, "contains_abstract_terms"

    # Evidence-text integrity: workflow concepts must be supported by the provided structured context.
    def _ctx_blob() -> str:
        bundle_titles = [str(b.get("title", "")) for b in (inp.signal_bundles or []) if isinstance(b, dict)]
        wf_titles = [str(w.get("title", "")) for w in (inp.workflow_nodes or []) if isinstance(w, dict)]
        parts = [
            str(inp.risk_vector_summary or ""),
            " ".join([str(x) for x in (inp.conditions or [])]),
            " ".join(bundle_titles),
            " ".join(wf_titles),
            " ".join([str(x) for x in (inp.channel_cues or [])]),
            " ".join([str(x) for x in (inp.vendor_cues or [])]),
        ]
        return " ".join(parts).lower()

    ctx = _ctx_blob()
    out_low = t.lower()
    allows_payment = any(k in ctx for k in ("payment", "billing", "invoice", "refund", "stripe", "adyen", "paypal"))
    allows_booking = any(k in ctx for k in ("booking", "reservation", "concierge", "guest"))
    allows_donation = any(k in ctx for k in ("donation", "donate", "fundraising", "beneficiary"))
    allows_account = any(k in ctx for k in ("password", "login", "credentials", "account", "mfa", "otp", "sso"))
    allows_social = any(
        k in ctx
        for k in (
            "instagram",
            "linkedin",
            "facebook",
            "tiktok",
            "youtube",
            "x.com",
            "twitter",
            "social",
            "dm",
            "direct message",
        )
    )
    if any(k in out_low for k in ("payment", "billing", "invoice", "refund")) and not allows_payment:
        return False, "unreferenced_workflow:payment"
    if any(k in out_low for k in ("booking", "reservation", "concierge")) and not allows_booking:
        return False, "unreferenced_workflow:booking"
    if any(k in out_low for k in ("donation", "donate", "fundraising", "beneficiary")) and not allows_donation:
        return False, "unreferenced_workflow:donation"
    if any(k in out_low for k in ("password", "login", "credentials", "account takeover")) and not allows_account:
        return False, "unreferenced_workflow:account"
    if any(k in out_low for k in ("direct message", " dm ", "via dm")) and not allows_social:
        return False, "unreferenced_channel:social_dm"

    # Must not introduce vendor cues not provided.
    allowed_vendors = {v.lower() for v in _normalize_list(inp.vendor_cues, max_items=20)}
    for kw in [
        k
        for k in (
            "zendesk",
            "freshdesk",
            "intercom",
            "salesforce",
            "hubspot",
            "stripe",
            "adyen",
            "paypal",
            "cloudflare",
            "akamai",
            "okta",
            "auth0",
            "recaptcha",
            "google tag manager",
            "microsoft 365",
        )
    ]:
        if kw in t.lower():
            if not any(kw in v for v in allowed_vendors):
                return False, f"unreferenced_vendor:{kw}"
    if "Next verification:" not in t:
        return False, "missing_next_verification"
    if _contains_abstract_terms(first_para):
        return False, "contains_abstract_terms"
    if _contains_prohibited(t):
        return False, "prohibited"
    # Anti-repetition: reject if too similar to recent briefs.
    for prev in (recent_briefs or [])[:8]:
        if _shingle_similarity(t, prev) >= 0.60:
            return False, "too_similar"
    return True, "ok"


def _call_llm(*, api_key: str, model: str, inp: BriefInput, retry_hint: str = "") -> str | None:
    # Evidence-bound structured context (LLM is only used for wording at temperature=0).
    attack_type = _attack_type_from_input(inp)
    impact_phrase = _impact_from_input(inp)
    payload_ctx = {
        "primary_risk_type": inp.primary_risk_type,
        "risk_vector_summary": inp.risk_vector_summary,
        "attack_type_phrase": attack_type,
        "impact_phrase": impact_phrase,
        "signal_bundles": (inp.signal_bundles or [])[:6],
        "workflow_nodes": (inp.workflow_nodes or [])[:6],
        "vendor_cues": _normalize_list(inp.vendor_cues, max_items=10),
        "channel_cues": _normalize_list(inp.channel_cues, max_items=10),
        "impact_targets": _normalize_list(inp.impact_targets, max_items=5),
        "conditions": _normalize_list(inp.conditions, max_items=3),
    }
    system_prompt = (
        "You are a senior Cyber Threat Intelligence (CTI) analyst and defensive risk advisor. "
        "You must be evidence-first and defensive-only. "
        "Do NOT produce phishing emails, message templates, social-engineering scripts, or operational offensive steps. "
        "Do NOT ask for credentials or include real links as part of a lure. "
        "Your job is to explain what the indicators are, how they correlate, uncertainty, and defensive actions to reduce risk."
    )
    user_prompt = (
        "Write a short executive risk brief based strictly on the structured evidence context below.\n"
        "Constraints:\n"
        "- 120 to 200 words.\n"
        "- Temperature is 0: be consistent and deterministic.\n"
        "- Use probabilistic language and mention uncertainty.\n"
        "- Use concrete language focused on realistic attacker behavior and business impact.\n"
        "- Include a final sentence: 'Next verification:' followed by 1-2 concrete defensive verification items.\n"
        "- No offensive instructions. No phishing templates. No ready-to-send messages.\n\n"
        "Mandatory first paragraph format (2 sentences):\n"
        f'1) "An external actor could {attack_type.lower()} by exploiting [mechanism from provided evidence]."\n'
        f'2) "If successful, this may result in {impact_phrase}."\n\n'
        "Rules:\n"
        "- Only use the exact bundle titles / workflow node titles / cues provided in JSON.\n"
        "- Do not introduce new vendors, channels, or workflows.\n"
        "- Do not introduce a different risk type.\n"
        f"- Do not use these terms in the first paragraph: {', '.join(ABSTRACT_TERMS)}.\n"
        f"{('Retry hint: ' + retry_hint) if retry_hint else ''}\n\n"
        "JSON context:\n" + json.dumps(payload_ctx, ensure_ascii=True)
    )
    payload = {
        "model": model,
        "temperature": 0,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
    }
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    try:
        res = _post_llm_with_backoff(
            url="https://api.openai.com/v1/chat/completions",
            payload=payload,
            headers=headers,
            timeout_seconds=35,
            caller="RiskBrief",
        )
        if res is None:
            logger.warning("Risk brief LLM request failed after retry attempts without response")
            return None
        if res.status_code >= 400:
            logger.warning("Risk brief LLM request failed: status=%s body=%s", res.status_code, res.text[:400])
            return None
        body = res.json()
        content = body.get("choices", [{}])[0].get("message", {}).get("content", "")
        text = " ".join(str(content or "").split())
        if not text:
            return None
        text = _rewrite_abstract_terms(text)
        if _contains_prohibited(text):
            logger.info("Risk brief blocked by safety filter; switching to deterministic local brief")
            return None
        return text[:1100]
    except Exception:
        logger.exception("Risk brief LLM request failed unexpectedly")
        return None


def get_or_generate_brief(
    db: Session,
    inp: BriefInput,
    *,
    generate_if_missing: bool = True,
) -> str:
    evidence = inp.evidence or []
    avg_conf = _avg_conf(evidence)
    if len(evidence) < 2 or avg_conf < 45:
        return (
            "Insufficient evidence coverage to produce an executive brief. "
            "Run collection again and review RAG Debug to confirm key pages/documents were indexed."
        )

    input_hash = _hash_input(inp)
    existing = (
        db.execute(
            select(RiskBrief)
            .where(
                RiskBrief.assessment_id == inp.assessment_id,
                RiskBrief.risk_kind == inp.risk_kind,
                RiskBrief.risk_id == inp.risk_id,
                RiskBrief.input_hash == input_hash,
            )
            .order_by(RiskBrief.created_at.desc(), RiskBrief.id.desc())
            .limit(1)
        )
        .scalars()
        .first()
    )
    if existing and (existing.brief or "").strip():
        return existing.brief
    if not bool(generate_if_missing):
        return ""

    llm_cfg = get_llm_runtime_config(db)
    model = str(llm_cfg.get("model") or "LOCAL").strip()
    api_key = str(llm_cfg.get("api_key") or "").strip()
    is_local = model.upper() == "LOCAL" or not api_key

    recent = [
        str(x.brief or "")
        for x in db.execute(
            select(RiskBrief)
            .where(RiskBrief.assessment_id == inp.assessment_id)
            .order_by(RiskBrief.created_at.desc(), RiskBrief.id.desc())
            .limit(8)
        )
        .scalars()
        .all()
        if (x.brief or "").strip()
    ]

    brief = ""
    if is_local:
        brief = _local_brief(inp, variant_offset=0)
        # Anti-repetition for LOCAL mode: if too similar to recent briefs, switch deterministic variant.
        for off in (1, 2):
            if not recent:
                break
            if any(_shingle_similarity(brief, prev) >= 0.60 for prev in recent[:8]):
                brief = _local_brief(inp, variant_offset=off)
            else:
                break
        brief = _rewrite_abstract_terms(brief)
    else:
        # One retry with stricter instruction if validation fails.
        last_reason = ""
        for attempt in range(0, 2):
            hint = ""
            if attempt == 1:
                hint = (
                    "Strict rewrite required. Previous draft failed validation: "
                    f"{last_reason or 'unknown'}. Keep only concrete attacker action, concrete mechanism, and concrete impact in first paragraph."
                )
            out = _call_llm(api_key=api_key, model=model, inp=inp, retry_hint=hint)
            if not out:
                continue
            out = _rewrite_abstract_terms(out)
            ok, reason = _validate_brief_text(out, inp=inp, recent_briefs=recent)
            if ok:
                brief = out
                break
            last_reason = reason
        if not brief:
            brief = _local_brief(inp, variant_offset=0)

    if _contains_prohibited(brief):
        brief = _local_brief(inp, variant_offset=0)
    brief = _rewrite_abstract_terms(brief)
    ok_final, _ = _validate_brief_text(brief, inp=inp, recent_briefs=[])
    if not ok_final:
        brief = _local_brief(inp, variant_offset=1)
        brief = _rewrite_abstract_terms(brief)

    row = RiskBrief(
        assessment_id=inp.assessment_id,
        risk_kind=inp.risk_kind[:32],
        risk_id=int(inp.risk_id),
        input_hash=input_hash,
        model=("LOCAL" if is_local else model)[:64],
        brief=brief,
    )
    db.add(row)
    db.commit()
    return brief


def _normalize_abuse_path_steps(value: Any, *, max_items: int = 6) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for idx, item in enumerate((value or [])[:max_items], start=1):
        if not isinstance(item, dict):
            continue
        title = " ".join(str(item.get("title", "")).split()).strip()
        detail = " ".join(str(item.get("detail", "")).split()).strip()
        if not title and not detail:
            continue
        out.append(
            {
                "step": str(item.get("step") or idx),
                "title": title,
                "detail": detail,
            }
        )
    return out


def _hash_how_input(
    *,
    assessment_id: int,
    risk_id: int,
    primary_risk_type: str,
    risk_type: str,
    abuse_steps: list[dict[str, str]],
    likelihood: str,
    impact_band: str,
    evidence_strength: str,
    confidence: int,
) -> str:
    blob = json.dumps(
        {
            "prompt_version": LLM_HYPOTHESIS_PROMPT_VERSION,
            "assessment_id": int(assessment_id),
            "risk_id": int(risk_id),
            "primary_risk_type": str(primary_risk_type or ""),
            "risk_type": str(risk_type or ""),
            "abuse_steps": abuse_steps,
            "likelihood": str(likelihood or ""),
            "impact_band": str(impact_band or ""),
            "evidence_strength": str(evidence_strength or ""),
            "confidence": int(confidence or 0),
        },
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def _sanitize_how_text(text: str) -> str:
    out = " ".join(str(text or "").split()).strip()
    out = out.strip("\"' ")
    out = re.sub(r"(?i)\bhow\s*:\s*", "", out).strip()
    out = re.sub(r"(?i)\s*(context|notes?|steps?)\s*[:\-]\s*$", "", out).strip()
    if out.endswith(":"):
        out = out[:-1].rstrip()
    return out[:1100]


def _local_how_from_abuse_path(
    *,
    primary_risk_type: str,
    abuse_steps: list[dict[str, str]],
    impact_band: str,
    likelihood: str,
) -> str:
    parts: list[str] = []
    for step in abuse_steps[:4]:
        title = " ".join(str(step.get("title", "")).split()).strip()
        detail = " ".join(str(step.get("detail", "")).split()).strip()
        if title and detail and detail.lower() not in title.lower():
            parts.append(f"{title.lower()} ({detail.lower()})")
        elif detail:
            parts.append(detail.lower())
        elif title:
            parts.append(title.lower())
    if not parts:
        return ""
    risk_label = str(primary_risk_type or "this risk").strip()
    if len(parts) == 1:
        text = (
            f"A likely exploitation path starts when an attacker leverages {parts[0]}. "
            f"This could support {risk_label.lower()} and create {str(impact_band or 'material').lower()}-impact disruption if controls are bypassed."
        )
    elif len(parts) == 2:
        text = (
            f"A plausible sequence starts with {parts[0]}, then moves to {parts[1]}. "
            f"Together, these conditions could enable {risk_label.lower()} and increase pressure on trust-heavy workflows."
        )
    else:
        text = (
            f"A plausible sequence starts with {parts[0]}, progresses through {parts[1]}, and then reaches {parts[2]}. "
            f"This chain could enable {risk_label.lower()} before detection, especially when requests appear consistent with public process cues."
        )
    text += f" Current likelihood is {str(likelihood or 'MED').upper()} and impact is {str(impact_band or 'MED').upper()}."
    return _sanitize_how_text(_rewrite_abstract_terms(text))


def _call_llm_how(
    *,
    api_key: str,
    model: str,
    primary_risk_type: str,
    risk_type: str,
    abuse_steps: list[dict[str, str]],
    likelihood: str,
    impact_band: str,
    evidence_strength: str,
    confidence: int,
    retry_hint: str = "",
) -> str | None:
    payload_ctx = {
        "primary_risk_type": str(primary_risk_type or ""),
        "risk_type": str(risk_type or ""),
        "likelihood": str(likelihood or ""),
        "impact_band": str(impact_band or ""),
        "evidence_strength": str(evidence_strength or ""),
        "confidence": int(confidence or 0),
        "abuse_path": abuse_steps[:6],
    }
    system_prompt = (
        "You are a CTI analyst writing defensive risk narratives for business stakeholders. "
        "Use only the provided structured evidence. "
        "Do not provide instructions, scripts, lures, or step-by-step attack guidance."
    )
    user_prompt = (
        "Write one concise, human-readable paragraph (90-150 words) titled implicitly as 'How' "
        "that explains how this risk could be exploited, using only the abuse_path steps in order.\n"
        "Requirements:\n"
        "- Keep it concrete and non-template.\n"
        "- Mention uncertainty using terms like 'could', 'likely', or 'plausible'.\n"
        "- Do not invent vendors/channels/workflows not present in JSON.\n"
        "- No bullets, no markdown, no headings, no JSON.\n"
        "- End with the potential business consequence in plain language.\n"
        f"{('Retry hint: ' + retry_hint) if retry_hint else ''}\n\n"
        "JSON context:\n"
        + json.dumps(payload_ctx, ensure_ascii=True)
    )
    payload = {
        "model": model,
        "temperature": 0,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
    }
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    try:
        res = _post_llm_with_backoff(
            url="https://api.openai.com/v1/chat/completions",
            payload=payload,
            headers=headers,
            timeout_seconds=30,
            caller="RiskHow",
        )
        if res is None or int(res.status_code or 0) >= 400:
            if res is not None and int(res.status_code or 0) >= 400:
                logger.warning("Risk HOW LLM request failed: status=%s", res.status_code)
            return None
        body = res.json()
        content = body.get("choices", [{}])[0].get("message", {}).get("content", "")
        text = _sanitize_how_text(str(content or ""))
        if not text:
            return None
        text = _rewrite_abstract_terms(text)
        if _contains_prohibited(text):
            logger.info("Risk HOW blocked by safety filter; switching to local fallback")
            return None
        return text
    except Exception:
        logger.exception("Risk HOW LLM request failed unexpectedly")
        return None


def get_or_generate_how_text(
    db: Session,
    *,
    assessment_id: int,
    risk_id: int,
    primary_risk_type: str,
    risk_type: str,
    abuse_path: list[dict[str, Any]],
    likelihood: str,
    impact_band: str,
    evidence_strength: str,
    confidence: int,
) -> str:
    steps = _normalize_abuse_path_steps(abuse_path, max_items=6)
    if not steps:
        return ""

    input_hash = _hash_how_input(
        assessment_id=int(assessment_id),
        risk_id=int(risk_id),
        primary_risk_type=str(primary_risk_type or ""),
        risk_type=str(risk_type or ""),
        abuse_steps=steps,
        likelihood=str(likelihood or ""),
        impact_band=str(impact_band or ""),
        evidence_strength=str(evidence_strength or ""),
        confidence=int(confidence or 0),
    )
    existing = (
        db.execute(
            select(RiskBrief)
            .where(
                RiskBrief.assessment_id == int(assessment_id),
                RiskBrief.risk_kind == "scenario_how",
                RiskBrief.risk_id == int(risk_id),
                RiskBrief.input_hash == input_hash,
            )
            .order_by(RiskBrief.created_at.desc(), RiskBrief.id.desc())
            .limit(1)
        )
        .scalars()
        .first()
    )
    if existing and str(existing.brief or "").strip():
        return str(existing.brief).strip()

    llm_cfg = get_llm_runtime_config(db)
    model = str(llm_cfg.get("model") or "LOCAL").strip()
    api_key = str(llm_cfg.get("api_key") or "").strip()
    is_local = model.upper() == "LOCAL" or not api_key

    how_text = ""
    if not is_local:
        last_empty = False
        for attempt in range(0, 2):
            hint = ""
            if attempt == 1 and last_empty:
                hint = "Use simpler sentence structure and directly connect step 1 -> step 2 -> step 3."
            out = _call_llm_how(
                api_key=api_key,
                model=model,
                primary_risk_type=primary_risk_type,
                risk_type=risk_type,
                abuse_steps=steps,
                likelihood=likelihood,
                impact_band=impact_band,
                evidence_strength=evidence_strength,
                confidence=confidence,
                retry_hint=hint,
            )
            if out:
                how_text = out
                break
            last_empty = True
    if not how_text:
        how_text = _local_how_from_abuse_path(
            primary_risk_type=primary_risk_type,
            abuse_steps=steps,
            impact_band=impact_band,
            likelihood=likelihood,
        )
    how_text = _sanitize_how_text(_rewrite_abstract_terms(how_text))
    if not how_text:
        return ""

    row = RiskBrief(
        assessment_id=int(assessment_id),
        risk_kind="scenario_how",
        risk_id=int(risk_id),
        input_hash=input_hash,
        model=("LOCAL" if is_local or not api_key else model)[:64],
        brief=how_text,
    )
    db.add(row)
    db.commit()
    return how_text


def _sanitize_hypothesis_line(text: str, *, max_chars: int = 220) -> str:
    out = " ".join(str(text or "").split()).strip()
    out = re.sub(r"^[\-\*\d\.\)\s]+", "", out).strip()
    out = out.strip("\"' ")
    out = _rewrite_abstract_terms(out)
    if _contains_prohibited(out):
        return ""
    return out[:max_chars]


def _normalize_llm_hypothesis_evidence(
    evidence: list[dict[str, Any]],
    *,
    max_items: int = 48,
) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    seen: set[str] = set()
    for ev in evidence or []:
        if not isinstance(ev, dict):
            continue
        snippet = _sanitize_hypothesis_line(str(ev.get("snippet", "")), max_chars=260)
        title = _sanitize_hypothesis_line(str(ev.get("title", "")), max_chars=120)
        signal_type = " ".join(str(ev.get("signal_type", "")).split()).strip().upper() or "UNCLASSIFIED"
        url = " ".join(str(ev.get("canonical_url", "") or ev.get("url", "")).split()).strip()[:240]
        domain = " ".join(str(ev.get("domain", "")).split()).strip()[:120]
        connectors = ev.get("connectors", [])
        if isinstance(connectors, list):
            conn_raw = ",".join(
                " ".join(str(x or "").split()).strip() for x in connectors if " ".join(str(x or "").split()).strip()
            )
        else:
            conn_raw = " ".join(str(ev.get("connector", "")).split()).strip()
        connector = conn_raw[:120]
        try:
            confidence = int(ev.get("confidence", 50) or 50)
        except Exception:
            confidence = 50
        dedupe_key = f"{signal_type}|{url.lower()}|{snippet.lower()[:120]}"
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        candidates.append(
            {
                "signal_type": signal_type,
                "title": title,
                "snippet": snippet,
                "url": url,
                "domain": domain,
                "connector": connector,
                "confidence": max(1, min(100, int(confidence))),
            }
        )
    candidates.sort(
        key=lambda x: (
            str(x.get("signal_type", "")),
            str(x.get("url", "")),
            -int(x.get("confidence", 0) or 0),
            str(x.get("title", "")),
            str(x.get("snippet", "")),
        )
    )
    return candidates[:max(1, int(max_items))]


def _safe_hypothesis_items(raw: Any, *, max_items: int = 4) -> list[str]:
    items: list[str] = []
    for x in (raw or []):
        line = _sanitize_hypothesis_line(str(x or ""), max_chars=220)
        if not line:
            continue
        if line in items:
            continue
        items.append(line)
        if len(items) >= max_items:
            break
    return items


def _parse_llm_hypothesis_blob(blob: str) -> dict[str, Any] | None:
    text = str(blob or "").strip()
    if not text:
        return None
    try:
        payload = json.loads(text)
        if not isinstance(payload, dict):
            return None
        items = _safe_hypothesis_items(payload.get("items") or payload.get("hypotheses") or [])
        rationale = _sanitize_hypothesis_line(str(payload.get("rationale", "")), max_chars=260)
        uncertainty = _sanitize_hypothesis_line(str(payload.get("uncertainty", "")), max_chars=260)
        mode = " ".join(str(payload.get("mode", "LOCAL")).split()).strip().upper() or "LOCAL"
        if mode not in {"LLM", "LOCAL"}:
            mode = "LOCAL"
        if not items:
            return None
        summary = _sanitize_hypothesis_line(
            str(payload.get("summary", "")).strip() or str(items[0] if items else ""),
            max_chars=280,
        )
        return {
            "items": items,
            "summary": summary,
            "rationale": rationale,
            "uncertainty": uncertainty,
            "mode": mode,
            "shadow_note": "Experimental output in shadow mode. It does not modify current score or status.",
        }
    except Exception:
        line = _sanitize_hypothesis_line(text, max_chars=260)
        if not line:
            return None
        return {
            "items": [line],
            "summary": line,
            "rationale": "",
            "uncertainty": "",
            "mode": "LOCAL",
            "shadow_note": "Experimental output in shadow mode. It does not modify current score or status.",
        }


def _hash_llm_hypothesis_input(
    *,
    assessment_id: int,
    risk_id: int,
    primary_risk_type: str,
    risk_type: str,
    likelihood: str,
    impact_band: str,
    evidence_strength: str,
    confidence: int,
    evidence_norm: list[dict[str, Any]],
) -> str:
    blob = json.dumps(
        {
            "assessment_id": int(assessment_id),
            "risk_id": int(risk_id),
            "primary_risk_type": str(primary_risk_type or ""),
            "risk_type": str(risk_type or ""),
            "likelihood": str(likelihood or ""),
            "impact_band": str(impact_band or ""),
            "evidence_strength": str(evidence_strength or ""),
            "confidence": int(confidence or 0),
            "evidence": evidence_norm[:48],
        },
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def _local_llm_hypothesis_payload(
    *,
    primary_risk_type: str,
    risk_type: str,
    likelihood: str,
    impact_band: str,
    evidence_norm: list[dict[str, Any]],
) -> dict[str, Any]:
    counts: dict[str, int] = {}
    artifacts: list[str] = []
    for ev in evidence_norm:
        st = str(ev.get("signal_type", "UNCLASSIFIED")).strip().upper()
        counts[st] = counts.get(st, 0) + 1
        for token in (str(ev.get("domain", "")), str(ev.get("title", ""))):
            token = " ".join(str(token or "").split()).strip()
            if token and token not in artifacts:
                artifacts.append(token)
            if len(artifacts) >= 6:
                break

    items: list[str] = []
    if counts.get("CONTACT_CHANNEL", 0) > 0 and counts.get("PROCESS_CUE", 0) > 0:
        items.append(
            "An external actor could impersonate official support/billing conversations and blend into routine process requests."
        )
    if counts.get("ORG_CUE", 0) > 0:
        items.append("Visible role cues could enable targeted social requests toward staff with operational authority.")
    if counts.get("VENDOR_CUE", 0) > 0 or counts.get("INFRA_CUE", 0) > 0:
        items.append("Public vendor or infrastructure cues could make fake portal/helpdesk interactions appear legitimate.")
    if counts.get("EXTERNAL_ATTENTION", 0) > 0:
        items.append("External narrative pressure could increase urgency and reduce verification quality in inbound requests.")
    if not items:
        label = str(primary_risk_type or risk_type or "trust-risk").strip().lower()
        items.append(
            f"Observed public signals could support a plausible {label} scenario if verification controls are inconsistent."
        )

    rationale = (
        f"Derived from {len(evidence_norm)} evidence items across {len([k for k, v in counts.items() if v > 0])} signal types."
    )
    if artifacts:
        rationale += f" Strongest recurring cues include {', '.join(artifacts[:3])}."
    uncertainty = (
        f"Likelihood is {str(likelihood or 'MED').upper()} and impact is {str(impact_band or 'MED').upper()}; "
        "this remains a defensive hypothesis, not confirmation of active abuse."
    )
    safe_items = _safe_hypothesis_items(items, max_items=4)
    summary = _sanitize_hypothesis_line(str(safe_items[0] if safe_items else ""), max_chars=280)
    return {
        "items": safe_items,
        "summary": summary,
        "rationale": _sanitize_hypothesis_line(rationale, max_chars=260),
        "uncertainty": _sanitize_hypothesis_line(uncertainty, max_chars=260),
        "mode": "LOCAL",
        "shadow_note": "Experimental output in shadow mode. It does not modify current score or status.",
    }


def _call_llm_risk_hypothesis(
    *,
    api_key: str,
    model: str,
    primary_risk_type: str,
    risk_type: str,
    likelihood: str,
    impact_band: str,
    evidence_strength: str,
    confidence: int,
    evidence_norm: list[dict[str, Any]],
) -> dict[str, Any] | None:
    ctx = {
        "primary_risk_type": str(primary_risk_type or ""),
        "risk_type": str(risk_type or ""),
        "likelihood": str(likelihood or ""),
        "impact_band": str(impact_band or ""),
        "evidence_strength": str(evidence_strength or ""),
        "confidence": int(confidence or 0),
        "evidence": evidence_norm[:48],
    }
    system_prompt = (
        "You are a defensive CTI analyst. "
        "Produce risk hypotheses only from provided evidence. "
        "Do not provide exploit steps, lures, scripts, or operational attack instructions."
    )
    user_prompt = (
        "Create 2-4 concise, evidence-grounded hypotheses about possible trust/social-engineering abuse paths.\n"
        "Return JSON only with keys:\n"
        "- hypotheses: array of short strings\n"
        "- rationale: one sentence about why these hypotheses are plausible from evidence\n"
        "- uncertainty: one sentence describing limits/uncertainty\n"
        "Rules:\n"
        "- Use only supplied evidence; do not invent entities/channels.\n"
        "- Keep each hypothesis <= 170 characters.\n"
        "- Frame results as plausible scenarios, never as confirmed incidents.\n"
        "- Avoid certainty words like 'will' or 'is happening'; prefer 'could', 'may', 'plausibly'.\n"
        "- Keep risk wording broad when evidence is mostly public role/contact/channel signals.\n"
        "- Defensive language only; no actionable abuse guidance.\n\n"
        "JSON context:\n"
        + json.dumps(ctx, ensure_ascii=True)
    )
    payload = {
        "model": model,
        "temperature": 0,
        "response_format": {"type": "json_object"},
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
    }
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    try:
        res = _post_llm_with_backoff(
            url="https://api.openai.com/v1/chat/completions",
            payload=payload,
            headers=headers,
            timeout_seconds=35,
            caller="RiskHypothesis",
        )
        if res is None or int(res.status_code or 0) >= 400:
            if res is not None and int(res.status_code or 0) >= 400:
                logger.warning("Risk hypothesis LLM request failed: status=%s", res.status_code)
            return None
        body = res.json()
        content = body.get("choices", [{}])[0].get("message", {}).get("content", "{}")
        parsed = json.loads(str(content or "{}"))
        if not isinstance(parsed, dict):
            return None
        items = _safe_hypothesis_items(parsed.get("hypotheses") or [], max_items=4)
        if not items:
            return None
        summary = _sanitize_hypothesis_line(str(parsed.get("summary", "")).strip() or str(items[0]), max_chars=280)
        rationale = _sanitize_hypothesis_line(str(parsed.get("rationale", "")), max_chars=260)
        uncertainty = _sanitize_hypothesis_line(str(parsed.get("uncertainty", "")), max_chars=260)
        return {
            "items": items,
            "summary": summary,
            "rationale": rationale,
            "uncertainty": uncertainty,
            "mode": "LLM",
            "shadow_note": "Experimental output in shadow mode. It does not modify current score or status.",
        }
    except Exception:
        logger.exception("Risk hypothesis LLM request failed unexpectedly")
        return None


def get_or_generate_llm_hypothesis(
    db: Session,
    *,
    assessment_id: int,
    risk_id: int,
    primary_risk_type: str,
    risk_type: str,
    likelihood: str,
    impact_band: str,
    evidence_strength: str,
    confidence: int,
    evidence: list[dict[str, Any]],
    generate_if_missing: bool = True,
) -> dict[str, Any]:
    evidence_norm = _normalize_llm_hypothesis_evidence(evidence, max_items=48)
    if len(evidence_norm) < 2:
        return {
            "items": [],
            "summary": "",
            "rationale": "",
            "uncertainty": "Insufficient evidence volume for additional LLM hypotheses.",
            "mode": "LOCAL",
            "shadow_note": "Experimental output in shadow mode. It does not modify current score or status.",
        }

    input_hash = _hash_llm_hypothesis_input(
        assessment_id=int(assessment_id),
        risk_id=int(risk_id),
        primary_risk_type=str(primary_risk_type or ""),
        risk_type=str(risk_type or ""),
        likelihood=str(likelihood or ""),
        impact_band=str(impact_band or ""),
        evidence_strength=str(evidence_strength or ""),
        confidence=int(confidence or 0),
        evidence_norm=evidence_norm,
    )
    existing = (
        db.execute(
            select(RiskBrief)
            .where(
                RiskBrief.assessment_id == int(assessment_id),
                RiskBrief.risk_kind == "scenario_llm_hypothesis",
                RiskBrief.risk_id == int(risk_id),
                RiskBrief.input_hash == input_hash,
            )
            .order_by(RiskBrief.created_at.desc(), RiskBrief.id.desc())
            .limit(1)
        )
        .scalars()
        .first()
    )
    if existing and str(existing.brief or "").strip():
        cached = _parse_llm_hypothesis_blob(str(existing.brief or ""))
        if cached:
            return cached
    if not bool(generate_if_missing):
        return {
            "items": [],
            "summary": "",
            "rationale": "",
            "uncertainty": "",
            "mode": "LOCAL",
            "shadow_note": "Experimental output in shadow mode. It does not modify current score or status.",
        }

    llm_cfg = get_llm_runtime_config(db)
    model = str(llm_cfg.get("model") or "LOCAL").strip()
    api_key = str(llm_cfg.get("api_key") or "").strip()
    is_local = model.upper() == "LOCAL" or not api_key

    payload: dict[str, Any] | None = None
    if not is_local:
        payload = _call_llm_risk_hypothesis(
            api_key=api_key,
            model=model,
            primary_risk_type=primary_risk_type,
            risk_type=risk_type,
            likelihood=likelihood,
            impact_band=impact_band,
            evidence_strength=evidence_strength,
            confidence=confidence,
            evidence_norm=evidence_norm,
        )
    if not payload:
        payload = _local_llm_hypothesis_payload(
            primary_risk_type=primary_risk_type,
            risk_type=risk_type,
            likelihood=likelihood,
            impact_band=impact_band,
            evidence_norm=evidence_norm,
        )

    if not isinstance(payload, dict):
        payload = {
            "items": [],
            "summary": "",
            "rationale": "",
            "uncertainty": "",
            "mode": "LOCAL",
            "shadow_note": "Experimental output in shadow mode. It does not modify current score or status.",
        }
    payload["mode"] = "LLM" if str(payload.get("mode", "LOCAL")).upper() == "LLM" and not is_local else "LOCAL"
    payload["items"] = _safe_hypothesis_items(payload.get("items") or [], max_items=4)
    payload["summary"] = _sanitize_hypothesis_line(
        str(payload.get("summary", "")).strip() or str((payload.get("items") or [""])[0]),
        max_chars=280,
    )
    payload["rationale"] = _sanitize_hypothesis_line(str(payload.get("rationale", "")), max_chars=260)
    payload["uncertainty"] = _sanitize_hypothesis_line(str(payload.get("uncertainty", "")), max_chars=260)
    payload["shadow_note"] = "Experimental output in shadow mode. It does not modify current score or status."

    if payload.get("items"):
        row = RiskBrief(
            assessment_id=int(assessment_id),
            risk_kind="scenario_llm_hypothesis",
            risk_id=int(risk_id),
            input_hash=input_hash,
            model=("LOCAL" if is_local else str(model or "LOCAL"))[:64],
            brief=json.dumps(payload, ensure_ascii=True),
        )
        try:
            db.add(row)
            db.commit()
        except Exception:
            logger.exception(
                "Failed to persist LLM shadow hypotheses for assessment=%s risk=%s",
                int(assessment_id),
                int(risk_id),
            )
            try:
                db.rollback()
            except Exception:
                pass
    return payload


def _safe_section_line(text: str, *, max_chars: int = 260) -> str:
    out = _sanitize_hypothesis_line(text, max_chars=max_chars)
    if not out:
        return ""
    return out


def _safe_section_points(raw: Any, *, max_items: int = 4, max_chars: int = 180) -> list[str]:
    out: list[str] = []
    for item in (raw or []):
        line = _safe_section_line(str(item or ""), max_chars=max_chars)
        if not line:
            continue
        if line in out:
            continue
        out.append(line)
        if len(out) >= max_items:
            break
    return out


def _normalize_effort(value: str, title: str = "") -> str:
    v = " ".join(str(value or "").split()).strip().upper()
    if v in {"LOW", "MED", "HIGH"}:
        return v
    t = str(title or "").lower()
    if any(k in t for k in ("enforce", "mandatory", "approval", "process redesign", "policy update")):
        return "MED"
    return "LOW"


def _normalize_reduction(value: str, title: str = "") -> str:
    v = " ".join(str(value or "").split()).strip().upper()
    if v in {"LOW", "MED", "HIGH"}:
        return v
    t = str(title or "").lower()
    if any(k in t for k in ("block", "deny", "out-of-band", "verification", "approval", "registry")):
        return "HIGH"
    if any(k in t for k in ("train", "awareness", "guidance")):
        return "MED"
    return "MED"


def _safe_control_points(raw: Any, *, max_items: int = 5) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    if not isinstance(raw, list):
        return out
    for item in raw:
        title = ""
        effort = "MED"
        reduction = "MED"
        if isinstance(item, dict):
            title = _safe_section_line(str(item.get("title", "")), max_chars=220)
            effort = _normalize_effort(str(item.get("effort", "")), title=title)
            reduction = _normalize_reduction(str(item.get("expected_reduction", "")), title=title)
        else:
            title = _safe_section_line(str(item or ""), max_chars=220)
            effort = _normalize_effort("", title=title)
            reduction = _normalize_reduction("", title=title)
        if not title:
            continue
        if any(title == str(x.get("title", "")) for x in out):
            continue
        out.append(
            {
                "title": title,
                "effort": effort,
                "expected_reduction": reduction,
            }
        )
        if len(out) >= max_items:
            break
    return out


def _safe_mitre_codes(raw: Any, *, max_items: int = 6) -> list[str]:
    out: list[str] = []
    if isinstance(raw, str):
        raw_items: list[str] = [raw]
    elif isinstance(raw, list):
        raw_items = [str(x or "") for x in raw]
    else:
        raw_items = []
    for item in raw_items:
        text = " ".join(str(item or "").split()).strip().upper()
        if not text:
            continue
        found = re.findall(r"\b(?:TA\d{4}|T\d{4}(?:\.\d{3})?)\b", text)
        if not found and re.fullmatch(r"[A-Z0-9 .:_/\-]{3,40}", text):
            found = [text]
        for code in found:
            clean = " ".join(str(code).split()).strip().upper()
            if not clean or clean in out:
                continue
            out.append(clean)
            if len(out) >= max_items:
                return out
    return out


def _safe_abuse_path_steps(raw: Any, *, max_items: int = 6) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    if not isinstance(raw, list):
        return out
    for idx, item in enumerate(raw, start=1):
        if not isinstance(item, dict):
            continue
        title = _safe_section_line(str(item.get("title", "")), max_chars=96)
        detail = _safe_section_line(str(item.get("detail", "")), max_chars=200)
        if not title and not detail:
            continue
        if not title:
            title = f"Step {len(out) + 1}"
        out.append(
            {
                "step": str(item.get("step") or len(out) + 1),
                "title": title,
                "detail": detail,
            }
        )
        if len(out) >= max_items:
            break
    for idx, row in enumerate(out, start=1):
        row["step"] = str(idx)
    return out


def _safe_abuse_path_graph(
    raw: Any,
    *,
    fallback_steps: list[dict[str, str]] | None = None,
    max_nodes: int = 10,
    max_links: int = 18,
) -> dict[str, Any]:
    def _from_steps(steps: list[dict[str, str]]) -> dict[str, Any]:
        safe_steps = _safe_abuse_path_steps(steps, max_items=6)
        nodes: list[dict[str, Any]] = []
        links: list[dict[str, Any]] = []
        for idx, step in enumerate(safe_steps, start=1):
            nid = f"s{idx}"
            nodes.append(
                {
                    "id": nid,
                    "stage": int(idx - 1),
                    "title": _safe_section_line(str(step.get("title", "")), max_chars=96) or f"Step {idx}",
                    "detail": _safe_section_line(str(step.get("detail", "")), max_chars=220),
                    "type": "step",
                }
            )
            if idx > 1:
                links.append({"source": f"s{idx-1}", "target": nid, "label": "", "weight": 3})
        return {"nodes": nodes[:max_nodes], "links": links[:max_links]}

    if not isinstance(raw, dict):
        return _from_steps(list(fallback_steps or []))

    raw_nodes = raw.get("nodes")
    raw_links = raw.get("links")
    if not isinstance(raw_nodes, list):
        raw_nodes = []
    if not isinstance(raw_links, list):
        raw_links = []

    nodes: list[dict[str, Any]] = []
    node_id_set: set[str] = set()
    for idx, item in enumerate(raw_nodes, start=1):
        if not isinstance(item, dict):
            continue
        node_id = re.sub(r"[^a-zA-Z0-9_\-]", "", str(item.get("id", f"n{idx}"))).strip().lower() or f"n{idx}"
        if node_id in node_id_set:
            continue
        title = _safe_section_line(str(item.get("title", "")), max_chars=96)
        detail = _safe_section_line(str(item.get("detail", "")), max_chars=220)
        if not title and not detail:
            continue
        if not title:
            title = f"Step {len(nodes) + 1}"
        if "stage" in item:
            stage_raw = item.get("stage")
            try:
                stage = int(stage_raw)
            except Exception:
                stage = len(nodes)
        else:
            try:
                stage = int(item.get("step", len(nodes) + 1)) - 1
            except Exception:
                stage = len(nodes)
        stage = max(0, min(6, int(stage)))
        node_type = " ".join(str(item.get("type", "step")).split()).strip().lower() or "step"
        if node_type not in {"entry", "action", "decision", "outcome", "step"}:
            node_type = "step"
        nodes.append({"id": node_id, "stage": stage, "title": title, "detail": detail, "type": node_type})
        node_id_set.add(node_id)
        if len(nodes) >= max_nodes:
            break

    if not nodes:
        return _from_steps(list(fallback_steps or []))

    links: list[dict[str, Any]] = []
    seen_links: set[str] = set()
    for item in raw_links:
        if not isinstance(item, dict):
            continue
        src = re.sub(r"[^a-zA-Z0-9_\-]", "", str(item.get("source", ""))).strip().lower()
        dst = re.sub(r"[^a-zA-Z0-9_\-]", "", str(item.get("target", ""))).strip().lower()
        if not src or not dst or src == dst:
            continue
        if src not in node_id_set or dst not in node_id_set:
            continue
        label = _safe_section_line(str(item.get("label", "")), max_chars=90)
        try:
            weight = int(item.get("weight", 2) or 2)
        except Exception:
            weight = 2
        weight = max(1, min(5, weight))
        key = f"{src}|{dst}|{label.lower()}"
        if key in seen_links:
            continue
        seen_links.add(key)
        links.append({"source": src, "target": dst, "label": label, "weight": weight})
        if len(links) >= max_links:
            break

    if not links and len(nodes) > 1:
        nodes_sorted = sorted(nodes, key=lambda x: (int(x.get("stage", 0) or 0), str(x.get("id", ""))))
        for idx in range(1, len(nodes_sorted)):
            src = str(nodes_sorted[idx - 1].get("id", ""))
            dst = str(nodes_sorted[idx].get("id", ""))
            if src and dst and src != dst:
                links.append({"source": src, "target": dst, "label": "", "weight": 3})
                if len(links) >= max_links:
                    break

    nodes.sort(key=lambda x: (int(x.get("stage", 0) or 0), str(x.get("id", ""))))
    return {"nodes": nodes[:max_nodes], "links": links[:max_links]}


def _local_abuse_path_graph(
    *,
    steps: list[dict[str, str]],
    contradictions: list[str],
    risk_type: str,
    primary_risk_type: str,
) -> dict[str, Any]:
    base = _safe_abuse_path_graph({}, fallback_steps=steps, max_nodes=10, max_links=18)
    nodes = list(base.get("nodes") or [])
    links = list(base.get("links") or [])
    if len(nodes) < 3:
        return {"nodes": nodes, "links": links}

    low = f"{str(risk_type or '')} {str(primary_risk_type or '')}".lower()
    if "payment" in low or "invoice" in low or "billing" in low:
        alt_title = "Alternate payment pretext"
        alt_detail = "Actor pivots to a different billing/finance persona when initial checks block the first route."
    elif "account" in low or "credential" in low or "login" in low:
        alt_title = "Alternate account-access pretext"
        alt_detail = "Actor pivots to account recovery urgency if the first social route is rejected."
    else:
        alt_title = "Alternate trusted-channel pretext"
        alt_detail = "Actor switches to another official-looking channel or role to keep the interaction credible."

    pivot = nodes[1]
    target = nodes[min(len(nodes) - 1, 3)]
    alt_id = "alt-branch-1"
    if all(str(n.get("id", "")).lower() != alt_id for n in nodes):
        stage = int(pivot.get("stage", 0) or 0) + 1
        nodes.append(
            {
                "id": alt_id,
                "stage": max(1, min(5, stage)),
                "title": alt_title,
                "detail": _safe_section_line(alt_detail, max_chars=220),
                "type": "decision",
            }
        )
        links.append({"source": str(pivot.get("id", "")), "target": alt_id, "label": "alternate route", "weight": 2})
        links.append({"source": alt_id, "target": str(target.get("id", "")), "label": "rejoin path", "weight": 2})

    if contradictions and nodes:
        last_stage = max(int(n.get("stage", 0) or 0) for n in nodes)
        guard_id = "outcome-blocked"
        if all(str(n.get("id", "")).lower() != guard_id for n in nodes):
            nodes.append(
                {
                    "id": guard_id,
                    "stage": max(1, min(6, last_stage + 1)),
                    "title": "Attempt blocked by controls",
                    "detail": _safe_section_line(
                        "Out-of-band verification or strict channel policy blocks the malicious progression.",
                        max_chars=220,
                    ),
                    "type": "outcome",
                }
            )
            links.append(
                {
                    "source": str(nodes[min(len(nodes) - 2, 2)].get("id", "")),
                    "target": guard_id,
                    "label": "defensive branch",
                    "weight": 1,
                }
            )

    return _safe_abuse_path_graph({"nodes": nodes, "links": links}, fallback_steps=steps, max_nodes=10, max_links=18)


def _hash_llm_sections_input(
    *,
    assessment_id: int,
    risk_id: int,
    primary_risk_type: str,
    risk_type: str,
    likelihood: str,
    impact_band: str,
    evidence_strength: str,
    confidence: int,
    why_it_matters: str,
    contradictions: list[str],
    base_timeline: list[dict[str, str]],
    evidence_norm: list[dict[str, Any]],
) -> str:
    blob = json.dumps(
        {
            "prompt_version": LLM_SECTIONS_PROMPT_VERSION,
            "assessment_id": int(assessment_id),
            "risk_id": int(risk_id),
            "primary_risk_type": str(primary_risk_type or ""),
            "risk_type": str(risk_type or ""),
            "likelihood": str(likelihood or ""),
            "impact_band": str(impact_band or ""),
            "evidence_strength": str(evidence_strength or ""),
            "confidence": int(confidence or 0),
            "why_it_matters": str(why_it_matters or ""),
            "contradictions": [str(x) for x in (contradictions or []) if str(x).strip()][:5],
            "base_timeline": base_timeline[:6],
            "evidence": evidence_norm[:48],
        },
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def _parse_llm_sections_blob(blob: str) -> dict[str, Any] | None:
    raw = str(blob or "").strip()
    if not raw:
        return None
    try:
        payload = json.loads(raw)
    except Exception:
        return None
    if not isinstance(payload, dict):
        return None
    why_it_matters = _safe_section_line(str(payload.get("why_it_matters", "")), max_chars=320)
    how = _sanitize_how_text(str(payload.get("how", "")))
    business_impact = _safe_section_line(str(payload.get("business_impact", "")), max_chars=420)
    confirm_points = _safe_section_points(payload.get("confirm_points") or [], max_items=4, max_chars=190)
    deny_points = _safe_section_points(payload.get("deny_points") or [], max_items=4, max_chars=190)
    control_points = _safe_control_points(payload.get("control_points") or [], max_items=5)
    mitre_categories = _safe_mitre_codes(
        payload.get("mitre_categories") or payload.get("mitre_attack_categories") or [],
        max_items=6,
    )
    abuse_path = _safe_abuse_path_steps(
        payload.get("abuse_path") or payload.get("abuse_path_steps") or [],
        max_items=6,
    )
    abuse_path_graph = _safe_abuse_path_graph(
        payload.get("abuse_path_graph") or payload.get("abuse_graph") or {},
        fallback_steps=abuse_path,
        max_nodes=10,
        max_links=18,
    )
    mode = " ".join(str(payload.get("mode", "LOCAL")).split()).strip().upper() or "LOCAL"
    if mode not in {"LLM", "LOCAL"}:
        mode = "LOCAL"
    if not why_it_matters:
        return None
    return {
        "why_it_matters": why_it_matters,
        "how": how,
        "business_impact": business_impact,
        "confirm_points": confirm_points,
        "deny_points": deny_points,
        "control_points": control_points,
        "mitre_categories": mitre_categories,
        "abuse_path": abuse_path,
        "abuse_path_graph": abuse_path_graph,
        "mode": mode,
        "shadow_note": "Generated from evidence with stable prompts and cache.",
    }


def _local_llm_sections_payload(
    *,
    why_it_matters: str,
    primary_risk_type: str,
    risk_type: str,
    likelihood: str,
    impact_band: str,
    contradictions: list[str],
    base_timeline: list[dict[str, str]],
    evidence_norm: list[dict[str, Any]],
) -> dict[str, Any]:
    why = _safe_section_line(str(why_it_matters or ""), max_chars=320)
    if not why:
        label = str(primary_risk_type or risk_type or "trust risk").strip().lower()
        why = f"Publicly observable signals indicate a plausible {label} path if verification controls are not consistently enforced."

    evidence_bits: list[str] = []
    for ev in evidence_norm[:6]:
        st = str(ev.get("signal_type", "")).strip().upper()
        dom = str(ev.get("domain", "")).strip()
        if st and dom:
            token = f"{st.lower()} on {dom}"
        elif st:
            token = st.lower()
        else:
            token = str(ev.get("title", "")).strip().lower()
        token = " ".join(token.split()).strip()
        if token and token not in evidence_bits:
            evidence_bits.append(token)
        if len(evidence_bits) >= 3:
            break

    evidence_hint = ", ".join(evidence_bits) if evidence_bits else "multiple public trust-related signals"
    how = (
        f"A malicious actor would likely start from {evidence_hint} to identify a believable contact path, "
        f"then align the message with routine workflow language to reduce suspicion. "
        f"They could progress from low-friction interaction to a higher-impact request once trust is established, "
        f"especially if independent verification is skipped under urgency. "
        f"This path remains a defensive hypothesis based on current evidence."
    )
    how = _sanitize_how_text(how)

    business_impact = (
        f"If successful, this could cause trust erosion, operational disruption, and potentially financial loss. "
        f"Current risk posture is likelihood {str(likelihood or 'MED').upper()} with impact {str(impact_band or 'MED').upper()}."
    )
    business_impact = _safe_section_line(business_impact, max_chars=420)

    confirm_points = [
        "Suspicious requests reusing official channel/process wording are observed in external interactions.",
        "Sensitive workflow actions are initiated from channels not listed as authoritative.",
        "Urgency is used to bypass normal verification or approval steps.",
    ]
    deny_points = [
        "A single authoritative channel registry is published and consistently referenced.",
        "Sensitive requests are blocked unless verified out-of-band and approved by policy.",
        "Users and partners consistently reject off-channel or identity-ambiguous requests.",
    ]
    control_points: list[dict[str, str]] = [
        {"title": "Enforce out-of-band verification for sensitive requests", "effort": "MED", "expected_reduction": "HIGH"},
        {"title": "Publish and maintain one official channel registry", "effort": "LOW", "expected_reduction": "HIGH"},
        {"title": "Require approval gates for high-impact workflow changes", "effort": "MED", "expected_reduction": "HIGH"},
    ]
    if contradictions:
        control_points.insert(
            0,
            {
                "title": f"Resolve contradiction: {str(contradictions[0])[:180]}",
                "effort": "MED",
                "expected_reduction": "HIGH",
            },
        )

    rt = str(risk_type or "").strip().lower()
    primary = str(primary_risk_type or "").strip().lower()
    mitre_categories: list[str] = []
    if any(k in f"{rt} {primary}" for k in ("impersonation", "social", "phish", "channel", "trust")):
        mitre_categories.extend(["T1566", "T1598"])
    if any(k in f"{rt} {primary}" for k in ("credential", "account", "login")):
        mitre_categories.append("T1078")
    if any(k in f"{rt} {primary}" for k in ("payment", "invoice", "fraud", "booking", "vendor")):
        mitre_categories.append("T1656")
    mitre_categories = _safe_mitre_codes(mitre_categories, max_items=6)

    abuse_path = _safe_abuse_path_steps(base_timeline, max_items=6)
    if not abuse_path:
        abuse_path = _safe_abuse_path_steps(
            [
                {
                    "step": "1",
                    "title": "Recon public trust signals",
                    "detail": "Collect official channels, role cues, and workflow wording from public sources.",
                },
                {
                    "step": "2",
                    "title": "Craft credible interaction",
                    "detail": "Align message with observed process language and expected communication style.",
                },
                {
                    "step": "3",
                    "title": "Move to sensitive workflow",
                    "detail": "Escalate from low-friction contact into a request touching payment/account/process actions.",
                },
                {
                    "step": "4",
                    "title": "Exploit verification gaps",
                    "detail": "Use urgency or channel ambiguity to bypass out-of-band checks and approvals.",
                },
            ],
            max_items=6,
        )
    abuse_path_graph = _local_abuse_path_graph(
        steps=abuse_path,
        contradictions=list(contradictions or []),
        risk_type=str(risk_type or ""),
        primary_risk_type=str(primary_risk_type or ""),
    )

    return {
        "why_it_matters": why,
        "how": how,
        "business_impact": business_impact,
        "confirm_points": _safe_section_points(confirm_points, max_items=4, max_chars=190),
        "deny_points": _safe_section_points(deny_points, max_items=4, max_chars=190),
        "control_points": _safe_control_points(control_points, max_items=5),
        "mitre_categories": mitre_categories,
        "abuse_path": abuse_path,
        "abuse_path_graph": abuse_path_graph,
        "mode": "LOCAL",
        "shadow_note": "Generated from evidence with stable prompts and cache.",
    }


def _call_llm_risk_sections(
    *,
    api_key: str,
    model: str,
    primary_risk_type: str,
    risk_type: str,
    likelihood: str,
    impact_band: str,
    evidence_strength: str,
    confidence: int,
    why_it_matters: str,
    contradictions: list[str],
    base_timeline: list[dict[str, str]],
    evidence_norm: list[dict[str, Any]],
) -> dict[str, Any] | None:
    ctx = {
        "primary_risk_type": str(primary_risk_type or ""),
        "risk_type": str(risk_type or ""),
        "likelihood": str(likelihood or ""),
        "impact_band": str(impact_band or ""),
        "evidence_strength": str(evidence_strength or ""),
        "confidence": int(confidence or 0),
        "why_it_matters": str(why_it_matters or ""),
        "contradictions": [str(x) for x in (contradictions or []) if str(x).strip()][:5],
        "base_timeline": base_timeline[:6],
        "evidence": evidence_norm[:48],
    }
    system_prompt = (
        "You are a defensive CTI analyst writing clear business-facing risk reasoning. "
        "Only use provided evidence. No exploit instructions, no phishing scripts, no offensive guidance."
    )
    user_prompt = (
        "Return JSON only with keys:\n"
        "- why_it_matters (1 short paragraph)\n"
        "- how (1 paragraph, 90-140 words, plausible workflow of a malicious actor)\n"
        "- business_impact (1-2 concise sentences)\n"
        "- mitre_categories (array of ATT&CK codes like T1566, T1078, T1598, max 6)\n"
        "- abuse_path (array 4-6 objects: {step,title,detail})\n"
        "- abuse_path_graph (object with nodes+links for sankey-style branching: "
        "{nodes:[{id,stage,title,detail,type}], links:[{source,target,label,weight}]})\n"
        "- confirm_points (array 2-4)\n"
        "- deny_points (array 2-4)\n"
        "- control_points (array 3-5 objects: {title, effort[LOW|MED|HIGH], expected_reduction[LOW|MED|HIGH]})\n"
        "Rules:\n"
        "- Keep why_it_matters semantically consistent with input why_it_matters.\n"
        "- Keep language concrete and human.\n"
        "- Use only evidence in context.\n"
        "- Use probabilistic language: could/may/likely; avoid deterministic claims.\n"
        "- Treat output as a risk hypothesis, not proof of an active incident.\n"
        "- If evidence is mainly contact/role/channel visibility, keep outcomes broad (e.g., unauthorized access/data exposure) and avoid overly specific claims.\n"
        "- If contradictions are present, include at least one control point to resolve them.\n"
        "- abuse_path must reflect a plausible sequence and remain defensive-only.\n"
        "- abuse_path_graph must be consistent with abuse_path, but can include realistic branch/deviation paths when evidence supports them.\n"
        "- Prefer 4-10 nodes and 4-14 links; include at least one decision/branch node when plausible.\n"
        "- No markdown, no bullets outside arrays.\n\n"
        "JSON context:\n"
        + json.dumps(ctx, ensure_ascii=True)
    )
    payload = {
        "model": model,
        "temperature": 0,
        "response_format": {"type": "json_object"},
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
    }
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    try:
        res = _post_llm_with_backoff(
            url="https://api.openai.com/v1/chat/completions",
            payload=payload,
            headers=headers,
            timeout_seconds=40,
            caller="RiskSections",
        )
        if res is None or int(res.status_code or 0) >= 400:
            if res is not None and int(res.status_code or 0) >= 400:
                logger.warning("Risk sections LLM request failed: status=%s", res.status_code)
            return None
        body = res.json()
        content = body.get("choices", [{}])[0].get("message", {}).get("content", "{}")
        parsed = _parse_llm_sections_blob(str(content or ""))
        if not parsed:
            return None
        parsed["mode"] = "LLM"
        return parsed
    except Exception:
        logger.exception("Risk sections LLM request failed unexpectedly")
        return None


def get_or_generate_llm_risk_sections(
    db: Session,
    *,
    assessment_id: int,
    risk_id: int,
    primary_risk_type: str,
    risk_type: str,
    likelihood: str,
    impact_band: str,
    evidence_strength: str,
    confidence: int,
    why_it_matters: str,
    contradictions: list[str] | None,
    base_timeline: list[dict[str, str]] | None,
    evidence: list[dict[str, Any]],
    generate_if_missing: bool = True,
) -> dict[str, Any]:
    evidence_norm = _normalize_llm_hypothesis_evidence(evidence, max_items=48)
    contradiction_rows = [str(x).strip() for x in (contradictions or []) if str(x).strip()][:5]
    timeline_rows = _normalize_abuse_path_steps(base_timeline, max_items=6)
    safe_why = _safe_section_line(str(why_it_matters or ""), max_chars=320)
    if len(evidence_norm) < 2:
        if not bool(generate_if_missing):
            return {}
        return _local_llm_sections_payload(
            why_it_matters=safe_why,
            primary_risk_type=primary_risk_type,
            risk_type=risk_type,
            likelihood=likelihood,
            impact_band=impact_band,
            contradictions=contradiction_rows,
            base_timeline=timeline_rows,
            evidence_norm=evidence_norm,
        )

    input_hash = _hash_llm_sections_input(
        assessment_id=int(assessment_id),
        risk_id=int(risk_id),
        primary_risk_type=str(primary_risk_type or ""),
        risk_type=str(risk_type or ""),
        likelihood=str(likelihood or ""),
        impact_band=str(impact_band or ""),
        evidence_strength=str(evidence_strength or ""),
        confidence=int(confidence or 0),
        why_it_matters=safe_why,
        contradictions=contradiction_rows,
        base_timeline=timeline_rows,
        evidence_norm=evidence_norm,
    )
    existing = (
        db.execute(
            select(RiskBrief)
            .where(
                RiskBrief.assessment_id == int(assessment_id),
                RiskBrief.risk_kind == "scenario_llm_sections",
                RiskBrief.risk_id == int(risk_id),
                RiskBrief.input_hash == input_hash,
            )
            .order_by(RiskBrief.created_at.desc(), RiskBrief.id.desc())
            .limit(1)
        )
        .scalars()
        .first()
    )
    if existing and str(existing.brief or "").strip():
        cached = _parse_llm_sections_blob(str(existing.brief or ""))
        if cached:
            return cached
    if not bool(generate_if_missing):
        return {}

    llm_cfg = get_llm_runtime_config(db)
    model = str(llm_cfg.get("model") or "LOCAL").strip()
    api_key = str(llm_cfg.get("api_key") or "").strip()
    is_local = model.upper() == "LOCAL" or not api_key

    payload: dict[str, Any] | None = None
    if not is_local:
        payload = _call_llm_risk_sections(
            api_key=api_key,
            model=model,
            primary_risk_type=primary_risk_type,
            risk_type=risk_type,
            likelihood=likelihood,
            impact_band=impact_band,
            evidence_strength=evidence_strength,
            confidence=confidence,
            why_it_matters=safe_why,
            contradictions=contradiction_rows,
            base_timeline=timeline_rows,
            evidence_norm=evidence_norm,
        )
    if not payload:
        payload = _local_llm_sections_payload(
            why_it_matters=safe_why,
            primary_risk_type=primary_risk_type,
            risk_type=risk_type,
            likelihood=likelihood,
            impact_band=impact_band,
            contradictions=contradiction_rows,
            base_timeline=timeline_rows,
            evidence_norm=evidence_norm,
        )

    payload["mode"] = "LLM" if str(payload.get("mode", "LOCAL")).upper() == "LLM" and not is_local else "LOCAL"
    payload["why_it_matters"] = _safe_section_line(str(payload.get("why_it_matters", "") or safe_why), max_chars=320)
    payload["how"] = _sanitize_how_text(str(payload.get("how", "")))
    payload["business_impact"] = _safe_section_line(str(payload.get("business_impact", "")), max_chars=420)
    payload["confirm_points"] = _safe_section_points(payload.get("confirm_points") or [], max_items=4, max_chars=190)
    payload["deny_points"] = _safe_section_points(payload.get("deny_points") or [], max_items=4, max_chars=190)
    payload["control_points"] = _safe_control_points(payload.get("control_points") or [], max_items=5)
    payload["mitre_categories"] = _safe_mitre_codes(payload.get("mitre_categories") or [], max_items=6)
    payload["abuse_path"] = _safe_abuse_path_steps(payload.get("abuse_path") or timeline_rows, max_items=6)
    payload["abuse_path_graph"] = _safe_abuse_path_graph(
        payload.get("abuse_path_graph") or payload.get("abuse_graph") or {},
        fallback_steps=list(payload.get("abuse_path") or timeline_rows),
        max_nodes=10,
        max_links=18,
    )
    payload["shadow_note"] = "Generated from evidence with stable prompts and cache."

    if payload.get("why_it_matters"):
        row = RiskBrief(
            assessment_id=int(assessment_id),
            risk_kind="scenario_llm_sections",
            risk_id=int(risk_id),
            input_hash=input_hash,
            model=("LOCAL" if is_local else str(model or "LOCAL"))[:64],
            brief=json.dumps(payload, ensure_ascii=True),
        )
        try:
            db.add(row)
            db.commit()
        except Exception:
            logger.exception(
                "Failed to persist LLM risk sections for assessment=%s risk=%s",
                int(assessment_id),
                int(risk_id),
            )
            try:
                db.rollback()
            except Exception:
                pass
    return payload
