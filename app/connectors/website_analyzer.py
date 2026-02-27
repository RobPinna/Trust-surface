import re
from datetime import datetime
from urllib.parse import urlparse

from sqlalchemy import select

from app.db import SessionLocal
from app.connectors.base import ConnectorBase, ConnectorTarget, EvidencePayload
from app.models import Document

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
PATH_RE = re.compile(r"\b/(?:[a-z0-9][a-z0-9/_-]{2,90})\b", re.IGNORECASE)

HIGH_RISK_CTA_PATTERNS: tuple[tuple[str, str, str], ...] = (
    ("payment", "High-risk CTA detected: payment request", r"\b(pay now|make payment|payment now|pay invoice|wire transfer)\b"),
    (
        "reset",
        "High-risk CTA detected: account reset/recovery",
        r"\b(reset (?:password|account)|recover account|unlock account|verify account)\b",
    ),
    (
        "bank_update",
        "High-risk CTA detected: bank/payment detail update",
        r"\b(update (?:bank|iban|payment|account) details|change (?:bank|beneficiary) account)\b",
    ),
    ("urgency", "High-risk CTA detected: urgency language", r"\b(urgent|immediately|asap|action required|today only)\b"),
)

RISK_ENDPOINT_HINTS: tuple[tuple[str, str], ...] = (
    ("login", "authentication"),
    ("signin", "authentication"),
    ("auth", "authentication"),
    ("account", "account"),
    ("reset", "account recovery"),
    ("password", "account recovery"),
    ("payment", "payment"),
    ("billing", "billing"),
    ("invoice", "invoice"),
    ("checkout", "payment"),
    ("refund", "refund"),
    ("bank", "bank update"),
    ("iban", "bank update"),
    ("wallet", "payment"),
    ("helpdesk", "support"),
    ("support", "support"),
    ("ticket", "support"),
    ("portal", "portal"),
)

PROVIDER_HINTS = {
    "googletagmanager": "Google Tag Manager",
    "google-analytics": "Google Analytics",
    "recaptcha": "Google reCAPTCHA",
    "zendesk": "Zendesk",
    "intercom": "Intercom",
    "hubspot": "HubSpot",
    "freshdesk": "Freshdesk",
}


class WebsiteAnalyzerConnector(ConnectorBase):
    name = "website_analyzer"
    description = "Builds website public information exposure indicators from collector_v2 normalized HTML documents"

    def _context_excerpt(self, text: str, start: int, end: int, window: int = 84) -> str:
        left = max(0, int(start) - int(window))
        right = min(len(text), int(end) + int(window))
        excerpt = " ".join(str(text[left:right] or "").split()).strip()
        return excerpt[:260]

    def _endpoint_hint(self, value: str) -> str:
        low = str(value or "").lower()
        for marker, label in RISK_ENDPOINT_HINTS:
            if marker in low:
                return label
        return ""

    def _normalize_url_or_path(self, value: str) -> str:
        raw = str(value or "").strip()
        if not raw:
            return ""
        if raw.startswith("http://") or raw.startswith("https://"):
            try:
                p = urlparse(raw)
                host = (p.netloc or "").strip().lower()
                path = (p.path or "/").strip() or "/"
                if not host:
                    return ""
                return f"{p.scheme.lower()}://{host}{path}"
            except Exception:
                return raw[:240]
        if raw.startswith("/"):
            return raw[:240]
        return ""

    def run(self, target: ConnectorTarget, api_key: str | None = None) -> list[EvidencePayload]:
        if not target.assessment_id:
            target.log_examination(
                url="connector://website_analyzer",
                source_type="manual",
                status="skipped",
                discovered_from="connector-run",
                parse_summary="missing assessment_id for document lookup",
                fetched_at=datetime.utcnow(),
            )
            return []

        with SessionLocal() as db:
            docs = (
                db.execute(
                    select(Document).where(
                        Document.assessment_id == target.assessment_id,
                        Document.doc_type == "html",
                    )
                )
                .scalars()
                .all()
            )

        if not docs:
            target.log_examination(
                url="connector://website_analyzer",
                source_type="manual",
                status="skipped",
                discovered_from="collector_v2 output",
                parse_summary="no html documents available",
                fetched_at=datetime.utcnow(),
            )
            return []

        evidences: list[EvidencePayload] = []
        seen_emails: set[str] = set()
        seen_providers: set[str] = set()
        seen_touchpoints: set[str] = set()
        seen_cta: set[str] = set()
        seen_endpoints: set[str] = set()

        for doc in docs:
            text = str(doc.extracted_text or "")
            lower = text.lower()
            if not lower:
                continue

            for email in EMAIL_RE.findall(lower):
                if email in seen_emails:
                    continue
                seen_emails.add(email)
                evidences.append(
                    EvidencePayload(
                        connector=self.name,
                        category="exposure",
                        title="Public contact email exposed in website content",
                        snippet=f"Found public email: {email}",
                        source_url=doc.url,
                        confidence=90,
                        raw={"email": email, "document_id": doc.id},
                    )
                )

            for marker, provider in PROVIDER_HINTS.items():
                if marker in lower and provider not in seen_providers:
                    seen_providers.add(provider)
                    evidences.append(
                        EvidencePayload(
                            connector=self.name,
                            category="touchpoint",
                            title=f"Third-party provider detected: {provider}",
                            snippet=f"Provider marker '{marker}' found in normalized document text.",
                            source_url=doc.url,
                            confidence=76,
                            raw={"provider": provider, "marker": marker, "document_id": doc.id},
                        )
                    )

            for keyword in ("support", "billing", "helpdesk", "contact", "careers"):
                if keyword in lower and keyword not in seen_touchpoints:
                    seen_touchpoints.add(keyword)
                    evidences.append(
                        EvidencePayload(
                            connector=self.name,
                            category="touchpoint",
                            title=f"Public external contact channel exposed: {keyword}",
                            snippet=f"'{keyword}' external contact channel appears in public website content.",
                            source_url=doc.url,
                            confidence=70,
                            raw={"keyword": keyword, "document_id": doc.id},
                        )
                    )

            for cta_key, cta_title, cta_pattern in HIGH_RISK_CTA_PATTERNS:
                for match in re.finditer(cta_pattern, lower, flags=re.IGNORECASE):
                    phrase = " ".join(str(match.group(0) or "").split()).strip().lower()
                    if not phrase:
                        continue
                    dedupe_key = f"{cta_key}|{phrase}|{doc.url}"
                    if dedupe_key in seen_cta:
                        continue
                    seen_cta.add(dedupe_key)
                    context = self._context_excerpt(text, match.start(), match.end())
                    evidences.append(
                        EvidencePayload(
                            connector=self.name,
                            category="pivot" if cta_key in {"payment", "bank_update"} else "touchpoint",
                            title=cta_title,
                            snippet=f"Phrase '{phrase}' appears in public page context: {context}",
                            source_url=doc.url,
                            confidence=82 if cta_key in {"payment", "bank_update"} else 76,
                            raw={
                                "cta_type": cta_key,
                                "phrase": phrase,
                                "context": context,
                                "document_id": doc.id,
                            },
                        )
                    )
                    if len(evidences) >= 180:
                        break
                if len(evidences) >= 180:
                    break

            endpoint_candidates: set[str] = set()
            for url_hit in URL_RE.findall(text):
                norm = self._normalize_url_or_path(url_hit)
                if norm:
                    endpoint_candidates.add(norm)
            for path_hit in PATH_RE.findall(text):
                norm = self._normalize_url_or_path(path_hit)
                if norm:
                    endpoint_candidates.add(norm)
            if doc.url:
                parsed_path = ""
                try:
                    parsed_path = str(urlparse(doc.url).path or "").strip()
                except Exception:
                    parsed_path = ""
                if parsed_path:
                    endpoint_candidates.add(parsed_path)

            endpoint_hits = sorted(endpoint_candidates)
            for endpoint in endpoint_hits:
                hint = self._endpoint_hint(endpoint)
                if not hint:
                    continue
                dkey = f"{endpoint.lower()}|{hint}"
                if dkey in seen_endpoints:
                    continue
                seen_endpoints.add(dkey)
                risky = hint in {"payment", "billing", "invoice", "bank update", "account recovery", "authentication"}
                evidences.append(
                    EvidencePayload(
                        connector=self.name,
                        category="pivot" if risky else "touchpoint",
                        title="Sensitive workflow endpoint publicly reachable",
                        snippet=f"Endpoint `{endpoint}` appears publicly and maps to `{hint}` workflow.",
                        source_url=doc.url,
                        confidence=78 if risky else 71,
                        raw={
                            "endpoint": endpoint,
                            "workflow_hint": hint,
                            "document_id": doc.id,
                        },
                    )
                )
                if len(evidences) >= 180:
                    break

        target.log_examination(
            url="connector://website_analyzer",
            source_type="manual",
            status="parsed",
            discovered_from="collector_v2 output",
            parse_summary=f"documents={len(docs)} evidences={len(evidences)}",
            fetched_at=datetime.utcnow(),
        )

        return evidences[:140]
