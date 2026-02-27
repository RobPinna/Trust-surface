import re
from datetime import datetime

from sqlalchemy import select

from app.connectors.base import ConnectorBase, ConnectorTarget, EvidencePayload
from app.db import SessionLocal
from app.models import Document

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.IGNORECASE)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

POLICY_PATTERNS: dict[str, tuple[re.Pattern[str], ...]] = {
    "thresholds": (
        re.compile(
            r"\b(?:threshold|limit|ceiling|cap)\b[^.\n]{0,90}\b(?:€|\$|£)?\s?\d[\d.,]{2,}\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(?:over|above|exceed(?:s|ing)?|greater than|more than|below|under|up to|at least|min(?:imum)?|max(?:imum)?)\b[^.\n]{0,80}\b(?:€|\$|£)?\s?\d[\d.,]{2,}\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(?:€|\$|£)\s?\d[\d.,]{2,}\b[^.\n]{0,90}\b(?:approval|authori[sz]ation|sign-?off|threshold|limit)\b",
            re.IGNORECASE,
        ),
    ),
    "approvals": (
        re.compile(
            r"\b(?:approval required|approved by|manager approval|dual approval|two[- ]person|four-eyes|sign[- ]off|authori[sz]ed by)\b[^.\n]{0,100}",
            re.IGNORECASE,
        ),
    ),
    "allowed_channels": (
        re.compile(
            r"\b(?:only|must|shall|required to|exclusively)\b[^.\n]{0,80}\b(?:portal|ticket(?:ing)? system|helpdesk|official email|approved channel|web form)\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(?:do not|must not|not allowed|prohibited)\b[^.\n]{0,90}\b(?:email|dm|direct message|whatsapp|telegram|sms|phone)\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(?:approved|authori[sz]ed|allowed)\s+(?:channels?|communication)\b[^.\n]{0,80}",
            re.IGNORECASE,
        ),
    ),
    "urgency_exceptions": (
        re.compile(
            r"\b(?:urgent|emergency|exception|expedite|fast[- ]track)\b[^.\n]{0,100}\b(?:override|bypass|waive|without|outside standard|temporary deviation)\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(?:in case of|under)\b[^.\n]{0,50}\b(?:urgent|emergency)\b[^.\n]{0,100}\b(?:exception|deviation|temporary)\b",
            re.IGNORECASE,
        ),
    ),
}


class PublicDocsPdfConnector(ConnectorBase):
    name = "public_docs_pdf"
    description = "Builds IOC/external-contact-channel evidence from collector_v2 normalized PDF documents"

    def _context_excerpt(self, text: str, start: int, end: int, window: int = 90) -> str:
        left = max(0, int(start) - int(window))
        right = min(len(text), int(end) + int(window))
        return " ".join(str(text[left:right] or "").split()).strip()[:280]

    def _extract_policy_hits(self, text: str) -> dict[str, list[str]]:
        hits: dict[str, list[str]] = {k: [] for k in POLICY_PATTERNS.keys()}
        for policy_type, patterns in POLICY_PATTERNS.items():
            seen: set[str] = set()
            for pattern in patterns:
                for match in pattern.finditer(text):
                    excerpt = self._context_excerpt(text, match.start(), match.end())
                    key = excerpt.lower()
                    if not excerpt or key in seen:
                        continue
                    seen.add(key)
                    hits[policy_type].append(excerpt)
                    if len(hits[policy_type]) >= 8:
                        break
                if len(hits[policy_type]) >= 8:
                    break
        return hits

    def run(self, target: ConnectorTarget, api_key: str | None = None) -> list[EvidencePayload]:
        if not target.assessment_id:
            target.log_examination(
                url="connector://public_docs_pdf",
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
                        Document.doc_type == "pdf",
                    )
                )
                .scalars()
                .all()
            )

        if not docs:
            target.log_examination(
                url="connector://public_docs_pdf",
                source_type="manual",
                status="skipped",
                discovered_from="collector_v2 output",
                parse_summary="no pdf documents available",
                fetched_at=datetime.utcnow(),
            )
            return []

        evidences: list[EvidencePayload] = []
        touchpoint_keywords = {
            "billing": "Billing external contact channel appears in public document text",
            "invoice": "Invoice processing external contact channel appears in public document text",
            "support": "Support process external contact channel appears in public document text",
            "helpdesk": "Helpdesk process external contact channel appears in public document text",
            "onboarding": "Onboarding process external contact channel appears in public document text",
            "vendor": "Vendor interaction external contact channel appears in public document text",
            "procurement": "Procurement external contact channel appears in public document text",
            "donation": "Donation channel external contact flow appears in public document text",
            "refund": "Refund process external contact channel appears in public document text",
            "beneficiary": "Beneficiary support external contact channel appears in public document text",
        }

        for doc in docs:
            text = (doc.extracted_text or "").strip()
            if not text:
                continue
            lower = text.lower()

            evidences.append(
                EvidencePayload(
                    connector=self.name,
                    category="exposure",
                    title="Public PDF document parsed",
                    snippet=f"Normalized PDF document available: {doc.title or doc.url}",
                    source_url=doc.url,
                    confidence=70,
                    raw={"document_id": doc.id, "language": doc.language},
                )
            )

            emails = sorted(set(EMAIL_RE.findall(lower)))[:8]
            domains = [d for d in sorted(set(DOMAIN_RE.findall(lower))) if "." in d][:10]
            ips = sorted(set(IPV4_RE.findall(text)))[:10]

            if emails:
                evidences.append(
                    EvidencePayload(
                        connector=self.name,
                        category="exposure",
                        title="IOC from PDF: public emails detected",
                        snippet=", ".join(emails[:5]),
                        source_url=doc.url,
                        confidence=86,
                        raw={"ioc_type": "email", "values": emails, "document_id": doc.id},
                    )
                )

            if domains:
                evidences.append(
                    EvidencePayload(
                        connector=self.name,
                        category="exposure",
                        title="IOC from PDF: domains detected",
                        snippet=", ".join(domains[:6]),
                        source_url=doc.url,
                        confidence=84,
                        raw={"ioc_type": "domain", "values": domains, "document_id": doc.id},
                    )
                )

            if ips:
                evidences.append(
                    EvidencePayload(
                        connector=self.name,
                        category="exposure",
                        title="IOC from PDF: IPv4 addresses detected",
                        snippet=", ".join(ips[:5]),
                        source_url=doc.url,
                        confidence=82,
                        raw={"ioc_type": "ipv4", "values": ips, "document_id": doc.id},
                    )
                )

            for keyword, message in touchpoint_keywords.items():
                if keyword in lower:
                    evidences.append(
                        EvidencePayload(
                            connector=self.name,
                            category="touchpoint",
                            title=f"Document external contact channel indicator: {keyword}",
                            snippet=message,
                            source_url=doc.url,
                            confidence=76,
                            raw={"keyword": keyword, "document_id": doc.id},
                        )
                    )

            policy_hits = self._extract_policy_hits(text)
            policy_config = {
                "thresholds": ("Operational policy thresholds detected", "touchpoint", 77),
                "approvals": ("Operational approval rules detected", "touchpoint", 78),
                "allowed_channels": ("Operational allowed-channel rules detected", "touchpoint", 79),
                "urgency_exceptions": ("Operational urgency exception rules detected", "pivot", 83),
            }
            for policy_type, entries in policy_hits.items():
                if not entries:
                    continue
                title, category, confidence = policy_config[policy_type]
                evidences.append(
                    EvidencePayload(
                        connector=self.name,
                        category=category,
                        title=title,
                        snippet=" | ".join(entries[:2]),
                        source_url=doc.url,
                        confidence=confidence,
                        raw={
                            "policy_type": policy_type,
                            "matches": entries[:8],
                            "document_id": doc.id,
                        },
                    )
                )

            has_portal_only = bool(
                re.search(
                    r"\b(?:only|must|exclusively)\b[^.\n]{0,60}\b(?:portal|ticket(?:ing)? system|web form)\b",
                    lower,
                )
            )
            has_off_channel = bool(
                re.search(
                    r"\b(?:email|shared mailbox|dm|direct message|whatsapp|telegram|sms)\b",
                    lower,
                )
            )
            if has_portal_only and has_off_channel:
                evidences.append(
                    EvidencePayload(
                        connector=self.name,
                        category="pivot",
                        title="Policy-channel contradiction detected in public documentation",
                        snippet=(
                            "Policy language indicates portal-only workflow, while the same document also references "
                            "email/DM channels for similar operational requests."
                        ),
                        source_url=doc.url,
                        confidence=84,
                        raw={
                            "policy_type": "channel_contradiction",
                            "document_id": doc.id,
                            "portal_only": True,
                            "off_channel_refs": True,
                        },
                    )
                )

        target.log_examination(
            url="connector://public_docs_pdf",
            source_type="manual",
            status="parsed",
            discovered_from="collector_v2 output",
            parse_summary=f"documents={len(docs)} evidences={len(evidences)}",
            fetched_at=datetime.utcnow(),
        )

        return evidences[:120]
