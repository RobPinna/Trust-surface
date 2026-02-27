from __future__ import annotations

import re
from datetime import datetime

from sqlalchemy import select

from app.connectors.base import ConnectorBase, ConnectorTarget, EvidencePayload
from app.db import SessionLocal
from app.models import Document

PROCUREMENT_TERMS = (
    "procurement",
    "supplier",
    "vendor",
    "tender",
    "rfp",
    "purchase order",
    "invoice",
    "accounts payable",
    "payment instruction",
)

HIGH_RISK_TERMS = (
    "bank account change",
    "payment update",
    "wire",
    "urgent invoice",
    "shared mailbox",
    "email approval",
)

POLICY_PATTERNS: dict[str, tuple[re.Pattern[str], ...]] = {
    "thresholds": (
        re.compile(
            r"\b(?:threshold|limit|cap|ceiling)\b[^.\n]{0,90}\b(?:€|\$|£)?\s?\d[\d.,]{2,}\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(?:over|above|exceed(?:s|ing)?|greater than|more than|at least|min(?:imum)?)\b[^.\n]{0,80}\b(?:€|\$|£)?\s?\d[\d.,]{2,}\b",
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
    ),
    "urgency_exceptions": (
        re.compile(
            r"\b(?:urgent|emergency|exception|expedite|fast[- ]track)\b[^.\n]{0,100}\b(?:override|bypass|waive|without|outside standard|temporary deviation)\b",
            re.IGNORECASE,
        ),
    ),
}


class ProcurementDocumentsConnector(ConnectorBase):
    name = "procurement_documents"
    description = "Extracts procurement-workflow exposure signals from collected HTML/PDF documents"

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
                url="connector://procurement_documents",
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
                        Document.doc_type.in_(["html", "pdf"]),
                    )
                )
                .scalars()
                .all()
            )

        evidences: list[EvidencePayload] = []
        hit_docs = 0
        for doc in docs:
            source_text = f"{doc.url} {doc.title} {doc.extracted_text}"
            low = source_text.lower()
            if not any(term in low for term in PROCUREMENT_TERMS):
                continue
            hit_docs += 1
            evidences.append(
                EvidencePayload(
                    connector=self.name,
                    category="touchpoint",
                    title="Procurement workflow publicly discoverable",
                    snippet=f"Document references procurement/supplier flow: {doc.title or doc.url}",
                    source_url=doc.url,
                    confidence=76,
                    raw={"doc_id": doc.id, "doc_type": doc.doc_type},
                )
            )
            if any(term in low for term in HIGH_RISK_TERMS):
                evidences.append(
                    EvidencePayload(
                        connector=self.name,
                        category="pivot",
                        title="Procurement communication abuse risk",
                        snippet=(
                            "Public workflow language includes payment/invoice cues that can be reused in impersonation attempts "
                            "toward suppliers or finance contacts."
                        ),
                        source_url=doc.url,
                        confidence=78,
                        raw={"doc_id": doc.id, "risk": "procurement_impersonation"},
                    )
                )

            policy_hits = self._extract_policy_hits(source_text)
            policy_config = {
                "thresholds": ("Procurement policy thresholds detected", "touchpoint", 80),
                "approvals": ("Procurement approval controls detected", "touchpoint", 82),
                "allowed_channels": ("Procurement allowed-channel rules detected", "touchpoint", 82),
                "urgency_exceptions": ("Procurement urgency exception language detected", "pivot", 86),
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
                            "doc_id": doc.id,
                            "policy_type": policy_type,
                            "matches": entries[:8],
                        },
                    )
                )

            has_portal_only = bool(
                re.search(
                    r"\b(?:only|must|exclusively)\b[^.\n]{0,60}\b(?:portal|ticket(?:ing)? system|web form)\b",
                    low,
                )
            )
            has_email_dm = bool(
                re.search(
                    r"\b(?:email|shared mailbox|dm|direct message|whatsapp|telegram|sms)\b",
                    low,
                )
            )
            if has_portal_only and has_email_dm:
                evidences.append(
                    EvidencePayload(
                        connector=self.name,
                        category="pivot",
                        title="Procurement workflow channel contradiction",
                        snippet=(
                            "Document states portal-only flow while also exposing email/DM pathways for related "
                            "procurement requests."
                        ),
                        source_url=doc.url,
                        confidence=85,
                        raw={
                            "doc_id": doc.id,
                            "policy_type": "channel_contradiction",
                            "portal_only": True,
                            "off_channel_refs": True,
                        },
                    )
                )

        target.log_examination(
            url="connector://procurement_documents",
            source_type="manual",
            status="parsed" if hit_docs else "skipped",
            discovered_from="collector_v2 output",
            parse_summary=f"documents={len(docs)} procurement_hits={hit_docs} evidences={len(evidences)}",
            fetched_at=datetime.utcnow(),
        )

        return evidences[:80]
