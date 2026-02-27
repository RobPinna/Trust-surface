from __future__ import annotations

from datetime import datetime
from typing import Any

import requests

from app.config import get_settings
from app.connectors.base import ConnectorBase, ConnectorTarget, EvidencePayload
from app.connectors.utils import canonical_domain_for_api


class HIBPBreachDomainConnector(ConnectorBase):
    name = "hibp_breach_domain"
    requires_api_key = True
    description = "Have I Been Pwned domain breach enrichment (verified domain/API required)"

    def ping(self, api_key: str | None = None) -> tuple[bool, str]:
        if not api_key:
            return False, "Missing API key"
        return True, "API key present"

    def _candidate_calls(self, domain: str) -> list[tuple[str, dict[str, str]]]:
        return [
            (
                f"https://haveibeenpwned.com/api/v3/breacheddomain/{domain}",
                {"truncateResponse": "false"},
            ),
            (f"https://haveibeenpwned.com/api/v3/breacheddomain/{domain}", {}),
            (f"https://haveibeenpwned.com/api/v3/breachesfordomain/{domain}", {}),
        ]

    def _extract_breaches(self, payload: Any) -> list[dict[str, Any]]:
        if isinstance(payload, list):
            return [x for x in payload if isinstance(x, dict)]
        if isinstance(payload, dict):
            direct = payload.get("breaches")
            if isinstance(direct, list):
                return [x for x in direct if isinstance(x, dict)]
            nested = payload.get("Breaches")
            if isinstance(nested, list):
                return [x for x in nested if isinstance(x, dict)]
        return []

    def run(self, target: ConnectorTarget, api_key: str | None = None) -> list[EvidencePayload]:
        domain = canonical_domain_for_api(target.domain)
        if not domain:
            target.log_examination(
                url="hibp://invalid-domain",
                source_type="news",
                status="failed",
                discovered_from="hibp connector",
                error_message="invalid target domain",
                fetched_at=datetime.utcnow(),
            )
            return []

        if not api_key:
            target.log_examination(
                url=f"hibp://{domain}",
                source_type="news",
                status="skipped",
                discovered_from="hibp connector",
                parse_summary="missing api key",
                fetched_at=datetime.utcnow(),
            )
            return []

        settings = get_settings()
        headers = {
            "hibp-api-key": api_key,
            "User-Agent": settings.website_user_agent,
            "Accept": "application/json",
        }

        fetched_at = datetime.utcnow()
        breaches: list[dict[str, Any]] = []
        used_url = ""
        call_errors: list[str] = []
        no_breach_observed = False

        for url, params in self._candidate_calls(domain):
            try:
                res = requests.get(url, params=params, headers=headers, timeout=max(8, settings.request_timeout_seconds))
                used_url = res.url or url
                if res.status_code == 404:
                    no_breach_observed = True
                    call_errors.append(f"{used_url} -> 404")
                    continue
                if res.status_code in {401, 403, 429}:
                    call_errors.append(f"{used_url} -> {res.status_code}")
                    continue
                res.raise_for_status()
                payload = res.json() if res.text.strip() else []
                breaches = self._extract_breaches(payload)
                target.log_examination(
                    url=used_url,
                    source_type="news",
                    status="parsed",
                    discovered_from="hibp api",
                    http_status=res.status_code,
                    bytes_size=len(res.content or b""),
                    parse_summary=f"domain breach lookup entries={len(breaches)}",
                    fetched_at=fetched_at,
                )
                break
            except Exception as exc:
                call_errors.append(f"{url} -> {exc.__class__.__name__}")

        if not breaches:
            target.log_examination(
                url=used_url or f"https://haveibeenpwned.com/api/v3/breacheddomain/{domain}",
                source_type="news",
                status="parsed" if no_breach_observed else "failed",
                discovered_from="hibp api",
                parse_summary="no breaches for domain" if no_breach_observed else "hibp call failed",
                error_message="" if no_breach_observed else "; ".join(call_errors)[:255],
                fetched_at=fetched_at,
            )
            return []

        entries: list[dict[str, Any]] = []
        total_pwned = 0
        for row in breaches[:18]:
            name = str(row.get("Name") or row.get("name") or row.get("Title") or "Unknown breach").strip()
            breach_date = str(row.get("BreachDate") or row.get("breachDate") or "").strip()
            pwn_count_raw = row.get("PwnCount", row.get("pwnCount", 0))
            try:
                pwn_count = int(pwn_count_raw or 0)
            except Exception:
                pwn_count = 0
            total_pwned += max(0, pwn_count)
            entries.append(
                {
                    "name": name,
                    "breach_date": breach_date,
                    "pwn_count": pwn_count,
                    "data_classes": row.get("DataClasses") or row.get("dataClasses") or [],
                    "is_verified": bool(row.get("IsVerified", row.get("isVerified", False))),
                }
            )

        out: list[EvidencePayload] = []
        out.append(
            EvidencePayload(
                connector=self.name,
                category="pivot",
                title=f"Domain breach exposure observed ({len(entries)} breaches)",
                snippet=(
                    f"HIBP domain search returned {len(entries)} breach datasets for `{domain}`. "
                    f"Estimated impacted records across datasets: {total_pwned}."
                ),
                source_url="https://haveibeenpwned.com/DomainSearch",
                confidence=86,
                raw={"domain": domain, "breaches": entries[:12], "total_pwned": total_pwned},
            )
        )

        for item in entries[:8]:
            snippet = (
                f"Breach `{item['name']}` dated {item['breach_date'] or 'unknown date'} "
                f"with approx {item['pwn_count']} records."
            )
            out.append(
                EvidencePayload(
                    connector=self.name,
                    category="pivot",
                    title=f"Domain breach dataset: {item['name']}",
                    snippet=snippet,
                    source_url="https://haveibeenpwned.com/DomainSearch",
                    confidence=82 if item["is_verified"] else 76,
                    raw=item,
                )
            )
        return out
