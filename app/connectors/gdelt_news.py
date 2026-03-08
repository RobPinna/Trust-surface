from datetime import datetime
import hashlib

import requests

from app.config import get_settings
from app.connectors.base import ConnectorBase, ConnectorTarget, EvidencePayload

# MENA region keywords used to trigger bilingual (Arabic) GDELT queries.
_MENA_KEYWORDS = frozenset({
    "uae", "dubai", "abu dhabi", "saudi", "ksa", "riyadh", "jeddah",
    "qatar", "doha", "kuwait", "bahrain", "oman", "muscat", "jordan",
    "amman", "lebanon", "beirut", "egypt", "cairo", "iraq", "baghdad",
    "morocco", "casablanca", "algeria", "tunisia", "libya", "yemen",
    "syria", "palestine", "iran", "turkey", "israel", "mena", "gulf",
    "gcc", "levant", "maghreb", "middle east",
})


class GDELTNewsConnector(ConnectorBase):
    name = "gdelt_news"
    description = "Fetches recent global news mentions from GDELT (bilingual EN+AR for MENA targets)"

    _API_URL = "https://api.gdeltproject.org/api/v2/doc/doc"

    def _is_mena_target(self, target: ConnectorTarget) -> bool:
        regions_lower = (target.regions or "").lower()
        return any(kw in regions_lower for kw in _MENA_KEYWORDS)

    def _fetch_articles(
        self,
        query: str,
        target: ConnectorTarget,
        settings,
        lang_label: str = "en",
    ) -> list[dict]:
        """Run a single GDELT query and return raw article dicts."""
        params = {
            "query": query,
            "mode": "ArtList",
            "maxrecords": 20,
            "format": "json",
            "sort": "DateDesc",
        }
        fetched_at = datetime.utcnow()
        try:
            res = requests.get(
                self._API_URL,
                params=params,
                timeout=settings.request_timeout_seconds,
                headers={"User-Agent": settings.website_user_agent},
            )
            res.raise_for_status()
            payload = res.json()
            target.log_examination(
                url=res.url or self._API_URL,
                source_type="news",
                status="fetched",
                discovered_from=f"gdelt api query [{lang_label}]",
                http_status=res.status_code,
                content_hash=hashlib.sha256(res.content).hexdigest()[:32] if res.content else "",
                bytes_size=len(res.content or b""),
                parse_summary=f"query={query}",
                fetched_at=fetched_at,
            )
            return payload.get("articles", []) if isinstance(payload, dict) else []
        except Exception as exc:
            target.log_examination(
                url=self._API_URL,
                source_type="news",
                status="failed",
                discovered_from=f"gdelt api query [{lang_label}]",
                error_message=exc.__class__.__name__,
                fetched_at=fetched_at,
            )
            return []

    def run(self, target: ConnectorTarget, api_key: str | None = None) -> list[EvidencePayload]:
        settings = get_settings()

        # --- Build primary (English) query ---
        base_query = target.company_name
        if target.regions:
            base_query = f"{base_query} {target.regions.split(',')[0].strip()}"

        articles: list[dict] = self._fetch_articles(base_query, target, settings, lang_label="en")

        # --- Bilingual pass: add Arabic-language sources for MENA targets ---
        if self._is_mena_target(target):
            arabic_query = f"{target.company_name} sourcelang:arabic"
            arabic_articles = self._fetch_articles(arabic_query, target, settings, lang_label="ar")
            # Deduplicate by URL before merging
            seen_urls: set[str] = {str(a.get("url") or "") for a in articles}
            for art in arabic_articles:
                url = str(art.get("url") or "")
                if url not in seen_urls:
                    articles.append(art)
                    seen_urls.add(url)

        if not articles:
            if target.demo_mode:
                fallback_url = "https://example.local/news/demo-1"
                target.log_examination(
                    url=fallback_url,
                    source_type="news",
                    status="parsed",
                    discovered_from="gdelt fallback",
                    parse_summary="demo fallback article",
                    fetched_at=datetime.utcnow(),
                )
                return [
                    EvidencePayload(
                        connector=self.name,
                        category="mention",
                        title=f"Demo news pressure around {target.company_name}",
                        snippet="Local media discussed service disruption rumors impacting brand trust.",
                        source_url=fallback_url,
                        confidence=52,
                        raw={"demo": True},
                    )
                ]
            return []

        evidences: list[EvidencePayload] = []
        for article in articles[:40]:
            title = article.get("title") or "Untitled article"
            url = article.get("url") or ""
            source = article.get("sourceCommonName") or article.get("domain") or "unknown source"
            seen = article.get("seendate") or ""
            lang = article.get("language") or ""
            snippet = f"{source} | seen {seen}" + (f" | lang={lang}" if lang else "")
            evidences.append(
                EvidencePayload(
                    connector=self.name,
                    category="mention",
                    title=title[:250],
                    snippet=snippet,
                    source_url=url,
                    confidence=65,
                    raw=article,
                )
            )
            target.log_examination(
                url=url or "gdelt://result",
                source_type="news",
                status="parsed",
                discovered_from="gdelt result",
                parse_summary=title[:200],
                fetched_at=datetime.utcnow(),
            )

        return evidences
