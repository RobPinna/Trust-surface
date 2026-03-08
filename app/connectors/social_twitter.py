"""Twitter/X v2 Recent Search connector for brand mention monitoring.

Authentication: Bearer token (api_key parameter).
    - With Bearer token  → calls Twitter API v2 /tweets/search/recent
    - Without token, demo_mode=True → returns curated mock mentions (same as social_mock)
    - Without token, demo_mode=False → returns [] with audit log

Free-tier note: Twitter API v2 Basic allows up to 500K tweet reads/month.
The Free tier is read-only and rate-limited to 1 request per 15 minutes per endpoint
per app. This connector respects 429 responses with a graceful skip.

MENA bilingual: when MENA regions are detected an additional Arabic-language query
is issued (lang:ar) to surface regional brand mentions.

References
----------
- https://developer.twitter.com/en/docs/twitter-api/tweets/search/api-reference/get-tweets-search-recent
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

import requests

from app.config import get_settings
from app.connectors.base import ConnectorBase, ConnectorTarget, EvidencePayload

_API_URL = "https://api.twitter.com/2/tweets/search/recent"

_MENA_KEYWORDS = frozenset({
    "uae", "dubai", "abu dhabi", "saudi", "ksa", "riyadh", "jeddah",
    "qatar", "doha", "kuwait", "bahrain", "oman", "muscat", "jordan",
    "amman", "lebanon", "beirut", "egypt", "cairo", "iraq", "baghdad",
    "morocco", "casablanca", "algeria", "tunisia", "libya", "yemen",
    "syria", "palestine", "iran", "turkey", "israel", "mena", "gulf",
    "gcc", "levant", "maghreb", "middle east",
})

# Mock posts used as fallback in demo mode (mirrors social_mock dataset).
_MOCK_POSTS = [
    {
        "title": "Community thread questions invoice portal legitimacy",
        "tone": "concerned",
        "theme": "billing impersonation",
        "community": "regional business forum",
    },
    {
        "title": "Volunteer group discusses fake donation messages",
        "tone": "alarmed",
        "theme": "charity spoofing",
        "community": "ngo supporters",
    },
    {
        "title": "Customer post cites delayed support responses",
        "tone": "frustrated",
        "theme": "support trust",
        "community": "social feed",
    },
    {
        "title": "Industry chatter links brand with partner onboarding scams",
        "tone": "neutral",
        "theme": "partner pivot",
        "community": "supply chain group",
    },
]


class SocialTwitterConnector(ConnectorBase):
    name = "social_twitter"
    requires_api_key = True
    description = (
        "Twitter/X v2 brand mention monitor. "
        "Requires Bearer token; falls back to curated mock signals in demo mode."
    )

    def ping(self, api_key: str | None = None) -> tuple[bool, str]:
        if not api_key:
            return False, "Missing Bearer token"
        return True, "Bearer token present"

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _is_mena_target(self, target: ConnectorTarget) -> bool:
        regions_lower = (target.regions or "").lower()
        return any(kw in regions_lower for kw in _MENA_KEYWORDS)

    def _build_queries(self, target: ConnectorTarget) -> list[tuple[str, str]]:
        """Return list of (query_string, lang_label) tuples to execute."""
        company = target.company_name.strip()
        # Wrap in quotes only if no special chars that would break the query
        safe_name = company.replace('"', "")
        queries: list[tuple[str, str]] = [
            (f'"{safe_name}" -is:retweet -is:reply lang:en', "en"),
        ]
        if self._is_mena_target(target):
            queries.append((f'"{safe_name}" -is:retweet -is:reply lang:ar', "ar"))
        return queries

    def _fetch_tweets(
        self,
        query: str,
        bearer_token: str,
        settings,
        lang_label: str,
        target: ConnectorTarget,
    ) -> list[dict[str, Any]]:
        headers = {
            "Authorization": f"Bearer {bearer_token}",
            "User-Agent": settings.website_user_agent,
        }
        params = {
            "query": query,
            "max_results": 20,
            "tweet.fields": "text,created_at,public_metrics,lang",
            "expansions": "author_id",
            "user.fields": "username,name",
        }
        fetched_at = datetime.utcnow()
        try:
            res = requests.get(
                _API_URL,
                headers=headers,
                params=params,
                timeout=max(12, settings.request_timeout_seconds),
            )
            if res.status_code == 429:
                target.log_examination(
                    url=_API_URL,
                    source_type="manual",
                    status="skipped",
                    discovered_from=f"twitter v2 [{lang_label}]",
                    http_status=429,
                    parse_summary="rate limited",
                    fetched_at=fetched_at,
                )
                return []
            if res.status_code in {401, 403}:
                target.log_examination(
                    url=_API_URL,
                    source_type="manual",
                    status="failed",
                    discovered_from=f"twitter v2 [{lang_label}]",
                    http_status=res.status_code,
                    parse_summary="auth error",
                    fetched_at=fetched_at,
                )
                return []
            res.raise_for_status()
            payload = res.json() if res.text.strip() else {}
            target.log_examination(
                url=res.url or _API_URL,
                source_type="manual",
                status="parsed",
                discovered_from=f"twitter v2 [{lang_label}]",
                http_status=res.status_code,
                bytes_size=len(res.content or b""),
                parse_summary=f"query={query[:120]}",
                fetched_at=fetched_at,
            )
            data = payload.get("data") if isinstance(payload, dict) else None
            return data if isinstance(data, list) else []
        except Exception as exc:
            target.log_examination(
                url=_API_URL,
                source_type="manual",
                status="failed",
                discovered_from=f"twitter v2 [{lang_label}]",
                error_message=exc.__class__.__name__,
                fetched_at=fetched_at,
            )
            return []

    def _tweet_to_evidence(self, tweet: dict[str, Any]) -> EvidencePayload:
        tweet_id = str(tweet.get("id") or "")
        text = str(tweet.get("text") or "").strip()
        created_at = str(tweet.get("created_at") or "")
        lang = str(tweet.get("lang") or "")
        metrics = tweet.get("public_metrics") or {}
        likes = int(metrics.get("like_count") or 0)
        rts = int(metrics.get("retweet_count") or 0)
        replies = int(metrics.get("reply_count") or 0)

        source_url = (
            f"https://twitter.com/i/web/status/{tweet_id}"
            if tweet_id
            else "https://twitter.com"
        )
        snippet = f"likes={likes} retweets={rts} replies={replies} | {created_at}"
        if lang:
            snippet += f" | lang={lang}"

        # Higher engagement → slightly higher confidence
        engagement = likes + rts * 2 + replies
        confidence = 55 + min(20, engagement // 5)

        return EvidencePayload(
            connector=self.name,
            category="mention",
            title=text[:200] if text else "Twitter mention",
            snippet=snippet,
            source_url=source_url,
            confidence=confidence,
            raw=tweet,
        )

    def _mock_results(self, target: ConnectorTarget) -> list[EvidencePayload]:
        evidences: list[EvidencePayload] = []
        for idx, post in enumerate(_MOCK_POSTS, start=1):
            source_url = f"mock://social/mention/{idx}"
            evidences.append(
                EvidencePayload(
                    connector=self.name,
                    category="mention",
                    title=f"{target.company_name}: {post['title']}",
                    snippet=f"Theme={post['theme']}; Tone={post['tone']}; Community={post['community']}",
                    source_url=source_url,
                    confidence=58,
                    raw={"target": target.company_name, **post},
                )
            )
            target.log_examination(
                url=source_url,
                source_type="manual",
                status="parsed",
                discovered_from="social mock dataset",
                parse_summary=post["title"][:200],
                fetched_at=datetime.utcnow(),
            )
        return evidences

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def run(self, target: ConnectorTarget, api_key: str | None = None) -> list[EvidencePayload]:
        settings = get_settings()

        if not api_key:
            if target.demo_mode:
                return self._mock_results(target)
            target.log_examination(
                url=_API_URL,
                source_type="manual",
                status="skipped",
                discovered_from="twitter v2 connector",
                parse_summary="missing bearer token",
                fetched_at=datetime.utcnow(),
            )
            return []

        evidences: list[EvidencePayload] = []
        seen_ids: set[str] = set()

        for query, lang_label in self._build_queries(target):
            tweets = self._fetch_tweets(query, api_key, settings, lang_label, target)
            for tweet in tweets:
                tweet_id = str(tweet.get("id") or "")
                if tweet_id in seen_ids:
                    continue
                seen_ids.add(tweet_id)
                evidences.append(self._tweet_to_evidence(tweet))

        return evidences[:40]
