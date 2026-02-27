from __future__ import annotations

from datetime import datetime
from difflib import SequenceMatcher
from typing import Any

import dns.resolver
import requests

from app.config import get_settings
from app.connectors.base import ConnectorBase, ConnectorTarget, EvidencePayload
from app.connectors.utils import canonical_domain_for_api


COMMON_TLDS = ("com", "org", "net", "co", "io", "info", "biz")
MULTI_LABEL_SUFFIXES = {"co.uk", "org.uk", "com.au", "co.jp", "co.in", "com.br", "com.mx"}

KEYBOARD_NEIGHBORS: dict[str, str] = {
    "a": "qwsz",
    "b": "vghn",
    "c": "xdfv",
    "d": "ersfxc",
    "e": "rdsw",
    "f": "rtgdvc",
    "g": "tyfhvb",
    "h": "yugjbn",
    "i": "uojk",
    "j": "uikhmn",
    "k": "iojlm",
    "l": "opk",
    "m": "njk",
    "n": "bhjm",
    "o": "pikl",
    "p": "ol",
    "q": "wa",
    "r": "tfde",
    "s": "wedxza",
    "t": "ygfr",
    "u": "yihj",
    "v": "cfgb",
    "w": "qase",
    "x": "zsdc",
    "y": "tugh",
    "z": "asx",
}

CHAR_SUBSTITUTIONS: dict[str, str] = {
    "a": "4",
    "e": "3",
    "i": "1",
    "l": "1",
    "o": "0",
    "s": "5",
    "t": "7",
}


class BrandImpersonationMonitorConnector(ConnectorBase):
    name = "brand_impersonation_monitor"
    description = "Typosquat and impersonation monitor via DNS, RDAP and certificate transparency"

    max_candidates = 72
    max_rdap_checks = 28
    max_ct_checks = 18

    def _split_registered_domain(self, domain: str) -> tuple[str, str, str]:
        labels = [x for x in (domain or "").strip(".").lower().split(".") if x]
        if len(labels) < 2:
            return "", "", ""
        tail = ".".join(labels[-2:])
        if len(labels) >= 3 and tail in MULTI_LABEL_SUFFIXES:
            base = labels[-3]
            suffix = tail
        else:
            base = labels[-2]
            suffix = labels[-1]
        registered = f"{base}.{suffix}"
        return base, suffix, registered

    def _variant_score(self, base_label: str, candidate_label: str, tld_changed: bool) -> float:
        ratio = SequenceMatcher(None, base_label, candidate_label).ratio()
        penalty = 0.08 if tld_changed else 0.0
        return ratio - penalty

    def _add_variant(self, variants: dict[str, set[str]], value: str, reason: str, base_label: str) -> None:
        cleaned = value.strip("-").lower()
        if not cleaned or cleaned == base_label:
            return
        if len(cleaned) < 3 or len(cleaned) > 32:
            return
        variants.setdefault(cleaned, set()).add(reason)

    def _generate_label_variants(self, label: str) -> dict[str, set[str]]:
        variants: dict[str, set[str]] = {}
        if len(label) < 4:
            return variants

        # omission
        for idx in range(len(label)):
            self._add_variant(variants, label[:idx] + label[idx + 1 :], f"omission@{idx}", label)

        # transposition
        for idx in range(len(label) - 1):
            swapped = list(label)
            swapped[idx], swapped[idx + 1] = swapped[idx + 1], swapped[idx]
            self._add_variant(variants, "".join(swapped), f"transpose@{idx}", label)

        # duplication
        for idx, ch in enumerate(label):
            self._add_variant(variants, label[:idx] + ch + label[idx:], f"duplicate@{idx}", label)

        # keyboard near replacement
        for idx, ch in enumerate(label):
            neigh = KEYBOARD_NEIGHBORS.get(ch, "")
            for repl in neigh[:3]:
                self._add_variant(variants, label[:idx] + repl + label[idx + 1 :], f"kbd@{idx}", label)

        # visual char substitution
        for idx, ch in enumerate(label):
            repl = CHAR_SUBSTITUTIONS.get(ch, "")
            if repl:
                self._add_variant(variants, label[:idx] + repl + label[idx + 1 :], f"sub@{idx}", label)

        # hyphen insertion
        if len(label) >= 6:
            mid = max(2, len(label) // 2)
            self._add_variant(variants, f"{label[:mid]}-{label[mid:]}", "hyphen", label)

        # trust-themed suffixes frequently used in impersonation campaigns
        for suffix in ("secure", "support", "verify", "account"):
            self._add_variant(variants, f"{label}{suffix}", f"suffix:{suffix}", label)
            self._add_variant(variants, f"{label}-{suffix}", f"hyphen-suffix:{suffix}", label)

        return variants

    def _resolve_records(self, host: str, record_type: str) -> list[str]:
        try:
            answers = dns.resolver.resolve(host, record_type, lifetime=3.5)
            return [str(a).strip() for a in answers][:8]
        except Exception:
            return []

    def _lookup_rdap(self, domain: str) -> tuple[bool, str, dict[str, Any]]:
        settings = get_settings()
        rdap_url = f"https://rdap.org/domain/{domain}"
        try:
            res = requests.get(
                rdap_url,
                timeout=max(8, settings.request_timeout_seconds),
                headers={"User-Agent": settings.website_user_agent},
            )
            if res.status_code == 404:
                return False, rdap_url, {}
            res.raise_for_status()
            payload = res.json() if res.text.strip() else {}
            return True, rdap_url, payload if isinstance(payload, dict) else {}
        except Exception:
            return False, rdap_url, {}

    def _lookup_ct_count(self, domain: str) -> tuple[int, str]:
        settings = get_settings()
        ct_url = "https://crt.sh/"
        params = {"q": domain, "output": "json"}
        try:
            res = requests.get(
                ct_url,
                params=params,
                timeout=max(8, settings.request_timeout_seconds),
                headers={"User-Agent": settings.website_user_agent},
            )
            if res.status_code >= 400 or not res.text.strip():
                return 0, f"{ct_url}?q={domain}"
            data = res.json()
            return len(data) if isinstance(data, list) else 0, f"{ct_url}?q={domain}"
        except Exception:
            return 0, f"{ct_url}?q={domain}"

    def run(self, target: ConnectorTarget, api_key: str | None = None) -> list[EvidencePayload]:
        domain = canonical_domain_for_api(target.domain)
        base_label, base_tld, registered_domain = self._split_registered_domain(domain)
        if not domain or not base_label or not base_tld or not registered_domain:
            target.log_examination(
                url="brand-impersonation://invalid-domain",
                source_type="dns",
                status="failed",
                discovered_from="brand impersonation monitor",
                error_message="invalid target domain",
                fetched_at=datetime.utcnow(),
            )
            return []

        label_variants = self._generate_label_variants(base_label)
        ranked: list[tuple[str, str, float, tuple[str, ...], bool]] = []
        for variant, reasons in label_variants.items():
            fqdn = f"{variant}.{base_tld}"
            if fqdn == registered_domain:
                continue
            ranked.append((fqdn, variant, self._variant_score(base_label, variant, False), tuple(sorted(reasons)), False))

        # TLD-swapped variants for the original brand label.
        for alt_tld in COMMON_TLDS:
            if alt_tld == base_tld:
                continue
            fqdn = f"{base_label}.{alt_tld}"
            ranked.append((fqdn, base_label, self._variant_score(base_label, base_label, True), ("tld-swap",), True))

        ranked.sort(key=lambda item: item[2], reverse=True)
        candidates = ranked[: self.max_candidates]

        suspicious: list[dict[str, Any]] = []
        rdap_checked = 0
        ct_checked = 0
        for fqdn, variant_label, score, reasons, tld_changed in candidates:
            a_records = self._resolve_records(fqdn, "A")
            mx_records = self._resolve_records(fqdn, "MX")
            has_dns = bool(a_records or mx_records)

            needs_rdap = has_dns or rdap_checked < self.max_rdap_checks
            rdap_exists = False
            rdap_payload: dict[str, Any] = {}
            rdap_url = f"https://rdap.org/domain/{fqdn}"
            if needs_rdap:
                rdap_exists, rdap_url, rdap_payload = self._lookup_rdap(fqdn)
                rdap_checked += 1
                target.log_examination(
                    url=rdap_url,
                    source_type="dns",
                    status="parsed" if rdap_exists else "failed",
                    discovered_from="rdap lookup",
                    parse_summary=f"domain={fqdn} registered={str(rdap_exists).lower()}",
                    fetched_at=datetime.utcnow(),
                )

            needs_ct = (has_dns or rdap_exists) and ct_checked < self.max_ct_checks
            ct_count = 0
            ct_url = f"https://crt.sh/?q={fqdn}"
            if needs_ct:
                ct_count, ct_url = self._lookup_ct_count(fqdn)
                ct_checked += 1
                target.log_examination(
                    url=ct_url,
                    source_type="dns",
                    status="parsed",
                    discovered_from="crt.sh",
                    parse_summary=f"domain={fqdn} cert_entries={ct_count}",
                    fetched_at=datetime.utcnow(),
                )

            if not (has_dns or rdap_exists or ct_count > 0):
                continue

            registrar = ""
            if rdap_payload:
                entities = rdap_payload.get("entities") or []
                if isinstance(entities, list):
                    for entity in entities[:5]:
                        roles = entity.get("roles") if isinstance(entity, dict) else []
                        if isinstance(roles, list) and "registrar" in [str(x).lower() for x in roles]:
                            handle = str(entity.get("handle", "")).strip()
                            if handle:
                                registrar = handle
                                break

            confidence = 48
            if a_records:
                confidence += 12
            if mx_records:
                confidence += 16
            if rdap_exists:
                confidence += 10
            if ct_count > 0:
                confidence += 8
            if score >= 0.90:
                confidence += 8
            elif score >= 0.82:
                confidence += 4
            confidence = max(45, min(94, confidence))

            suspicious.append(
                {
                    "domain": fqdn,
                    "variant_label": variant_label,
                    "reasons": list(reasons),
                    "tld_changed": bool(tld_changed),
                    "similarity": round(score, 3),
                    "a_records": a_records[:6],
                    "mx_records": mx_records[:6],
                    "rdap_exists": bool(rdap_exists),
                    "rdap_url": rdap_url,
                    "ct_count": int(ct_count),
                    "ct_url": ct_url,
                    "registrar": registrar,
                    "confidence": int(confidence),
                }
            )

        if not suspicious:
            return []

        suspicious.sort(key=lambda row: (int(row["confidence"]), int(row["ct_count"]), len(row["mx_records"])), reverse=True)
        out: list[EvidencePayload] = []
        out.append(
            EvidencePayload(
                connector=self.name,
                category="pivot",
                title=f"Potential brand impersonation surface: {len(suspicious)} lookalike domains",
                snippet=(
                    "Lookalike domains detected via typo generation + DNS/RDAP/CT checks. "
                    "Prioritize domains with MX records, active certs, and high lexical similarity."
                ),
                source_url=f"https://crt.sh/?q={registered_domain}",
                confidence=max(70, min(92, 60 + min(28, len(suspicious) * 2))),
                raw={"target_domain": registered_domain, "matches": suspicious[:20]},
            )
        )

        for row in suspicious[:14]:
            signals: list[str] = []
            if row["a_records"]:
                signals.append("A")
            if row["mx_records"]:
                signals.append("MX")
            if row["rdap_exists"]:
                signals.append("RDAP")
            if int(row["ct_count"]) > 0:
                signals.append("CT")
            if row["tld_changed"]:
                signals.append("TLD_SWAP")
            reason_txt = ", ".join(row["reasons"][:4]) if row["reasons"] else "variant"
            signal_txt = "+".join(signals) if signals else "variant"
            snippet = (
                f"Lookalike `{row['domain']}` (similarity {row['similarity']}) via {reason_txt}. "
                f"Signals: {signal_txt}."
            )
            source_url = row["rdap_url"] if row["rdap_exists"] else row["ct_url"]
            category = "pivot" if (row["mx_records"] or int(row["ct_count"]) > 0 or int(row["confidence"]) >= 76) else "exposure"
            out.append(
                EvidencePayload(
                    connector=self.name,
                    category=category,
                    title=f"Potential lookalike domain: {row['domain']}",
                    snippet=snippet,
                    source_url=source_url,
                    confidence=int(row["confidence"]),
                    raw=row,
                )
            )
        return out
