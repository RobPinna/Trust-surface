from datetime import datetime
from typing import Any

import requests

from app.config import get_settings
from app.connectors.base import ConnectorBase, ConnectorTarget, EvidencePayload
from app.connectors.utils import canonical_domain_for_api


class ShodanConnector(ConnectorBase):
    name = "shodan"
    requires_api_key = True
    description = "Optional Shodan attack-surface enrichment (DNS + host exposure)"

    risky_ports = {21, 23, 445, 1433, 3306, 3389, 5432, 5900, 6379, 9200, 11211, 27017}

    def ping(self, api_key: str | None = None) -> tuple[bool, str]:
        if not api_key:
            return False, "Missing API key"
        return True, "API key present"

    def _api_get(self, url: str, *, params: dict[str, str], settings) -> tuple[dict[str, Any], int, int]:
        res = requests.get(url, params=params, timeout=settings.request_timeout_seconds)
        res.raise_for_status()
        data = res.json() if res.text.strip() else {}
        return (data if isinstance(data, dict) else {}), int(res.status_code), int(len(res.content or b""))

    def run(self, target: ConnectorTarget, api_key: str | None = None) -> list[EvidencePayload]:
        settings = get_settings()
        domain = canonical_domain_for_api(target.domain)
        if not domain:
            target.log_examination(
                url="shodan://invalid-domain",
                source_type="news",
                status="failed",
                discovered_from="shodan connector",
                error_message="invalid target domain",
                fetched_at=datetime.utcnow(),
            )
            return []
        params = {"key": api_key} if api_key else {}
        dns_url = f"https://api.shodan.io/dns/domain/{domain}"
        fetched_at = datetime.utcnow()

        if not api_key:
            target.log_examination(
                url=dns_url,
                source_type="news",
                status="skipped",
                discovered_from="shodan connector",
                parse_summary="missing api key",
                fetched_at=fetched_at,
            )
            return []

        dns_data: dict[str, Any]
        try:
            dns_data, status_code, payload_size = self._api_get(dns_url, params=params, settings=settings)
            target.log_examination(
                url=dns_url,
                source_type="news",
                status="parsed",
                discovered_from="shodan api",
                http_status=status_code,
                bytes_size=payload_size,
                parse_summary="dns metadata fetched",
                fetched_at=fetched_at,
            )
        except Exception as exc:
            target.log_examination(
                url=dns_url,
                source_type="news",
                status="failed",
                discovered_from="shodan api",
                error_message=exc.__class__.__name__,
                fetched_at=fetched_at,
            )
            return []

        subdomains = dns_data.get("subdomains", []) if isinstance(dns_data, dict) else []
        hostname_candidates: list[str] = [domain]
        if isinstance(subdomains, list):
            for raw in subdomains[:40]:
                part = str(raw or "").strip().lower().strip(".")
                if not part:
                    continue
                host = part if part.endswith(domain) else f"{part}.{domain}"
                if host not in hostname_candidates:
                    hostname_candidates.append(host)
        hostname_candidates = hostname_candidates[:25]

        ip_map: dict[str, str] = {}
        resolve_url = "https://api.shodan.io/dns/resolve"
        if hostname_candidates:
            try:
                resolve_params = {
                    "key": api_key,
                    "hostnames": ",".join(hostname_candidates),
                }
                resolved, status_code, payload_size = self._api_get(resolve_url, params=resolve_params, settings=settings)
                for host, ip in (resolved or {}).items():
                    host_clean = str(host or "").strip().lower()
                    ip_clean = str(ip or "").strip()
                    if host_clean and ip_clean:
                        ip_map[host_clean] = ip_clean
                target.log_examination(
                    url=resolve_url,
                    source_type="dns",
                    status="parsed",
                    discovered_from="shodan api",
                    http_status=status_code,
                    bytes_size=payload_size,
                    parse_summary=f"dns resolve hostnames={len(hostname_candidates)} ips={len(ip_map)}",
                    fetched_at=datetime.utcnow(),
                )
            except Exception as exc:
                target.log_examination(
                    url=resolve_url,
                    source_type="dns",
                    status="failed",
                    discovered_from="shodan api",
                    error_message=exc.__class__.__name__,
                    fetched_at=datetime.utcnow(),
                )

        ip_rows: list[dict[str, Any]] = []
        unique_ips: list[str] = []
        seen_ips: set[str] = set()
        for _, ip in sorted(ip_map.items()):
            if ip in seen_ips:
                continue
            seen_ips.add(ip)
            unique_ips.append(ip)
        unique_ips = unique_ips[:10]

        for ip in unique_ips:
            host_url = f"https://api.shodan.io/shodan/host/{ip}"
            try:
                host_data, status_code, payload_size = self._api_get(
                    host_url,
                    params={"key": api_key, "minify": "true"},
                    settings=settings,
                )
                ports_raw = host_data.get("ports") or []
                ports = sorted({int(p) for p in ports_raw if str(p).isdigit()})
                vulns_raw = host_data.get("vulns") or {}
                if isinstance(vulns_raw, dict):
                    vulns = sorted([str(k) for k in vulns_raw.keys()])[:20]
                elif isinstance(vulns_raw, list):
                    vulns = sorted([str(v) for v in vulns_raw])[:20]
                else:
                    vulns = []
                risky = [p for p in ports if p in self.risky_ports]
                ip_rows.append(
                    {
                        "ip": ip,
                        "ports": ports[:24],
                        "risky_ports": risky[:16],
                        "vulns": vulns,
                        "org": str(host_data.get("org") or "").strip(),
                        "isp": str(host_data.get("isp") or "").strip(),
                        "hostnames": [h for h, host_ip in ip_map.items() if host_ip == ip][:8],
                    }
                )
                target.log_examination(
                    url=host_url,
                    source_type="dns",
                    status="parsed",
                    discovered_from="shodan api",
                    http_status=status_code,
                    bytes_size=payload_size,
                    parse_summary=f"host={ip} ports={len(ports)} vulns={len(vulns)}",
                    fetched_at=datetime.utcnow(),
                )
            except Exception as exc:
                target.log_examination(
                    url=host_url,
                    source_type="dns",
                    status="failed",
                    discovered_from="shodan api",
                    error_message=exc.__class__.__name__,
                    fetched_at=datetime.utcnow(),
                )

        evidences: list[EvidencePayload] = [
            EvidencePayload(
                connector=self.name,
                category="exposure",
                title="Shodan DNS metadata",
                snippet=f"Observed subdomains: {len(subdomains)} | Resolved hosts: {len(ip_map)}",
                source_url=f"https://www.shodan.io/domain/{domain}",
                confidence=67,
                raw={
                    "subdomains": subdomains[:60] if isinstance(subdomains, list) else [],
                    "resolved": dict(list(ip_map.items())[:30]),
                },
            )
        ]

        if ip_rows:
            risky_hosts = [row for row in ip_rows if row["risky_ports"] or row["vulns"]]
            summary_conf = 72 + min(18, len(risky_hosts) * 3)
            evidences.append(
                EvidencePayload(
                    connector=self.name,
                    category="pivot" if risky_hosts else "exposure",
                    title=f"Shodan host exposure summary ({len(ip_rows)} hosts)",
                    snippet=(
                        f"Resolved {len(ip_rows)} hosts for `{domain}`. "
                        f"{len(risky_hosts)} hosts expose risky ports and/or vulnerability tags."
                    ),
                    source_url=f"https://www.shodan.io/domain/{domain}",
                    confidence=min(95, summary_conf),
                    raw={"hosts": ip_rows[:12], "risky_host_count": len(risky_hosts)},
                )
            )

            for row in ip_rows[:12]:
                risky_ports = row.get("risky_ports") or []
                vulns = row.get("vulns") or []
                category = "pivot" if (risky_ports or vulns) else "exposure"
                confidence = 70
                if risky_ports:
                    confidence += 10
                if vulns:
                    confidence += 12
                confidence = min(94, confidence)
                snippet = (
                    f"IP {row['ip']} exposes ports {', '.join(str(p) for p in (row.get('ports') or [])[:8]) or 'none'}. "
                    f"Risky ports: {', '.join(str(p) for p in risky_ports[:8]) or 'none'}. "
                    f"Vulnerability tags: {', '.join(vulns[:4]) or 'none'}."
                )
                evidences.append(
                    EvidencePayload(
                        connector=self.name,
                        category=category,
                        title=f"Shodan host exposure: {row['ip']}",
                        snippet=snippet,
                        source_url=f"https://www.shodan.io/host/{row['ip']}",
                        confidence=confidence,
                        raw=row,
                    )
                )

        return evidences[:28]
