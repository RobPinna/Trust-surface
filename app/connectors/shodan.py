import re
from datetime import datetime
from typing import Any

import requests

from app.config import get_settings
from app.connectors.base import ConnectorBase, ConnectorTarget, EvidencePayload
from app.connectors.utils import canonical_domain_for_api

OWNERSHIP_STOP_WORDS = {
    "com",
    "net",
    "org",
    "www",
    "inc",
    "ltd",
    "llc",
    "spa",
    "srl",
    "group",
    "holding",
    "holdings",
    "solutions",
    "services",
    "global",
}

GENERIC_INFRA_OWNERS = {
    "amazon",
    "aws",
    "google",
    "gcp",
    "microsoft",
    "azure",
    "cloudflare",
    "akamai",
    "ovh",
    "digitalocean",
    "hetzner",
    "linode",
    "fastly",
}

TRUST_SERVICE_PATTERNS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    (
        "login_portal",
        "login portal",
        (
            "login",
            "signin",
            "single sign-on",
            "sso",
            "auth",
            "oauth",
            "okta",
            "entra",
            "identity",
        ),
    ),
    (
        "helpdesk",
        "helpdesk/support",
        (
            "helpdesk",
            "service desk",
            "ticket",
            "support portal",
            "zendesk",
            "freshdesk",
            "jira service management",
        ),
    ),
    (
        "vpn",
        "vpn access",
        (
            "vpn",
            "openvpn",
            "ipsec",
            "anyconnect",
            "globalprotect",
            "pulse secure",
            "wireguard",
            "fortigate ssl vpn",
        ),
    ),
    (
        "remote_admin",
        "remote admin",
        (
            "rdp",
            "remote desktop",
            "vnc",
            "ssh",
            "teamviewer",
            "anydesk",
            "screenconnect",
            "winrm",
        ),
    ),
)

PORT_WORKFLOW_HINTS: dict[int, tuple[str, str]] = {
    22: ("remote_admin", "remote admin"),
    23: ("remote_admin", "remote admin"),
    3389: ("remote_admin", "remote admin"),
    5900: ("remote_admin", "remote admin"),
    5985: ("remote_admin", "remote admin"),
    5986: ("remote_admin", "remote admin"),
    1194: ("vpn", "vpn access"),
    500: ("vpn", "vpn access"),
    4500: ("vpn", "vpn access"),
    1701: ("vpn", "vpn access"),
    1723: ("vpn", "vpn access"),
}


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

    def _expected_ownership_tokens(self, target: ConnectorTarget, domain: str) -> set[str]:
        tokens: set[str] = set()
        for part in re.split(r"[^a-z0-9]+", str(target.company_name or "").lower()):
            part = part.strip()
            if len(part) >= 4 and part not in OWNERSHIP_STOP_WORDS:
                tokens.add(part)
        for part in re.split(r"[^a-z0-9]+", str(domain or "").lower()):
            part = part.strip()
            if len(part) >= 4 and part not in OWNERSHIP_STOP_WORDS:
                tokens.add(part)
        return tokens

    def _classify_trust_services(self, host_data: dict[str, Any], ip: str) -> list[dict[str, Any]]:
        service_hits: list[dict[str, Any]] = []
        seen: set[str] = set()
        for item in list(host_data.get("data") or [])[:120]:
            if not isinstance(item, dict):
                continue
            port_raw = item.get("port")
            port = int(port_raw) if str(port_raw).isdigit() else 0
            product = str(item.get("product") or "").strip()
            module = str((item.get("_shodan") or {}).get("module") or "").strip()
            http = item.get("http") if isinstance(item.get("http"), dict) else {}
            http_title = str(http.get("title") or "").strip()
            http_server = str(http.get("server") or "").strip()
            ssl = item.get("ssl") if isinstance(item.get("ssl"), dict) else {}
            cert = ssl.get("cert") if isinstance(ssl.get("cert"), dict) else {}
            subject = cert.get("subject") if isinstance(cert.get("subject"), dict) else {}
            cert_cn = str(subject.get("CN") or "").strip()
            raw_banner = str(item.get("data") or "").strip().lower()
            if len(raw_banner) > 280:
                raw_banner = raw_banner[:280]
            scan_text = " ".join(
                x for x in [product, module, http_title, http_server, cert_cn, raw_banner] if x
            ).lower()

            matched: list[tuple[str, str]] = []
            for workflow_key, workflow_label, markers in TRUST_SERVICE_PATTERNS:
                if any(marker in scan_text for marker in markers):
                    matched.append((workflow_key, workflow_label))
            if port and port in PORT_WORKFLOW_HINTS:
                matched.append(PORT_WORKFLOW_HINTS[port])
            if not matched:
                continue

            for workflow_key, workflow_label in matched:
                dedupe = f"{ip}|{port}|{workflow_key}|{module}|{product}"
                if dedupe in seen:
                    continue
                seen.add(dedupe)
                service_hits.append(
                    {
                        "ip": ip,
                        "port": port,
                        "workflow_key": workflow_key,
                        "workflow_label": workflow_label,
                        "module": module,
                        "product": product,
                        "http_title": http_title,
                        "http_server": http_server,
                        "cert_cn": cert_cn,
                    }
                )
        return service_hits[:30]

    def _ownership_mismatch(self, row: dict[str, Any], expected_tokens: set[str]) -> dict[str, Any]:
        org = str(row.get("org") or "").strip()
        isp = str(row.get("isp") or "").strip()
        hostnames = [str(x).strip() for x in list(row.get("hostnames") or []) if str(x).strip()]
        observed = " ".join([org, isp, " ".join(hostnames)]).lower()
        if not observed:
            return {"mismatch": False, "reason": ""}
        if expected_tokens and any(token in observed for token in expected_tokens):
            return {"mismatch": False, "reason": ""}
        generic_owner = any(g in observed for g in GENERIC_INFRA_OWNERS)
        if expected_tokens:
            if generic_owner:
                return {
                    "mismatch": True,
                    "reason": "Infrastructure ownership appears third-party and does not match brand/domain tokens.",
                }
            return {
                "mismatch": True,
                "reason": "Observed ownership metadata does not align with expected company/domain naming.",
            }
        return {"mismatch": False, "reason": ""}

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
        trust_service_hits: list[dict[str, Any]] = []
        unique_ips: list[str] = []
        seen_ips: set[str] = set()
        expected_tokens = self._expected_ownership_tokens(target, domain)
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
                    params={"key": api_key},
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
                trust_services = self._classify_trust_services(host_data, ip)
                trust_service_hits.extend(trust_services)
                ip_rows.append(
                    {
                        "ip": ip,
                        "ports": ports[:24],
                        "risky_ports": risky[:16],
                        "vulns": vulns,
                        "org": str(host_data.get("org") or "").strip(),
                        "isp": str(host_data.get("isp") or "").strip(),
                        "hostnames": [h for h, host_ip in ip_map.items() if host_ip == ip][:8],
                        "trust_services": trust_services,
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

            if trust_service_hits:
                unique_service_types = sorted(
                    {str(x.get("workflow_label") or "").strip() for x in trust_service_hits if x.get("workflow_label")}
                )
                evidences.append(
                    EvidencePayload(
                        connector=self.name,
                        category="touchpoint",
                        title="Shodan trust-workflow services exposed",
                        snippet=(
                            f"Detected {len(trust_service_hits)} service banners linked to trust workflows "
                            f"({', '.join(unique_service_types[:4])})."
                        ),
                        source_url=f"https://www.shodan.io/domain/{domain}",
                        confidence=min(92, 74 + len(unique_service_types) * 4),
                        raw={
                            "service_types": unique_service_types,
                            "services": trust_service_hits[:24],
                        },
                    )
                )

                for hit in trust_service_hits[:24]:
                    service_name = str(hit.get("product") or hit.get("module") or "service").strip()
                    ip = str(hit.get("ip") or "").strip()
                    port = int(hit.get("port") or 0)
                    workflow = str(hit.get("workflow_label") or "").strip()
                    detail_bits = [x for x in [service_name, str(hit.get("http_title") or "").strip()] if x]
                    detail = " | ".join(detail_bits[:2]) or "banner signature"
                    evidences.append(
                        EvidencePayload(
                            connector=self.name,
                            category="pivot" if workflow in {"vpn access", "remote admin", "login portal"} else "touchpoint",
                            title=f"Trust workflow service exposed: {workflow}",
                            snippet=f"Host {ip}:{port} exposes `{detail}` mapped to `{workflow}`.",
                            source_url=f"https://www.shodan.io/host/{ip}" if ip else f"https://www.shodan.io/domain/{domain}",
                            confidence=82 if workflow in {"vpn access", "remote admin", "login portal"} else 76,
                            raw=hit,
                        )
                    )

            mismatches: list[dict[str, Any]] = []
            for row in ip_rows:
                verdict = self._ownership_mismatch(row, expected_tokens)
                if verdict.get("mismatch"):
                    mismatches.append(
                        {
                            "ip": row.get("ip"),
                            "org": row.get("org"),
                            "isp": row.get("isp"),
                            "hostnames": row.get("hostnames"),
                            "reason": verdict.get("reason"),
                        }
                    )
            if mismatches:
                evidences.append(
                    EvidencePayload(
                        connector=self.name,
                        category="pivot",
                        title="Potential ownership mismatch on externally exposed hosts",
                        snippet=(
                            f"{len(mismatches)} resolved hosts show ownership metadata not aligned with "
                            f"expected company/domain naming."
                        ),
                        source_url=f"https://www.shodan.io/domain/{domain}",
                        confidence=min(91, 76 + len(mismatches) * 4),
                        raw={
                            "expected_tokens": sorted(expected_tokens),
                            "mismatches": mismatches[:16],
                        },
                    )
                )

                for item in mismatches[:16]:
                    ip = str(item.get("ip") or "").strip()
                    org = str(item.get("org") or "").strip() or "unknown"
                    isp = str(item.get("isp") or "").strip() or "unknown"
                    evidences.append(
                        EvidencePayload(
                            connector=self.name,
                            category="touchpoint",
                            title=f"Ownership mismatch detail: {ip}",
                            snippet=(
                                f"Host ownership metadata org=`{org}` isp=`{isp}` appears inconsistent with "
                                "target brand/domain identity."
                            ),
                            source_url=f"https://www.shodan.io/host/{ip}" if ip else f"https://www.shodan.io/domain/{domain}",
                            confidence=79,
                            raw=item,
                        )
                    )

        return evidences[:120]
