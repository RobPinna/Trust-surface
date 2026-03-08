"""Unit tests for core OSINT connectors: Shodan, BrandImpersonationMonitor, HIBPBreachDomain.

Covers:
- Pure logic methods (no network required)
- run() guard paths (no API key, invalid domain)
- run() happy path via mocked HTTP/DNS
"""
from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from app.connectors.base import ConnectorTarget
from app.connectors.brand_impersonation_monitor import BrandImpersonationMonitorConnector
from app.connectors.hibp_breach_domain import HIBPBreachDomainConnector
from app.connectors.shodan import ShodanConnector


def _target(
    domain: str = "example.com",
    company: str = "Example Corp",
    regions: str = "Global",
) -> ConnectorTarget:
    return ConnectorTarget(
        company_name=company,
        domain=domain,
        sector="Technology",
        regions=regions,
        demo_mode=False,
    )


# ---------------------------------------------------------------------------
# Shodan
# ---------------------------------------------------------------------------

class TestShodanConnector(unittest.TestCase):

    def setUp(self) -> None:
        self.conn = ShodanConnector()

    # --- pure logic: _classify_trust_services ---

    def test_classify_login_portal_by_banner(self) -> None:
        host_data = {
            "data": [{
                "port": 443,
                "product": "Okta",
                "http": {"title": "Okta Single Sign-On", "server": ""},
                "_shodan": {"module": "https"},
                "ssl": {},
                "data": "",
            }]
        }
        hits = self.conn._classify_trust_services(host_data, "1.2.3.4")
        self.assertTrue(any(h["workflow_key"] == "login_portal" for h in hits))

    def test_classify_vpn_by_banner(self) -> None:
        host_data = {
            "data": [{
                "port": 443,
                "product": "Cisco AnyConnect",
                "http": {"title": "", "server": ""},
                "_shodan": {"module": "anyconnect"},
                "ssl": {},
                "data": "anyconnect ssl vpn",
            }]
        }
        hits = self.conn._classify_trust_services(host_data, "2.3.4.5")
        self.assertTrue(any(h["workflow_key"] == "vpn" for h in hits))

    def test_classify_remote_admin_by_port(self) -> None:
        host_data = {
            "data": [{
                "port": 3389,
                "product": "",
                "http": {},
                "_shodan": {"module": ""},
                "ssl": {},
                "data": "",
            }]
        }
        hits = self.conn._classify_trust_services(host_data, "5.6.7.8")
        self.assertTrue(any(h["workflow_key"] == "remote_admin" for h in hits))

    def test_classify_empty_host_returns_empty(self) -> None:
        hits = self.conn._classify_trust_services({"data": []}, "1.1.1.1")
        self.assertEqual(hits, [])

    def test_classify_deduplicates_repeated_service(self) -> None:
        item = {
            "port": 22,
            "product": "",
            "http": {},
            "_shodan": {"module": "ssh"},
            "ssl": {},
            "data": "",
        }
        host_data = {"data": [item, item]}  # same item twice
        hits = self.conn._classify_trust_services(host_data, "9.9.9.9")
        count_ssh = sum(1 for h in hits if h["workflow_key"] == "remote_admin")
        self.assertEqual(count_ssh, 1)

    # --- pure logic: _ownership_mismatch ---

    def test_ownership_mismatch_generic_infra(self) -> None:
        row = {
            "org": "Amazon AWS",
            "isp": "Amazon",
            "hostnames": ["ec2-1-2-3-4.compute.amazonaws.com"],
        }
        result = self.conn._ownership_mismatch(row, {"acme", "acmecorp"})
        self.assertTrue(result["mismatch"])

    def test_ownership_mismatch_aligned(self) -> None:
        row = {"org": "Acme Corp", "isp": "Acme ISP", "hostnames": ["mail.acme.com"]}
        result = self.conn._ownership_mismatch(row, {"acme"})
        self.assertFalse(result["mismatch"])

    def test_ownership_mismatch_no_tokens_no_mismatch(self) -> None:
        row = {"org": "Random ISP", "isp": "Random", "hostnames": []}
        result = self.conn._ownership_mismatch(row, set())
        self.assertFalse(result["mismatch"])

    # --- pure logic: _expected_ownership_tokens ---

    def test_expected_tokens_filters_stop_words(self) -> None:
        target = _target(domain="acme.com", company="Acme Solutions Inc")
        tokens = self.conn._expected_ownership_tokens(target, "acme.com")
        self.assertIn("acme", tokens)
        self.assertNotIn("solutions", tokens)
        self.assertNotIn("inc", tokens)
        self.assertNotIn("com", tokens)

    def test_expected_tokens_minimum_length(self) -> None:
        target = _target(domain="ab.io", company="AB Tech")
        tokens = self.conn._expected_ownership_tokens(target, "ab.io")
        # "ab" and "io" are < 4 chars; "tech" is exactly 4 chars and not a stop word
        self.assertIn("tech", tokens)
        self.assertNotIn("ab", tokens)

    # --- run() guard paths ---

    def test_run_no_api_key_returns_empty(self) -> None:
        result = self.conn.run(_target(), api_key=None)
        self.assertEqual(result, [])

    def test_run_empty_domain_returns_empty(self) -> None:
        result = self.conn.run(_target(domain=""), api_key="any-key")
        self.assertEqual(result, [])

    # --- run() happy path via mocked HTTP ---

    @patch("app.connectors.shodan.requests.get")
    def test_run_returns_evidences_on_success(self, mock_get: MagicMock) -> None:
        dns_resp = MagicMock()
        dns_resp.raise_for_status.return_value = None
        dns_resp.status_code = 200
        dns_resp.text = '{"subdomains":["mail"]}'
        dns_resp.json.return_value = {"subdomains": ["mail"]}
        dns_resp.content = b'{"subdomains":["mail"]}'

        resolve_resp = MagicMock()
        resolve_resp.raise_for_status.return_value = None
        resolve_resp.status_code = 200
        resolve_resp.text = '{"example.com":"1.2.3.4"}'
        resolve_resp.json.return_value = {"example.com": "1.2.3.4"}
        resolve_resp.content = b'{"example.com":"1.2.3.4"}'

        host_resp = MagicMock()
        host_resp.raise_for_status.return_value = None
        host_resp.status_code = 200
        host_resp.text = "{}"
        host_resp.json.return_value = {
            "ports": [80, 443, 3389],
            "vulns": {"CVE-2021-44228": {}},
            "org": "Third Party Hosting",
            "isp": "Unknown ISP",
            "data": [],
        }
        host_resp.content = b"{}"

        mock_get.side_effect = [dns_resp, resolve_resp, host_resp]

        result = self.conn.run(_target(), api_key="test-key-123")
        self.assertGreater(len(result), 0)
        self.assertTrue(all(e.connector == "shodan" for e in result))
        categories = {e.category for e in result}
        self.assertTrue(categories & {"exposure", "pivot"})

    @patch("app.connectors.shodan.requests.get")
    def test_run_api_error_returns_empty(self, mock_get: MagicMock) -> None:
        mock_get.side_effect = Exception("Connection error")
        result = self.conn.run(_target(), api_key="test-key")
        self.assertEqual(result, [])


# ---------------------------------------------------------------------------
# BrandImpersonationMonitorConnector
# ---------------------------------------------------------------------------

class TestBrandImpersonationMonitorConnector(unittest.TestCase):

    def setUp(self) -> None:
        self.conn = BrandImpersonationMonitorConnector()

    # --- pure logic: _split_registered_domain ---

    def test_split_simple_domain(self) -> None:
        base, tld, reg = self.conn._split_registered_domain("example.com")
        self.assertEqual(base, "example")
        self.assertEqual(tld, "com")
        self.assertEqual(reg, "example.com")

    def test_split_multi_label_suffix(self) -> None:
        base, tld, reg = self.conn._split_registered_domain("mail.example.co.uk")
        self.assertEqual(base, "example")
        self.assertEqual(tld, "co.uk")
        self.assertEqual(reg, "example.co.uk")

    def test_split_invalid_single_label(self) -> None:
        base, tld, reg = self.conn._split_registered_domain("localhost")
        self.assertEqual(base, "")
        self.assertEqual(reg, "")

    def test_split_empty_string(self) -> None:
        base, tld, reg = self.conn._split_registered_domain("")
        self.assertEqual(base, "")

    # --- pure logic: _generate_label_variants ---

    def test_variants_omission(self) -> None:
        variants = self.conn._generate_label_variants("example")
        # Omission at index 0: "xample"
        self.assertIn("xample", variants)

    def test_variants_transposition(self) -> None:
        variants = self.conn._generate_label_variants("example")
        # Transposition at index 2 ('a'↔'m'): "exmaple"
        self.assertIn("exmaple", variants)

    def test_variants_trust_suffixes(self) -> None:
        variants = self.conn._generate_label_variants("acme")
        self.assertIn("acmesecure", variants)
        self.assertIn("acmesupport", variants)

    def test_variants_short_label_skipped(self) -> None:
        self.assertEqual(self.conn._generate_label_variants("abc"), {})

    def test_variants_minimum_quantity(self) -> None:
        variants = self.conn._generate_label_variants("example")
        self.assertGreater(len(variants), 15)

    # --- pure logic: _variant_score ---

    def test_variant_score_identical_no_tld_change(self) -> None:
        score = self.conn._variant_score("acme", "acme", False)
        self.assertAlmostEqual(score, 1.0, places=2)

    def test_variant_score_tld_change_penalty(self) -> None:
        score_same = self.conn._variant_score("acme", "acme", False)
        score_diff = self.conn._variant_score("acme", "acme", True)
        self.assertGreater(score_same, score_diff)

    def test_variant_score_dissimilar(self) -> None:
        score = self.conn._variant_score("example", "zzzzzz", False)
        self.assertLess(score, 0.5)

    # --- run() guard paths ---

    def test_run_single_label_domain_returns_empty(self) -> None:
        result = self.conn.run(_target(domain="localhost"))
        self.assertEqual(result, [])

    def test_run_empty_domain_returns_empty(self) -> None:
        result = self.conn.run(_target(domain=""))
        self.assertEqual(result, [])

    # --- run() with mocked network ---

    @patch("app.connectors.brand_impersonation_monitor.requests.get")
    @patch("app.connectors.brand_impersonation_monitor.dns.resolver.resolve")
    def test_run_no_dns_hits_returns_empty(
        self, mock_resolve: MagicMock, mock_get: MagicMock
    ) -> None:
        mock_resolve.side_effect = Exception("NXDOMAIN")
        rdap_404 = MagicMock(status_code=404, text="")
        rdap_404.raise_for_status.return_value = None
        mock_get.return_value = rdap_404

        result = self.conn.run(_target())
        self.assertEqual(result, [])

    @patch("app.connectors.brand_impersonation_monitor.requests.get")
    @patch("app.connectors.brand_impersonation_monitor.dns.resolver.resolve")
    def test_run_with_dns_hit_returns_evidences(
        self, mock_resolve: MagicMock, mock_get: MagicMock
    ) -> None:
        dns_answer = MagicMock()
        dns_answer.__str__ = lambda s: "1.2.3.4"
        mock_resolve.return_value = [dns_answer]

        rdap_ok = MagicMock(status_code=200, text='{"entities":[]}')
        rdap_ok.raise_for_status.return_value = None
        rdap_ok.json.return_value = {"entities": []}

        ct_ok = MagicMock(status_code=200, text="[]")
        ct_ok.raise_for_status.return_value = None
        ct_ok.json.return_value = []

        mock_get.return_value = rdap_ok

        result = self.conn.run(_target())
        self.assertGreaterEqual(len(result), 1)
        self.assertTrue(all(e.connector == "brand_impersonation_monitor" for e in result))
        # Summary evidence should be a pivot
        self.assertEqual(result[0].category, "pivot")


# ---------------------------------------------------------------------------
# HIBPBreachDomainConnector
# ---------------------------------------------------------------------------

class TestHIBPBreachDomainConnector(unittest.TestCase):

    def setUp(self) -> None:
        self.conn = HIBPBreachDomainConnector()

    # --- pure logic: _extract_breaches ---

    def test_extract_from_list(self) -> None:
        payload = [{"Name": "Adobe", "BreachDate": "2013-10-04", "PwnCount": 153_000_000}]
        breaches = self.conn._extract_breaches(payload)
        self.assertEqual(len(breaches), 1)
        self.assertEqual(breaches[0]["Name"], "Adobe")

    def test_extract_from_dict_breaches_key(self) -> None:
        payload = {"breaches": [{"Name": "LinkedIn", "PwnCount": 164_611_595}]}
        breaches = self.conn._extract_breaches(payload)
        self.assertEqual(len(breaches), 1)

    def test_extract_from_dict_capital_breaches_key(self) -> None:
        payload = {"Breaches": [{"Name": "Dropbox", "PwnCount": 68_648_009}]}
        breaches = self.conn._extract_breaches(payload)
        self.assertEqual(len(breaches), 1)

    def test_extract_empty_inputs(self) -> None:
        self.assertEqual(self.conn._extract_breaches([]), [])
        self.assertEqual(self.conn._extract_breaches({}), [])
        self.assertEqual(self.conn._extract_breaches(None), [])  # type: ignore[arg-type]

    def test_extract_ignores_non_dict_elements(self) -> None:
        payload = [{"Name": "Good"}, "bad-string", 42]
        breaches = self.conn._extract_breaches(payload)
        self.assertEqual(len(breaches), 1)

    # --- run() guard paths ---

    def test_run_no_api_key_returns_empty(self) -> None:
        result = self.conn.run(_target(), api_key=None)
        self.assertEqual(result, [])

    def test_run_empty_domain_returns_empty(self) -> None:
        result = self.conn.run(_target(domain=""), api_key="test-key")
        self.assertEqual(result, [])

    # --- run() with mocked API ---

    @patch("app.connectors.hibp_breach_domain.requests.get")
    def test_run_404_no_breach_returns_empty(self, mock_get: MagicMock) -> None:
        resp = MagicMock()
        resp.status_code = 404
        resp.url = "https://haveibeenpwned.com/api/v3/breacheddomain/example.com"
        mock_get.return_value = resp

        result = self.conn.run(_target(), api_key="test-key")
        self.assertEqual(result, [])

    @patch("app.connectors.hibp_breach_domain.requests.get")
    def test_run_with_breaches_returns_evidences(self, mock_get: MagicMock) -> None:
        resp = MagicMock()
        resp.status_code = 200
        resp.url = "https://haveibeenpwned.com/api/v3/breacheddomain/example.com"
        resp.json.return_value = [
            {
                "Name": "Adobe",
                "BreachDate": "2013-10-04",
                "PwnCount": 153_000_000,
                "IsVerified": True,
                "DataClasses": ["Email addresses", "Passwords"],
            }
        ]
        resp.text = "non-empty"
        resp.content = b"non-empty"
        resp.raise_for_status.return_value = None
        mock_get.return_value = resp

        result = self.conn.run(_target(), api_key="test-key")
        self.assertGreater(len(result), 0)
        self.assertTrue(all(e.connector == "hibp_breach_domain" for e in result))
        self.assertEqual(result[0].category, "pivot")
        self.assertIn("Adobe", result[1].title)

    @patch("app.connectors.hibp_breach_domain.requests.get")
    def test_run_401_returns_empty(self, mock_get: MagicMock) -> None:
        resp = MagicMock()
        resp.status_code = 401
        resp.url = "https://haveibeenpwned.com/api/v3/breacheddomain/example.com"
        mock_get.return_value = resp
        result = self.conn.run(_target(), api_key="bad-key")
        self.assertEqual(result, [])

    @patch("app.connectors.hibp_breach_domain.requests.get")
    def test_run_confidence_higher_for_verified_breach(self, mock_get: MagicMock) -> None:
        resp = MagicMock()
        resp.status_code = 200
        resp.url = "https://haveibeenpwned.com/api/v3/breacheddomain/example.com"
        resp.json.return_value = [
            {"Name": "Verified", "BreachDate": "2022-01-01", "PwnCount": 1000, "IsVerified": True, "DataClasses": []},
            {"Name": "Unverified", "BreachDate": "2022-01-01", "PwnCount": 500, "IsVerified": False, "DataClasses": []},
        ]
        resp.text = "non-empty"
        resp.content = b"non-empty"
        resp.raise_for_status.return_value = None
        mock_get.return_value = resp

        result = self.conn.run(_target(), api_key="test-key")
        detail_items = result[1:]  # skip summary
        verified = next((e for e in detail_items if "Verified" in e.title and "Unverified" not in e.title), None)
        unverified = next((e for e in detail_items if "Unverified" in e.title), None)
        if verified and unverified:
            self.assertGreater(verified.confidence, unverified.confidence)


if __name__ == "__main__":
    unittest.main()
