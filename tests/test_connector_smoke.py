"""Smoke tests for all registered OSINT connectors.

Goals
-----
1. Every connector can be imported and instantiated without error.
2. Every connector exposes the required interface: name, description, ping, run.
3. Connectors that declare requires_api_key=True return [] (not crash) when run
   without a key, for both valid and empty domains.
4. The connector_registry() and connector_map() helpers return consistent data.

These tests never hit real network endpoints.
"""
from __future__ import annotations

import unittest

from app.connectors.base import ConnectorBase, ConnectorTarget
from app.connectors.brand_impersonation_monitor import BrandImpersonationMonitorConnector
from app.connectors.dns_footprint import DNSFootprintConnector
from app.connectors.email_posture_analyzer import EmailPostureAnalyzerConnector
from app.connectors.gdelt_news import GDELTNewsConnector
from app.connectors.hibp_breach_domain import HIBPBreachDomainConnector
from app.connectors.job_postings_live import JobPostingsLiveConnector
from app.connectors.media_trend import MediaTrendConnector
from app.connectors.official_channel_enumerator import OfficialChannelEnumeratorConnector
from app.connectors.procurement_documents import ProcurementDocumentsConnector
from app.connectors.public_docs_pdf import PublicDocsPdfConnector
from app.connectors.public_role_extractor import PublicRoleExtractorConnector
from app.connectors.registry import connector_map, connector_registry
from app.connectors.shodan import ShodanConnector
from app.connectors.social_twitter import SocialTwitterConnector
from app.connectors.subdomain_discovery import SubdomainDiscoveryConnector
from app.connectors.vendor_js_detection import VendorJsDetectionConnector
from app.connectors.virustotal import VirusTotalConnector
from app.connectors.website_analyzer import WebsiteAnalyzerConnector


def _target(domain: str = "example.com") -> ConnectorTarget:
    return ConnectorTarget(
        company_name="Smoke Test Corp",
        domain=domain,
        sector="Technology",
        regions="Global",
        demo_mode=False,
    )


# All connector classes used in the registry
_ALL_CONNECTOR_CLASSES: list[type[ConnectorBase]] = [
    WebsiteAnalyzerConnector,
    OfficialChannelEnumeratorConnector,
    PublicRoleExtractorConnector,
    EmailPostureAnalyzerConnector,
    DNSFootprintConnector,
    SubdomainDiscoveryConnector,
    BrandImpersonationMonitorConnector,
    GDELTNewsConnector,
    MediaTrendConnector,
    SocialTwitterConnector,
    JobPostingsLiveConnector,
    VendorJsDetectionConnector,
    ProcurementDocumentsConnector,
    PublicDocsPdfConnector,
    VirusTotalConnector,
    ShodanConnector,
    HIBPBreachDomainConnector,
]


class TestConnectorInstantiation(unittest.TestCase):
    """Every connector class must instantiate without arguments."""

    def test_all_connectors_instantiate(self) -> None:
        for cls in _ALL_CONNECTOR_CLASSES:
            with self.subTest(connector=cls.__name__):
                instance = cls()
                self.assertIsInstance(instance, ConnectorBase)

    def test_all_connectors_have_name(self) -> None:
        for cls in _ALL_CONNECTOR_CLASSES:
            with self.subTest(connector=cls.__name__):
                instance = cls()
                self.assertIsInstance(instance.name, str)
                self.assertTrue(instance.name, f"{cls.__name__}.name must be non-empty")

    def test_all_connectors_have_description(self) -> None:
        for cls in _ALL_CONNECTOR_CLASSES:
            with self.subTest(connector=cls.__name__):
                instance = cls()
                self.assertIsInstance(instance.description, str)

    def test_all_connectors_have_callable_run(self) -> None:
        for cls in _ALL_CONNECTOR_CLASSES:
            with self.subTest(connector=cls.__name__):
                instance = cls()
                self.assertTrue(callable(instance.run))

    def test_all_connectors_have_callable_ping(self) -> None:
        for cls in _ALL_CONNECTOR_CLASSES:
            with self.subTest(connector=cls.__name__):
                instance = cls()
                self.assertTrue(callable(instance.ping))

    def test_requires_api_key_is_bool(self) -> None:
        for cls in _ALL_CONNECTOR_CLASSES:
            with self.subTest(connector=cls.__name__):
                instance = cls()
                self.assertIsInstance(instance.requires_api_key, bool)


class TestConnectorRegistry(unittest.TestCase):
    """Registry helpers must return consistent data."""

    def test_registry_returns_list(self) -> None:
        result = connector_registry()
        self.assertIsInstance(result, list)
        self.assertGreater(len(result), 0)

    def test_registry_all_are_connector_base(self) -> None:
        for connector in connector_registry():
            with self.subTest(connector=type(connector).__name__):
                self.assertIsInstance(connector, ConnectorBase)

    def test_registry_no_duplicate_names(self) -> None:
        names = [c.name for c in connector_registry()]
        self.assertEqual(len(names), len(set(names)), "Duplicate connector names detected")

    def test_connector_map_keys_match_names(self) -> None:
        cmap = connector_map()
        for key, connector in cmap.items():
            self.assertEqual(key, connector.name)

    def test_connector_map_covers_registry(self) -> None:
        registry_names = {c.name for c in connector_registry()}
        map_keys = set(connector_map().keys())
        self.assertEqual(registry_names, map_keys)

    def test_social_twitter_registered(self) -> None:
        """social_twitter must appear in registry (replaces social_mock)."""
        names = {c.name for c in connector_registry()}
        self.assertIn("social_twitter", names)
        self.assertNotIn("social_mock", names)


class TestApiKeyRequiredConnectors(unittest.TestCase):
    """Connectors declaring requires_api_key=True must return [] without a key."""

    _API_KEY_CONNECTORS: list[type[ConnectorBase]] = [
        ShodanConnector,
        HIBPBreachDomainConnector,
        VirusTotalConnector,
        SocialTwitterConnector,
    ]

    def test_returns_empty_without_key_valid_domain(self) -> None:
        for cls in self._API_KEY_CONNECTORS:
            with self.subTest(connector=cls.__name__):
                self.assertTrue(cls.requires_api_key)
                result = cls().run(_target("example.com"), api_key=None)
                self.assertEqual(result, [], f"{cls.__name__}.run() should return [] without API key")

    def test_returns_empty_without_key_empty_domain(self) -> None:
        for cls in self._API_KEY_CONNECTORS:
            with self.subTest(connector=cls.__name__):
                result = cls().run(_target(""), api_key=None)
                self.assertEqual(result, [])

    def test_ping_fails_without_key(self) -> None:
        for cls in self._API_KEY_CONNECTORS:
            with self.subTest(connector=cls.__name__):
                ok, msg = cls().ping(api_key=None)
                self.assertFalse(ok, f"{cls.__name__}.ping() should return False without API key")
                self.assertIsInstance(msg, str)

    def test_ping_ok_with_any_key(self) -> None:
        for cls in self._API_KEY_CONNECTORS:
            with self.subTest(connector=cls.__name__):
                ok, msg = cls().ping(api_key="dummy-key-for-smoke-test")
                self.assertTrue(ok)


class TestSocialTwitterConnector(unittest.TestCase):
    """Additional smoke tests specific to the new Twitter connector."""

    def setUp(self) -> None:
        self.conn = SocialTwitterConnector()

    def test_no_key_no_demo_returns_empty(self) -> None:
        target = _target()
        target.demo_mode = False
        self.assertEqual(self.conn.run(target, api_key=None), [])

    def test_no_key_demo_mode_returns_mock(self) -> None:
        target = _target()
        target.demo_mode = True
        result = self.conn.run(target, api_key=None)
        self.assertGreater(len(result), 0)
        self.assertTrue(all(e.connector == "social_twitter" for e in result))
        self.assertTrue(all(e.category == "mention" for e in result))

    def test_is_mena_target_detects_uae(self) -> None:
        target = ConnectorTarget(
            company_name="Test Co",
            domain="example.com",
            sector="Finance",
            regions="UAE, Dubai",
        )
        self.assertTrue(self.conn._is_mena_target(target))

    def test_is_mena_target_detects_gcc(self) -> None:
        target = ConnectorTarget(
            company_name="Test Co",
            domain="example.com",
            sector="Finance",
            regions="GCC",
        )
        self.assertTrue(self.conn._is_mena_target(target))

    def test_is_mena_target_global_not_mena(self) -> None:
        target = ConnectorTarget(
            company_name="Test Co",
            domain="example.com",
            sector="Finance",
            regions="Global",
        )
        self.assertFalse(self.conn._is_mena_target(target))

    def test_build_queries_mena_includes_arabic(self) -> None:
        target = ConnectorTarget(
            company_name="ACME Corp",
            domain="acme.com",
            sector="Finance",
            regions="Saudi Arabia, Riyadh",
        )
        queries = self.conn._build_queries(target)
        langs = [lang for _, lang in queries]
        self.assertIn("en", langs)
        self.assertIn("ar", langs)

    def test_build_queries_non_mena_english_only(self) -> None:
        target = ConnectorTarget(
            company_name="ACME Corp",
            domain="acme.com",
            sector="Finance",
            regions="United States",
        )
        queries = self.conn._build_queries(target)
        self.assertEqual(len(queries), 1)
        self.assertEqual(queries[0][1], "en")


class TestGDELTBilingualSupport(unittest.TestCase):
    """Smoke tests for GDELT Arabic/bilingual logic (no network)."""

    def setUp(self) -> None:
        self.conn = GDELTNewsConnector()

    def test_is_mena_detects_uae(self) -> None:
        target = ConnectorTarget(
            company_name="Test", domain="test.com", sector="X", regions="UAE"
        )
        self.assertTrue(self.conn._is_mena_target(target))

    def test_is_mena_detects_middle_east(self) -> None:
        target = ConnectorTarget(
            company_name="Test", domain="test.com", sector="X", regions="Middle East"
        )
        self.assertTrue(self.conn._is_mena_target(target))

    def test_is_mena_not_detected_for_europe(self) -> None:
        target = ConnectorTarget(
            company_name="Test", domain="test.com", sector="X", regions="Europe, Germany"
        )
        self.assertFalse(self.conn._is_mena_target(target))


if __name__ == "__main__":
    unittest.main()
