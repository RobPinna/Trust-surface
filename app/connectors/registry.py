from app.connectors.base import ConnectorBase
from app.connectors.brand_impersonation_monitor import BrandImpersonationMonitorConnector
from app.connectors.dns_footprint import DNSFootprintConnector
from app.connectors.email_posture_analyzer import EmailPostureAnalyzerConnector
from app.connectors.gdelt_news import GDELTNewsConnector
from app.connectors.hibp_breach_domain import HIBPBreachDomainConnector
from app.connectors.job_postings_live import JobPostingsLiveConnector
from app.connectors.media_trend import MediaTrendConnector
from app.connectors.official_channel_enumerator import OfficialChannelEnumeratorConnector
from app.connectors.procurement_documents import ProcurementDocumentsConnector
from app.connectors.public_role_extractor import PublicRoleExtractorConnector
from app.connectors.public_docs_pdf import PublicDocsPdfConnector
from app.connectors.shodan import ShodanConnector
from app.connectors.social_twitter import SocialTwitterConnector
from app.connectors.subdomain_discovery import SubdomainDiscoveryConnector
from app.connectors.vendor_js_detection import VendorJsDetectionConnector
from app.connectors.virustotal import VirusTotalConnector
from app.connectors.website_analyzer import WebsiteAnalyzerConnector


def connector_registry() -> list[ConnectorBase]:
    return [
        WebsiteAnalyzerConnector(),
        OfficialChannelEnumeratorConnector(),
        PublicRoleExtractorConnector(),
        EmailPostureAnalyzerConnector(),
        DNSFootprintConnector(),
        SubdomainDiscoveryConnector(),
        BrandImpersonationMonitorConnector(),
        GDELTNewsConnector(),
        MediaTrendConnector(),
        SocialTwitterConnector(),
        JobPostingsLiveConnector(),
        VendorJsDetectionConnector(),
        ProcurementDocumentsConnector(),
        PublicDocsPdfConnector(),
        VirusTotalConnector(),
        ShodanConnector(),
        HIBPBreachDomainConnector(),
    ]


def connector_map() -> dict[str, ConnectorBase]:
    items = connector_registry()
    return {c.name: c for c in items}
