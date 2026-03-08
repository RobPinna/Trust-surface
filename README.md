# Trust Surface

> **Defensive research project** — Educational CTI tooling for studying automated OSINT collection, trust-surface mapping, and LLM-assisted risk reasoning. Built as a practical portfolio demonstrating end-to-end Cyber Threat Intelligence analyst skills.

---

## What it does

**Trust Surface** is an evidence-first framework that automates the OSINT collection and analysis workflow a CTI analyst would normally perform manually. Given a target organization (company name + domain + sector), it:

1. **Collects** public signals from 17 specialized connectors (DNS, breach data, brand impersonation, job postings, news, social mentions, web infrastructure, procurement documents, and more)
2. **Classifies** each evidence signal by quality tier (`BOILERPLATE → LOW → MED → HIGH`) and filters noise automatically
3. **Correlates** evidence cross-source using a BM25 RAG pipeline to surface non-obvious relationships
4. **Reasons** over correlated evidence with an LLM (OpenAI GPT-4.1 / Anthropic Claude / local fallback) to generate structured risk hypotheses
5. **Scores** each risk with a multi-component confidence formula accounting for signal diversity, source independence, and coverage depth
6. **Reports** findings as a structured PDF/JSON artifact with risk narrative, evidence chain, and confidence metadata

The analytical focus is **trust leverage and social engineering risk** — the attack surface exposed through an organization's public workflows, vendor relationships, and communication channels that an adversary could exploit to conduct BEC, spear-phishing, impersonation, or supply-chain manipulation.

---

## Why this exists

Most CTI tooling at entry/mid level involves operating commercial platforms (Maltego, Recorded Future, etc.). This project was built from scratch to demonstrate:

- Deep understanding of **CTI methodology** (evidence collection → correlation → reasoning → production)
- **Software engineering discipline** applied to security tooling (typed API, ORM schema, quality gates, test coverage)
- **LLM integration patterns** for intelligence analysis (RAG, multi-provider resilience, safety filters on output)
- **Original domain modeling** — the "trust surface" and "operational leverage" concepts are novel framings of known social engineering risk vectors

> This project is **strictly defensive and educational**. It surfaces publicly available information to help defenders understand their exposure. It does not perform active scanning, exploitation, or data exfiltration.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  FastAPI + Jinja2 Web UI                    CLI (trust-surface)      │
└────────────────────────┬───────────────────────────────────────┘
                         │
          ┌──────────────▼──────────────┐
          │     Assessment Orchestrator  │
          │   (collector_v2 + services)  │
          └──────┬──────────────┬───────┘
                 │              │
    ┌────────────▼───┐   ┌──────▼──────────────┐
    │  17 Connectors  │   │  Evidence Quality    │
    │  (OSINT sources)│   │  Classifier + Scorer │
    └────────────────┘   └──────┬───────────────┘
                                │
                    ┌───────────▼──────────────┐
                    │  RAG Pipeline (BM25)      │
                    │  6-query extraction plan  │
                    └───────────┬──────────────┘
                                │
                    ┌───────────▼──────────────┐
                    │  LLM Reasoner             │
                    │  (OpenAI / Anthropic /    │
                    │   deterministic fallback) │
                    └───────────┬──────────────┘
                                │
                    ┌───────────▼──────────────┐
                    │  Risk Story Builder       │
                    │  Confidence Scoring       │
                    │  PDF / JSON Export        │
                    └──────────────────────────┘
```

### Source layout

```
Operational-Leverage-Framework/
├── app/                          # FastAPI runtime application
│   ├── connectors/               # 17 OSINT data connectors
│   ├── routers/                  # API endpoints
│   ├── services/                 # Core business logic
│   │   ├── collector_v2.py       # Orchestration and collection
│   │   ├── evidence_quality_classifier.py
│   │   ├── signal_model.py       # Confidence scoring formula
│   │   ├── risk_story.py         # Risk narrative builder
│   │   └── trust_workflows.py    # Trust surface mapping
│   └── utils/                    # Reporting, graphing, PDF export
├── src/operational_leverage_framework/   # Typed public package
│   ├── cli/                      # CLI entry point (trust-surface)
│   ├── core/scoring.py           # Reusable scoring API
│   ├── io/json_loader.py         # Evidence input parsing
│   └── models/evidence.py        # Evidence schema
├── src/rag/                      # BM25 retrieval pipeline
├── src/reasoner/                 # LLM reasoning layer
├── examples/                     # Offline deterministic scenarios
├── tests/                        # Unit, integration, smoke tests
├── docs/                         # Architecture and design decisions
└── scripts/                      # Build, setup, safety tools
```

---

## Connectors (17)

| Connector | Source | API Key | Signal type |
|-----------|--------|---------|-------------|
| `website_analyzer` | Target website | No | Vendor deps, workflow cues |
| `official_channel_enumerator` | Public social/web | No | Channel ambiguity |
| `public_role_extractor` | Public web | No | Role exposure |
| `email_posture_analyzer` | DNS (SPF/DMARC/DKIM) | No | Email spoofing risk |
| `dns_footprint` | DNS (A/MX/NS/CNAME) | No | Infrastructure exposure |
| `subdomain_discovery` | DNS brute + CT | No | Attack surface expansion |
| `brand_impersonation_monitor` | DNS + RDAP + crt.sh | No | Typosquat / lookalike domains |
| `gdelt_news` | GDELT API | No | News mentions (EN + AR for MENA) |
| `media_trend` | Public news | No | Brand sentiment trend |
| `social_twitter` | Twitter/X v2 API | Bearer token | Social mentions (EN + AR for MENA) |
| `job_postings_live` | Public job boards | No | Stack/vendor disclosure |
| `vendor_js_detection` | Website JS analysis | No | Workflow vendor fingerprinting |
| `procurement_documents` | Public procurement | No | Partner/supplier relationships |
| `public_docs_pdf` | Indexed PDFs | No | Document exposure |
| `public_role_extractor` | LinkedIn/public | No | Org chart leakage |
| `virustotal` | VirusTotal API | Required | Domain/IP reputation |
| `shodan` | Shodan API | Required | Host/port/vuln exposure |
| `hibp_breach_domain` | HIBP API | Required | Credential breach data |

---

## Risk types analyzed

| Risk type | Description |
|-----------|-------------|
| **Impersonation** | Brand lookalike domains, channel spoofing, fake portals |
| **Fraud process** | Invoice fraud vectors, payment workflow exposure |
| **Social engineering** | Trust relationship exploitation, pretexting surface |
| **Operational leverage** | Vendor/partner chain as entry point for manipulation |
| **Credential exposure** | Breach data correlated with active infrastructure |

---

## Key design decisions

- **Evidence-first, not heuristic-first** — every risk finding is traceable to at least one collected evidence item with source URL and quality weight
- **Boilerplate suppression** — generic analytics vendors (GTM, GA4, etc.) are classified as `BOILERPLATE` and excluded from confidence calculation
- **Multi-provider LLM with offline fallback** — the reasoner supports OpenAI GPT-4.1, Anthropic Claude, and a deterministic local path for reproducible offline demos
- **BM25 RAG without vector store** — evidence is indexed locally using BM25 TF-IDF; no embedding API cost, no external dependency
- **Safety filters on LLM output** — the reasoner prompt explicitly prohibits generating actionable attack instructions

See [docs/decisions.md](docs/decisions.md) for full architectural rationale.

---

## Scoring model

Confidence (1–100) is computed as:

```
confidence = baseline_avg
           + signal_diversity_bonus     # unique signal types covered
           + url_diversity_bonus        # source independence
           - boilerplate_penalty        # low-quality evidence weight
           + critical_signal_bonus      # risk-type-specific required signals
```

Each risk type has a set of **critical signals** that must be present to reach `STRONG` coverage. Missing critical signals are surfaced in the output as `missing_signals`, giving defenders an explicit gap analysis.

---

## Quick start

### Requirements

- Python `>= 3.11`
- `OPENAI_API_KEY` for LLM reasoning (recommended); local/offline mode available for testing

### Setup

```bash
python scripts/run.py setup --venv
```

Enable code quality hooks:

```bash
python -m pre_commit install
```

### Run the web UI

```bash
python scripts/run.py web
# Opens http://127.0.0.1:56461
```

### Run the CLI (offline, deterministic)

```bash
pip install -e .
trust-surface examples/scenario_hospitality/input.json \
  --out output.json --risk-type impersonation
```

### Configuration

Copy `.env.example` to `.env` and set values:

```env
OPENAI_API_KEY=sk-...
SECRET_KEY=change-me
PASSWORD_PEPPER=change-me
API_KEY_PEPPER=change-me
DEFAULT_ADMIN_PASSWORD=change-me
```

Optional connector keys (configured in-app from the Settings page):

```env
# Shodan — host/port/vuln exposure
SHODAN_API_KEY=...

# Have I Been Pwned — domain breach lookup
HIBP_API_KEY=...

# Twitter/X v2 — social mention monitoring
TWITTER_BEARER_TOKEN=...

# VirusTotal — domain/IP reputation
VIRUSTOTAL_API_KEY=...
```

### Safety check (before sharing exports)

```bash
python scripts/run.py safety
```

---

## Testing

```bash
python -m pytest
```

Test suite (75 tests):

| File | Coverage |
|------|----------|
| `test_evidence_quality_layer.py` | Evidence classification, boilerplate suppression, scoring |
| `test_risk_ranking_regressions.py` | Risk ranking stability, DB side effects |
| `test_connectors_core.py` | Shodan / BrandImpersonation / HIBP — pure logic + mocked HTTP |
| `test_connector_smoke.py` | All 17 connectors — instantiation, interface, API key guards |
| `test_cli_smoke.py` | CLI entry point, FastAPI health endpoint |

---

## Roadmap / TODO

The following capabilities are planned for future development:

### Regional specialization — MENA

- [ ] Arabic-language NLP for evidence classification and signal extraction (beyond GDELT language filter)
- [ ] MENA-specific threat actor TTP library integrated into LLM reasoning prompts (APT34, Charming Kitten, etc.)
- [ ] Regional OSINT sources: Gulf News, Al Arabiya, NCSC-SA feeds, regional CERT advisories
- [ ] GCC/Levant sector taxonomy (government, energy, finance, telecom) for sector-adjusted risk scoring
- [ ] Arabic domain typosquat generation in `brand_impersonation_monitor` (Arabic script lookalikes)
- [ ] Localized PDF report templates (bilingual AR/EN output)

### Connector enhancements

- [ ] Replace mock social connector with real Reddit API (public mentions, no payment required)
- [ ] Telegram channel monitoring for brand abuse signals
- [ ] LinkedIn organizational footprint (public scraping within ToS)
- [ ] Regional procurement portals (Gulf tendering databases)

### Platform

- [ ] MITRE ATT&CK technique tagging on risk hypotheses
- [ ] Multi-assessment trend analysis (risk delta over time)
- [ ] Team/multi-user assessment workflow
- [ ] Webhook/SIEM integration for continuous monitoring mode

---

## Limitations

- Confidence scores are heuristic and evidence-dependent — they reflect public signal coverage, not ground truth
- Public-source visibility is inherently incomplete; absence of signals does not indicate absence of risk
- The LLM reasoning step is only as good as the evidence collected; thin evidence → low-confidence hypotheses
- Social connector (Twitter/X) requires a paid developer account for meaningful rate limits on the free API tier
- This is a research/study project, not a production security product — no SLA, no warranty

---

## Ethical notice

This tool queries only publicly available information using standard HTTP requests and documented APIs. It does not perform port scanning, exploit execution, credential testing, or any form of active intrusion. All collected data is stored locally and never transmitted to third parties beyond the configured LLM provider.

Intended use: defensive research, CTI analyst training, organizational self-assessment, academic study.

---

## License

See [LICENSE](LICENSE).
