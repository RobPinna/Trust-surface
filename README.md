# Trust Surface

Evidence-led trust risk assessments.

Trust Surface is an evidence-first CTI/cyber risk assessment project that maps public exposure signals into actionable confidence outputs.

> Disclaimer: this project is an MVP/demo. It is provided as-is, with no warranty or assurance of correct/complete functioning in all scenarios.
> Main usage: run with OpenAI LLM enabled (`OPENAI_API_KEY`). Local/offline mode is for testing only.

## For Users (Recommended)
1. Configure `OPENAI_API_KEY` (environment variable or `.env` file).
2. Download the latest executable from GitHub Releases.
3. Run the executable.
4. The app opens the local web UI automatically, or you can use the URL printed in the console.

Runtime data is stored locally on your machine. Default location is `./data` (or `RUNTIME_DIR` if configured).

## For Developers
Prerequisite: Python `>=3.11`.

Install dependencies:

```bash
python scripts/run.py setup --venv
```

Enable pre-commit hooks (recommended):

```bash
python -m pre_commit install
```

Run web app locally:

```bash
python scripts/run.py web
```

Build executable:

```bash
python scripts/build_release.py
```

Clean build artifacts:

```bash
python scripts/clean_release.py
```

## Optional Configuration
Create `.env` from `.env.example` if you need persistent settings.
For the recommended main mode, set `OPENAI_API_KEY`.
Use local/offline mode only for testing.

Optional OSINT connectors for social-engineering/trust-leverage enrichment are available in the in-app `Settings` page:
- `brand_impersonation_monitor` (typosquat + RDAP + certificate transparency)
- `hibp_breach_domain` (Have I Been Pwned domain breach search, API key required)
- `shodan` (attack-surface DNS/host exposure enrichment, API key required)

Key placeholders available in `.env.example`:

```env
SECRET_KEY=change-me-exposuremapper-secret
PASSWORD_PEPPER=change-me-password-pepper
API_KEY_PEPPER=change-me-api-key-pepper
DEFAULT_ADMIN_PASSWORD=change-me-admin-password
```

## Troubleshooting
- Browser does not open automatically: use the URL printed in console.
- OpenAI-related errors: verify `OPENAI_API_KEY` and quota/billing status.
- Safety checks: `python scripts/run.py safety`.

