<div align="center">

# VulPulse

**Open-source vulnerability intelligence platform**

Collect · Normalize · Deduplicate · Score · Alert

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-alpha-orange)

</div>

VulPulse aggregates public vulnerability data from sources such as NVD, CISA KEV,
Exploit-DB and FIRST EPSS. It normalizes records into a single model, deduplicates
them across sources, enriches them with exploit intelligence, and exposes the
result through a REST API, a web dashboard, and configurable alerts
(WeCom / email).

> **Status:** early development (`v0.1.0` in progress). The API and database
> schema may change before `v1.0`.

## Screenshots

![VulPulse dashboard](docs/dashboard.png)

![Vulnerability list](docs/vulnerabilities.png)

Screenshots use 31k+ real records collected by VulPulse from NVD, CISA KEV,
Exploit-DB and FIRST EPSS.

## Why VulPulse

Vulnerability information is scattered across dozens of sites with different
formats, identifiers and update cadences. Security teams and researchers end up
checking NVD, vendor advisories, KEV and exploit feeds by hand.

VulPulse turns that into one pipeline:

- **One model** — CVE-centric records with CVSS, CWE, affected products, EPSS,
  KEV status and exploit availability.
- **One source of truth** — every field keeps a link back to the raw records it
  came from, so merges are auditable.
- **One place to watch** — filter by severity, vendor, product or keyword and
  get alerts only for what matters.

## Architecture

```mermaid
flowchart LR
    subgraph Sources
        NVD[NVD API]
        KEV[CISA KEV]
        EDB[Exploit-DB]
        EPSS[FIRST EPSS]
    end

    SCH[Scheduler worker] --> C
    Sources --> C[Crawler layer<br/>rate limit · retry · checkpoint]
    C --> N[Normalizer]
    N --> M[Merger / dedupe]
    M --> DB[(SQLite / PostgreSQL)]
    DB --> API[FastAPI]
    DB --> WEB[Web dashboard]
    DB --> NOTIFY[Notifier]
    NOTIFY --> WECOM[WeCom]
    NOTIFY --> MAIL[Email]
```

The scheduler runs in its own process (`vulpulse worker`), separate from the API,
so multiple API workers can never trigger duplicate crawls.

## Roadmap

| Phase | Scope | Status |
|---|---|---|
| **M0** | Repository scaffolding, lint, tests, CI, license | ✅ |
| **M1** | Configuration, structured logging, CLI entry point | ✅ |
| **M2** | Database models, migrations, repositories | ✅ |
| **M3** | Crawler framework: source base class, registry, rate limiting, retries | ✅ |
| **M4** | NVD + CISA KEV ingestion with idempotent upserts | ✅ |
| **M5** | Exploit-DB + EPSS enrichment | ✅ |
| **M6** | Scheduler worker and crawl run history | ✅ |
| **M7** | REST API: vulnerabilities, statistics, sources | ✅ |
| **M8** | Web dashboard | ✅ |
| **M9** | Subscription rules and WeCom / email alerts | ✅ |
| **M10** | Docker packaging, demo data, `v0.1.0` release | 🗓 |

Phase 2 adds a configurable 0–100 risk score, vendor/product correlation,
user-defined subscriptions, export to Markdown/HTML and stronger rate control.
Phase 3 adds a vulnerability graph, optional LLM summaries and a plugin system
for additional sources.

## Quickstart (development)

```bash
git clone <your-repo-url> VulPulse
cd VulPulse

python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/macOS: source .venv/bin/activate

pip install -e ".[dev]"
cp .env.example .env

pytest
ruff check .
vulpulse init-db
vulpulse sources
vulpulse crawl --source cisa_kev --since-days 1
vulpulse crawl --source nvd --since-days 7
vulpulse crawl --source exploitdb --since-days 1
vulpulse enrich --source epss
vulpulse version
```

`vulpulse crawl` writes to the SQLite database and records every run in
`crawl_runs`. Re-running a source is idempotent: records are merged by CVE,
not duplicated. `vulpulse enrich --source epss` only updates CVEs that already
exist, so importing EPSS does not create hundreds of thousands of context-free
rows.

Python 3.10+ is required. The default database is SQLite, so no external
services are needed.

## API

Start the FastAPI application:

```bash
vulpulse init-db   # first time only
vulpulse serve --host 0.0.0.0 --port 8000
```

| Endpoint | Purpose |
|---|---|
| `GET /docs` | Swagger UI and OpenAPI schema |
| `GET /healthz` | Health and database check |
| `GET /api/v1/vulns` | Paginated list with search and filters |
| `GET /api/v1/vulns/{cve_or_id}` | Vulnerability detail with sources, products, CWEs |
| `GET /api/v1/stats/overview` | Totals, severity breakdown and publication trend |
| `GET /api/v1/sources` | Source status and last crawl run |
| `POST /api/v1/admin/crawl` | Trigger one crawl (requires `X-API-Key`) |

Example:

```bash
curl "http://localhost:8000/api/v1/vulns?severity=critical&kev=true&size=5"
curl "http://localhost:8000/api/v1/vulns/CVE-2024-0001"
curl "http://localhost:8000/api/v1/stats/overview?days=30"
```

Admin requests need `VULPULSE_API_KEY` and an `X-API-Key` header. The admin
endpoint runs the crawl as a background task in the API process, which is
convenient for a single-node setup; production deployments should use the
scheduler worker or the CLI.

## Web dashboard

The same process serves the dashboard at `http://localhost:8000/`:

- overview cards for total, KEV, public exploits and EPSS coverage
- 30-day publication trend
- vulnerability search, filters and pagination
- detail pages with affected products, CWEs, references and source records
- crawler status page

Bootstrap and Chart.js are vendored under `vulpulse/web/static/vendor`, so the
dashboard works without a CDN and offline.

## Scheduler

Run the scheduler in its own process:

```bash
vulpulse init-db   # first time only
vulpulse worker
```

| Job | Default interval | Behavior |
|---|---|---|
| `crawl:nvd` | 60 min | Incremental, using the last successful checkpoint |
| `crawl:cisa_kev` | 6 h | Full KEV feed sync |
| `crawl:exploitdb` | 24 h | Full Exploit-DB CSV sync |
| `enrich:epss` | 24 h | Updates existing CVEs with EPSS scores |
| `notify:alerts` | 5 min | Matches subscriptions and delivers alerts |

Intervals are configurable through `VULPULSE_*` environment variables. Every
run is recorded in `crawl_runs`; a failing source is logged and does not stop
the scheduler. `vulpulse worker --once` runs all jobs once and exits, which is
handy for Cron or a manual refresh.

## Alerts

Create a WeCom robot channel and a critical/KEV subscription:

```bash
vulpulse channel add --name wecom --type wecom \
  --webhook-url "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=..."

vulpulse subscription add --name critical-kev --channel wecom \
  --severity critical --severity high --kev
```

Email uses the `VULPULSE_SMTP_*` settings:

```bash
vulpulse channel add --name email --type email --email-to security@example.com
```

Verify and run a cycle:

```bash
vulpulse notify-test --channel wecom   # one test message
vulpulse notify --dry-run              # match only, no writes or sends
vulpulse notify                        # create deliveries and send
```

Rules support `--severity`, `--keyword`, `--vendor`, `--product`, `--source`,
`--kev/--no-kev`, `--exploit/--no-exploit`, `--cvss-min`, `--epss-min` and
`--within-days`. Advanced rules can be passed as JSON with `--rule`.

Deliveries are deduplicated per `(subscription, vulnerability, channel)`, so a
CVE is never sent twice. Failed sends are retried up to
`VULPULSE_NOTIFY_MAX_ATTEMPTS`; successful and failed attempts are visible in the
`deliveries` table. The scheduler runs the `notify:alerts` job every 5 minutes.

## Configuration

All settings use the `VULPULSE_` prefix and can be provided via environment
variables or `.env`. See [`.env.example`](.env.example) for the full list.

| Variable | Default | Purpose |
|---|---|---|
| `VULPULSE_ENV` | `dev` | `dev`, `test` or `prod` |
| `VULPULSE_LOG_LEVEL` | `INFO` | Console/file log level |
| `VULPULSE_DATABASE_URL` | `sqlite+aiosqlite:///./data/vulpulse.db` | SQLAlchemy URL |
| `VULPULSE_API_KEY` | empty | Protects admin endpoints |
| `VULPULSE_NVD_API_KEY` | empty | Raises NVD rate limit from 5 to 50 req/30s |
| `VULPULSE_WECOM_WEBHOOK_URL` | empty | WeCom alert channel |
| `VULPULSE_SMTP_*` | empty | Email alert channel |
| `VULPULSE_PUBLIC_BASE_URL` | `http://localhost:8000` | Base URL used in alert links |
| `VULPULSE_NOTIFY_MAX_ATTEMPTS` | `3` | Delivery retry limit |

Never commit `.env`.

## Data sources and compliance

VulPulse only collects **publicly accessible** vulnerability metadata. It does
not provide proof-of-concept code, exploit tooling, or attack capabilities.

- Requests are rate-limited and identify the client via `User-Agent`.
- No login, CAPTCHA, paywall or access-control bypass is implemented.
- Raw records are stored for auditability; source terms and licenses remain with
  their respective owners. The MIT license covers VulPulse code only.
- Chinese sources such as CNVD are not enabled by default because they lack
  stable public APIs and have unclear scraping terms. Any future adapter will be
  opt-in and disabled by default.

See the [disclaimer](#disclaimer) below.

## Project layout

```
vulpulse/
├── crawler/      # source adapters, HTTP client, raw models
├── analyzer/     # normalization, merging, scoring
├── db/           # SQLAlchemy models, sessions, repositories
├── notifier/     # subscription rules and delivery channels
├── scheduler/    # APScheduler jobs and worker entry point
├── api/          # FastAPI application and routers
├── web/          # Jinja2 templates and static assets
├── config.py     # environment-driven settings
├── logging.py    # loguru configuration
└── cli.py        # Typer entry point
```

## Contributing

Issues and pull requests are welcome. Please run `ruff check .`,
`ruff format --check .` and `pytest` before opening a PR. Commit messages follow
[Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`,
`docs:`, ...).

## Disclaimer

VulPulse is intended for defensive security research and vulnerability
management. It aggregates publicly available information and does not perform
scanning or exploitation. Users are responsible for complying with the terms of
service of every data source and with applicable laws and regulations. The
maintainers are not liable for misuse.

## License

[MIT](LICENSE)
