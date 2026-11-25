# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2026-11-25

### Added

- Filterable Markdown and HTML vulnerability reports with summary cards,
  risk/KEV/exploit columns and safe escaping of untrusted fields.
- `vulpulse export` CLI with the same filters as the query API.
- `GET /api/v1/export` returning the report as a downloadable attachment.
- Export MD / Export HTML buttons on the vulnerability list that preserve the
  active filters.

## [0.3.0] - 2026-11-25

### Added

- Vendor aggregation API (`/api/v1/vendors`) with product counts, risk-level
  breakdowns and average/max risk.
- Vendor detail API (`/api/v1/vendors/{vendor}`) with correlated products and
  top-risk vulnerabilities.
- Vendor and product analytics pages in the web dashboard, plus links between
  vendor, product and vulnerability views.
- Product filtering on vulnerability list endpoints (`product=...`).
- Risk badges on vendor pages and product links in vulnerability details.

## [0.2.0] - 2026-11-25

### Added

- Explainable 0-100 risk scoring combining CVSS, EPSS, CISA KEV, public exploit
  availability and recency, with configurable and normalized weights.
- `risk_score` and `risk_level` columns, an Alembic migration and a `vulpulse
  score` backfill/refresh command.
- Risk scoring on ingest, after EPSS enrichment and in a scheduled
  `score:refresh` worker job.
- API fields `risk_score` / `risk_level` / `risk_breakdown`, a `risk_min` filter
  and `sort=risk_score`; statistics now include risk-level counts.
- Risk column and full component breakdown in the web dashboard.

## [0.1.1] - 2026-11-25

### Fixed

- Serialized scheduled jobs inside the worker, preventing concurrent SQLite
  writers from failing with `database is locked` when several sources start at
  the same time.
- Raised the SQLite busy timeout from 5s to 30s for short API/worker contention.
- Verified the full Docker Compose stack end to end: `init` migrations, `api`
  health check, `worker` job ordering and the persistent data volume.

## [0.1.0] - 2026-11-25

### Added

- Multi-source ingestion for NVD, CISA KEV and Exploit-DB with per-source rate
  limiting, retries and checkpoint-based incremental sync.
- Unified CVE-centric model with cross-source deduplication, field-level merging,
  products, CWEs and references.
- FIRST EPSS enrichment for existing vulnerabilities.
- APScheduler worker with separate crawl, enrichment and notification jobs.
- FastAPI query API with search, filters, pagination, statistics, source status
  and an API-key protected manual crawl endpoint.
- Server-rendered Bootstrap dashboard with a 30-day trend, vulnerability search,
  detail pages and source status; frontend assets are vendored for offline use.
- Subscription rules and WeCom / SMTP alert delivery with deduplication and
  retries.
- SQLite schema managed by Alembic, with WAL and foreign keys enabled.
- Docker image and Compose stack (`init`, `api`, `worker`) with a persistent
  data volume and health checks.
- CI across Python 3.10, 3.12 and 3.14, plus a container build job.

[0.4.0]: https://github.com/1233223z/VulPulse/releases/tag/v0.4.0
[0.3.0]: https://github.com/1233223z/VulPulse/releases/tag/v0.3.0
[0.2.0]: https://github.com/1233223z/VulPulse/releases/tag/v0.2.0
[0.1.1]: https://github.com/1233223z/VulPulse/releases/tag/v0.1.1
[0.1.0]: https://github.com/1233223z/VulPulse/releases/tag/v0.1.0
