# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[0.1.0]: https://github.com/1233223z/VulPulse/releases/tag/v0.1.0
