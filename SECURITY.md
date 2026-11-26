# Security Policy

## Reporting a vulnerability

Please report security issues in VulPulse privately through GitHub Security
Advisories:

https://github.com/1233223z/VulPulse/security/advisories/new

Do not open a public issue for a vulnerability. Include reproduction steps,
affected versions and any relevant logs.

## Scope

VulPulse aggregates publicly available vulnerability metadata. It does not
provide exploit code, scanning capability or attack tooling. Reports about the
accuracy of third-party vulnerability data should be directed to the original
source (NVD, CISA, Exploit-DB, FIRST).

## Supported versions

The latest `0.10.x` release receives security fixes. Older releases may not be
supported.

## Security model

### Trust boundaries

- **Public internet → API**: untrusted clients can query `/api` and the
  dashboard. They must not be able to read admin data or exhaust the process.
- **Admin → web UI/API**: the shared `VULPULSE_API_KEY` is the only
  administrative credential. It is sent as `X-API-Key` for the API and exchanged
  for a signed, HttpOnly session cookie in the web UI.
- **Crawler → public sources**: source responses are untrusted input. They are
  size-limited, redirect-constrained and parsed before being merged into the
  database.
- **Notifier → WeCom/SMTP**: delivery endpoints are configured by an
  administrator and receive vulnerability data. WeCom URLs must be HTTPS and
  match an allowlist; SMTP uses verified TLS.
- **Container → host**: the image runs as a non-root user; the SQLite database
  and logs live in a dedicated volume.
- **Plugin → process**: source plugins are imported into the API/worker process
  and can execute arbitrary code. Only installed, trusted distributions are
  discovered; `VULPULSE_PLUGINS_ENABLED=false` disables third-party discovery.
- **Admin → LLM provider**: when AI summaries are enabled, an authenticated
  admin action sends bounded vulnerability metadata to Anthropic. The provider
  key is a secret; summaries are untrusted output and are rendered as text.

### Implemented controls

- API-key authentication with constant-time comparison; admin sessions expire
  after eight hours and are invalidated when the key rotates.
- CSRF tokens on state-changing admin forms, SameSite=Lax session cookies,
  login rate limiting and open-redirect protection.
- Per-client-IP API rate limiting with `X-Forwarded-For` honored only from
  configured trusted proxy CIDRs.
- Crawler response caps, same-host HTTPS redirects and a bounded retry policy;
  EPSS decompression is capped.
- SMTP certificate verification and WeCom host allowlisting; webhook URLs and
  keys are excluded from logs and delivery errors.
- Hash-locked dependencies installed with `--require-hashes`; GitHub Actions
  pinned to commit SHAs; Docker base image pinned by digest.
- Source plugins are version-checked against `PLUGIN_API_VERSION` and loaded
  independently, so one broken plugin cannot stop the other sources.
- AI summaries are opt-in and admin-triggered; input is size-bounded, the
  system prompt treats vulnerability text as untrusted data, and output is
  capped and escaped in the dashboard.
- Escaped Markdown/HTML report output and security headers on HTTP responses.

### Residual risks

- There is one shared administrator key rather than multi-user accounts or
  granular roles.
- Rate limiting is in-process. Multi-worker deployments need a limit at the
  reverse proxy as well.
- SQLite is single-writer. Run one scheduler worker and avoid concurrent bulk
  imports on a production instance.
- Notification webhook URLs and SMTP settings are stored in the local SQLite
  database. Protect the data directory (`0700`) and database backups.
- Third-party vulnerability data may be incomplete or inaccurate; VulPulse does
  not independently verify vendor claims.
- Enabling AI summaries sends selected metadata to Anthropic and may incur API
  costs. Review the provider's terms and your own data-handling policy first.
  AI summaries can be wrong; they are not a substitute for source review.
- Public deployments should terminate HTTPS at a reverse proxy, set
  `VULPULSE_SESSION_HTTPS_ONLY=true`, and restrict `/admin` and `/api/v1/admin`
  to trusted networks.
