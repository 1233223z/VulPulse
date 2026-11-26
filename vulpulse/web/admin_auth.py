"""Session and CSRF helpers for the admin web UI."""

from __future__ import annotations

import hashlib
import secrets
import time
from urllib.parse import quote

from fastapi import Request
from fastapi.responses import RedirectResponse

from vulpulse.api.rate_limit import client_ip, parse_trusted_proxies
from vulpulse.config import get_settings

ADMIN_SESSION_KEY = "vul_pulse_admin"
ADMIN_KEY_FP = "vul_pulse_key_fp"
CSRF_SESSION_KEY = "vul_pulse_csrf"
LOGIN_WINDOW_SECONDS = 300.0
LOGIN_MAX_ATTEMPTS = 5
LOGIN_GLOBAL_MAX_ATTEMPTS = 50
LOGIN_MAX_TRACKED_CLIENTS = 4096
_LOGIN_ATTEMPTS: dict[str, list[float]] = {}
_GLOBAL_ATTEMPTS: list[float] = []


def _fingerprint(api_key: str) -> str:
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def is_admin(request: Request) -> bool:
    if not request.session.get(ADMIN_SESSION_KEY):
        return False
    expected = _fingerprint(get_settings().api_key)
    stored = str(request.session.get(ADMIN_KEY_FP, ""))
    return secrets.compare_digest(stored, expected)


def login_admin(request: Request, api_key: str) -> None:
    request.session[ADMIN_SESSION_KEY] = True
    request.session[ADMIN_KEY_FP] = _fingerprint(api_key)
    request.session[CSRF_SESSION_KEY] = secrets.token_urlsafe(32)


def logout_admin(request: Request) -> None:
    request.session.clear()


def current_csrf(request: Request) -> str:
    token = request.session.get(CSRF_SESSION_KEY)
    if not token:
        token = secrets.token_urlsafe(32)
        request.session[CSRF_SESSION_KEY] = token
    return str(token)


def verify_csrf(request: Request, token: str | None) -> bool:
    expected = request.session.get(CSRF_SESSION_KEY)
    return bool(expected and token and secrets.compare_digest(str(expected), str(token)))


def admin_redirect(request: Request) -> RedirectResponse | None:
    if is_admin(request):
        return None
    target = quote(request.url.path, safe="")
    return RedirectResponse(f"/admin/login?next={target}", status_code=303)


def safe_next(value: str | None) -> str | None:
    """Only allow local absolute paths as post-login redirects."""
    if not value:
        return None
    if not value.startswith("/") or value.startswith("//"):
        return None
    return value


def _login_key(request: Request) -> str:
    settings = get_settings()
    return client_ip(request, parse_trusted_proxies(settings.trusted_proxies))


def _recent(attempts: list[float], now: float) -> list[float]:
    return [attempt for attempt in attempts if now - attempt < LOGIN_WINDOW_SECONDS]


def _recent_attempts(key: str, now: float) -> list[float]:
    attempts = _recent(_LOGIN_ATTEMPTS.get(key, []), now)
    if attempts:
        _LOGIN_ATTEMPTS[key] = attempts
    else:
        _LOGIN_ATTEMPTS.pop(key, None)
    return attempts


def _recent_global(now: float) -> list[float]:
    global _GLOBAL_ATTEMPTS
    _GLOBAL_ATTEMPTS = _recent(_GLOBAL_ATTEMPTS, now)
    return _GLOBAL_ATTEMPTS


def _prune_login_attempts(now: float) -> None:
    """Bound memory when many distinct clients fail to log in.

    Only the per-IP dictionary needs bounding: the global list is capped by
    ``LOGIN_GLOBAL_MAX_ATTEMPTS`` before new failures are recorded. Entries are
    dropped from least to most recently seen once the client cap is exceeded.
    """
    if len(_LOGIN_ATTEMPTS) <= LOGIN_MAX_TRACKED_CLIENTS:
        return

    cutoff = now - LOGIN_WINDOW_SECONDS
    stale = [
        key for key, attempts in _LOGIN_ATTEMPTS.items() if not attempts or attempts[-1] <= cutoff
    ]
    for key in stale:
        del _LOGIN_ATTEMPTS[key]

    overflow = len(_LOGIN_ATTEMPTS) - LOGIN_MAX_TRACKED_CLIENTS
    if overflow > 0:
        oldest = sorted(_LOGIN_ATTEMPTS, key=lambda key: _LOGIN_ATTEMPTS[key][-1])[:overflow]
        for key in oldest:
            del _LOGIN_ATTEMPTS[key]


def login_allowed(request: Request) -> bool:
    now = time.monotonic()
    return (
        len(_recent_attempts(_login_key(request), now)) < LOGIN_MAX_ATTEMPTS
        and len(_recent_global(now)) < LOGIN_GLOBAL_MAX_ATTEMPTS
    )


def record_login_failure(request: Request) -> None:
    now = time.monotonic()
    key = _login_key(request)
    attempts = _recent_attempts(key, now)
    attempts.append(now)
    _LOGIN_ATTEMPTS[key] = attempts
    _recent_global(now).append(now)
    _prune_login_attempts(now)


def clear_login_failures(request: Request) -> None:
    _LOGIN_ATTEMPTS.pop(_login_key(request), None)


def reset_login_attempts() -> None:
    _LOGIN_ATTEMPTS.clear()
    _GLOBAL_ATTEMPTS.clear()
