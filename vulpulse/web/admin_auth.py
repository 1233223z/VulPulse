"""Session and CSRF helpers for the admin web UI."""

from __future__ import annotations

import secrets
import time
from urllib.parse import quote

from fastapi import Request
from fastapi.responses import RedirectResponse

ADMIN_SESSION_KEY = "vul_pulse_admin"
CSRF_SESSION_KEY = "vul_pulse_csrf"
LOGIN_WINDOW_SECONDS = 300.0
LOGIN_MAX_ATTEMPTS = 5
_LOGIN_ATTEMPTS: dict[str, list[float]] = {}


def is_admin(request: Request) -> bool:
    return bool(request.session.get(ADMIN_SESSION_KEY))


def login_admin(request: Request) -> None:
    request.session[ADMIN_SESSION_KEY] = True
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
    return request.client.host if request.client else "unknown"


def _recent_attempts(key: str, now: float) -> list[float]:
    attempts = [
        attempt for attempt in _LOGIN_ATTEMPTS.get(key, []) if now - attempt < LOGIN_WINDOW_SECONDS
    ]
    _LOGIN_ATTEMPTS[key] = attempts
    return attempts


def login_allowed(request: Request) -> bool:
    now = time.monotonic()
    return len(_recent_attempts(_login_key(request), now)) < LOGIN_MAX_ATTEMPTS


def record_login_failure(request: Request) -> None:
    now = time.monotonic()
    key = _login_key(request)
    attempts = _recent_attempts(key, now)
    attempts.append(now)
    _LOGIN_ATTEMPTS[key] = attempts


def clear_login_failures(request: Request) -> None:
    _LOGIN_ATTEMPTS.pop(_login_key(request), None)


def reset_login_attempts() -> None:
    _LOGIN_ATTEMPTS.clear()
