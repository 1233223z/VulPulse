from __future__ import annotations

import time
from collections.abc import Iterator

import pytest
from starlette.requests import Request

from vulpulse.web import admin_auth


@pytest.fixture(autouse=True)
def _reset_login_state() -> Iterator[None]:
    admin_auth.reset_login_attempts()
    yield
    admin_auth.reset_login_attempts()


def _request(ip: str = "203.0.113.9") -> Request:
    return Request({"type": "http", "client": (ip, 1234), "headers": []})


def test_prune_drops_stale_clients(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(admin_auth, "LOGIN_MAX_TRACKED_CLIENTS", 3)
    now = time.monotonic()
    admin_auth._LOGIN_ATTEMPTS.update({f"192.0.2.{i}": [now - 600] for i in range(10)})

    admin_auth._prune_login_attempts(now)

    assert admin_auth._LOGIN_ATTEMPTS == {}


def test_prune_keeps_most_recent_clients(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(admin_auth, "LOGIN_MAX_TRACKED_CLIENTS", 2)
    now = time.monotonic()
    admin_auth._LOGIN_ATTEMPTS.update(
        {
            "stale-1": [now - 600],
            "stale-2": [now - 600],
            "recent-1": [now - 10],
            "recent-2": [now - 5],
        }
    )

    admin_auth._prune_login_attempts(now)

    assert set(admin_auth._LOGIN_ATTEMPTS) == {"recent-1", "recent-2"}


def test_record_login_failure_prunes_overflow(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(admin_auth, "LOGIN_MAX_TRACKED_CLIENTS", 2)
    now = time.monotonic()
    admin_auth._LOGIN_ATTEMPTS.update({f"198.51.100.{i}": [now - 600] for i in range(5)})

    admin_auth.record_login_failure(_request())

    assert len(admin_auth._LOGIN_ATTEMPTS) <= 2
    assert "203.0.113.9" in admin_auth._LOGIN_ATTEMPTS


def test_login_allowed_blocks_after_per_client_limit() -> None:
    request = _request()

    for _ in range(admin_auth.LOGIN_MAX_ATTEMPTS):
        assert admin_auth.login_allowed(request)
        admin_auth.record_login_failure(request)

    assert not admin_auth.login_allowed(request)

    admin_auth.clear_login_failures(request)
    assert admin_auth.login_allowed(request)
