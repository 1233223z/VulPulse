"""Admin web UI: login, notification channels and subscriptions."""

from __future__ import annotations

import secrets
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession

from vulpulse.api.deps import get_session
from vulpulse.config import get_settings
from vulpulse.db.repositories import ChannelRepository, SubscriptionRepository
from vulpulse.notifier.rules import SubscriptionRule
from vulpulse.web.admin_auth import (
    admin_redirect,
    current_csrf,
    is_admin,
    login_admin,
    logout_admin,
    safe_next,
    verify_csrf,
)
from vulpulse.web.routes import templates

router = APIRouter(prefix="/admin", tags=["admin-ui"])

_SEVERITIES = ["critical", "high", "medium", "low"]


def _split(value: Any) -> list[str]:
    if not value:
        return []
    return [part.strip() for part in str(value).split(",") if part.strip()]


def _parse_float(value: Any) -> float | None:
    if value is None or str(value).strip() == "":
        return None
    return float(str(value))


def _login_page(
    request: Request,
    *,
    error: str | None = None,
    next_url: str = "/admin/subscriptions",
    status_code: int = status.HTTP_200_OK,
) -> HTMLResponse:
    return templates.TemplateResponse(
        request=request,
        name="admin/login.html",
        context={
            "error": error,
            "next": next_url,
            "active": "admin",
            "api_key_configured": bool(get_settings().api_key),
        },
        status_code=status_code,
    )


@router.get("/login", response_class=HTMLResponse, response_model=None)
async def login_page(request: Request) -> HTMLResponse | RedirectResponse:
    if is_admin(request):
        return RedirectResponse("/admin/subscriptions", status_code=303)
    next_url = safe_next(request.query_params.get("next")) or "/admin/subscriptions"
    return _login_page(request, next_url=next_url)


@router.post("/login", response_model=None)
async def login_submit(request: Request) -> HTMLResponse | RedirectResponse:
    form = await request.form()
    api_key = str(form.get("api_key") or "")
    next_url = safe_next(str(form.get("next") or "")) or "/admin/subscriptions"
    settings = get_settings()

    if not settings.api_key:
        return _login_page(
            request,
            error="Admin UI disabled: set VULPULSE_API_KEY.",
            next_url=next_url,
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )
    if not secrets.compare_digest(api_key, settings.api_key):
        return _login_page(
            request,
            error="Invalid API key.",
            next_url=next_url,
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    login_admin(request)
    return RedirectResponse(next_url, status_code=303)


@router.post("/logout")
async def logout(request: Request) -> RedirectResponse:
    redirect = admin_redirect(request)
    if redirect is not None:
        return redirect
    form = await request.form()
    if not verify_csrf(request, str(form.get("csrf_token") or "")):
        raise HTTPException(status_code=400, detail="Invalid CSRF token")
    logout_admin(request)
    return RedirectResponse("/", status_code=303)


@router.get("", include_in_schema=False)
async def admin_home(request: Request) -> RedirectResponse:
    redirect = admin_redirect(request)
    if redirect is not None:
        return redirect
    return RedirectResponse("/admin/subscriptions", status_code=303)


async def _render_channels(
    request: Request,
    session: AsyncSession,
    *,
    error: str | None = None,
    status_code: int = status.HTTP_200_OK,
) -> HTMLResponse:
    channels = await ChannelRepository(session).list_all()
    return templates.TemplateResponse(
        request=request,
        name="admin/channels.html",
        context={
            "channels": channels,
            "csrf_token": current_csrf(request),
            "active": "admin",
            "error": error,
            "msg": request.query_params.get("msg"),
        },
        status_code=status_code,
    )


@router.get("/channels", response_class=HTMLResponse, response_model=None)
async def channels_page(
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> HTMLResponse | RedirectResponse:
    redirect = admin_redirect(request)
    if redirect is not None:
        return redirect
    return await _render_channels(request, session)


@router.post("/channels", response_model=None)
async def create_channel(
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> HTMLResponse | RedirectResponse:
    redirect = admin_redirect(request)
    if redirect is not None:
        return redirect

    form = await request.form()
    if not verify_csrf(request, str(form.get("csrf_token") or "")):
        raise HTTPException(status_code=400, detail="Invalid CSRF token")

    name = str(form.get("name") or "").strip()
    channel_type = str(form.get("channel_type") or "").strip()
    webhook_url = str(form.get("webhook_url") or "").strip()
    email_to = str(form.get("email_to") or "").strip()
    repository = ChannelRepository(session)

    error: str | None = None
    config: dict[str, Any] = {}

    if not name:
        error = "Name is required."
    elif channel_type not in {"wecom", "email"}:
        error = "Channel type must be wecom or email."
    elif await repository.get_by_name(name) is not None:
        error = "A channel with that name already exists."
    elif channel_type == "wecom":
        url = webhook_url or get_settings().wecom_webhook_url
        if not url:
            error = "WeCom requires a webhook URL."
        else:
            config = {"webhook_url": url}
    elif not email_to:
        error = "Email requires a recipient."
    else:
        config = {"to": [email_to]}

    if error is not None:
        return await _render_channels(
            request,
            session,
            error=error,
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    await repository.create(name, channel_type, config)
    await session.commit()
    return RedirectResponse("/admin/channels?msg=Channel+created", status_code=303)


@router.post("/channels/{channel_id}/toggle")
async def toggle_channel(
    channel_id: int,
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> RedirectResponse:
    redirect = admin_redirect(request)
    if redirect is not None:
        return redirect
    form = await request.form()
    if not verify_csrf(request, str(form.get("csrf_token") or "")):
        raise HTTPException(status_code=400, detail="Invalid CSRF token")

    channel = await ChannelRepository(session).get_by_id(channel_id)
    if channel is None:
        raise HTTPException(status_code=404, detail="Channel not found")
    channel.enabled = not channel.enabled
    await session.commit()
    return RedirectResponse("/admin/channels?msg=Channel+updated", status_code=303)


@router.post("/channels/{channel_id}/delete")
async def delete_channel(
    channel_id: int,
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> RedirectResponse:
    redirect = admin_redirect(request)
    if redirect is not None:
        return redirect
    form = await request.form()
    if not verify_csrf(request, str(form.get("csrf_token") or "")):
        raise HTTPException(status_code=400, detail="Invalid CSRF token")

    repository = ChannelRepository(session)
    channel = await repository.get_by_id(channel_id)
    if channel is None:
        raise HTTPException(status_code=404, detail="Channel not found")
    await repository.delete(channel)
    await session.commit()
    return RedirectResponse("/admin/channels?msg=Channel+deleted", status_code=303)


async def _render_subscriptions(
    request: Request,
    session: AsyncSession,
    *,
    error: str | None = None,
    status_code: int = status.HTTP_200_OK,
) -> HTMLResponse:
    subscriptions = await SubscriptionRepository(session).list_all()
    channels = await ChannelRepository(session).list_all()
    return templates.TemplateResponse(
        request=request,
        name="admin/subscriptions.html",
        context={
            "subscriptions": subscriptions,
            "channels": channels,
            "severities": _SEVERITIES,
            "csrf_token": current_csrf(request),
            "active": "admin",
            "error": error,
            "msg": request.query_params.get("msg"),
        },
        status_code=status_code,
    )


@router.get("/subscriptions", response_class=HTMLResponse, response_model=None)
async def subscriptions_page(
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> HTMLResponse | RedirectResponse:
    redirect = admin_redirect(request)
    if redirect is not None:
        return redirect
    return await _render_subscriptions(request, session)


@router.post("/subscriptions", response_model=None)
async def create_subscription(
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> HTMLResponse | RedirectResponse:
    redirect = admin_redirect(request)
    if redirect is not None:
        return redirect

    form = await request.form()
    if not verify_csrf(request, str(form.get("csrf_token") or "")):
        raise HTTPException(status_code=400, detail="Invalid CSRF token")

    name = str(form.get("name") or "").strip()
    channel_id_raw = str(form.get("channel_id") or "").strip()
    error: str | None = None

    try:
        channel_id = int(channel_id_raw)
    except ValueError:
        channel_id = 0

    channel_repository = ChannelRepository(session)
    channel = await channel_repository.get_by_id(channel_id) if channel_id else None
    subscription_repository = SubscriptionRepository(session)

    if not name:
        error = "Name is required."
    elif channel is None:
        error = "Choose a valid channel."
    elif await subscription_repository.get_by_name(name) is not None:
        error = "A subscription with that name already exists."

    rule: SubscriptionRule | None = None
    if error is None:
        rule_data: dict[str, Any] = {
            "severities": form.getlist("severities"),
            "keywords": _split(form.get("keywords")),
            "vendors": _split(form.get("vendors")),
            "products": _split(form.get("products")),
            "sources": _split(form.get("sources")),
            "in_kev": True if form.get("kev") else None,
            "exploit_available": True if form.get("exploit") else None,
        }
        try:
            cvss_min = _parse_float(form.get("cvss_min"))
            epss_min = _parse_float(form.get("epss_min"))
            within_days = str(form.get("within_days") or "").strip()
            if cvss_min is not None:
                rule_data["cvss_min"] = cvss_min
            if epss_min is not None:
                rule_data["epss_min"] = epss_min
            if within_days:
                rule_data["published_within_days"] = int(within_days)
            rule = SubscriptionRule.model_validate(rule_data)
        except (ValueError, ValidationError) as exc:
            error = f"Invalid rule: {exc}"

    if error is not None or rule is None:
        return await _render_subscriptions(
            request,
            session,
            error=error or "Invalid rule.",
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    assert channel is not None
    await subscription_repository.create(
        name,
        channel.id,
        rule.model_dump(),
    )
    await session.commit()
    return RedirectResponse(
        "/admin/subscriptions?msg=Subscription+created",
        status_code=303,
    )


@router.post("/subscriptions/{subscription_id}/toggle")
async def toggle_subscription(
    subscription_id: int,
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> RedirectResponse:
    redirect = admin_redirect(request)
    if redirect is not None:
        return redirect
    form = await request.form()
    if not verify_csrf(request, str(form.get("csrf_token") or "")):
        raise HTTPException(status_code=400, detail="Invalid CSRF token")

    repository = SubscriptionRepository(session)
    subscription = await repository.get_by_id(subscription_id)
    if subscription is None:
        raise HTTPException(status_code=404, detail="Subscription not found")
    subscription.enabled = not subscription.enabled
    await session.commit()
    return RedirectResponse(
        "/admin/subscriptions?msg=Subscription+updated",
        status_code=303,
    )


@router.post("/subscriptions/{subscription_id}/delete")
async def delete_subscription(
    subscription_id: int,
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> RedirectResponse:
    redirect = admin_redirect(request)
    if redirect is not None:
        return redirect
    form = await request.form()
    if not verify_csrf(request, str(form.get("csrf_token") or "")):
        raise HTTPException(status_code=400, detail="Invalid CSRF token")

    repository = SubscriptionRepository(session)
    subscription = await repository.get_by_id(subscription_id)
    if subscription is None:
        raise HTTPException(status_code=404, detail="Subscription not found")
    await repository.delete(subscription)
    await session.commit()
    return RedirectResponse(
        "/admin/subscriptions?msg=Subscription+deleted",
        status_code=303,
    )
