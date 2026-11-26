"""Prometheus metrics for HTTP requests."""

from __future__ import annotations

from fastapi import Request
from prometheus_client import Counter, Histogram

HTTP_REQUESTS = Counter(
    "vulpulse_http_requests_total",
    "HTTP requests by method, route template and status.",
    ("method", "route", "status"),
)
HTTP_LATENCY = Histogram(
    "vulpulse_http_request_duration_seconds",
    "HTTP request latency by method and route template.",
    ("method", "route"),
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0),
)


def route_template(request: Request) -> str:
    """Return a low-cardinality route label.

    FastAPI's route object contains the router-local template (``/vulns``),
    while the request path contains the include prefix (``/api/v1``). Prefix
    with the top-level scope so API and web routes with the same template do
    not collapse into one series.
    """
    route = request.scope.get("route")
    path = getattr(route, "path", None)
    if not path:
        return "unmatched"
    scope = request.url.path.strip("/").split("/", 1)[0] or "root"
    return f"{scope}:{path}"


def observe_http_request(request: Request, status_code: int, duration: float) -> None:
    route = route_template(request)
    HTTP_REQUESTS.labels(
        method=request.method,
        route=route,
        status=str(status_code),
    ).inc()
    HTTP_LATENCY.labels(method=request.method, route=route).observe(duration)
