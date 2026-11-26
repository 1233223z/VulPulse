#!/usr/bin/env python3
"""Small read-only benchmark for a running VulPulse instance."""

from __future__ import annotations

import argparse
import statistics
import time

import httpx

Endpoint = tuple[str, str]


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round((len(ordered) - 1) * fraction)))
    return ordered[index]


def measure(
    client: httpx.Client,
    path: str,
    *,
    requests: int,
    warmup: int,
) -> tuple[list[float], int]:
    for _ in range(warmup):
        client.get(path)
    samples: list[float] = []
    status = 0
    for _ in range(requests):
        started = time.perf_counter()
        response = client.get(path)
        samples.append((time.perf_counter() - started) * 1000)
        status = response.status_code
    return samples, status


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--cve", default="CVE-2021-44228")
    parser.add_argument("--requests", type=int, default=20)
    parser.add_argument("--warmup", type=int, default=2)
    parser.add_argument("--timeout", type=float, default=30.0)
    args = parser.parse_args()
    if args.requests < 1 or args.warmup < 0:
        parser.error("--requests must be positive and --warmup must be non-negative")

    endpoints: list[Endpoint] = [
        ("health", "/healthz"),
        ("vuln list", "/api/v1/vulns?size=20"),
        ("vuln detail", f"/api/v1/vulns/{args.cve}"),
        ("graph", f"/api/v1/vulns/{args.cve}/graph"),
        ("stats", "/api/v1/stats/overview?days=30"),
    ]

    failed = False
    print(f"base_url={args.base_url} requests={args.requests} warmup={args.warmup}")
    print(f"{'endpoint':<14} {'n':>4} {'mean':>8} {'p50':>8} {'p95':>8} {'max':>8} {'status':>7}")
    with httpx.Client(base_url=args.base_url, timeout=args.timeout, trust_env=False) as client:
        for label, path in endpoints:
            samples, status = measure(
                client,
                path,
                requests=args.requests,
                warmup=args.warmup,
            )
            if status >= 400:
                failed = True
            print(
                f"{label:<14} {len(samples):>4} "
                f"{statistics.fmean(samples):>8.1f} "
                f"{percentile(samples, 0.50):>8.1f} "
                f"{percentile(samples, 0.95):>8.1f} "
                f"{max(samples):>8.1f} {status:>7}"
            )
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
