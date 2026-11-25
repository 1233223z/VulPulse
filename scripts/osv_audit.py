"""Audit installed Python packages and vendored frontend assets with OSV.

Run after installing the project environment:
    python scripts/osv_audit.py

Exits non-zero when a known vulnerability is found.
"""

from __future__ import annotations

import sys
from importlib.metadata import distributions

import httpx

OSV_QUERY_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_QUERY = "https://api.osv.dev/v1/query"

# Keep in sync with vulpulse/web/static/vendor/README.md.
NPM_PACKAGES = (
    ("bootstrap", "5.3.3"),
    ("chart.js", "4.4.3"),
)


def main() -> int:
    packages = sorted(
        {
            (distribution.metadata["Name"], distribution.version)
            for distribution in distributions()
            if distribution.metadata["Name"] and distribution.version
        }
    )
    queries = [
        {"package": {"name": name, "ecosystem": "PyPI"}, "version": version}
        for name, version in packages
    ]

    with httpx.Client(timeout=30) as client:
        response = client.post(OSV_QUERY_BATCH, json={"queries": queries})
        response.raise_for_status()
        results = response.json()["results"]

        findings: list[str] = []
        for (name, version), result in zip(packages, results, strict=True):
            for vulnerability in result.get("vulns", []):
                aliases = ",".join(vulnerability.get("aliases", []))
                findings.append(
                    f"PyPI {name} {version}: {vulnerability['id']} "
                    f"{aliases} {vulnerability.get('summary', '')}".strip()
                )

        for name, version in NPM_PACKAGES:
            response = client.post(
                OSV_QUERY,
                json={
                    "package": {"name": name, "ecosystem": "npm"},
                    "version": version,
                },
            )
            response.raise_for_status()
            for vulnerability in response.json().get("vulns", []):
                findings.append(
                    f"npm {name} {version}: {vulnerability['id']} "
                    f"{vulnerability.get('summary', '')}".strip()
                )

    if findings:
        print("Known vulnerabilities found:")
        for finding in findings:
            print(f"  - {finding}")
        return 1

    print(
        "No known vulnerabilities: "
        f"{len(packages)} Python packages, {len(NPM_PACKAGES)} npm assets."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
