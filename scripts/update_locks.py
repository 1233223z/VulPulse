#!/usr/bin/env python3
"""Regenerate hash-pinned requirements files from pyproject.toml."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
UV_INSTALL_HINT = "python -m pip install 'uv>=0.13,<0.14'"


def find_uv() -> str | None:
    """Prefer the uv installed next to the running interpreter."""
    name = "uv.exe" if os.name == "nt" else "uv"
    local = Path(sys.executable).with_name(name)
    if local.exists():
        return str(local)
    return shutil.which("uv")


def main() -> int:
    uv = find_uv()
    if not uv:
        print(f"uv is required to update locks. Install it with: {UV_INSTALL_HINT}")
        return 1

    base = [
        uv,
        "pip",
        "compile",
        "pyproject.toml",
        "--universal",
        "--python-version",
        "3.10",
        "--generate-hashes",
        "--unsafe-package",
        "vulpulse",
    ]
    subprocess.run([*base, "-o", "requirements.txt"], cwd=ROOT, check=True)
    subprocess.run(
        [*base, "--extra", "dev", "-o", "requirements-dev.txt"],
        cwd=ROOT,
        check=True,
    )
    print("Regenerated requirements.txt and requirements-dev.txt")
    return 0


if __name__ == "__main__":
    sys.exit(main())
