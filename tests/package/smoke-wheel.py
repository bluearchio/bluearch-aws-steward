#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="Install and smoke-test a built Steward wheel.")
    parser.add_argument("wheel", type=Path)
    parser.add_argument("--expected-version", required=True)
    args = parser.parse_args()
    wheel = args.wheel.resolve()
    if not wheel.is_file():
        parser.error(f"wheel does not exist: {wheel}")

    temp_root = os.environ.get("STEWARD_TEST_TMPDIR", "/tmp")
    with tempfile.TemporaryDirectory(prefix="bluearch-steward-wheel-", dir=temp_root) as temp_dir:
        installed = Path(temp_dir) / "site"

        subprocess.run(
            [
                sys.executable,
                "-m",
                "pip",
                "install",
                "--disable-pip-version-check",
                "--no-cache-dir",
                "--no-deps",
                "--target",
                str(installed),
                str(wheel),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        environment = {**os.environ, "PYTHONPATH": str(installed)}
        version = subprocess.run(
            [sys.executable, "-m", "bluearch_aws_steward", "--version"],
            check=True,
            capture_output=True,
            text=True,
            cwd=temp_dir,
            env=environment,
        ).stdout.strip()
        if version != f"bluearch-steward {args.expected_version}":
            raise RuntimeError(f"unexpected wheel version: {version}")
        subprocess.run(
            [sys.executable, "-m", "bluearch_aws_steward", "mcp", "smoke"],
            check=True,
            stdout=subprocess.DEVNULL,
            cwd=temp_dir,
            env=environment,
        )
        entry_points = (
            installed
            / f"bluearch_aws_steward-{args.expected_version}.dist-info"
            / "entry_points.txt"
        ).read_text()
        if "bluearch-steward =" not in entry_points or "bluearch-steward-mcp =" not in entry_points:
            raise RuntimeError("wheel is missing Steward console entry points")

    print(f"Wheel smoke test passed: {wheel.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
