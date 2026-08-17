#!/usr/bin/env python3
"""Generate the Python client from the committed OpenAPI contract.

The clients in ``sdks/`` were generated once, by hand, from a spec that no longer exists —
12,189 tracked files with no reproducible source, and the Python client committed twice
under two names with identical file sets (ADR-004). Generated code with no owner drifts,
buries real changes under unreviewable diffs, and tells nobody which copy is real.

This makes the client an output again: the contract in ``contracts/`` is the source, this
script is the build step, and the result belongs in a published package rather than in
version control.

It generates from the **core** contract deliberately. Core mode advertises 454 of 6,564
paths and 238 of 4,025 schemas, and the generator emits roughly one module per schema —
which is precisely how the committed client reached 4,465 files.

Usage::

    python scripts/generate_sdk.py                  # build into build/sdk/
    python scripts/generate_sdk.py --check          # CI: generation succeeds and imports
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
CONTRACT = REPO_ROOT / "contracts" / "openapi-core.json"
OUTPUT_ROOT = REPO_ROOT / "build" / "sdk"
PACKAGE_NAME = "aldeci_client"


def _display(path: Path) -> str:
    """Path relative to the repo when it is inside it, absolute otherwise.

    --check generates into a temporary directory, which is not under the repo.
    """
    try:
        return str(path.relative_to(REPO_ROOT))
    except ValueError:
        return str(path)


def _require_generator() -> str:
    """Return the generator executable, or explain how to get it."""
    executable = shutil.which("openapi-python-client")
    if executable:
        return executable
    print(
        "openapi-python-client is not installed.\n"
        "  pipx install openapi-python-client   (or: pip install openapi-python-client)",
        file=sys.stderr,
    )
    raise SystemExit(2)


def generate(output_root: Path) -> Path:
    """Generate the client and return the package directory."""
    if not CONTRACT.exists():
        print(
            f"contract not found: {CONTRACT.relative_to(REPO_ROOT)}\n"
            "  run: python scripts/export_openapi_spec.py",
            file=sys.stderr,
        )
        raise SystemExit(2)

    executable = _require_generator()
    spec = json.loads(CONTRACT.read_text(encoding="utf-8"))
    paths = len(spec.get("paths", {}))
    schemas = len((spec.get("components") or {}).get("schemas") or {})
    print(f"contract: {paths} paths, {schemas} schemas")

    if output_root.exists():
        shutil.rmtree(output_root)
    output_root.mkdir(parents=True)

    # The generator writes a project directory named after the spec title; build in a
    # scratch directory and move the package out, so the output layout is ours to define
    # rather than a function of whatever the title happens to be.
    with tempfile.TemporaryDirectory() as scratch:
        result = subprocess.run(
            [
                executable,
                "generate",
                "--path",
                str(CONTRACT),
                "--output-path",
                str(Path(scratch) / "client"),
                "--overwrite",
                "--meta",
                "none",
            ],
            capture_output=True,
            text=True,
            timeout=1800,
            cwd=scratch,
        )
        if result.returncode != 0:
            sys.stderr.write(result.stdout[-4000:])
            sys.stderr.write(result.stderr[-4000:])
            raise SystemExit(f"generation failed (exit {result.returncode})")

        produced = Path(scratch) / "client"
        # --meta none emits the package contents directly.
        destination = output_root / PACKAGE_NAME
        shutil.copytree(produced, destination)

    files = sum(1 for _ in destination.rglob("*.py"))
    print(f"generated {files} modules -> {_display(destination)}")
    return destination


def verify(package_dir: Path) -> None:
    """Import the freshly generated client in a clean interpreter."""
    probe = (
        "import sys; sys.path.insert(0, %r); "
        "import %s as c; "
        "from %s import Client; "
        "Client(base_url='http://localhost:8000'); "
        "print('import OK')" % (str(package_dir.parent), PACKAGE_NAME, PACKAGE_NAME)
    )
    result = subprocess.run(
        [sys.executable, "-c", probe], capture_output=True, text=True, timeout=300
    )
    if result.returncode != 0:
        sys.stderr.write(result.stderr[-3000:])
        raise SystemExit("generated client does not import")
    print(f"verify: {result.stdout.strip()}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=OUTPUT_ROOT)
    parser.add_argument(
        "--check",
        action="store_true",
        help="generate into a temporary directory and verify it imports",
    )
    args = parser.parse_args()

    if args.check:
        with tempfile.TemporaryDirectory() as scratch:
            package = generate(Path(scratch) / "sdk")
            verify(package)
        print("OK    the contract regenerates a working client")
        return 0

    package = generate(args.output)
    verify(package)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
