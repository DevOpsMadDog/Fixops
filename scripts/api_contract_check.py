#!/usr/bin/env python3
"""
API Contract Checker for ALdeci UI

Parses suite-ui/aldeci/SCREEN_API_MAPPING.md and verifies all endpoints exist in
the FastAPI OpenAPI spec. Exits non-zero if any mapped endpoint is missing.

Usage:
    # Against running server:
    python scripts/api_contract_check.py --openapi-url http://localhost:8000/openapi.json

    # Against local app (introspection):
    python scripts/api_contract_check.py --introspect

    # Just show endpoints from mapping:
    python scripts/api_contract_check.py --parse-only
"""

import argparse
import json
import re
import sys
from pathlib import Path
from typing import NamedTuple


class EndpointSpec(NamedTuple):
    """An API endpoint specification from the mapping document."""

    method: str
    path: str
    screen: str
    purpose: str


def parse_screen_api_mapping(mapping_path: Path) -> list[EndpointSpec]:
    """Parse SCREEN_API_MAPPING.md and extract all endpoints."""
    endpoints: list[EndpointSpec] = []
    content = mapping_path.read_text()

    current_screen = "Unknown"

    # Match screen headers like "### Dashboard (`/dashboard`)"
    screen_pattern = re.compile(r"^###\s+([^(]+)\s*\(`([^`]+)`\)", re.MULTILINE)

    # Match table rows with endpoint info
    # Format: | `api.xxx.method()` | `GET /api/v1/path` | Purpose |
    # or:     | `api.xxx.method()` | `GET /path` | Purpose |
    endpoint_pattern = re.compile(
        r"\|\s*`[^`]+`\s*\|\s*`(GET|POST|PUT|DELETE|PATCH)\s+(/[^`]+)`\s*\|\s*([^|]+)\|"
    )

    lines = content.split("\n")
    for line in lines:
        screen_match = screen_pattern.match(line)
        if screen_match:
            current_screen = screen_match.group(2).strip()
            continue

        endpoint_match = endpoint_pattern.search(line)
        if endpoint_match:
            method = endpoint_match.group(1).upper()
            path = endpoint_match.group(2).strip()
            purpose = endpoint_match.group(3).strip()

            endpoints.append(
                EndpointSpec(
                    method=method, path=path, screen=current_screen, purpose=purpose
                )
            )

    return endpoints


def normalize_path(path: str) -> str:
    """Normalize path for comparison, stripping query params."""
    # Remove query string if present
    if "?" in path:
        path = path.split("?")[0]
    return path.strip()


def get_openapi_endpoints_from_url(url: str) -> set[tuple[str, str]]:
    """Fetch OpenAPI spec from URL and extract endpoints."""
    import urllib.error
    import urllib.request

    try:
        with urllib.request.urlopen(url, timeout=10) as response:
            spec = json.loads(response.read().decode())
    except urllib.error.URLError as e:
        print(f"ERROR: Failed to fetch OpenAPI spec from {url}: {e}", file=sys.stderr)
        sys.exit(2)

    return extract_openapi_endpoints(spec)


def get_openapi_endpoints_from_introspect() -> set[tuple[str, str]]:
    """Get OpenAPI spec by importing the app directly."""
    import os
    import sys

    # Add project root and suite-api to path (apps/ lives under suite-api/)
    project_root = Path(__file__).parent.parent
    sys.path.insert(0, str(project_root))
    sys.path.insert(0, str(project_root / "suite-api"))

    # Set minimal environment for app creation (introspection only - not live calls)
    import secrets as _secrets

    os.environ.setdefault("FIXOPS_JWT_SECRET", _secrets.token_hex(32))
    os.environ.setdefault("FIXOPS_API_TOKEN", _secrets.token_urlsafe(32))
    os.environ.setdefault("FIXOPS_DEMO_MODE", "false")

    from apps.api.app import create_app

    app = create_app()
    spec = app.openapi()

    return extract_openapi_endpoints(spec)


def extract_openapi_endpoints(spec: dict) -> set[tuple[str, str]]:
    """Extract (method, path) tuples from OpenAPI spec."""
    endpoints: set[tuple[str, str]] = set()

    paths = spec.get("paths", {})
    for path, methods in paths.items():
        for method in methods:
            if method.upper() in ("GET", "POST", "PUT", "DELETE", "PATCH"):
                endpoints.add((method.upper(), path))

    return endpoints


def path_matches(spec_path: str, openapi_path: str) -> bool:
    """Check if a spec path matches an OpenAPI path, handling path parameters."""
    # Convert path parameters to regex pattern
    # {param} in both -> match
    spec_parts = spec_path.split("/")
    openapi_parts = openapi_path.split("/")

    if len(spec_parts) != len(openapi_parts):
        return False

    for spec_part, openapi_part in zip(spec_parts, openapi_parts):
        # Both are parameters (e.g., {id} and {findingId})
        if spec_part.startswith("{") and openapi_part.startswith("{"):
            continue
        # Exact match
        if spec_part == openapi_part:
            continue
        # No match
        return False

    return True


def find_matching_endpoint(
    method: str, path: str, openapi_endpoints: set[tuple[str, str]]
) -> bool:
    """Check if an endpoint exists in OpenAPI, handling path parameter variations."""
    # Normalize path (strip query params)
    normalized_path = normalize_path(path)

    # First try exact match
    if (method, normalized_path) in openapi_endpoints:
        return True

    # Try matching with path parameter variations
    for openapi_method, openapi_path in openapi_endpoints:
        if method == openapi_method and path_matches(normalized_path, openapi_path):
            return True

    return False


def main():
    parser = argparse.ArgumentParser(
        description="Check ALdeci UI API contract against FastAPI OpenAPI spec"
    )
    parser.add_argument(
        "--openapi-url",
        default="http://localhost:8000/openapi.json",
        help="URL to fetch OpenAPI spec from (default: http://localhost:8000/openapi.json)",
    )
    parser.add_argument(
        "--introspect",
        action="store_true",
        help="Import app directly instead of fetching from URL",
    )
    parser.add_argument(
        "--parse-only",
        action="store_true",
        help="Only parse and display endpoints from mapping, don't verify",
    )
    parser.add_argument(
        "--mapping",
        default=None,
        help="Path to SCREEN_API_MAPPING.md (default: auto-detect)",
    )
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Show all endpoints, not just missing ones",
    )

    args = parser.parse_args()

    # Find mapping file
    if args.mapping:
        mapping_path = Path(args.mapping)
    else:
        # Try to find it relative to script
        script_dir = Path(__file__).parent
        candidates = [
            script_dir.parent / "suite-ui" / "aldeci" / "SCREEN_API_MAPPING.md",
            Path("suite-ui/aldeci/SCREEN_API_MAPPING.md"),
            Path.cwd() / "suite-ui" / "aldeci" / "SCREEN_API_MAPPING.md",
            # Legacy paths for backward compatibility
            script_dir.parent / "ui" / "aldeci" / "SCREEN_API_MAPPING.md",
            Path("ui/aldeci/SCREEN_API_MAPPING.md"),
        ]
        mapping_path = None
        for candidate in candidates:
            if candidate.exists():
                mapping_path = candidate
                break

        if not mapping_path:
            print("ERROR: Could not find SCREEN_API_MAPPING.md", file=sys.stderr)
            print("Try: --mapping /path/to/SCREEN_API_MAPPING.md", file=sys.stderr)
            sys.exit(2)

    if not mapping_path.exists():
        print(f"ERROR: Mapping file not found: {mapping_path}", file=sys.stderr)
        sys.exit(2)

    # Parse the mapping
    endpoints = parse_screen_api_mapping(mapping_path)

    if not endpoints:
        print("ERROR: No endpoints found in mapping file", file=sys.stderr)
        sys.exit(2)

    print(f"Parsed {len(endpoints)} endpoints from {mapping_path.name}")

    if args.parse_only:
        print("\n--- Endpoints from SCREEN_API_MAPPING.md ---\n")
        by_screen: dict[str, list[EndpointSpec]] = {}
        for ep in endpoints:
            by_screen.setdefault(ep.screen, []).append(ep)

        for screen, eps in sorted(by_screen.items()):
            print(f"\n{screen}:")
            for ep in eps:
                print(f"  {ep.method:6} {ep.path}")
        return

    # Get OpenAPI endpoints
    if args.introspect:
        print("Introspecting app for OpenAPI spec...")
        openapi_endpoints = get_openapi_endpoints_from_introspect()
    else:
        print(f"Fetching OpenAPI spec from {args.openapi_url}...")
        openapi_endpoints = get_openapi_endpoints_from_url(args.openapi_url)

    print(f"Found {len(openapi_endpoints)} endpoints in OpenAPI spec")

    # Check each mapped endpoint
    missing: list[EndpointSpec] = []
    found: list[EndpointSpec] = []

    for ep in endpoints:
        if find_matching_endpoint(ep.method, ep.path, openapi_endpoints):
            found.append(ep)
        else:
            missing.append(ep)

    # Output results
    if args.json:
        result = {
            "total_mapped": len(endpoints),
            "total_openapi": len(openapi_endpoints),
            "found": len(found),
            "missing": len(missing),
            "missing_endpoints": [
                {
                    "method": ep.method,
                    "path": ep.path,
                    "screen": ep.screen,
                    "purpose": ep.purpose,
                }
                for ep in missing
            ],
        }
        print(json.dumps(result, indent=2))
    else:
        if args.verbose:
            print("\n✅ Found endpoints:")
            for ep in found:
                print(f"  {ep.method:6} {ep.path}")

        if missing:
            print(f"\n❌ Missing endpoints ({len(missing)}):\n")
            by_screen: dict[str, list[EndpointSpec]] = {}
            for ep in missing:
                by_screen.setdefault(ep.screen, []).append(ep)

            for screen, eps in sorted(by_screen.items()):
                print(f"  {screen}:")
                for ep in eps:
                    print(f"    {ep.method:6} {ep.path} - {ep.purpose}")
            print()

        print("\n--- Summary ---")
        print(f"Mapped endpoints:  {len(endpoints)}")
        print(f"Found in OpenAPI:  {len(found)}")
        print(f"Missing:           {len(missing)}")
        print(f"Coverage:          {100 * len(found) / len(endpoints):.1f}%")

    if missing:
        print("\n❌ CONTRACT CHECK FAILED: Missing endpoints detected")
        sys.exit(1)
    else:
        print("\n✅ CONTRACT CHECK PASSED: All mapped endpoints exist")
        sys.exit(0)


if __name__ == "__main__":
    main()
