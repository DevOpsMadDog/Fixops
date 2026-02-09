#!/usr/bin/env python3
"""
API Surface Report for FixOps

Reports the API surface size by introspecting the FastAPI app factory.
Reconciles endpoint counts between documentation and OpenAPI spec.

Usage:
    # Basic report to stdout:
    python scripts/api_surface_report.py

    # Export JSON:
    python scripts/api_surface_report.py --json api_surface.json

    # Fail if fewer than N endpoints:
    python scripts/api_surface_report.py --min-endpoints 363

    # Filter to specific prefix:
    python scripts/api_surface_report.py --only-prefix /api/v1
"""

import argparse
import json
import os
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


def setup_environment() -> None:
    """Set minimal environment for app creation without uvicorn."""
    os.environ.setdefault("FIXOPS_JWT_SECRET", "report-secret")
    os.environ.setdefault("FIXOPS_API_TOKEN", "report-token")
    os.environ.setdefault("FIXOPS_DEMO_MODE", "true")


def load_app():
    """Load FastAPI app from factory. Exits with code 1 on failure."""
    try:
        # Use same factory as README: uvicorn apps.api.app:create_app --factory
        from apps.api.app import create_app
        return create_app()
    except ImportError as e:
        print(f"FATAL: Failed to import app factory: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"FATAL: Failed to create app: {e}", file=sys.stderr)
        sys.exit(1)


def get_openapi_spec(app) -> dict:
    """Get OpenAPI spec from app. Exits with code 1 on failure."""
    try:
        return app.openapi()
    except Exception as e:
        print(f"FATAL: Failed to generate OpenAPI spec: {e}", file=sys.stderr)
        sys.exit(1)


def extract_routes_from_app(app) -> List[Dict[str, Any]]:
    """Extract route info directly from app.routes (APIRoute objects)."""
    from fastapi.routing import APIRoute
    
    routes = []
    for route in app.routes:
        if isinstance(route, APIRoute):
            for method in route.methods:
                if method.upper() in ("GET", "POST", "PUT", "DELETE", "PATCH"):
                    endpoint_func = route.endpoint
                    routes.append({
                        "method": method.upper(),
                        "path": route.path,
                        "name": route.name,
                        "endpoint_module": getattr(endpoint_func, "__module__", "unknown"),
                        "endpoint_name": getattr(endpoint_func, "__name__", "unknown"),
                    })
    return routes


def extract_openapi_operations(spec: dict) -> List[Dict[str, Any]]:
    """Extract operations from OpenAPI spec with tag info."""
    operations = []
    paths = spec.get("paths", {})
    
    for path, methods in paths.items():
        for method, details in methods.items():
            if method.upper() in ("GET", "POST", "PUT", "DELETE", "PATCH"):
                tags = details.get("tags", [])
                operations.append({
                    "method": method.upper(),
                    "path": path,
                    "tags": tags,
                    "operationId": details.get("operationId", ""),
                    "summary": details.get("summary", ""),
                })
    return operations


def get_prefix_bucket(path: str) -> str:
    """Determine which prefix bucket a path belongs to."""
    if path == "/health":
        return "/health"
    if path == "/metrics":
        return "/metrics"
    if path in ("/docs", "/redoc"):
        return "/docs"
    if path == "/openapi.json":
        return "/openapi.json"
    if path.startswith("/api/v1"):
        return "/api/v1"
    if path.startswith("/api/"):
        return "/api/other"
    return "other"


def detect_aliases(routes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Detect same endpoint function mapped to multiple paths for same method."""
    # Group by (module, function_name, method)
    endpoint_paths: Dict[Tuple[str, str, str], List[str]] = defaultdict(list)
    
    for route in routes:
        key = (route["endpoint_module"], route["endpoint_name"], route["method"])
        endpoint_paths[key].append(route["path"])
    
    aliases = []
    for (module, func_name, method), paths in endpoint_paths.items():
        if len(paths) > 1:
            aliases.append({
                "module": module,
                "function": func_name,
                "method": method,
                "paths": sorted(paths),
            })
    
    return aliases


def generate_report(
    app,
    spec: dict,
    only_prefix: Optional[str] = None
) -> Dict[str, Any]:
    """Generate comprehensive API surface report."""
    # Extract from both sources
    routes = extract_routes_from_app(app)
    openapi_ops = extract_openapi_operations(spec)
    
    # Apply prefix filter if specified
    if only_prefix:
        routes = [r for r in routes if r["path"].startswith(only_prefix)]
        openapi_ops = [op for op in openapi_ops if op["path"].startswith(only_prefix)]
    
    # Unique (method, path) operations
    unique_operations: Set[Tuple[str, str]] = set()
    for route in routes:
        unique_operations.add((route["method"], route["path"]))
    
    # Also add from OpenAPI (may have slight differences)
    openapi_operations: Set[Tuple[str, str]] = set()
    for op in openapi_ops:
        openapi_operations.add((op["method"], op["path"]))
    
    # Unique paths
    unique_paths = set(path for _, path in unique_operations)
    
    # Count by method
    by_method: Dict[str, int] = defaultdict(int)
    for method, _ in unique_operations:
        by_method[method] += 1
    
    # Count by prefix bucket
    by_prefix: Dict[str, int] = defaultdict(int)
    for _, path in unique_operations:
        bucket = get_prefix_bucket(path)
        by_prefix[bucket] += 1
    
    # Count by endpoint module (top 20)
    by_module: Dict[str, int] = defaultdict(int)
    for route in routes:
        by_module[route["endpoint_module"]] += 1
    by_module_top20 = dict(sorted(by_module.items(), key=lambda x: -x[1])[:20])
    
    # Count by OpenAPI tag (top 20)
    by_tag: Dict[str, int] = defaultdict(int)
    for op in openapi_ops:
        for tag in op["tags"]:
            by_tag[tag] += 1
    by_tag_top20 = dict(sorted(by_tag.items(), key=lambda x: -x[1])[:20])
    
    # Detect aliases
    aliases = detect_aliases(routes)
    
    return {
        "total_operations": len(unique_operations),
        "unique_paths": len(unique_paths),
        "openapi_operations": len(openapi_operations),
        "by_method": dict(sorted(by_method.items())),
        "by_prefix": dict(sorted(by_prefix.items())),
        "by_endpoint_module": by_module_top20,
        "by_openapi_tag": by_tag_top20,
        "aliases": aliases,
        "filter_prefix": only_prefix,
    }


def print_report(report: Dict[str, Any]) -> None:
    """Print human-readable report to stdout."""
    print("=" * 60)
    print("API SURFACE REPORT")
    print("=" * 60)
    
    if report.get("filter_prefix"):
        print(f"Filter: {report['filter_prefix']}")
        print("-" * 60)
    
    print(f"\nTotal Operations (method+path): {report['total_operations']}")
    print(f"Unique Paths:                   {report['unique_paths']}")
    print(f"OpenAPI Operations:             {report['openapi_operations']}")
    
    print("\n--- By HTTP Method ---")
    for method, count in report["by_method"].items():
        print(f"  {method:8s}: {count:4d}")
    
    print("\n--- By Prefix Bucket ---")
    for prefix, count in report["by_prefix"].items():
        print(f"  {prefix:20s}: {count:4d}")
    
    print("\n--- By Endpoint Module (Top 20) ---")
    for module, count in report["by_endpoint_module"].items():
        # Truncate long module names
        display_module = module if len(module) <= 45 else "..." + module[-42:]
        print(f"  {display_module:45s}: {count:4d}")
    
    if report["by_openapi_tag"]:
        print("\n--- By OpenAPI Tag (Top 20) ---")
        for tag, count in report["by_openapi_tag"].items():
            print(f"  {tag:30s}: {count:4d}")
    
    if report["aliases"]:
        print(f"\n--- Aliases ({len(report['aliases'])} found) ---")
        for alias in report["aliases"][:10]:  # Show first 10
            paths_str = ", ".join(alias["paths"])
            print(f"  {alias['method']} {alias['function']} -> {paths_str}")
        if len(report["aliases"]) > 10:
            print(f"  ... and {len(report['aliases']) - 10} more")
    else:
        print("\n--- Aliases ---")
        print("  (none detected)")
    
    print("\n" + "=" * 60)


def main():
    parser = argparse.ArgumentParser(
        description="Report API surface size from FastAPI app factory"
    )
    parser.add_argument(
        "--json",
        type=str,
        metavar="PATH",
        help="Write JSON summary to file",
    )
    parser.add_argument(
        "--min-endpoints",
        type=int,
        default=363,
        metavar="N",
        help="Fail if total_operations < N (default: 363)",
    )
    parser.add_argument(
        "--only-prefix",
        type=str,
        metavar="PREFIX",
        help="Only report endpoints matching this prefix (e.g., /api/v1)",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress stdout report (useful with --json)",
    )
    
    args = parser.parse_args()
    
    # Setup environment and load app
    setup_environment()
    app = load_app()
    spec = get_openapi_spec(app)
    
    # Generate report
    report = generate_report(app, spec, only_prefix=args.only_prefix)
    
    # Print to stdout
    if not args.quiet:
        print_report(report)
    
    # Write JSON if requested
    if args.json:
        json_path = Path(args.json)
        json_path.write_text(json.dumps(report, indent=2))
        if not args.quiet:
            print(f"\nJSON report written to: {args.json}")
    
    # Check minimum endpoints
    if report["total_operations"] < args.min_endpoints:
        print(
            f"\n❌ FAIL: Found {report['total_operations']} operations, "
            f"expected at least {args.min_endpoints}",
            file=sys.stderr
        )
        sys.exit(1)
    else:
        if not args.quiet:
            print(
                f"\n✅ PASS: {report['total_operations']} operations "
                f"(>= {args.min_endpoints} minimum)"
            )
    
    sys.exit(0)


if __name__ == "__main__":
    main()
