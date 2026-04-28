"""OpenAPI Documentation Generator for ALDECI.

Scans all router files, extracts endpoint metadata, generates
enriched OpenAPI 3.1 spec with:
- Security scheme documentation (API key auth)
- Request/response examples for all endpoints
- Endpoint categorization by security domain
- Rate limit documentation
- Persona-endpoint mapping
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_ROUTERS_DIR = Path(__file__).resolve().parents[2] / "suite-api" / "apps" / "api"

# HTTP methods recognised in @router.<method> decorators
_HTTP_METHODS = {"get", "post", "put", "patch", "delete", "options", "head"}

# Tag → security domain mapping (based on ALDECI domain taxonomy)
_TAG_TO_DOMAIN: Dict[str, str] = {
    # Vulnerability Management
    "pipeline": "vulnerability_management",
    "findings": "vulnerability_management",
    "vuln_lifecycle": "vulnerability_management",
    "risk_register": "vulnerability_management",
    "trivy": "vulnerability_management",
    "semgrep": "vulnerability_management",
    "snyk": "vulnerability_management",
    # Threat Intelligence
    "threatintel": "threat_intelligence",
    "threat_intel": "threat_intelligence",
    "feeds": "threat_intelligence",
    "threat_hunting": "threat_intelligence",
    # Cloud Security
    "cspm": "cloud_security",
    "aws_security_hub": "cloud_security",
    "azure_defender": "cloud_security",
    "cloud_discovery": "cloud_security",
    # Identity & Access
    "auth": "identity_access",
    "users": "identity_access",
    "teams": "identity_access",
    "rbac": "identity_access",
    "access_matrix": "identity_access",
    "zero_trust": "identity_access",
    # Compliance
    "compliance": "compliance",
    "evidence": "compliance",
    "audit": "compliance",
    "policies": "compliance",
    "sla": "compliance",
    # Incident Response
    "ir": "incident_response",
    "soar": "incident_response",
    "playbook": "incident_response",
    # Developer Security
    "Developer Portal": "developer_security",
    "developer": "developer_security",
    "sbom": "developer_security",
    "secret_scanner": "developer_security",
    # Platform
    "admin": "platform",
    "system": "platform",
    "analytics": "platform",
    "trustgraph": "platform",
    "pipeline_api": "platform",
}


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class EndpointDoc:
    """Metadata for a single API endpoint."""

    path: str
    method: str
    tags: List[str] = field(default_factory=list)
    summary: str = ""
    description: str = ""
    request_example: Optional[Dict[str, Any]] = None
    response_example: Optional[Dict[str, Any]] = None
    auth_required: bool = True
    rate_limited: bool = True
    router_file: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "method": self.method.upper(),
            "tags": self.tags,
            "summary": self.summary,
            "description": self.description,
            "auth_required": self.auth_required,
            "rate_limited": self.rate_limited,
            "router_file": self.router_file,
            "request_example": self.request_example,
            "response_example": self.response_example,
        }


# ---------------------------------------------------------------------------
# Generator
# ---------------------------------------------------------------------------


class APIDocGenerator:
    """Generates enriched OpenAPI 3.1 documentation for the ALDECI platform.

    Works in two modes:
    1. **Live mode** — calls ``app.openapi()`` on the running FastAPI application
       to get the full machine-generated spec, then enriches it.
    2. **Static mode** — parses router source files as text to extract endpoint
       metadata without importing the full application.  This is the default
       and works in test / CI environments with no running server.
    """

    #: ALDECI platform version
    API_VERSION = "2.5.0"
    #: Platform title used in the OpenAPI info block
    API_TITLE = "ALDECI Security Platform API"
    #: Short platform description
    API_DESCRIPTION = (
        "Unified ASPM + CTEM + CSPM platform. "
        "Self-hosted, AI-native security intelligence. "
        "Replaces enterprise tools with a $35-60/month self-hosted stack."
    )

    def __init__(self, routers_dir: Optional[Path] = None) -> None:
        self._routers_dir = Path(routers_dir) if routers_dir else _ROUTERS_DIR
        self._cached_endpoints: Optional[List[EndpointDoc]] = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan_routers(self) -> List[EndpointDoc]:
        """Walk all ``*_router.py`` / ``*_routes.py`` files and extract endpoint docs.

        Returns a cached list; call with ``force=True`` (not exposed) or create a
        new instance to invalidate the cache.
        """
        if self._cached_endpoints is not None:
            return self._cached_endpoints

        endpoints: List[EndpointDoc] = []
        router_files = sorted(self._routers_dir.glob("*.py"))

        for rfile in router_files:
            if rfile.name.startswith("__"):
                continue
            # Only process router/routes files
            if not (rfile.name.endswith("_router.py") or rfile.name.endswith("_routes.py")):
                continue
            try:
                endpoints.extend(self._parse_router_file(rfile))
            except Exception as exc:  # noqa: BLE001
                logger.debug("Could not parse %s: %s", rfile.name, exc)

        self._cached_endpoints = endpoints
        return endpoints

    def generate_openapi_spec(self, include_examples: bool = True) -> Dict[str, Any]:
        """Generate an OpenAPI 3.1 specification dict.

        Attempts to load the live FastAPI app first; falls back to the static
        parser if the app cannot be imported.

        Args:
            include_examples: Whether to embed request/response examples.

        Returns:
            OpenAPI 3.1 compliant dict.
        """
        # Try live app first
        live_spec = self._try_live_spec()
        if live_spec:
            return self._enrich_spec(live_spec, include_examples=include_examples)

        # Fall back to static parse
        return self._build_static_spec(include_examples=include_examples)

    def generate_postman_collection(self) -> Dict[str, Any]:
        """Generate a Postman Collection v2.1 dict from scanned endpoints."""
        endpoints = self.scan_routers()

        # Group by tag/domain for folders
        folders: Dict[str, List[EndpointDoc]] = {}
        for ep in endpoints:
            tag = ep.tags[0] if ep.tags else "General"
            folders.setdefault(tag, []).append(ep)

        items = []
        for folder_name, eps in sorted(folders.items()):
            folder_items = []
            for ep in eps:
                request_body = None
                if ep.method.lower() in ("post", "put", "patch") and ep.request_example:
                    request_body = {
                        "mode": "raw",
                        "raw": json.dumps(ep.request_example, indent=2),
                        "options": {"raw": {"language": "json"}},
                    }

                item: Dict[str, Any] = {
                    "name": ep.summary or f"{ep.method.upper()} {ep.path}",
                    "request": {
                        "method": ep.method.upper(),
                        "header": [
                            {
                                "key": "X-API-Key",
                                "value": "{{ALDECI_API_KEY}}",
                                "description": "ALDECI API key",
                            },
                            {
                                "key": "Content-Type",
                                "value": "application/json",
                            },
                        ],
                        "url": {
                            "raw": "{{BASE_URL}}" + ep.path,
                            "host": ["{{BASE_URL}}"],
                            "path": [p for p in ep.path.split("/") if p],
                        },
                        "description": ep.description or ep.summary,
                    },
                }
                if request_body:
                    item["request"]["body"] = request_body
                folder_items.append(item)

            items.append(
                {
                    "name": folder_name,
                    "item": folder_items,
                }
            )

        return {
            "info": {
                "name": self.API_TITLE,
                "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
                "description": self.API_DESCRIPTION,
                "version": self.API_VERSION,
            },
            "variable": [
                {
                    "key": "BASE_URL",
                    "value": "http://localhost:8000",
                    "description": "ALDECI API base URL",
                },
                {
                    "key": "ALDECI_API_KEY",
                    "value": "",
                    "description": "Your ALDECI API key",
                },
            ],
            "item": items,
        }

    def count_endpoints_by_tag(self) -> Dict[str, int]:
        """Return a dict mapping each tag to the number of endpoints with that tag."""
        endpoints = self.scan_routers()
        counts: Dict[str, int] = {}
        for ep in endpoints:
            for tag in ep.tags or ["untagged"]:
                counts[tag] = counts.get(tag, 0) + 1
        return dict(sorted(counts.items()))

    def get_endpoints_by_security_domain(self) -> Dict[str, List[EndpointDoc]]:
        """Return endpoints grouped by security domain.

        The domain is derived from the endpoint's first tag via ``_TAG_TO_DOMAIN``.
        Unrecognised tags land in the ``other`` bucket.
        """
        endpoints = self.scan_routers()
        domains: Dict[str, List[EndpointDoc]] = {}
        for ep in endpoints:
            domain = "other"
            for tag in ep.tags:
                domain = _TAG_TO_DOMAIN.get(tag.lower(), _TAG_TO_DOMAIN.get(tag, "other"))
                if domain != "other":
                    break
            domains.setdefault(domain, []).append(ep)
        return domains

    def export_markdown_summary(self) -> str:
        """Return a human-readable Markdown API reference."""
        endpoints = self.scan_routers()
        domain_map = self.get_endpoints_by_security_domain()
        tag_counts = self.count_endpoints_by_tag()

        lines: List[str] = [
            f"# {self.API_TITLE}",
            "",
            f"> Version {self.API_VERSION} — {self.API_DESCRIPTION}",
            "",
            "## Overview",
            "",
            f"- **Total endpoints**: {len(endpoints)}",
            f"- **Security domains**: {len(domain_map)}",
            f"- **Tags**: {len(tag_counts)}",
            "",
            "## Authentication",
            "",
            "All endpoints (unless marked public) require one of:",
            "",
            "| Method | Header / Param | Example |",
            "|--------|---------------|---------|",
            "| API Key | `X-API-Key: <token>` | `X-API-Key: sk-aldeci-...` |",
            "| Bearer JWT | `Authorization: Bearer <jwt>` | `Authorization: Bearer eyJ...` |",
            "| Query param | `?api_key=<token>` | `GET /api/v1/findings?api_key=sk-...` |",
            "",
            "## Rate Limiting",
            "",
            "Default limits: **100 req/min** per API key. "
            "Burst up to **200 req/min** for premium tiers. "
            "Returns `429 Too Many Requests` with `Retry-After` header when exceeded.",
            "",
            "## Endpoints by Security Domain",
            "",
        ]

        for domain, eps in sorted(domain_map.items()):
            lines.append(f"### {domain.replace('_', ' ').title()}")
            lines.append("")
            lines.append("| Method | Path | Summary |")
            lines.append("|--------|------|---------|")
            for ep in sorted(eps, key=lambda e: e.path):
                summary = (ep.summary or "").replace("|", "\\|")
                lines.append(f"| `{ep.method.upper()}` | `{ep.path}` | {summary} |")
            lines.append("")

        lines.append("## Endpoint Counts by Tag")
        lines.append("")
        lines.append("| Tag | Count |")
        lines.append("|-----|-------|")
        for tag, count in sorted(tag_counts.items()):
            lines.append(f"| {tag} | {count} |")
        lines.append("")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _try_live_spec(self) -> Optional[Dict[str, Any]]:
        """Attempt to import the FastAPI app and call app.openapi().

        Only attempted when routers_dir matches the real suite-api location to
        avoid expensive import attempts during unit tests that use temp dirs.
        """
        # Skip live import when using a non-default (e.g. test) routers dir
        if self._routers_dir != _ROUTERS_DIR:
            return None
        try:
            import sys

            # Ensure suite paths are on sys.path
            project_root = self._routers_dir.parents[2]
            for suite_dir in project_root.glob("suite-*"):
                if str(suite_dir) not in sys.path:
                    sys.path.insert(0, str(suite_dir))

            from apps.api.app import create_app  # type: ignore[import]

            app = create_app()
            return app.openapi()
        except Exception as exc:  # noqa: BLE001
            logger.debug("Live app import failed (%s), using static parser", exc)
            return None

    def _build_static_spec(self, include_examples: bool = True) -> Dict[str, Any]:
        """Build a minimal but valid OpenAPI 3.1 spec from static file parsing."""
        endpoints = self.scan_routers()

        paths: Dict[str, Any] = {}
        for ep in endpoints:
            path_item = paths.setdefault(ep.path, {})
            op: Dict[str, Any] = {
                "summary": ep.summary,
                "description": ep.description,
                "tags": ep.tags,
                "operationId": self._make_operation_id(ep),
                "responses": {
                    "200": {
                        "description": "Successful response",
                    },
                    "401": {"description": "Unauthorized — missing or invalid API key"},
                    "403": {"description": "Forbidden — insufficient permissions"},
                    "422": {"description": "Validation error"},
                },
                "security": [{"ApiKeyAuth": []}, {"BearerAuth": []}],
            }
            if include_examples and ep.response_example:
                op["responses"]["200"]["content"] = {
                    "application/json": {
                        "example": ep.response_example,
                    }
                }
            if include_examples and ep.request_example and ep.method.lower() in ("post", "put", "patch"):
                op["requestBody"] = {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {"type": "object"},
                            "example": ep.request_example,
                        }
                    },
                }
            path_item[ep.method.lower()] = op

        return self._wrap_spec(paths)

    def _enrich_spec(self, spec: Dict[str, Any], include_examples: bool = True) -> Dict[str, Any]:
        """Add ALDECI-specific metadata to a live FastAPI-generated spec."""
        spec.setdefault("info", {})
        spec["info"]["x-aldeci-version"] = self.API_VERSION
        spec["info"]["x-rate-limit"] = "100 req/min per API key"
        spec["info"]["x-personas"] = [
            "ciso", "security-analyst", "developer", "compliance-officer",
            "soc-tier1", "soc-tier2", "executive", "pentest-engineer",
        ]

        # Ensure security schemes present
        spec.setdefault("components", {}).setdefault("securitySchemes", {})
        spec["components"]["securitySchemes"].update(self._security_schemes())

        spec["x-tagGroups"] = self._build_tag_groups(spec.get("tags", []))
        return spec

    def _wrap_spec(self, paths: Dict[str, Any]) -> Dict[str, Any]:
        """Wrap paths dict in a full OpenAPI 3.1 envelope."""
        all_tags = sorted({tag for ep in (self._cached_endpoints or []) for tag in ep.tags})
        return {
            "openapi": "3.1.0",
            "info": {
                "title": self.API_TITLE,
                "description": self.API_DESCRIPTION,
                "version": self.API_VERSION,
                "contact": {
                    "name": "ALDECI Platform Team",
                    "url": "https://github.com/DevOpsMadDog/Fixops",
                },
                "license": {
                    "name": "MIT",
                },
                "x-rate-limit": "100 req/min per API key",
                "x-personas": [
                    "ciso", "security-analyst", "developer", "compliance-officer",
                    "soc-tier1", "soc-tier2", "executive", "pentest-engineer",
                ],
            },
            "servers": [
                {"url": "http://localhost:8000", "description": "Local development"},
                {"url": "https://api.aldeci.example.com", "description": "Production"},
            ],
            "security": [{"ApiKeyAuth": []}, {"BearerAuth": []}],
            "tags": [{"name": t} for t in all_tags],
            "paths": paths,
            "components": {
                "securitySchemes": self._security_schemes(),
            },
            "x-tagGroups": self._build_tag_groups([{"name": t} for t in all_tags]),
        }

    @staticmethod
    def _security_schemes() -> Dict[str, Any]:
        return {
            "ApiKeyAuth": {
                "type": "apiKey",
                "in": "header",
                "name": "X-API-Key",
                "description": "ALDECI API key. Set via FIXOPS_API_TOKEN env var.",
            },
            "BearerAuth": {
                "type": "http",
                "scheme": "bearer",
                "bearerFormat": "JWT",
                "description": "JWT token obtained from POST /api/v1/auth/token.",
            },
            "QueryApiKey": {
                "type": "apiKey",
                "in": "query",
                "name": "api_key",
                "description": "API key as query param (for browser-opened URLs).",
            },
        }

    @staticmethod
    def _build_tag_groups(tags: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Organise tags into display groups for Redoc / Stoplight."""
        domain_tags: Dict[str, List[str]] = {}
        for tag_obj in tags:
            name = tag_obj.get("name", "")
            domain = _TAG_TO_DOMAIN.get(name.lower(), _TAG_TO_DOMAIN.get(name, "other"))
            domain_tags.setdefault(domain, []).append(name)

        return [
            {"name": domain.replace("_", " ").title(), "tags": sorted(tag_list)}
            for domain, tag_list in sorted(domain_tags.items())
        ]

    @staticmethod
    def _make_operation_id(ep: EndpointDoc) -> str:
        """Derive a camelCase operationId from method + path."""
        parts = [ep.method.lower()]
        for segment in ep.path.split("/"):
            if not segment:
                continue
            # Strip path params {id} → ById
            if segment.startswith("{") and segment.endswith("}"):
                parts.append("by_" + segment[1:-1])
            else:
                parts.append(segment)
        return "_".join(parts).replace("-", "_")

    def _parse_router_file(self, rfile: Path) -> List[EndpointDoc]:
        """Parse a router source file with regex to extract endpoint metadata."""
        source = rfile.read_text(encoding="utf-8", errors="replace")
        endpoints: List[EndpointDoc] = []

        # Extract prefix from APIRouter(prefix=...)
        prefix_match = re.search(r'APIRouter\([^)]*prefix\s*=\s*["\']([^"\']+)["\']', source)
        prefix = prefix_match.group(1) if prefix_match else ""

        # Extract tags from APIRouter(tags=[...])
        file_tags: List[str] = []
        tags_match = re.search(r'APIRouter\([^)]*tags\s*=\s*\[([^\]]+)\]', source)
        if tags_match:
            file_tags = re.findall(r'["\']([^"\']+)["\']', tags_match.group(1))

        # Find all @router.<method>(...) decorators
        # Pattern: @router.METHOD("PATH", ...) optional summary/description args
        decorator_re = re.compile(
            r'@router\.\s*(?P<method>' + '|'.join(_HTTP_METHODS) + r')\s*\(\s*'
            r'["\'](?P<path>[^"\']+)["\']'
            r'(?P<rest>[^)]*(?:\([^)]*\)[^)]*)*)\)',
            re.IGNORECASE | re.DOTALL,
        )

        for m in decorator_re.finditer(source):
            method = m.group("method").lower()
            path_suffix = m.group("path")
            rest = m.group("rest")

            # Build full path
            full_path = (prefix + path_suffix).replace("//", "/")

            # Extract summary
            summary_match = re.search(r'summary\s*=\s*["\']([^"\']+)["\']', rest)
            summary = summary_match.group(1) if summary_match else ""

            # Extract description
            desc_match = re.search(r'description\s*=\s*["\']([^"\']+)["\']', rest)
            description = desc_match.group(1) if desc_match else ""

            # Extract tags (endpoint-level override)
            ep_tags_match = re.search(r'tags\s*=\s*\[([^\]]+)\]', rest)
            ep_tags = re.findall(r'["\']([^"\']+)["\']', ep_tags_match.group(1)) if ep_tags_match else file_tags[:]

            endpoints.append(
                EndpointDoc(
                    path=full_path,
                    method=method,
                    tags=ep_tags or file_tags[:],
                    summary=summary,
                    description=description,
                    auth_required=True,
                    rate_limited=True,
                    router_file=rfile.name,
                )
            )

        return endpoints
