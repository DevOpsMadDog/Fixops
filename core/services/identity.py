"""Identity Resolution - Map findings to org/app/component IDs."""

import hashlib
import re
from pathlib import Path
from typing import Any, Dict, Optional

try:
    import yaml  # type: ignore[import-untyped]

    HAS_YAML = True
except ImportError:
    HAS_YAML = False


class IdentityResolver:
    """Resolve application and component IDs from findings."""

    def __init__(self, mappings_path: Optional[Path] = None):
        """Initialize with optional mappings file."""
        self.mappings: Dict[str, Any] = {}
        if mappings_path and mappings_path.exists() and HAS_YAML:
            with mappings_path.open("r") as f:
                self.mappings = yaml.safe_load(f) or {}

    def resolve_app_id(self, finding: Dict[str, Any]) -> str:
        """Resolve application ID from finding."""
        if self.mappings.get("apps"):
            for app_pattern in self.mappings["apps"]:
                if self._matches_pattern(finding, app_pattern):
                    return app_pattern["app_id"]

        file_path = finding.get("file_path", "")
        if file_path:
            if "/api/" in file_path or "api-" in file_path:
                return "api-service"
            elif "/frontend/" in file_path or "/ui/" in file_path:
                return "frontend-app"
            elif "/backend/" in file_path:
                return "backend-service"

        resource_id = finding.get("resource_id", "")
        if resource_id:
            if resource_id.startswith("arn:aws:"):
                parts = resource_id.split(":")
                if len(parts) >= 6:
                    resource_name = parts[5]
                    match = re.match(r"([a-z-]+)-(?:prod|staging|dev)", resource_name)
                    if match:
                        return match.group(1)

        return "unknown"

    def resolve_component_id(self, finding: Dict[str, Any]) -> str:
        """Resolve component ID from finding."""
        if self.mappings.get("components"):
            for comp_pattern in self.mappings["components"]:
                if self._matches_pattern(finding, comp_pattern):
                    return comp_pattern["component_id"]

        file_path = finding.get("file_path", "")
        if file_path:
            parts = file_path.split("/")
            if len(parts) >= 2:
                for part in parts:
                    if part.endswith("-service") or part.endswith("-api"):
                        return part
                    elif part in ["auth", "payment", "user", "order", "inventory"]:
                        return f"{part}-service"

        resource_id = finding.get("resource_id", "")
        if resource_id:
            if "/" in resource_id:
                namespace, name = resource_id.split("/", 1)
                return name.split("-")[0] if "-" in name else name

            if resource_id.startswith("arn:aws:"):
                parts = resource_id.split(":")
                if len(parts) >= 6:
                    resource_name = parts[5]
                    return resource_name.split("-")[0]

        package = finding.get("package", "")
        if package:
            return package.split("/")[0] if "/" in package else package.split(".")[0]

        return "unknown"

    def resolve_asset_id(self, finding: Dict[str, Any]) -> str:
        """Generate unique asset ID."""
        asset_key = finding.get("asset_key", "")
        if asset_key:
            return asset_key

        parts = []
        if finding.get("resource_id"):
            parts.append(finding["resource_id"])
        elif finding.get("file_path"):
            parts.append(finding["file_path"])
        elif finding.get("package"):
            parts.append(f"pkg:{finding['package']}")

        if finding.get("version"):
            parts.append(finding["version"])

        return ":".join(parts) if parts else "unknown"

    def compute_correlation_key(self, finding: Dict[str, Any]) -> str:
        """Compute deterministic correlation key for cross-run matching."""
        parts = [
            finding.get("category", ""),
            finding.get("cve_id", ""),
            finding.get("rule_id", ""),
            finding.get("app_id", ""),
            finding.get("component_id", ""),
            self._normalize_location(finding),
        ]

        key_str = "|".join(p for p in parts if p)

        return hashlib.sha256(key_str.encode()).hexdigest()[:16]

    def compute_fingerprint(self, finding: Dict[str, Any]) -> str:
        """Compute content-based fingerprint for similarity matching."""
        parts = [
            finding.get("title", ""),
            finding.get("description", "")[:200],  # First 200 chars
            finding.get("cve_id", ""),
            finding.get("rule_id", ""),
        ]

        content = " ".join(p for p in parts if p)

        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def _matches_pattern(
        self, finding: Dict[str, Any], pattern: Dict[str, Any]
    ) -> bool:
        """Check if finding matches a pattern."""
        for key, value in pattern.get("match", {}).items():
            if key not in finding:
                return False
            if isinstance(value, str):
                if not re.search(value, str(finding[key])):
                    return False
            elif finding[key] != value:
                return False
        return True

    def _normalize_location(self, finding: Dict[str, Any]) -> str:
        """Normalize location for correlation."""
        if finding.get("file_path"):
            path = finding["file_path"]
            path = re.sub(r":\d+$", "", path)  # Remove trailing line numbers
            return path.replace("\\", "/")
        elif finding.get("resource_id"):
            return finding["resource_id"]
        elif finding.get("package"):
            return f"pkg:{finding['package']}"
        return ""
