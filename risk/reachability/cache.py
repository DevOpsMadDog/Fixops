"""Caching for reachability analysis results."""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

from risk.reachability.analyzer import VulnerabilityReachability

logger = logging.getLogger(__name__)


class AnalysisCache:
    """Cache for reachability analysis results to improve performance."""

    def __init__(
        self,
        cache_dir: Optional[Path] = None,
        ttl_hours: int = 24,
        max_size_mb: int = 1000,
    ):
        """Initialize analysis cache.

        Parameters
        ----------
        cache_dir
            Directory for cache storage. If None, uses temp directory.
        ttl_hours
            Time-to-live for cache entries in hours.
        max_size_mb
            Maximum cache size in MB.
        """
        import tempfile

        self.cache_dir = (
            cache_dir or Path(tempfile.gettempdir()) / "fixops_reachability_cache"
        )
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.ttl_hours = ttl_hours
        self.max_size_mb = max_size_mb

    def get_cache_key(
        self,
        cve_id: str,
        component_name: str,
        component_version: str,
        repo_url: str,
        repo_commit: Optional[str] = None,
    ) -> str:
        """Generate cache key for analysis result."""
        key_parts = [
            cve_id,
            component_name,
            component_version,
            repo_url,
            repo_commit or "HEAD",
        ]
        key_string = "|".join(key_parts)
        return hashlib.sha256(key_string.encode()).hexdigest()

    def get(
        self,
        cve_id: str,
        component_name: str,
        component_version: str,
        repo_url: str,
        repo_commit: Optional[str] = None,
    ) -> Optional[VulnerabilityReachability]:
        """Get cached analysis result.

        Returns
        -------
        Optional[VulnerabilityReachability]
            Cached result if found and not expired, None otherwise.
        """
        cache_key = self.get_cache_key(
            cve_id, component_name, component_version, repo_url, repo_commit
        )
        cache_file = self.cache_dir / f"{cache_key}.json"

        if not cache_file.exists():
            return None

        try:
            with open(cache_file) as f:
                data = json.load(f)

            # Check TTL
            cached_at = datetime.fromisoformat(data["cached_at"])
            age = datetime.now(timezone.utc) - cached_at.replace(tzinfo=timezone.utc)

            if age > timedelta(hours=self.ttl_hours):
                # Expired, delete and return None
                cache_file.unlink()
                return None

            # Reconstruct result
            return VulnerabilityReachability(**data["result"])
        except Exception as e:
            logger.warning(f"Failed to load cache entry: {e}")
            cache_file.unlink(missing_ok=True)
            return None

    def set(
        self,
        result: VulnerabilityReachability,
        repo_url: str,
        repo_commit: Optional[str] = None,
    ) -> None:
        """Cache analysis result."""
        cache_key = self.get_cache_key(
            result.cve_id,
            result.component_name,
            result.component_version,
            repo_url,
            repo_commit,
        )
        cache_file = self.cache_dir / f"{cache_key}.json"

        try:
            data = {
                "cached_at": datetime.now(timezone.utc).isoformat(),
                "result": result.to_dict(),
            }

            with open(cache_file, "w") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.warning(f"Failed to cache result: {e}")

    def clear_expired(self) -> int:
        """Clear expired cache entries.

        Returns
        -------
        int
            Number of entries cleared.
        """
        cleared = 0
        cutoff = datetime.now(timezone.utc) - timedelta(hours=self.ttl_hours)

        for cache_file in self.cache_dir.glob("*.json"):
            try:
                with open(cache_file) as f:
                    data = json.load(f)

                cached_at = datetime.fromisoformat(data["cached_at"])
                if cached_at.replace(tzinfo=timezone.utc) < cutoff:
                    cache_file.unlink()
                    cleared += 1
            except Exception:
                # Invalid cache file, delete it
                cache_file.unlink(missing_ok=True)
                cleared += 1

        return cleared

    def clear_all(self) -> None:
        """Clear all cache entries."""
        for cache_file in self.cache_dir.glob("*.json"):
            cache_file.unlink()
