"""Base classes for extensible threat intelligence feeds."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from urllib.error import URLError
from urllib.request import urlopen

FEEDS_DIR = Path("data/feeds")

LOGGER = logging.getLogger(__name__)

Fetcher = Callable[[str], bytes]


def default_fetcher(url: str, timeout: int = 30) -> bytes:
    """Default HTTP fetcher with timeout."""
    with urlopen(url, timeout=timeout) as response:  # nosec - controlled URL
        return response.read()


@dataclass
class VulnerabilityRecord:
    """Unified vulnerability record across all threat intelligence sources."""

    id: str
    source: str
    severity: Optional[str] = None
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    description: Optional[str] = None
    published: Optional[str] = None
    modified: Optional[str] = None
    affected_packages: List[str] = field(default_factory=list)
    affected_versions: List[str] = field(default_factory=list)
    fixed_versions: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    cwe_ids: List[str] = field(default_factory=list)
    exploit_available: bool = False
    exploit_maturity: Optional[str] = None
    epss_score: Optional[float] = None
    kev_listed: bool = False
    vendor_advisory: Optional[str] = None
    ecosystem: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "id": self.id,
            "source": self.source,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "description": self.description,
            "published": self.published,
            "modified": self.modified,
            "affected_packages": self.affected_packages,
            "affected_versions": self.affected_versions,
            "fixed_versions": self.fixed_versions,
            "references": self.references,
            "cwe_ids": self.cwe_ids,
            "exploit_available": self.exploit_available,
            "exploit_maturity": self.exploit_maturity,
            "epss_score": self.epss_score,
            "kev_listed": self.kev_listed,
            "vendor_advisory": self.vendor_advisory,
            "ecosystem": self.ecosystem,
            "metadata": self.metadata,
        }


@dataclass
class FeedMetadata:
    """Metadata about a threat intelligence feed."""

    name: str
    source: str
    url: str
    last_updated: Optional[str] = None
    record_count: int = 0
    version: Optional[str] = None
    description: Optional[str] = None


class ThreatIntelligenceFeed(ABC):
    """Abstract base class for threat intelligence feeds."""

    def __init__(
        self,
        cache_dir: str | Path = FEEDS_DIR,
        fetcher: Optional[Fetcher] = None,
    ):
        """Initialize threat intelligence feed.

        Parameters
        ----------
        cache_dir:
            Directory to cache feed data.
        fetcher:
            Optional custom HTTP fetcher function.
        """
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.fetcher = fetcher or default_fetcher
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    @property
    @abstractmethod
    def feed_name(self) -> str:
        """Return the feed name."""
        pass

    @property
    @abstractmethod
    def feed_url(self) -> str:
        """Return the feed URL."""
        pass

    @property
    @abstractmethod
    def cache_filename(self) -> str:
        """Return the cache filename."""
        pass

    @abstractmethod
    def parse_feed(self, data: bytes) -> List[VulnerabilityRecord]:
        """Parse raw feed data into vulnerability records.

        Parameters
        ----------
        data:
            Raw feed data.

        Returns
        -------
        List[VulnerabilityRecord]
            List of parsed vulnerability records.
        """
        pass

    def update_feed(self, url: Optional[str] = None) -> Path:
        """Fetch and cache the feed.

        Parameters
        ----------
        url:
            Optional custom URL to fetch from.

        Returns
        -------
        Path
            Path to cached feed file.
        """
        feed_url = url or self.feed_url
        cache_path = self.cache_dir / self.cache_filename

        try:
            self.logger.info("Fetching %s feed from %s", self.feed_name, feed_url)
            data = self.fetcher(feed_url)
            cache_path.write_bytes(data)
            self.logger.info("Cached %s feed to %s", self.feed_name, cache_path)
            return cache_path
        except (URLError, TimeoutError, OSError) as exc:
            self.logger.warning(
                "Failed to fetch %s feed (%s). Using cached data if available.",
                self.feed_name,
                exc,
            )
            if cache_path.exists():
                return cache_path
            raise

    def load_feed(self, path: Optional[str | Path] = None) -> List[VulnerabilityRecord]:
        """Load and parse the feed.

        Parameters
        ----------
        path:
            Optional path to feed file. If None, uses cached file.

        Returns
        -------
        List[VulnerabilityRecord]
            List of vulnerability records.
        """
        if path is None:
            path = self.cache_dir / self.cache_filename

        feed_path = Path(path)
        if not feed_path.exists():
            raise FileNotFoundError(f"{self.feed_name} feed not found at {feed_path}")

        self.logger.info("Loading %s feed from %s", self.feed_name, feed_path)
        data = feed_path.read_bytes()
        records = self.parse_feed(data)
        self.logger.info("Loaded %d records from %s feed", len(records), self.feed_name)
        return records

    def get_metadata(self) -> FeedMetadata:
        """Get feed metadata.

        Returns
        -------
        FeedMetadata
            Feed metadata.
        """
        cache_path = self.cache_dir / self.cache_filename
        last_updated = None
        record_count = 0

        if cache_path.exists():
            stat = cache_path.stat()
            last_updated = datetime.fromtimestamp(stat.st_mtime).isoformat()
            try:
                records = self.load_feed(cache_path)
                record_count = len(records)
            except Exception as exc:
                self.logger.debug("Failed to count records: %s", exc)

        return FeedMetadata(
            name=self.feed_name,
            source=self.__class__.__name__,
            url=self.feed_url,
            last_updated=last_updated,
            record_count=record_count,
        )


class FeedRegistry:
    """Registry for managing multiple threat intelligence feeds."""

    def __init__(self, cache_dir: str | Path = FEEDS_DIR):
        """Initialize feed registry.

        Parameters
        ----------
        cache_dir:
            Directory to cache feed data.
        """
        self.cache_dir = Path(cache_dir)
        self.feeds: Dict[str, ThreatIntelligenceFeed] = {}

    def register(self, feed: ThreatIntelligenceFeed) -> None:
        """Register a threat intelligence feed.

        Parameters
        ----------
        feed:
            Threat intelligence feed to register.
        """
        self.feeds[feed.feed_name] = feed
        LOGGER.info("Registered feed: %s", feed.feed_name)

    def update_all(self) -> Dict[str, Path]:
        """Update all registered feeds.

        Returns
        -------
        Dict[str, Path]
            Mapping of feed names to cache paths.
        """
        results: Dict[str, Path] = {}
        for name, feed in self.feeds.items():
            try:
                path = feed.update_feed()
                results[name] = path
                LOGGER.info("Updated feed: %s", name)
            except Exception as exc:
                LOGGER.error("Failed to update feed %s: %s", name, exc)
        return results

    def load_all(self) -> Dict[str, List[VulnerabilityRecord]]:
        """Load all registered feeds.

        Returns
        -------
        Dict[str, List[VulnerabilityRecord]]
            Mapping of feed names to vulnerability records.
        """
        results: Dict[str, List[VulnerabilityRecord]] = {}
        for name, feed in self.feeds.items():
            try:
                records = feed.load_feed()
                results[name] = records
                LOGGER.info("Loaded feed: %s (%d records)", name, len(records))
            except Exception as exc:
                LOGGER.error("Failed to load feed %s: %s", name, exc)
        return results

    def get_all_metadata(self) -> List[FeedMetadata]:
        """Get metadata for all registered feeds.

        Returns
        -------
        List[FeedMetadata]
            List of feed metadata.
        """
        return [feed.get_metadata() for feed in self.feeds.values()]

    def get_feed(self, name: str) -> Optional[ThreatIntelligenceFeed]:
        """Get a registered feed by name.

        Parameters
        ----------
        name:
            Feed name.

        Returns
        -------
        Optional[ThreatIntelligenceFeed]
            Feed instance or None if not found.
        """
        return self.feeds.get(name)

    def list_feeds(self) -> List[str]:
        """List all registered feed names.

        Returns
        -------
        List[str]
            List of feed names.
        """
        return list(self.feeds.keys())


__all__ = [
    "VulnerabilityRecord",
    "FeedMetadata",
    "ThreatIntelligenceFeed",
    "FeedRegistry",
    "default_fetcher",
]
