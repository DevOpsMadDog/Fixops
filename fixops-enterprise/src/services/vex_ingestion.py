"""Stub VEX ingestion service for test compatibility."""

from __future__ import annotations

from typing import Iterable, Mapping


class VEXIngestor:
    """Minimal placeholder that records ingested advisories."""

    def __init__(self) -> None:
        self._advisories: list[Mapping[str, str]] = []

    def ingest(self, advisories: Iterable[Mapping[str, str]]) -> int:
        items = [dict(item) for item in advisories]
        self._advisories.extend(items)
        return len(items)

    @property
    def advisories(self) -> list[Mapping[str, str]]:
        return list(self._advisories)


__all__ = ["VEXIngestor"]
