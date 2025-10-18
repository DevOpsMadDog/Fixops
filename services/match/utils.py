"""Token utilities shared across matching services."""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Tuple

Matcher = Callable[[Any], str]


@dataclass(slots=True)
class LookupTokens:
    """Computed lookup metadata for design rows."""

    components: List[str]
    token_by_index: Dict[int, str]
    tokens: Tuple[str, ...]


@lru_cache(maxsize=1024)
def _lower(value: Optional[str]) -> Optional[str]:
    return value.lower() if isinstance(value, str) else None


def extract_component_name(row: Mapping[str, Any]) -> Optional[str]:
    """Return the first non-empty component identifier from a design row."""

    for key in ("component", "Component", "service", "name"):
        value = row.get(key)
        if isinstance(value, str):
            stripped = value.strip()
            if stripped:
                return stripped
    return None


def build_lookup_tokens(rows: Iterable[Mapping[str, Any]]) -> LookupTokens:
    """Extract lookup tokens for design rows once."""

    components: List[str] = []
    token_by_index: Dict[int, str] = {}
    for index, row in enumerate(rows):
        name = extract_component_name(row)
        if not name:
            continue
        normalised = _lower(name)
        if not normalised:
            continue
        components.append(name)
        token_by_index[index] = normalised
    tokens = tuple(sorted(set(token_by_index.values())))
    return LookupTokens(
        components=components, token_by_index=token_by_index, tokens=tokens
    )


@lru_cache(maxsize=256)
def compile_token_pattern(tokens: Tuple[str, ...]) -> Optional[re.Pattern[str]]:
    """Build a compiled regex for substring lookups across artefacts."""

    cleaned = [token for token in tokens if token]
    if not cleaned:
        return None
    sorted_tokens = sorted(cleaned, key=len, reverse=True)
    pattern = "|".join(re.escape(token) for token in sorted_tokens)
    return re.compile(pattern)


def group_matches(
    records: Iterable[Any],
    tokens: Tuple[str, ...],
    *,
    search: Matcher,
    to_mapping: Callable[[Any], Mapping[str, Any]],
) -> Dict[str, List[Mapping[str, Any]]]:
    """Group artefacts by matching design tokens once."""

    pattern = compile_token_pattern(tokens)
    matches: Dict[str, List[Mapping[str, Any]]] = defaultdict(list)
    if not pattern:
        return matches

    for record in records:
        haystack = search(record)
        if not haystack:
            continue
        haystack = haystack.lower()
        mapping = dict(to_mapping(record))
        for token in set(pattern.findall(haystack)):
            matches[token].append(mapping)
    return matches


def build_finding_search_text(finding: Mapping[str, Any]) -> str:
    parts: List[str] = []
    file = finding.get("file")
    if isinstance(file, str):
        parts.append(file)
    message = finding.get("message")
    if isinstance(message, str):
        parts.append(message)
    rule_id = finding.get("rule_id")
    if isinstance(rule_id, str):
        parts.append(rule_id)
    raw = finding.get("raw")
    if raw:
        try:
            parts.append(json.dumps(raw, sort_keys=True, separators=(",", ":")))
        except TypeError:
            parts.append(str(raw))
    return " ".join(parts)


def build_record_search_text(record: Mapping[str, Any]) -> str:
    parts: List[str] = []
    for key in ("cve_id", "title", "severity"):
        value = record.get(key)
        if isinstance(value, str):
            parts.append(value)
    raw = record.get("raw")
    if raw:
        try:
            parts.append(json.dumps(raw, sort_keys=True, separators=(",", ":")))
        except TypeError:
            parts.append(str(raw))
    return " ".join(parts)
