from __future__ import annotations

from typing import Dict, List

import pytest
from core.vector_store import SecurityPatternMatcher


def _sample_crosswalk() -> List[Dict[str, object]]:
    return [
        {
            "design_row": {
                "component": "customer-api",
                "exposure": "internet",
                "data_classification": "pii",
            },
            "findings": [
                {
                    "rule_id": "SNYK-JS-SQLINJECTION",
                    "message": "Potential SQL injection in query builder",
                    "file": "services/customer-api/db.js",
                }
            ],
            "cves": [
                {
                    "cve_id": "CVE-2024-1234",
                    "severity": "critical",
                    "raw": {"shortDescription": "SQL injection vulnerability"},
                }
            ],
        }
    ]


def test_security_pattern_matcher_returns_matches() -> None:
    matcher = SecurityPatternMatcher(
        {"patterns_path": "fixtures/security_patterns.json", "provider": "memory"}
    )
    matches = matcher.recommend_for_crosswalk(_sample_crosswalk())
    assert matches, "Vector matcher should surface at least one component match"
    first = matches[0]
    assert first["component"] == "customer-api"
    assert first["patterns"], "Pattern recommendations should be present"


def test_security_pattern_metadata_exposes_provider() -> None:
    matcher = SecurityPatternMatcher(
        {"patterns_path": "fixtures/security_patterns.json", "provider": "auto"}
    )
    metadata = matcher.provider_metadata
    assert metadata.get("provider"), "Vector store metadata must include provider name"
    assert metadata.get("patterns_indexed", 0) >= 1
    matches = matcher.recommend_for_crosswalk(_sample_crosswalk())
    assert isinstance(matches, list)


@pytest.mark.parametrize(
    "config",
    [
        {"patterns_path": "fixtures/security_patterns.json", "provider": "memory"},
        {"patterns_path": "fixtures/security_patterns.json", "provider": "chromadb"},
    ],
)
def test_vector_store_handles_provider_variants(config: Dict[str, object]) -> None:
    matcher = SecurityPatternMatcher(config)
    metadata = matcher.provider_metadata
    assert metadata.get("provider") in {"in_memory", "chromadb"}
    matches = matcher.recommend_for_crosswalk(_sample_crosswalk())
    assert isinstance(matches, list)
