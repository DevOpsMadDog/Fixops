"""What a caller submits must reach the pipeline.

Pydantic drops undeclared fields silently, so the request model is a filter as much as a
schema: anything it does not declare is discarded at the API boundary regardless of what
the client sent, with no error and no warning.

``FindingInput`` declared eight fields. Everything else a scanner integration would
naturally send — ``source_tool``, ``file_path``, ``line``, ``finding_id`` — was thrown
away before the pipeline ever ran. Two consequences, both measured on 2026-08-17:

* The evidence bundle reported every finding as coming from an ``"unknown"`` tool, even
  when the caller had said ``trivy``. Attribution is among the first things an assessor
  asks for.
* **Deduplication had no location to work with.** It merges on title plus ``file:line``
  precisely so two same-titled findings in different files stay separate — the fix for a
  bug that once collapsed 1,636 findings into 8. Submitted through the API, every finding
  arrived location-less, so that fix could not apply.

These tests pin the boundary: the fields the pipeline reads must survive it.
"""

from __future__ import annotations

import pytest

from api.pipeline_router import FindingInput

# Fields brain_pipeline demonstrably reads from a finding.
PIPELINE_FIELDS = (
    "finding_id",
    "cve_id",
    "severity",
    "title",
    "source",
    "source_tool",
    "scanner",
    "rule_id",
    "file_path",
    "line",
    "cvss_score",
    "epss_score",
    "in_kev",
    "cwe_id",
    "asset_name",
)


@pytest.mark.parametrize("field", PIPELINE_FIELDS)
def test_the_model_declares_every_field_the_pipeline_reads(field: str) -> None:
    """An undeclared field is silently discarded — so absence here is data loss."""
    assert field in FindingInput.model_fields, (
        f"FindingInput does not declare {field!r}; Pydantic will drop it at the API "
        "boundary and the pipeline will never see what the caller sent"
    )


def test_attribution_survives_the_boundary() -> None:
    """The evidence bundle cannot say 'trivy' if the API threw 'trivy' away."""
    finding = FindingInput(
        title="Log4Shell", severity="critical", source_tool="trivy", scanner="trivy"
    )
    assert finding.source_tool == "trivy"


def test_location_survives_the_boundary() -> None:
    """Location is what makes two same-titled findings distinguishable."""
    finding = FindingInput(title="Log4Shell", file_path="pom.xml", line=12)
    assert finding.file_path == "pom.xml"
    assert finding.line == 12


def test_two_findings_differing_only_by_location_stay_distinguishable() -> None:
    """The exact shape deduplication needs in order not to over-merge."""
    first = FindingInput(
        title="Log4Shell", cve_id="CVE-2021-44228", file_path="pom.xml", line=12
    )
    second = FindingInput(
        title="Log4Shell", cve_id="CVE-2021-44228", file_path="build.gradle", line=40
    )
    assert (first.file_path, first.line) != (second.file_path, second.line)


def test_caller_supplied_scores_are_kept() -> None:
    """Discarding a score the caller already holds only forces us to look it up again."""
    finding = FindingInput(title="x", cvss_score=10.0, epss_score=0.97, in_kev=True)
    assert finding.cvss_score == 10.0
    assert finding.epss_score == 0.97
    assert finding.in_kev is True


def test_scores_are_still_validated() -> None:
    """Accepting more fields must not mean accepting nonsense."""
    with pytest.raises(ValueError):
        FindingInput(title="x", cvss_score=11.0)
    with pytest.raises(ValueError):
        FindingInput(title="x", epss_score=1.5)
    with pytest.raises(ValueError):
        FindingInput(title="x", line=-1)


def test_a_minimal_finding_is_still_accepted() -> None:
    """Widening the model must not make previously valid payloads invalid."""
    finding = FindingInput(title="x")
    assert finding.severity == "medium"
    assert finding.source_tool == ""
    assert finding.line is None


def test_optional_fields_are_omitted_rather_than_sent_as_null() -> None:
    """A declared-but-None field is worse than an absent one.

    The pipeline reads findings with ``f.get("x", default)``, which returns ``None`` when
    the key exists holding ``None`` — so emitting explicit nulls silently replaces every
    default. Widening this model without excluding nulls took risk scoring down with
    ``unsupported operand type(s) for *: 'NoneType' and 'float'``, and the pipeline
    reported ``status=failed`` while the API still answered 200 with a "degraded" verdict.

    The router must therefore serialise with ``exclude_none=True``.
    """
    payload = FindingInput(title="SQLi", severity="high").model_dump(exclude_none=True)

    for field in ("cvss_score", "epss_score", "in_kev", "line"):
        assert field not in payload, (
            f"{field} was serialised as null; the pipeline will read it instead of its "
            "own default and arithmetic on it will fail"
        )
    assert payload["title"] == "SQLi"


def test_router_serialises_findings_without_nulls() -> None:
    """Pin the call site, not just the capability."""
    from pathlib import Path

    source = (
        Path(__file__).resolve().parents[1] / "suite-core" / "api" / "pipeline_router.py"
    ).read_text(encoding="utf-8")

    assert "model_dump()" not in source, (
        "pipeline_router serialises a model without exclude_none; optional fields will "
        "reach the pipeline as explicit nulls and override its defaults"
    )
