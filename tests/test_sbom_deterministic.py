"""Test SBOM normalization determinism."""

import json
import os

import pytest

from lib4sbom.normalizer import write_normalized_sbom


@pytest.fixture
def sample_sbom():
    """Create a minimal sample SBOM."""
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "version": 1,
        "metadata": {"tools": [{"name": "test-tool", "version": "1.0.0"}]},
        "components": [
            {
                "name": "component-a",
                "version": "1.0.0",
                "purl": "pkg:npm/component-a@1.0.0",
            },
            {
                "name": "component-b",
                "version": "2.0.0",
                "purl": "pkg:npm/component-b@2.0.0",
            },
        ],
    }


def test_sbom_deterministic_output(sample_sbom, tmp_path):
    """Test that SBOM normalization produces identical output on consecutive runs."""
    seed = "2025-10-19T12:00:00Z"
    os.environ["FIXOPS_TEST_SEED"] = seed

    sbom_path = tmp_path / "input.json"
    sbom_path.write_text(json.dumps(sample_sbom))

    output1 = tmp_path / "output1.json"
    output2 = tmp_path / "output2.json"

    write_normalized_sbom([sbom_path], output1)
    write_normalized_sbom([sbom_path], output2)

    content1 = output1.read_text()
    content2 = output2.read_text()

    assert content1 == content2, "SBOM normalization should be deterministic"

    data1 = json.loads(content1)
    data2 = json.loads(content2)

    assert data1["metadata"]["generated_at"] == data2["metadata"]["generated_at"]
    assert data1["components"] == data2["components"]


def test_sbom_component_ordering(sample_sbom, tmp_path):
    """Test that components are sorted consistently."""
    seed = "2025-10-19T12:00:00Z"
    os.environ["FIXOPS_TEST_SEED"] = seed

    sbom_path = tmp_path / "input.json"
    sbom_path.write_text(json.dumps(sample_sbom))

    output = tmp_path / "output.json"
    write_normalized_sbom([sbom_path], output)

    data = json.loads(output.read_text())
    components = data["components"]

    assert len(components) == 2
    assert components[0]["purl"] == "pkg:npm/component-a@1.0.0"
    assert components[1]["purl"] == "pkg:npm/component-b@2.0.0"


def test_sbom_strict_schema_validation(sample_sbom, tmp_path):
    """Test strict schema validation."""
    seed = "2025-10-19T12:00:00Z"
    os.environ["FIXOPS_TEST_SEED"] = seed

    invalid_sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "version": 1,
        "components": [
            {"name": "component-missing-version"},
        ],
    }

    sbom_path = tmp_path / "invalid.json"
    sbom_path.write_text(json.dumps(invalid_sbom))

    output = tmp_path / "output.json"

    with pytest.raises(ValueError, match="Strict schema validation failed"):
        write_normalized_sbom([sbom_path], output, strict_schema=True)


def test_sbom_json_key_ordering(sample_sbom, tmp_path):
    """Test that JSON keys are sorted alphabetically."""
    seed = "2025-10-19T12:00:00Z"
    os.environ["FIXOPS_TEST_SEED"] = seed

    sbom_path = tmp_path / "input.json"
    sbom_path.write_text(json.dumps(sample_sbom))

    output = tmp_path / "output.json"
    write_normalized_sbom([sbom_path], output)

    content = output.read_text()
    lines = content.split("\n")

    metadata_line_idx = next(i for i, line in enumerate(lines) if '"metadata"' in line)
    components_line_idx = next(
        i for i, line in enumerate(lines) if '"components"' in line
    )

    assert (
        components_line_idx < metadata_line_idx
    ), "Keys should be sorted alphabetically (components before metadata)"
