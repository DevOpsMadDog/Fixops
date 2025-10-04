from pathlib import Path

from fixops.configuration import OverlayConfig
from fixops.evidence import EvidenceHub


def _minimal_pipeline_result() -> dict:
    return {
        "design_summary": {},
        "sbom_summary": {},
        "sarif_summary": {},
        "cve_summary": {},
        "severity_overview": {},
    }


def test_evidence_hub_uses_allowlisted_root_and_sanitises_name(tmp_path: Path) -> None:
    overlay = OverlayConfig(
        evidence_hub={"bundle_name": "../Danger Bundle"},
        toggles={"include_overlay_metadata_in_bundles": False},
        allowed_data_roots=(tmp_path.resolve(),),
    )
    hub = EvidenceHub(overlay)

    result = hub.persist(_minimal_pipeline_result(), None, None, None)

    bundle_path = Path(result["files"]["bundle"]).resolve()
    assert tmp_path.resolve() in bundle_path.parents
    assert bundle_path.name.startswith("Danger-Bundle")


def test_evidence_hub_falls_back_to_default_bundle_name(tmp_path: Path) -> None:
    overlay = OverlayConfig(
        evidence_hub={"bundle_name": "!!!"},
        toggles={"include_overlay_metadata_in_bundles": False},
        allowed_data_roots=(tmp_path.resolve(),),
    )
    hub = EvidenceHub(overlay)

    result = hub.persist(_minimal_pipeline_result(), None, None, None)
    bundle_path = Path(result["files"]["bundle"]).resolve()
    assert bundle_path.name.startswith("fixops-demo-run")
