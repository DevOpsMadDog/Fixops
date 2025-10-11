import json
from pathlib import Path

from core.configuration import OverlayConfig
from core.evidence import EvidenceHub


def test_evidence_hub_persists_manifest_and_checksum(tmp_path: Path) -> None:
    overlay = OverlayConfig(
        mode="enterprise",
        data={"evidence_dir": str(tmp_path / "evidence")},
        limits={"evidence": {"bundle_max_bytes": 4096, "compress": False, "encrypt": False}},
        evidence_hub={"bundle_name": "integration-test"},
    )
    overlay.allowed_data_roots = (tmp_path,)

    hub = EvidenceHub(overlay)
    pipeline_result = {
        "design_summary": {"rows": 3},
        "sbom_summary": {"components": 2},
        "sarif_summary": {"findings": 4},
        "cve_summary": {"records": 2},
        "severity_overview": {"highest": "high"},
    }
    context_summary = {"summary": {"highest_score": 9}}
    compliance_status = {"status": "satisfied"}
    policy_summary = {"status": "ready"}

    result = hub.persist(pipeline_result, context_summary, compliance_status, policy_summary)

    bundle_path = Path(result["files"]["bundle"])
    manifest_path = Path(result["files"]["manifest"])
    assert bundle_path.exists()
    assert manifest_path.exists()
    assert result["sha256"]

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["sha256"] == result["sha256"]

    audit_log = bundle_path.parent.parent / "audit.log"
    assert audit_log.exists()
    assert bundle_path.name in audit_log.read_text(encoding="utf-8")
