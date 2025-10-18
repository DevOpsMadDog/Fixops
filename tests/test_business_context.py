import json
from pathlib import Path

from apps.api.normalizers import InputNormalizer


def test_load_business_context_fixops_yaml(tmp_path: Path) -> None:
    payload = (
        "components:\n"
        "  - name: customer-api\n"
        "    owner: appsec\n"
        "ssvc:\n"
        "  exploitation: poc\n"
        "  exposure: limited\n"
        "  utility: efficient\n"
        "  safety_impact: marginal\n"
        "  mission_impact: degraded\n"
    )
    normalizer = InputNormalizer()
    context = normalizer.load_business_context(
        payload.encode("utf-8"), content_type="application/x-yaml"
    )
    assert context.format.startswith("fixops")
    assert context.components and context.components[0]["name"] == "customer-api"
    assert context.ssvc["exposure"] == "limited"


def test_load_business_context_otm_json(tmp_path: Path) -> None:
    otm_document = {
        "otmVersion": "0.1.0",
        "components": [
            {
                "name": "payments",
                "type": "service",
                "parent": {"trustZone": {"trustRating": 2}},
                "data": [{"classification": "financial"}],
            }
        ],
        "trustZones": [
            {
                "name": "Public",
                "risk": {"trustRating": 2},
            }
        ],
    }
    normalizer = InputNormalizer()
    context = normalizer.load_business_context(json.dumps(otm_document).encode("utf-8"))
    assert context.format == "otm.json"
    assert context.components[0]["name"] == "payments"
    assert context.ssvc["mission_impact"] in {"degraded", "mev"}


def test_load_business_context_ssvc_yaml() -> None:
    payload = (
        "exploitation: active\n"
        "exposure: open\n"
        "utility: super_effective\n"
        "safety_impact: major\n"
        "mission_impact: mev\n"
    )
    normalizer = InputNormalizer()
    context = normalizer.load_business_context(
        payload.encode("utf-8"), content_type="application/x-yaml"
    )
    assert context.format.startswith("ssvc")
    assert context.components == []
    assert context.ssvc["exploitation"] == "active"
