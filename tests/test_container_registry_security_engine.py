"""Tests for ContainerRegistrySecurityEngine — 32 tests covering all methods + org isolation."""

from __future__ import annotations

import pytest
from core.container_registry_security_engine import ContainerRegistrySecurityEngine


@pytest.fixture
def engine(tmp_path):
    return ContainerRegistrySecurityEngine(db_path=str(tmp_path / "crs.db"))


@pytest.fixture
def org():
    return "org-alpha"


@pytest.fixture
def org2():
    return "org-beta"


def _registry(engine, org, name="My ECR", registry_type="ecr"):
    return engine.register_registry(org, {"name": name, "registry_type": registry_type, "url": "123.dkr.ecr.us-east-1.amazonaws.com"})


def _scan(engine, org, registry_id, image_name="myapp/backend", vulns=None):
    if vulns is None:
        vulns = [
            {"cve_id": "CVE-2021-1234", "severity": "high", "package": "openssl"},
            {"cve_id": "CVE-2021-5678", "severity": "medium", "package": "curl"},
        ]
    return engine.scan_image(org, {
        "registry_id": registry_id,
        "image_name": image_name,
        "tag": "v1.0",
        "vulnerabilities": vulns,
    })


def _policy(engine, org, name="Strict Policy", block_critical=True, max_high=3):
    return engine.create_policy(org, {
        "name": name,
        "block_critical": block_critical,
        "max_high_vulns": max_high,
        "require_signed": False,
    })


# ---------------------------------------------------------------------------
# register_registry
# ---------------------------------------------------------------------------

def test_register_registry_returns_record(engine, org):
    reg = _registry(engine, org)
    assert reg["name"] == "My ECR"
    assert reg["registry_type"] == "ecr"
    assert reg["org_id"] == org
    assert "id" in reg
    assert reg["auth_configured"] is False


def test_register_registry_missing_name_raises(engine, org):
    with pytest.raises(ValueError, match="name"):
        engine.register_registry(org, {"name": ""})


def test_register_registry_invalid_type_raises(engine, org):
    with pytest.raises(ValueError, match="registry_type"):
        engine.register_registry(org, {"name": "X", "registry_type": "unknown"})


def test_register_registry_all_types(engine, org):
    for rtype in ("docker", "ecr", "gcr", "acr", "harbor"):
        r = engine.register_registry(org, {"name": f"reg-{rtype}", "registry_type": rtype})
        assert r["registry_type"] == rtype


def test_register_registry_auth_configured_true(engine, org):
    reg = engine.register_registry(org, {"name": "Signed", "auth_configured": True})
    assert reg["auth_configured"] is True


# ---------------------------------------------------------------------------
# list_registries / get_registry
# ---------------------------------------------------------------------------

def test_list_registries_empty(engine, org):
    assert engine.list_registries(org) == []


def test_list_registries_returns_all(engine, org):
    _registry(engine, org, "R1")
    _registry(engine, org, "R2")
    assert len(engine.list_registries(org)) == 2


def test_list_registries_org_isolation(engine, org, org2):
    _registry(engine, org, "R-alpha")
    _registry(engine, org2, "R-beta")
    assert len(engine.list_registries(org)) == 1
    assert len(engine.list_registries(org2)) == 1


def test_get_registry_returns_record(engine, org):
    reg = _registry(engine, org)
    fetched = engine.get_registry(org, reg["id"])
    assert fetched["id"] == reg["id"]
    assert fetched["name"] == reg["name"]


def test_get_registry_wrong_org_returns_none(engine, org, org2):
    reg = _registry(engine, org)
    assert engine.get_registry(org2, reg["id"]) is None


# ---------------------------------------------------------------------------
# scan_image
# ---------------------------------------------------------------------------

def test_scan_image_returns_record(engine, org):
    reg = _registry(engine, org)
    scan = _scan(engine, org, reg["id"])
    assert scan["image_name"] == "myapp/backend"
    assert scan["tag"] == "v1.0"
    assert scan["high_count"] == 1
    assert scan["medium_count"] == 1
    assert scan["critical_count"] == 0
    assert 0 <= scan["scan_score"] <= 100
    assert isinstance(scan["vulnerabilities"], list)


def test_scan_image_missing_registry_id_raises(engine, org):
    with pytest.raises(ValueError, match="registry_id"):
        engine.scan_image(org, {"registry_id": "", "image_name": "app"})


def test_scan_image_missing_image_name_raises(engine, org):
    reg = _registry(engine, org)
    with pytest.raises(ValueError, match="image_name"):
        engine.scan_image(org, {"registry_id": reg["id"], "image_name": ""})


def test_scan_image_critical_vuln_lowers_score(engine, org):
    reg = _registry(engine, org)
    scan = engine.scan_image(org, {
        "registry_id": reg["id"],
        "image_name": "risky/app",
        "vulnerabilities": [{"cve_id": "CVE-2024-999", "severity": "critical", "package": "base"}],
    })
    assert scan["critical_count"] == 1
    assert scan["scan_score"] < 100


def test_scan_image_override_scan_score(engine, org):
    reg = _registry(engine, org)
    scan = engine.scan_image(org, {
        "registry_id": reg["id"],
        "image_name": "app",
        "scan_score": 42,
        "vulnerabilities": [],
    })
    assert scan["scan_score"] == 42


def test_scan_image_no_vulns_score_100(engine, org):
    reg = _registry(engine, org)
    scan = engine.scan_image(org, {
        "registry_id": reg["id"],
        "image_name": "clean/app",
        "vulnerabilities": [],
    })
    assert scan["scan_score"] == 100
    assert scan["critical_count"] == 0


# ---------------------------------------------------------------------------
# list_image_scans / get_scan
# ---------------------------------------------------------------------------

def test_list_image_scans_empty(engine, org):
    assert engine.list_image_scans(org) == []


def test_list_image_scans_filter_by_registry(engine, org):
    r1 = _registry(engine, org, "R1")
    r2 = _registry(engine, org, "R2")
    _scan(engine, org, r1["id"], "app1")
    _scan(engine, org, r2["id"], "app2")
    assert len(engine.list_image_scans(org, registry_id=r1["id"])) == 1


def test_list_image_scans_filter_by_severity(engine, org):
    reg = _registry(engine, org)
    engine.scan_image(org, {
        "registry_id": reg["id"],
        "image_name": "clean/app",
        "vulnerabilities": [],
    })
    _scan(engine, org, reg["id"])
    critical_only = engine.list_image_scans(org, severity="critical")
    assert all(s["critical_count"] > 0 for s in critical_only)


def test_list_image_scans_org_isolation(engine, org, org2):
    r1 = _registry(engine, org)
    r2 = _registry(engine, org2)
    _scan(engine, org, r1["id"])
    _scan(engine, org2, r2["id"])
    assert len(engine.list_image_scans(org)) == 1
    assert len(engine.list_image_scans(org2)) == 1


def test_get_scan_returns_record(engine, org):
    reg = _registry(engine, org)
    scan = _scan(engine, org, reg["id"])
    fetched = engine.get_scan(org, scan["id"])
    assert fetched["id"] == scan["id"]


def test_get_scan_wrong_org_returns_none(engine, org, org2):
    reg = _registry(engine, org)
    scan = _scan(engine, org, reg["id"])
    assert engine.get_scan(org2, scan["id"]) is None


# ---------------------------------------------------------------------------
# create_policy / list_policies
# ---------------------------------------------------------------------------

def test_create_policy_returns_record(engine, org):
    p = _policy(engine, org)
    assert p["name"] == "Strict Policy"
    assert p["block_critical"] is True
    assert p["max_high_vulns"] == 3
    assert p["require_signed"] is False
    assert "id" in p


def test_create_policy_missing_name_raises(engine, org):
    with pytest.raises(ValueError, match="name"):
        engine.create_policy(org, {"name": ""})


def test_list_policies_org_isolation(engine, org, org2):
    _policy(engine, org, "P-alpha")
    _policy(engine, org2, "P-beta")
    assert len(engine.list_policies(org)) == 1
    assert len(engine.list_policies(org2)) == 1


# ---------------------------------------------------------------------------
# evaluate_image
# ---------------------------------------------------------------------------

def test_evaluate_image_allow_no_policies(engine, org):
    reg = _registry(engine, org)
    scan = _scan(engine, org, reg["id"])
    result = engine.evaluate_image(org, scan["id"])
    assert result["policy_result"] == "allow"
    assert result["policies_evaluated"] == 0


def test_evaluate_image_block_on_critical(engine, org):
    reg = _registry(engine, org)
    scan = engine.scan_image(org, {
        "registry_id": reg["id"],
        "image_name": "bad/app",
        "vulnerabilities": [{"cve_id": "CVE-2024-999", "severity": "critical", "package": "os"}],
    })
    _policy(engine, org, block_critical=True)
    result = engine.evaluate_image(org, scan["id"])
    assert result["policy_result"] == "block"
    assert len(result["violations"]) > 0


def test_evaluate_image_block_on_too_many_high(engine, org):
    reg = _registry(engine, org)
    scan = engine.scan_image(org, {
        "registry_id": reg["id"],
        "image_name": "many-highs/app",
        "vulnerabilities": [
            {"cve_id": f"CVE-2024-{i}", "severity": "high", "package": "pkg"}
            for i in range(5)
        ],
    })
    engine.create_policy(org, {"name": "Low Threshold", "block_critical": False, "max_high_vulns": 2})
    result = engine.evaluate_image(org, scan["id"])
    assert result["policy_result"] == "block"


def test_evaluate_image_allow_clean_image(engine, org):
    reg = _registry(engine, org)
    scan = engine.scan_image(org, {
        "registry_id": reg["id"],
        "image_name": "clean/app",
        "vulnerabilities": [],
    })
    _policy(engine, org, block_critical=True, max_high=5)
    result = engine.evaluate_image(org, scan["id"])
    assert result["policy_result"] == "allow"
    assert result["violations"] == []


def test_evaluate_image_scan_not_found_raises(engine, org):
    with pytest.raises(KeyError):
        engine.evaluate_image(org, "nonexistent-id")


# ---------------------------------------------------------------------------
# get_registry_stats
# ---------------------------------------------------------------------------

def test_get_registry_stats_empty(engine, org):
    stats = engine.get_registry_stats(org)
    assert stats["registries"] == 0
    assert stats["scans"] == 0
    assert stats["critical_images"] == 0
    assert stats["avg_scan_score"] == 0.0


def test_get_registry_stats_populated(engine, org):
    reg = _registry(engine, org)
    engine.scan_image(org, {
        "registry_id": reg["id"],
        "image_name": "app",
        "vulnerabilities": [{"cve_id": "CVE-X", "severity": "critical", "package": "os"}],
    })
    engine.scan_image(org, {
        "registry_id": reg["id"],
        "image_name": "app2",
        "vulnerabilities": [],
    })
    stats = engine.get_registry_stats(org)
    assert stats["registries"] == 1
    assert stats["scans"] == 2
    assert stats["critical_images"] == 1
    assert 0 <= stats["avg_scan_score"] <= 100


def test_get_registry_stats_org_isolation(engine, org, org2):
    r1 = _registry(engine, org)
    r2 = _registry(engine, org2)
    _scan(engine, org, r1["id"])
    stats1 = engine.get_registry_stats(org)
    stats2 = engine.get_registry_stats(org2)
    assert stats1["registries"] == 1
    assert stats2["registries"] == 1
    assert stats1["scans"] == 1
    assert stats2["scans"] == 0
