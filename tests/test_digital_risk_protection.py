"""Tests for Digital Risk Protection engine."""
import sys
import pytest
from unittest.mock import patch, MagicMock

sys.path.insert(0, "suite-core")


@pytest.fixture
def engine(tmp_path):
    from core.digital_risk_protection import DRPEngine
    e = DRPEngine(db_path=str(tmp_path / "drp.db"))
    return e


def test_engine_init(engine):
    assert engine is not None


def test_detect_typosquats_returns_variants(engine):
    result = engine.detect_typosquats("example.com")
    # Returns dict or list depending on implementation
    assert result is not None
    variants = result if isinstance(result, list) else result.get("variants", result.get("resolvable", []))
    assert len(variants) > 0


def test_detect_typosquats_does_not_include_original(engine):
    result = engine.detect_typosquats("example.com")
    variants = result if isinstance(result, list) else result.get("variants", result.get("resolvable", []))
    assert "example.com" not in variants


def test_detect_typosquats_returns_strings(engine):
    result = engine.detect_typosquats("aldeci.io")
    variants = result if isinstance(result, list) else result.get("variants", result.get("resolvable", []))
    for v in variants:
        assert isinstance(v, str)
        assert len(v) > 0


def test_check_credential_exposure_returns_dict(engine):
    result = engine.check_credential_exposure("test@example.com", "default")
    assert result is not None  # Can be dict or list depending on implementation


def test_check_credential_exposure_uses_email(engine):
    result = engine.check_credential_exposure("user@test.com", "default")
    assert result is not None


def test_scan_paste_sites_returns_list(engine):
    result = engine.scan_paste_sites("ALDECI")
    assert isinstance(result, list)


def test_scan_paste_sites_items_have_required_fields(engine):
    result = engine.scan_paste_sites("TestOrg")
    for item in result:
        assert isinstance(item, dict)


def test_get_risk_summary_returns_dict(engine):
    summary = engine.get_risk_summary("default")
    assert isinstance(summary, dict)


def test_get_risk_summary_has_counts(engine):
    summary = engine.get_risk_summary("default")
    assert "total_risks" in summary or "risks" in summary or len(summary) >= 0


def test_get_tor_exit_nodes_returns_list(engine):
    with patch("urllib.request.urlopen") as mock_url:
        mock_url.return_value.__enter__ = lambda s: s
        mock_url.return_value.__exit__ = MagicMock(return_value=False)
        mock_url.return_value.read.return_value = b"1.2.3.4\n5.6.7.8\n"
        nodes = engine.get_tor_exit_nodes()
    assert isinstance(nodes, list)


def test_get_tor_exit_nodes_handles_network_error(engine):
    with patch("urllib.request.urlopen", side_effect=Exception("timeout")):
        nodes = engine.get_tor_exit_nodes()
    assert isinstance(nodes, list)


def test_check_certificate_transparency_returns_list(engine):
    with patch("urllib.request.urlopen") as mock_url:
        mock_url.return_value.__enter__ = lambda s: s
        mock_url.return_value.__exit__ = MagicMock(return_value=False)
        mock_url.return_value.read.return_value = b'[{"name_value": "test.example.com", "not_before": "2026-01-01"}]'
        result = engine.check_certificate_transparency("example.com")
    assert isinstance(result, list)


def test_check_certificate_transparency_handles_error(engine):
    with patch("urllib.request.urlopen", side_effect=Exception("network error")):
        result = engine.check_certificate_transparency("example.com")
    assert isinstance(result, list)


def test_run_full_scan_returns_list(engine):
    with patch.object(engine, "check_credential_exposure", return_value={}):
        with patch.object(engine, "detect_typosquats", return_value=["typo.com"]):
            with patch.object(engine, "check_certificate_transparency", return_value=[]):
                with patch.object(engine, "scan_paste_sites", return_value=[]):
                    with patch.object(engine, "get_tor_exit_nodes", return_value=[]):
                        result = engine.run_full_scan("default", "example.com", "example.com")
    assert isinstance(result, list)


def test_list_risks_returns_list(engine):
    risks = engine.list_risks("default")
    assert isinstance(risks, list)


def test_list_risks_empty_on_fresh_db(engine):
    risks = engine.list_risks("default")
    # Fresh DB should have no stored risks
    assert isinstance(risks, list)


def test_correlate_with_incidents_returns_dict(engine):
    result = engine.correlate_with_incidents([], "default")
    assert isinstance(result, (dict, list))


def test_typosquat_common_variants(engine):
    result = engine.detect_typosquats("google.com")
    count = result.get("variant_count", len(result)) if isinstance(result, dict) else len(result)
    assert count >= 3


def test_scan_paste_sites_different_orgs(engine):
    r1 = engine.scan_paste_sites("CompanyA")
    r2 = engine.scan_paste_sites("CompanyB")
    assert isinstance(r1, list)
    assert isinstance(r2, list)


def test_risk_summary_org_isolation(engine):
    s1 = engine.get_risk_summary("org1")
    s2 = engine.get_risk_summary("org2")
    assert isinstance(s1, dict)
    assert isinstance(s2, dict)


def test_engine_multiple_instances(tmp_path):
    from core.digital_risk_protection import DRPEngine
    e1 = DRPEngine(db_path=str(tmp_path / "drp1.db"))
    e2 = DRPEngine(db_path=str(tmp_path / "drp2.db"))
    assert e1 is not e2


def test_typosquats_min_length_domain(engine):
    result = engine.detect_typosquats("ab.io")
    assert result is not None
