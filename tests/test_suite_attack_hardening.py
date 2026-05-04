"""
Smoke tests for suite-attack OWASP hardening.

Covers the 5 real issues fixed:
1. dast_router: broad `except Exception` narrowed; exc text no longer leaked in 500 detail
2. dast_router: /status alias added
3. vuln_discovery_router: bare `except Exception` narrowed in TrustGraph fire-and-forget
4. vuln_discovery_router: proof_of_concept max_length=50_000; description max_length=32_000
5. vuln_discovery_router: ContributeRequest field lengths + email format validation
6. attack_sim_router: CreateScenarioRequest / GenerateScenarioRequest field max_length guards
"""
from __future__ import annotations

import inspect

import pytest


# ---------------------------------------------------------------------------
# 1. Module imports — ensure hardened files load without error
# ---------------------------------------------------------------------------

def test_dast_router_imports():
    from api import dast_router
    assert hasattr(dast_router, "router")


def test_attack_sim_router_imports():
    from api import attack_sim_router
    assert hasattr(attack_sim_router, "router")


def test_vuln_discovery_router_imports():
    from api import vuln_discovery_router
    assert hasattr(vuln_discovery_router, "router")


# ---------------------------------------------------------------------------
# 2. dast_router: /status route must exist
# ---------------------------------------------------------------------------

def test_dast_router_has_status_route():
    from api import dast_router
    paths = [r.path for r in dast_router.router.routes]
    assert "/api/v1/dast/status" in paths, f"Missing /status alias; routes: {paths}"


def test_dast_router_has_health_route():
    from api import dast_router
    paths = [r.path for r in dast_router.router.routes]
    assert "/api/v1/dast/health" in paths


# ---------------------------------------------------------------------------
# 3. dast_router: exception narrowing — no broad Exception catch leaking detail
# ---------------------------------------------------------------------------

def test_dast_router_no_broad_exception_in_start_scan():
    from api import dast_router
    src = inspect.getsource(dast_router.start_scan)
    assert "except Exception" not in src, "start_scan still uses broad `except Exception`"


def test_dast_router_no_exc_leak_in_headers_check():
    from api import dast_router
    src = inspect.getsource(dast_router.check_security_headers)
    assert "except Exception" not in src, "check_security_headers still uses broad `except Exception`"
    assert 'detail=f"Headers check failed: {exc}"' not in src


# ---------------------------------------------------------------------------
# 4. attack_sim_router: CreateScenarioRequest field length limits
# ---------------------------------------------------------------------------

def test_create_scenario_request_name_max_length():
    from api.attack_sim_router import CreateScenarioRequest
    import pydantic
    with pytest.raises(pydantic.ValidationError) as exc_info:
        CreateScenarioRequest(name="A" * 257, description="d", threat_actor="t", complexity="low")
    assert "name" in str(exc_info.value)


def test_create_scenario_request_description_max_length():
    from api.attack_sim_router import CreateScenarioRequest
    import pydantic
    with pytest.raises(pydantic.ValidationError) as exc_info:
        CreateScenarioRequest(name="valid", description="D" * 4097)
    assert "description" in str(exc_info.value)


def test_create_scenario_request_valid():
    from api.attack_sim_router import CreateScenarioRequest
    req = CreateScenarioRequest(
        name="Test Scenario",
        description="A test",
        threat_actor="nation_state",
        complexity="high",
    )
    assert req.name == "Test Scenario"


# ---------------------------------------------------------------------------
# 5. attack_sim_router: GenerateScenarioRequest field length limits
# ---------------------------------------------------------------------------

def test_generate_scenario_target_description_max_length():
    from api.attack_sim_router import GenerateScenarioRequest
    import pydantic
    with pytest.raises(pydantic.ValidationError) as exc_info:
        GenerateScenarioRequest(target_description="X" * 1025)
    assert "target_description" in str(exc_info.value)


def test_generate_scenario_attack_type_max_length():
    from api.attack_sim_router import GenerateScenarioRequest
    import pydantic
    with pytest.raises(pydantic.ValidationError) as exc_info:
        GenerateScenarioRequest(attack_type="x" * 65)
    assert "attack_type" in str(exc_info.value)


def test_generate_scenario_valid():
    from api.attack_sim_router import GenerateScenarioRequest
    req = GenerateScenarioRequest(target_description="Web API", threat_actor="cybercriminal")
    assert req.threat_actor == "cybercriminal"


# ---------------------------------------------------------------------------
# 6. vuln_discovery_router: DiscoveredVulnRequest field length limits
# ---------------------------------------------------------------------------

def test_discovered_vuln_request_description_max_length():
    from api.vuln_discovery_router import DiscoveredVulnRequest
    import pydantic
    with pytest.raises(pydantic.ValidationError) as exc_info:
        DiscoveredVulnRequest(title="t", description="D" * 32_001)
    assert "description" in str(exc_info.value)


def test_discovered_vuln_request_poc_max_length():
    from api.vuln_discovery_router import DiscoveredVulnRequest
    import pydantic
    with pytest.raises(pydantic.ValidationError) as exc_info:
        DiscoveredVulnRequest(title="t", proof_of_concept="P" * 50_001)
    assert "proof_of_concept" in str(exc_info.value)


def test_discovered_vuln_request_valid():
    from api.vuln_discovery_router import DiscoveredVulnRequest
    req = DiscoveredVulnRequest(title="XSS in login form", description="Reflected XSS via name param")
    assert req.title == "XSS in login form"


# ---------------------------------------------------------------------------
# 7. vuln_discovery_router: ContributeRequest email validation
# ---------------------------------------------------------------------------

def test_contribute_request_email_format_invalid():
    from api.vuln_discovery_router import ContributeRequest, ContributionProgram
    import pydantic
    with pytest.raises(pydantic.ValidationError) as exc_info:
        ContributeRequest(
            vuln_id="ALDECI-2026-0001",
            program=ContributionProgram.MITRE,
            researcher_name="Alice",
            researcher_email="not-an-email",
        )
    assert "researcher_email" in str(exc_info.value)


def test_contribute_request_email_format_valid():
    from api.vuln_discovery_router import ContributeRequest, ContributionProgram
    req = ContributeRequest(
        vuln_id="ALDECI-2026-0001",
        program=ContributionProgram.MITRE,
        researcher_name="Alice",
        researcher_email="alice@example.com",
    )
    assert req.researcher_email == "alice@example.com"


def test_contribute_request_email_max_length():
    from api.vuln_discovery_router import ContributeRequest, ContributionProgram
    import pydantic
    long_email = "a" * 250 + "@b.com"  # > 254 chars
    with pytest.raises(pydantic.ValidationError) as exc_info:
        ContributeRequest(
            vuln_id="ALDECI-2026-0001",
            program=ContributionProgram.MITRE,
            researcher_name="Alice",
            researcher_email=long_email,
        )
    assert "researcher_email" in str(exc_info.value)


def test_contribute_request_name_max_length():
    from api.vuln_discovery_router import ContributeRequest, ContributionProgram
    import pydantic
    with pytest.raises(pydantic.ValidationError) as exc_info:
        ContributeRequest(
            vuln_id="ALDECI-2026-0001",
            program=ContributionProgram.MITRE,
            researcher_name="A" * 257,
            researcher_email="alice@example.com",
        )
    assert "researcher_name" in str(exc_info.value)


# ---------------------------------------------------------------------------
# 8. vuln_discovery_router: bare except narrowed (source inspection)
# ---------------------------------------------------------------------------

def test_vuln_discovery_no_bare_except_in_report():
    from api import vuln_discovery_router
    src = inspect.getsource(vuln_discovery_router.report_discovered_vulnerability)
    assert "except Exception:" not in src, \
        "report_discovered_vulnerability still has bare `except Exception:`"
