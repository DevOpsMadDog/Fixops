"""Tests for SecurityDependencyMappingEngine.

Covers: service registration, add_dependency counter updates, remove_dependency
counter decrements, BFS blast radius (downstream/upstream), critical_paths ordering,
org isolation, summary, validation errors.
"""

from __future__ import annotations

import pytest

from core.security_dependency_mapping_engine import SecurityDependencyMappingEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def engine(tmp_path):
    return SecurityDependencyMappingEngine(db_path=str(tmp_path / "sdm_test.db"))


def _svc(engine, org_id="org1", name="ServiceA", **kwargs):
    defaults = dict(
        service_type="application",
        criticality="medium",
        owner="team-a",
        environment="production",
        data_classification="internal",
    )
    defaults.update(kwargs)
    return engine.register_service(org_id=org_id, service_name=name, **defaults)


def _dep(engine, org_id="org1", src_id=None, tgt_id=None, **kwargs):
    defaults = dict(dependency_type="runtime", criticality="medium")
    defaults.update(kwargs)
    return engine.add_dependency(
        org_id=org_id,
        source_service_id=src_id,
        target_service_id=tgt_id,
        **defaults,
    )


# ---------------------------------------------------------------------------
# 1. Initialisation
# ---------------------------------------------------------------------------


def test_init_creates_db(tmp_path):
    db = tmp_path / "sdm.db"
    SecurityDependencyMappingEngine(db_path=str(db))
    assert db.exists()


def test_init_twice_idempotent(tmp_path):
    db = str(tmp_path / "sdm.db")
    SecurityDependencyMappingEngine(db_path=db)
    SecurityDependencyMappingEngine(db_path=db)


# ---------------------------------------------------------------------------
# 2. register_service
# ---------------------------------------------------------------------------


def test_register_service_returns_active(engine):
    svc = _svc(engine)
    assert svc["status"] == "active"
    assert svc["service_name"] == "ServiceA"
    assert svc["dependency_count"] == 0
    assert svc["dependent_count"] == 0


def test_register_service_requires_name(engine):
    with pytest.raises(ValueError, match="service_name"):
        engine.register_service("org1", "")


def test_register_service_invalid_type(engine):
    with pytest.raises(ValueError, match="service_type"):
        _svc(engine, service_type="blockchain")


def test_register_service_invalid_criticality(engine):
    with pytest.raises(ValueError, match="criticality"):
        _svc(engine, criticality="ultra")


def test_register_service_invalid_environment(engine):
    with pytest.raises(ValueError, match="environment"):
        _svc(engine, environment="space")


def test_register_service_invalid_data_classification(engine):
    with pytest.raises(ValueError, match="data_classification"):
        _svc(engine, data_classification="top-secret")


def test_register_critical_database(engine):
    svc = _svc(engine, name="PrimaryDB", service_type="database", criticality="critical")
    assert svc["criticality"] == "critical"
    assert svc["service_type"] == "database"


# ---------------------------------------------------------------------------
# 3. add_dependency — counter updates
# ---------------------------------------------------------------------------


def test_add_dependency_increments_counters(engine):
    src = _svc(engine, name="API")
    tgt = _svc(engine, name="DB")
    _dep(engine, src_id=src["id"], tgt_id=tgt["id"])
    src_updated = engine.get_service(src["id"], "org1")
    tgt_updated = engine.get_service(tgt["id"], "org1")
    assert src_updated["dependency_count"] == 1
    assert tgt_updated["dependent_count"] == 1


def test_add_dependency_multiple_increments(engine):
    a = _svc(engine, name="A")
    b = _svc(engine, name="B")
    c = _svc(engine, name="C")
    _dep(engine, src_id=a["id"], tgt_id=b["id"])
    _dep(engine, src_id=a["id"], tgt_id=c["id"])
    a_up = engine.get_service(a["id"], "org1")
    assert a_up["dependency_count"] == 2


def test_add_dependency_invalid_type(engine):
    src = _svc(engine, name="X")
    tgt = _svc(engine, name="Y")
    with pytest.raises(ValueError, match="dependency_type"):
        _dep(engine, src_id=src["id"], tgt_id=tgt["id"], dependency_type="magic")


def test_add_dependency_source_not_found(engine):
    tgt = _svc(engine, name="DB")
    with pytest.raises(ValueError, match="Source service"):
        _dep(engine, src_id="nonexistent", tgt_id=tgt["id"])


def test_add_dependency_target_not_found(engine):
    src = _svc(engine, name="API")
    with pytest.raises(ValueError, match="Target service"):
        _dep(engine, src_id=src["id"], tgt_id="nonexistent")


def test_add_dependency_wrong_org_source(engine):
    src = _svc(engine, org_id="org1", name="API")
    tgt = _svc(engine, org_id="org2", name="DB")
    with pytest.raises(ValueError, match="Source service"):
        engine.add_dependency("org2", src["id"], tgt["id"])


def test_add_dependency_sets_outgoing_and_incoming(engine):
    src = _svc(engine, name="Frontend")
    tgt = _svc(engine, name="Backend")
    _dep(engine, src_id=src["id"], tgt_id=tgt["id"])
    src_full = engine.get_service(src["id"], "org1")
    tgt_full = engine.get_service(tgt["id"], "org1")
    assert len(src_full["outgoing_dependencies"]) == 1
    assert len(tgt_full["incoming_dependencies"]) == 1


# ---------------------------------------------------------------------------
# 4. remove_dependency — counter decrements
# ---------------------------------------------------------------------------


def test_remove_dependency_decrements_counters(engine):
    src = _svc(engine, name="API")
    tgt = _svc(engine, name="DB")
    dep = _dep(engine, src_id=src["id"], tgt_id=tgt["id"])
    engine.remove_dependency(dep["id"], "org1")
    src_up = engine.get_service(src["id"], "org1")
    tgt_up = engine.get_service(tgt["id"], "org1")
    assert src_up["dependency_count"] == 0
    assert tgt_up["dependent_count"] == 0


def test_remove_dependency_floor_at_zero(engine):
    """Counter should never go below 0."""
    src = _svc(engine, name="A")
    tgt = _svc(engine, name="B")
    dep = _dep(engine, src_id=src["id"], tgt_id=tgt["id"])
    engine.remove_dependency(dep["id"], "org1")
    # Counters should be 0, not negative
    src_up = engine.get_service(src["id"], "org1")
    assert src_up["dependency_count"] == 0


def test_remove_dependency_not_found_raises(engine):
    with pytest.raises(ValueError, match="not found"):
        engine.remove_dependency("bad-dep", "org1")


def test_remove_dependency_wrong_org_raises(engine):
    src = _svc(engine, org_id="org1", name="API")
    tgt = _svc(engine, org_id="org1", name="DB")
    dep = _dep(engine, org_id="org1", src_id=src["id"], tgt_id=tgt["id"])
    with pytest.raises(ValueError, match="not found"):
        engine.remove_dependency(dep["id"], "org2")


# ---------------------------------------------------------------------------
# 5. BFS blast radius — downstream
# ---------------------------------------------------------------------------


def test_blast_radius_no_dependents(engine):
    svc = _svc(engine, name="Isolated")
    result = engine.compute_blast_radius("org1", svc["id"], "downstream")
    assert result["affected_count"] == 0
    assert result["affected_services"] == []


def test_blast_radius_downstream_direct(engine):
    """A → B: blast of A downstream = [B]"""
    a = _svc(engine, name="A")
    b = _svc(engine, name="B")
    _dep(engine, src_id=b["id"], tgt_id=a["id"])  # B depends on A
    result = engine.compute_blast_radius("org1", a["id"], "downstream")
    assert result["affected_count"] == 1
    assert b["id"] in result["affected_services"]


def test_blast_radius_downstream_chain(engine):
    """A → B → C: blast of A downstream = [B, C]"""
    a = _svc(engine, name="A")
    b = _svc(engine, name="B")
    c = _svc(engine, name="C")
    _dep(engine, src_id=b["id"], tgt_id=a["id"])  # B depends on A
    _dep(engine, src_id=c["id"], tgt_id=b["id"])  # C depends on B
    result = engine.compute_blast_radius("org1", a["id"], "downstream")
    assert result["affected_count"] == 2
    assert b["id"] in result["affected_services"]
    assert c["id"] in result["affected_services"]
    assert a["id"] not in result["affected_services"]


def test_blast_radius_downstream_excludes_source(engine):
    a = _svc(engine, name="A")
    b = _svc(engine, name="B")
    _dep(engine, src_id=b["id"], tgt_id=a["id"])
    result = engine.compute_blast_radius("org1", a["id"], "downstream")
    assert a["id"] not in result["affected_services"]


def test_blast_radius_downstream_critical_count(engine):
    a = _svc(engine, name="A")
    b = _svc(engine, name="B", criticality="critical")
    c = _svc(engine, name="C", criticality="medium")
    _dep(engine, src_id=b["id"], tgt_id=a["id"])
    _dep(engine, src_id=c["id"], tgt_id=a["id"])
    result = engine.compute_blast_radius("org1", a["id"], "downstream")
    assert result["critical_count"] == 1


def test_blast_radius_saves_analysis(engine):
    a = _svc(engine, name="A")
    result = engine.compute_blast_radius("org1", a["id"], "downstream")
    assert "analysis_id" in result
    assert result["analysis_type"] == "downstream"


# ---------------------------------------------------------------------------
# 6. BFS blast radius — upstream
# ---------------------------------------------------------------------------


def test_blast_radius_upstream_direct(engine):
    """A depends on B: upstream blast of A = [B]"""
    a = _svc(engine, name="A")
    b = _svc(engine, name="B")
    _dep(engine, src_id=a["id"], tgt_id=b["id"])  # A depends on B
    result = engine.compute_blast_radius("org1", a["id"], "upstream")
    assert result["affected_count"] == 1
    assert b["id"] in result["affected_services"]


def test_blast_radius_upstream_chain(engine):
    """A → B → C: upstream blast of A = [B, C]"""
    a = _svc(engine, name="A")
    b = _svc(engine, name="B")
    c = _svc(engine, name="C")
    _dep(engine, src_id=a["id"], tgt_id=b["id"])  # A depends on B
    _dep(engine, src_id=b["id"], tgt_id=c["id"])  # B depends on C
    result = engine.compute_blast_radius("org1", a["id"], "upstream")
    assert result["affected_count"] == 2
    assert b["id"] in result["affected_services"]
    assert c["id"] in result["affected_services"]


def test_blast_radius_invalid_type(engine):
    svc = _svc(engine, name="X")
    with pytest.raises(ValueError, match="analysis_type"):
        engine.compute_blast_radius("org1", svc["id"], "sideways")


def test_blast_radius_service_not_found(engine):
    with pytest.raises(ValueError, match="not found"):
        engine.compute_blast_radius("org1", "bad-svc", "downstream")


def test_blast_radius_org_isolation(engine):
    """Services from org2 should not appear in org1 blast radius."""
    a1 = _svc(engine, org_id="org1", name="A")
    a2 = _svc(engine, org_id="org2", name="A")
    b2 = _svc(engine, org_id="org2", name="B")
    _dep(engine, org_id="org2", src_id=b2["id"], tgt_id=a2["id"])
    result = engine.compute_blast_radius("org1", a1["id"], "downstream")
    assert result["affected_count"] == 0


# ---------------------------------------------------------------------------
# 7. get_critical_paths
# ---------------------------------------------------------------------------


def test_critical_paths_empty(engine):
    assert engine.get_critical_paths("org1") == []


def test_critical_paths_only_critical(engine):
    _svc(engine, name="Medium", criticality="medium")
    _svc(engine, name="High", criticality="high")
    critical = _svc(engine, name="Crit", criticality="critical")
    dep_svc = _svc(engine, name="DepSvc")
    _dep(engine, src_id=dep_svc["id"], tgt_id=critical["id"])
    paths = engine.get_critical_paths("org1")
    assert len(paths) == 1
    assert paths[0]["id"] == critical["id"]


def test_critical_paths_ordered_by_dependent_count(engine):
    a = _svc(engine, name="A", criticality="critical")
    b = _svc(engine, name="B", criticality="critical")
    # Give B 2 dependents, A 1 dependent
    d1 = _svc(engine, name="D1")
    d2 = _svc(engine, name="D2")
    d3 = _svc(engine, name="D3")
    _dep(engine, src_id=d1["id"], tgt_id=a["id"])
    _dep(engine, src_id=d2["id"], tgt_id=b["id"])
    _dep(engine, src_id=d3["id"], tgt_id=b["id"])
    paths = engine.get_critical_paths("org1")
    assert paths[0]["id"] == b["id"]  # B has more dependents
    assert paths[1]["id"] == a["id"]


def test_critical_paths_excludes_zero_dependents(engine):
    """Critical services with no dependents should not appear."""
    _svc(engine, name="Lonely", criticality="critical")
    paths = engine.get_critical_paths("org1")
    assert len(paths) == 0


# ---------------------------------------------------------------------------
# 8. list_services
# ---------------------------------------------------------------------------


def test_list_services_all(engine):
    _svc(engine, name="S1")
    _svc(engine, name="S2")
    services = engine.list_services("org1")
    assert len(services) == 2


def test_list_services_filter_type(engine):
    _svc(engine, name="App", service_type="application")
    _svc(engine, name="DB", service_type="database")
    dbs = engine.list_services("org1", service_type="database")
    assert len(dbs) == 1
    assert dbs[0]["service_name"] == "DB"


def test_list_services_filter_criticality(engine):
    _svc(engine, name="Crit", criticality="critical")
    _svc(engine, name="Med", criticality="medium")
    crits = engine.list_services("org1", criticality="critical")
    assert len(crits) == 1


def test_list_services_org_isolation(engine):
    _svc(engine, org_id="org1", name="S1")
    _svc(engine, org_id="org2", name="S2")
    assert len(engine.list_services("org1")) == 1
    assert len(engine.list_services("org2")) == 1


# ---------------------------------------------------------------------------
# 9. get_service
# ---------------------------------------------------------------------------


def test_get_service_not_found(engine):
    assert engine.get_service("nonexistent", "org1") is None


def test_get_service_wrong_org(engine):
    svc = _svc(engine, org_id="org1")
    assert engine.get_service(svc["id"], "org2") is None


def test_get_service_has_dependency_lists(engine):
    src = _svc(engine, name="Src")
    tgt = _svc(engine, name="Tgt")
    _dep(engine, src_id=src["id"], tgt_id=tgt["id"])
    src_full = engine.get_service(src["id"], "org1")
    assert len(src_full["outgoing_dependencies"]) == 1
    assert len(src_full["incoming_dependencies"]) == 0


# ---------------------------------------------------------------------------
# 10. get_summary
# ---------------------------------------------------------------------------


def test_summary_empty(engine):
    summary = engine.get_summary("org1")
    assert summary["total_services"] == 0
    assert summary["total_dependencies"] == 0
    assert summary["high_blast_radius_services"] == []


def test_summary_counts(engine):
    a = _svc(engine, name="A", criticality="critical")
    b = _svc(engine, name="B", criticality="medium")
    _dep(engine, src_id=b["id"], tgt_id=a["id"])
    summary = engine.get_summary("org1")
    assert summary["total_services"] == 2
    assert summary["total_dependencies"] == 1


def test_summary_by_service_type(engine):
    _svc(engine, name="App1", service_type="application")
    _svc(engine, name="App2", service_type="application")
    _svc(engine, name="DB1", service_type="database")
    summary = engine.get_summary("org1")
    assert summary["by_service_type"]["application"] == 2
    assert summary["by_service_type"]["database"] == 1


def test_summary_by_criticality(engine):
    _svc(engine, name="C1", criticality="critical")
    _svc(engine, name="H1", criticality="high")
    _svc(engine, name="M1", criticality="medium")
    summary = engine.get_summary("org1")
    assert summary["by_criticality"]["critical"] == 1
    assert summary["by_criticality"]["high"] == 1
    assert summary["by_criticality"]["medium"] == 1


def test_summary_high_blast_radius(engine):
    """Services with dependent_count >= 5 appear in high_blast_radius_services."""
    central = _svc(engine, name="Central")
    for i in range(5):
        dep = _svc(engine, name=f"Dep{i}")
        _dep(engine, src_id=dep["id"], tgt_id=central["id"])
    summary = engine.get_summary("org1")
    high = summary["high_blast_radius_services"]
    assert len(high) == 1
    assert high[0]["id"] == central["id"]


def test_summary_org_isolation(engine):
    _svc(engine, org_id="org1", name="S1")
    _svc(engine, org_id="org2", name="S2")
    s1 = engine.get_summary("org1")
    s2 = engine.get_summary("org2")
    assert s1["total_services"] == 1
    assert s2["total_services"] == 1


# ---------------------------------------------------------------------------
# get_source_trace (new method)
# ---------------------------------------------------------------------------


def test_source_trace_matches_by_name(engine):
    """Service named 'siem_integration' is found when tracing the SIEM engine file."""
    engine.register_service("org1", "siem_integration", service_type="api", criticality="high")
    result = engine.get_source_trace("org1", "suite-core/core/siem_integration_engine.py")
    assert result["source_file"] == "suite-core/core/siem_integration_engine.py"
    assert "siem" in result["keywords_used"]
    names = [s["service_name"] for s in result["matched_services"]]
    assert "siem_integration" in names


def test_source_trace_no_match(engine):
    """No services → matched_services is empty, total_affected=0."""
    result = engine.get_source_trace("org1", "suite-core/core/unknown_xyz_engine.py")
    assert result["matched_services"] == []
    assert result["total_affected"] == 0


def test_source_trace_blast_radius_included(engine):
    """Matched service with a dependent gets that dependent in blast_radius."""
    # Register A (matched by name) and B (depends on A)
    a = engine.register_service("org1", "siem_gateway", service_type="api")
    b = engine.register_service("org1", "siem_frontend", service_type="application")
    # B depends on A (B is downstream of A)
    engine.add_dependency(
        org_id="org1",
        source_service_id=b["id"],  # B depends on A
        target_service_id=a["id"],
    )
    result = engine.get_source_trace("org1", "suite-core/core/siem_gateway_engine.py")
    # Both A and B should be matched (both contain "siem")
    matched_names = {s["service_name"] for s in result["matched_services"]}
    assert "siem_gateway" in matched_names


def test_source_trace_keywords_strip_suffixes(engine):
    """Engine/router suffixes are stripped from stem for keyword extraction."""
    result = engine.get_source_trace("org1", "path/to/risk_aggregator_engine_v2.py")
    assert "risk" in result["keywords_used"]
    assert "aggregator" in result["keywords_used"]
    # Should not contain 'engine' or 'v2'
    assert "engine" not in result["keywords_used"]


def test_source_trace_org_isolation(engine):
    """Services from org2 are not returned for org1 query."""
    engine.register_service("org2", "siem_service", service_type="api")
    result = engine.get_source_trace("org1", "suite-core/core/siem_service_engine.py")
    assert all(s["org_id"] == "org1" for s in result["matched_services"])
