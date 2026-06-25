"""SPEC-033 (extension) — UI panel stats contract: engines must return the keys
their dashboard panels read.

Guards the stats-contract-drift class fixed 2026-06-26 (10 panels whose engine
get_*_stats returned keys under different names -> blank/0 dashboard widgets).
Engine-level (no app boot): for each engine, call its stats method for a FRESH
org and assert the exact key set the UI panel reads is present AND honest-empty
(zeros, no fabrication). If a future refactor renames a key, this fails loudly.
"""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("FIXOPS_API_TOKEN", "ci-test-token")

# (import path, class, stats-method, {UI-required keys}, {numeric keys expected 0 for fresh org})
_CASES = [
    ("core.digital_forensics_engine", "DigitalForensicsEngine", "get_forensics_stats",
     {"total_cases", "open_cases", "closed_cases", "critical_cases"}, {"total_cases"}),
    ("core.certificate_lifecycle_engine", "CertificateLifecycleEngine", "get_certificate_stats",
     {"total", "valid", "expired", "expiring_soon"}, {"total"}),
    ("core.security_posture_scoring_engine", "SecurityPostureScoringEngine", "get_posture_stats",
     {"total_controls", "implemented", "not_implemented", "partial", "domain_scores", "overall_score"}, {"total_controls"}),
    ("core.threat_actor_engine", "ThreatActorEngine", "get_stats",
     {"total_actors", "active_actors", "avg_threat_score"}, {"total_actors"}),
    ("core.uba_engine", "UBAEngine", "get_uba_stats",
     {"total_users", "high_risk_users", "open_alerts", "anomalous_events"}, {"total_users"}),
    ("core.pki_management_engine", "PKIManagementEngine", "get_pki_stats",
     {"total_certificates", "active_certificates", "expiring_soon", "total_cas"}, {"total_certificates"}),
    ("core.privacy_gdpr_engine", "PrivacyGDPREngine", "get_privacy_stats",
     {"total_dsrs", "total_incidents", "overdue_dsrs", "total_processing_activities"}, {"total_dsrs"}),
    ("core.identity_governance_engine", "IdentityGovernanceEngine", "get_governance_stats",
     {"total_entitlements", "excessive_entitlements", "orphaned_entitlements", "open_reviews", "total_policies", "total_reviews"}, {"total_entitlements"}),
    ("core.pipeline_bom_engine", "PipelineBOMEngine", "stats",
     {"total_artifacts", "total_deployments", "total_runs", "total_steps", "runs_by_status", "ci_providers", "artifact_types"}, {"total_artifacts"}),
    ("core.crypto_key_management_engine", "CryptoKeyManagementEngine", "get_key_stats",
     {"total", "active", "by_algorithm", "expired", "expiring_soon", "revoked"}, {"total"}),
]


@pytest.mark.parametrize("mod,cls,method,keys,zero_keys", _CASES, ids=[c[1] for c in _CASES])
def test_panel_stats_contract(mod, cls, method, keys, zero_keys):
    import importlib

    engine = getattr(importlib.import_module(mod), cls)()
    stats = getattr(engine, method)(org_id=f"contract-fresh-{cls.lower()}")
    assert isinstance(stats, dict), f"{cls}.{method} did not return a dict"
    missing = keys - set(stats)
    assert not missing, f"{cls}.{method} missing UI keys {missing} (panel widgets would blank)"
    # honest-empty: a fresh org reports zeros, never fabricated data
    for k in zero_keys:
        assert stats[k] == 0, f"{cls}.{method}[{k}] not honest-empty for a fresh org: {stats[k]}"
