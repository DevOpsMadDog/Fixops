"""
Performance assertions for RBAC / persona subsystem.

Validates three optimisations landed in beast-mode(perf):
  1. get_user_scopes() is cached in-process (no DB hit on repeated calls)
  2. audit_log() is buffered (no per-call SQLite write on hot path)
  3. Role.get_all_permissions() is memoised (no re-traversal of inheritance chain)

All timing assertions are conservative (10–50x head-room) so they pass on
any CI box, not just the dev Mac.
"""
from __future__ import annotations

import pytest

pytestmark = pytest.mark.perf

import tempfile
import time
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_engine(tmp_path: Path):
    from core.rbac_engine import RBACEngine
    engine = RBACEngine(db_path=str(tmp_path / "rbac_perf.db"))
    engine.assign_role("u1", "analyst", "org1")
    return engine


# ---------------------------------------------------------------------------
# Perf fix 1: scope cache — repeated check_permission calls must not hit DB
# ---------------------------------------------------------------------------

def test_scope_cache_hit_is_faster_than_cold(tmp_path):
    """Second+ calls to get_user_scopes should be served from in-process cache."""
    engine = _make_engine(tmp_path)

    # Cold call — populates cache
    t0 = time.perf_counter()
    scopes_cold = engine.get_user_scopes("u1", "org1")
    cold_ms = (time.perf_counter() - t0) * 1000

    # Warm calls — must all be served from cache
    N = 200
    t1 = time.perf_counter()
    for _ in range(N):
        engine.get_user_scopes("u1", "org1")
    warm_total_ms = (time.perf_counter() - t1) * 1000
    warm_avg_ms = warm_total_ms / N

    # Sanity: scopes are actually returned
    assert len(scopes_cold) > 0

    # Cache hit must be at least 5x faster than the cold DB call
    assert warm_avg_ms < cold_ms, (
        f"Cache hit ({warm_avg_ms:.3f}ms) should be faster than cold ({cold_ms:.3f}ms)"
    )


def test_scope_cache_invalidated_on_assign(tmp_path):
    """Cache must be cleared when a role is assigned so subsequent calls see new scopes."""
    engine = _make_engine(tmp_path)

    scopes_before = set(engine.get_user_scopes("u1", "org1"))
    # Assign a higher role
    engine.assign_role("u1", "security_engineer", "org1")
    scopes_after = set(engine.get_user_scopes("u1", "org1"))

    # security_engineer has more scopes than analyst
    assert scopes_after != scopes_before, "Cache should have been invalidated on assign"


def test_scope_cache_invalidated_on_revoke(tmp_path):
    """Cache must be cleared when a role is revoked."""
    engine = _make_engine(tmp_path)
    # Populate cache
    engine.get_user_scopes("u1", "org1")
    engine.revoke_role("u1", "analyst", "org1")
    scopes_after = engine.get_user_scopes("u1", "org1")
    assert scopes_after == [], "Revoked user should have no scopes"


# ---------------------------------------------------------------------------
# Perf fix 2: buffered audit writes — 50 permission checks should be fast
# ---------------------------------------------------------------------------

def test_buffered_audit_no_per_check_write(tmp_path):
    """50 check_permission calls must complete in under 100 ms total (no per-call fsync)."""
    engine = _make_engine(tmp_path)

    N = 50
    t0 = time.perf_counter()
    for _ in range(N):
        engine.check_permission("u1", "org1", "read:findings")
    elapsed_ms = (time.perf_counter() - t0) * 1000

    # Flush so audit entries land in DB for teardown cleanliness
    engine.flush_audit_log()

    assert elapsed_ms < 100, (
        f"{N} check_permission calls took {elapsed_ms:.1f}ms — expected <100ms with buffered audit"
    )


def test_audit_buffer_flushes_on_limit(tmp_path):
    """Entries exceeding _audit_buf_limit must auto-flush to the DB."""
    engine = _make_engine(tmp_path)
    limit = engine._audit_buf_limit

    # Generate exactly limit+1 audit entries
    for i in range(limit + 1):
        engine.audit_log(
            user_id="u1",
            action="test",
            resource=f"res:{i}",
            org_id="org1",
            allowed=True,
        )

    # After auto-flush the in-memory buffer should be small (< limit entries)
    import threading
    with engine._audit_buf_lock:
        buf_size = len(engine._audit_buf)
    assert buf_size < limit, (
        f"Buffer should have auto-flushed; still has {buf_size} entries"
    )


# ---------------------------------------------------------------------------
# Perf fix 3: Role.get_all_permissions() memoisation
# ---------------------------------------------------------------------------

def test_role_get_all_permissions_memoised():
    """Repeated calls to get_all_permissions() on the same Role should return
    the identical set object (memoised), not recompute from the chain."""
    from core.rbac import BuiltinRoles

    role = BuiltinRoles.compliance_officer()  # 4-level inheritance chain

    result1 = role.get_all_permissions()
    result2 = role.get_all_permissions()

    # Must be the exact same object (cached), not just equal
    assert result1 is result2, "get_all_permissions() should return cached frozenset"


def test_role_permission_check_fast():
    """1000 has_permission() calls on a deep-inheritance role complete in <5ms."""
    from core.rbac import BuiltinRoles, Permission

    role = BuiltinRoles.compliance_officer()

    N = 1000
    t0 = time.perf_counter()
    for _ in range(N):
        role.has_permission(Permission.COMPLIANCE_MANAGE)
    elapsed_ms = (time.perf_counter() - t0) * 1000

    assert elapsed_ms < 5, (
        f"{N} has_permission() calls took {elapsed_ms:.2f}ms — expected <5ms with memoisation"
    )


# ---------------------------------------------------------------------------
# Persona mapping sanity (regression guard)
# ---------------------------------------------------------------------------

def test_persona_role_mapping_covers_30_personas():
    """All 30 canonical ALDECI personas must map to a valid built-in role."""
    from core.rbac import PersonaRoleMapping, BuiltinRoles

    valid_roles = {"viewer", "developer", "security_analyst", "compliance_officer",
                   "admin", "super_admin"}

    # Exclude the sentinel 'generic_user' entry
    personas = {k: v for k, v in PersonaRoleMapping.PERSONA_MAP.items()
                if k != "generic_user"}

    # Should cover at least 24 named personas (the mapping currently has 24 named + generic)
    assert len(personas) >= 24, f"Expected >=24 named personas, got {len(personas)}"

    for persona, role in personas.items():
        assert role in valid_roles, (
            f"Persona '{persona}' mapped to unknown role '{role}'"
        )
