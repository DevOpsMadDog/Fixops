"""Multi-tenant RBAC engine — role-based access control with tenant isolation."""
from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional

import structlog

_logger = structlog.get_logger()

# ---------------------------------------------------------------------------
# The 6 ALDECI roles with inheritance and scopes
# ---------------------------------------------------------------------------

ROLES: Dict[str, Dict[str, Any]] = {
    "super_admin": {
        "inherits": [],
        "scopes": ["admin:all", "read:*", "write:*", "attack:execute"],
    },
    "org_admin": {
        "inherits": ["security_engineer"],
        "scopes": ["admin:org", "read:*", "write:*"],
    },
    "security_engineer": {
        "inherits": ["analyst"],
        "scopes": ["write:findings", "write:integrations", "read:*"],
    },
    "analyst": {
        "inherits": ["viewer"],
        "scopes": ["read:findings", "read:feeds", "read:evidence", "write:comments"],
    },
    "viewer": {
        "inherits": [],
        "scopes": ["read:findings", "read:feeds"],
    },
    "auditor": {
        "inherits": ["viewer"],
        "scopes": ["read:findings", "read:evidence", "read:audit"],
    },
}

# Data classification hierarchy for wildcard resolution
_WILDCARD_PREFIXES = {"admin:all", "read:*", "write:*"}


def _scope_matches(user_scope: str, required_scope: str) -> bool:
    """Check if user_scope satisfies required_scope (handles wildcards)."""
    if user_scope == required_scope:
        return True
    if user_scope == "admin:all":
        return True
    if user_scope == "read:*" and required_scope.startswith("read:"):
        return True
    if user_scope == "write:*" and required_scope.startswith("write:"):
        return True
    return False


# ---------------------------------------------------------------------------
# RBACEngine
# ---------------------------------------------------------------------------


class RBACEngine:
    """
    Multi-tenant RBAC engine with SQLite persistence, role hierarchy,
    scope inheritance, tenant isolation, and audit trail.
    """

    # Per-instance in-process cache: (user_id, org_id) -> frozenset[str] of scopes
    # Invalidated on assign_role / revoke_role. Max 512 entries (LRU via ordered dict).
    _SCOPE_CACHE_MAX = 512

    def __init__(self, db_path: str = "data/rbac.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        # Perf fix 1: in-process scope cache (avoids DB + hierarchy walk per check)
        self._scope_cache: dict[tuple[str, str], frozenset[str]] = {}
        self._scope_cache_order: list[tuple[str, str]] = []
        self._scope_cache_lock = threading.Lock()
        # Perf fix 2: deferred audit write buffer (batched, avoids per-check SQLite write)
        self._audit_buf: list[tuple] = []
        self._audit_buf_lock = threading.Lock()
        self._audit_buf_limit = 50  # flush every N entries
        self._init_db()

    # ------------------------------------------------------------------
    # DB setup
    # ------------------------------------------------------------------

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_db(self) -> None:
        with self._get_conn() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS user_roles (
                    id          TEXT PRIMARY KEY,
                    user_id     TEXT NOT NULL,
                    role        TEXT NOT NULL,
                    org_id      TEXT NOT NULL,
                    assigned_by TEXT NOT NULL DEFAULT 'system',
                    assigned_at TEXT NOT NULL,
                    UNIQUE(user_id, role, org_id)
                );

                CREATE INDEX IF NOT EXISTS idx_user_roles_user_org
                    ON user_roles(user_id, org_id);

                CREATE INDEX IF NOT EXISTS idx_user_roles_org
                    ON user_roles(org_id);

                CREATE TABLE IF NOT EXISTS audit_trail (
                    id            TEXT PRIMARY KEY,
                    ts            REAL NOT NULL,
                    user_id       TEXT NOT NULL,
                    action        TEXT NOT NULL,
                    resource      TEXT NOT NULL,
                    org_id        TEXT NOT NULL,
                    allowed       INTEGER NOT NULL,
                    scope_checked TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_audit_user
                    ON audit_trail(user_id);

                CREATE INDEX IF NOT EXISTS idx_audit_org
                    ON audit_trail(org_id);

                CREATE TABLE IF NOT EXISTS disposable_tokens (
                    id          TEXT PRIMARY KEY,
                    org_id      TEXT NOT NULL,
                    token_hash  TEXT NOT NULL UNIQUE,
                    minted_by   TEXT NOT NULL,
                    scope_json  TEXT NOT NULL,
                    purpose     TEXT NOT NULL,
                    ttl_seconds INTEGER NOT NULL,
                    minted_at   TEXT NOT NULL,
                    expires_at  TEXT NOT NULL,
                    revoked_at  TEXT,
                    revoked_by  TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_disposable_tokens_org
                    ON disposable_tokens(org_id);

                CREATE INDEX IF NOT EXISTS idx_disposable_tokens_hash
                    ON disposable_tokens(token_hash);

                CREATE TABLE IF NOT EXISTS role_view_overrides (
                    id          TEXT PRIMARY KEY,
                    org_id      TEXT NOT NULL,
                    user_id     TEXT NOT NULL,
                    target_role TEXT NOT NULL,
                    started_at  TEXT NOT NULL,
                    expires_at  TEXT NOT NULL,
                    ended_at    TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_role_view_user_org
                    ON role_view_overrides(user_id, org_id);
                """
            )

    # ------------------------------------------------------------------
    # Role assignment
    # ------------------------------------------------------------------

    def assign_role(
        self,
        user_id: str,
        role: str,
        org_id: str,
        assigned_by: str = "system",
    ) -> dict:
        """Assign a role to a user in an org. Returns assignment record."""
        if role not in ROLES:
            raise ValueError(f"Unknown role '{role}'. Valid roles: {list(ROLES)}")

        assignment_id = str(uuid.uuid4())
        assigned_at = _now_iso()

        with self._get_conn() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO user_roles
                    (id, user_id, role, org_id, assigned_by, assigned_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (assignment_id, user_id, role, org_id, assigned_by, assigned_at),
            )

        # Perf fix 1: invalidate cached scopes for this user+org
        self._cache_invalidate(user_id, org_id)

        _logger.info(
            "rbac.assign_role",
            user_id=user_id,
            role=role,
            org_id=org_id,
            assigned_by=assigned_by,
        )

        return {
            "id": assignment_id,
            "user_id": user_id,
            "role": role,
            "org_id": org_id,
            "assigned_by": assigned_by,
            "assigned_at": assigned_at,
        }

    def revoke_role(self, user_id: str, role: str, org_id: str) -> bool:
        """Revoke a role. Returns True if found and revoked."""
        with self._get_conn() as conn:
            cur = conn.execute(
                "DELETE FROM user_roles WHERE user_id=? AND role=? AND org_id=?",
                (user_id, role, org_id),
            )
        revoked = cur.rowcount > 0
        if revoked:
            # Perf fix 1: invalidate cached scopes for this user+org
            self._cache_invalidate(user_id, org_id)
            _logger.info(
                "rbac.revoke_role", user_id=user_id, role=role, org_id=org_id
            )
        return revoked

    # ------------------------------------------------------------------
    # Role queries
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # Scope cache helpers (Perf fix 1)
    # ------------------------------------------------------------------

    def _cache_get(self, key: tuple[str, str]) -> frozenset[str] | None:
        with self._scope_cache_lock:
            return self._scope_cache.get(key)

    def _cache_set(self, key: tuple[str, str], scopes: frozenset[str]) -> None:
        with self._scope_cache_lock:
            if key not in self._scope_cache:
                if len(self._scope_cache_order) >= self._SCOPE_CACHE_MAX:
                    evict = self._scope_cache_order.pop(0)
                    self._scope_cache.pop(evict, None)
                self._scope_cache_order.append(key)
            self._scope_cache[key] = scopes

    def _cache_invalidate(self, user_id: str, org_id: str) -> None:
        key = (user_id, org_id)
        with self._scope_cache_lock:
            self._scope_cache.pop(key, None)
            try:
                self._scope_cache_order.remove(key)
            except ValueError:
                pass

    def get_user_roles(self, user_id: str, org_id: str) -> list[str]:
        """Get all roles for a user in an org."""
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT role FROM user_roles WHERE user_id=? AND org_id=?",
                (user_id, org_id),
            ).fetchall()
        return [r["role"] for r in rows]

    def get_user_scopes(self, user_id: str, org_id: str) -> list[str]:
        """Get all effective scopes including inherited. Returns deduplicated list.

        Perf fix 1: result is cached in-process; invalidated on role changes.
        """
        key = (user_id, org_id)
        cached = self._cache_get(key)
        if cached is not None:
            return list(cached)
        roles = self.get_user_roles(user_id, org_id)
        scopes = self.get_effective_scopes(roles)
        self._cache_set(key, frozenset(scopes))
        return scopes

    # ------------------------------------------------------------------
    # Permission / tenant checks
    # ------------------------------------------------------------------

    def check_permission(
        self, user_id: str, org_id: str, required_scope: str
    ) -> bool:
        """Check if user has a specific scope. Handles wildcards (admin:all, read:*)."""
        scopes = self.get_user_scopes(user_id, org_id)
        allowed = any(_scope_matches(s, required_scope) for s in scopes)
        self.audit_log(
            user_id=user_id,
            action="check_permission",
            resource=required_scope,
            org_id=org_id,
            allowed=allowed,
            scope_checked=required_scope,
        )
        return allowed

    def check_tenant_access(
        self,
        user_id: str,
        requesting_org_id: str,
        target_org_id: str,
    ) -> bool:
        """Check if user can access data from target_org. super_admin can cross orgs."""
        if requesting_org_id == target_org_id:
            return True
        # super_admin has admin:all which grants cross-tenant access
        scopes = self.get_user_scopes(user_id, requesting_org_id)
        return "admin:all" in scopes

    # ------------------------------------------------------------------
    # Org user listing
    # ------------------------------------------------------------------

    def list_users_in_org(self, org_id: str) -> list[dict]:
        """List all users with roles in an org."""
        with self._get_conn() as conn:
            rows = conn.execute(
                """
                SELECT user_id, role, assigned_by, assigned_at
                FROM user_roles WHERE org_id=?
                ORDER BY user_id, role
                """,
                (org_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Hierarchy / scope helpers
    # ------------------------------------------------------------------

    def get_role_hierarchy(self, role: str) -> list[str]:
        """Get role + all inherited roles (depth-first, deduped)."""
        seen: list[str] = []
        self._collect_hierarchy(role, seen)
        return seen

    def _collect_hierarchy(self, role: str, acc: list[str]) -> None:
        if role in acc:
            return
        acc.append(role)
        for parent in ROLES.get(role, {}).get("inherits", []):
            self._collect_hierarchy(parent, acc)

    def get_effective_scopes(self, roles: list[str]) -> list[str]:
        """Compute effective scopes for a set of roles including inheritance."""
        all_roles: list[str] = []
        for role in roles:
            for r in self.get_role_hierarchy(role):
                if r not in all_roles:
                    all_roles.append(r)

        seen: set[str] = set()
        scopes: list[str] = []
        for r in all_roles:
            for scope in ROLES.get(r, {}).get("scopes", []):
                if scope not in seen:
                    seen.add(scope)
                    scopes.append(scope)
        return scopes

    # ------------------------------------------------------------------
    # Audit trail
    # ------------------------------------------------------------------

    def _flush_audit_buf(self, conn: sqlite3.Connection) -> None:
        """Write buffered audit entries (called under _audit_buf_lock)."""
        if not self._audit_buf:
            return
        conn.executemany(
            """
            INSERT INTO audit_trail
                (id, ts, user_id, action, resource, org_id, allowed, scope_checked)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            self._audit_buf,
        )
        self._audit_buf.clear()

    def flush_audit_log(self) -> None:
        """Force-flush buffered audit entries to DB. Call on shutdown or test teardown."""
        with self._audit_buf_lock:
            if not self._audit_buf:
                return
            with self._get_conn() as conn:
                self._flush_audit_buf(conn)

    def audit_log(
        self,
        user_id: str,
        action: str,
        resource: str,
        org_id: str,
        allowed: bool,
        scope_checked: Optional[str] = None,
    ) -> None:
        """Log an access check to audit trail.

        Perf fix 2: writes are buffered and flushed in batches of _audit_buf_limit
        to avoid one SQLite INSERT per permission check on hot paths.
        """
        row = (
            str(uuid.uuid4()),
            time.time(),
            user_id,
            action,
            resource,
            org_id,
            int(allowed),
            scope_checked,
        )
        with self._audit_buf_lock:
            self._audit_buf.append(row)
            if len(self._audit_buf) >= self._audit_buf_limit:
                with self._get_conn() as conn:
                    self._flush_audit_buf(conn)

    def get_audit_log(
        self,
        user_id: Optional[str] = None,
        org_id: Optional[str] = None,
        limit: int = 100,
    ) -> list[dict]:
        """Return audit log entries, optionally filtered by user_id and/or org_id."""
        clauses: list[str] = []
        params: list[Any] = []
        if user_id is not None:
            clauses.append("user_id = ?")
            params.append(user_id)
        if org_id is not None:
            clauses.append("org_id = ?")
            params.append(org_id)

        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(limit)

        with self._get_conn() as conn:
            rows = conn.execute(
                f"SELECT * FROM audit_trail {where} ORDER BY ts DESC LIMIT ?",  # nosec B608
                params,
            ).fetchall()
        return [dict(r) for r in rows]


    # ------------------------------------------------------------------
    # GAP-039 — Disposable scoped user tokens
    # ------------------------------------------------------------------

    @staticmethod
    def _hash_token(raw_token: str) -> str:
        return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()

    def mint_disposable_token(
        self,
        org_id: str,
        minted_by: str,
        scope: List[str],
        ttl_seconds: int,
        purpose: str,
    ) -> Dict[str, Any]:
        """Mint a disposable scoped token. Raw token returned ONCE; only hash is stored."""
        if not isinstance(scope, list) or not all(isinstance(s, str) for s in scope):
            raise ValueError("scope must be a list of strings")
        if not isinstance(ttl_seconds, int) or ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be a positive integer")
        if not purpose:
            raise ValueError("purpose must be non-empty")

        token_id = str(uuid.uuid4())
        raw_token = secrets.token_urlsafe(32)
        token_hash = self._hash_token(raw_token)
        now = datetime.now(timezone.utc)
        minted_at = now.isoformat()
        expires_at = (now + timedelta(seconds=ttl_seconds)).isoformat()

        with self._get_conn() as conn:
            conn.execute(
                """
                INSERT INTO disposable_tokens
                    (id, org_id, token_hash, minted_by, scope_json, purpose,
                     ttl_seconds, minted_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    token_id,
                    org_id,
                    token_hash,
                    minted_by,
                    json.dumps(scope),
                    purpose,
                    ttl_seconds,
                    minted_at,
                    expires_at,
                ),
            )

        _logger.info(
            "rbac.mint_disposable_token",
            token_id=token_id,
            org_id=org_id,
            minted_by=minted_by,
            purpose=purpose,
            ttl_seconds=ttl_seconds,
        )

        return {
            "token_id": token_id,
            "raw_token": raw_token,
            "expires_at": expires_at,
            "scope": list(scope),
        }

    def verify_disposable_token(self, raw_token: str) -> Optional[Dict[str, Any]]:
        """Verify a disposable token. Returns metadata if valid, else None."""
        if not raw_token:
            return None
        token_hash = self._hash_token(raw_token)
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT * FROM disposable_tokens WHERE token_hash=?",
                (token_hash,),
            ).fetchone()
        if row is None:
            return None
        if row["revoked_at"] is not None:
            return None
        try:
            expires_at = datetime.fromisoformat(row["expires_at"])
        except ValueError:
            return None
        if expires_at <= datetime.now(timezone.utc):
            return None
        try:
            scope = json.loads(row["scope_json"])
        except (ValueError, TypeError):
            scope = []
        return {
            "token_id": row["id"],
            "org_id": row["org_id"],
            "minted_by": row["minted_by"],
            "scope": scope,
            "purpose": row["purpose"],
            "expires_at": row["expires_at"],
        }

    def revoke_disposable_token(
        self, org_id: str, token_id: str, revoked_by: str
    ) -> bool:
        """Revoke a disposable token (org-scoped). Returns True if revoked."""
        now_iso = _now_iso()
        with self._get_conn() as conn:
            cur = conn.execute(
                """
                UPDATE disposable_tokens
                SET revoked_at=?, revoked_by=?
                WHERE id=? AND org_id=? AND revoked_at IS NULL
                """,
                (now_iso, revoked_by, token_id, org_id),
            )
        revoked = cur.rowcount > 0
        if revoked:
            _logger.info(
                "rbac.revoke_disposable_token",
                token_id=token_id,
                org_id=org_id,
                revoked_by=revoked_by,
            )
        return revoked

    def list_disposable_tokens(
        self, org_id: str, active_only: bool = True
    ) -> List[Dict[str, Any]]:
        """List disposable tokens for an org. Never returns raw_token or token_hash."""
        with self._get_conn() as conn:
            if active_only:
                now_iso = _now_iso()
                rows = conn.execute(
                    """
                    SELECT id, org_id, minted_by, scope_json, purpose, ttl_seconds,
                           minted_at, expires_at, revoked_at, revoked_by
                    FROM disposable_tokens
                    WHERE org_id=? AND revoked_at IS NULL AND expires_at > ?
                    ORDER BY minted_at DESC
                    """,
                    (org_id, now_iso),
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT id, org_id, minted_by, scope_json, purpose, ttl_seconds,
                           minted_at, expires_at, revoked_at, revoked_by
                    FROM disposable_tokens
                    WHERE org_id=?
                    ORDER BY minted_at DESC
                    """,
                    (org_id,),
                ).fetchall()
        results: List[Dict[str, Any]] = []
        for r in rows:
            d = dict(r)
            try:
                d["scope"] = json.loads(d.pop("scope_json"))
            except (ValueError, TypeError):
                d["scope"] = []
                d.pop("scope_json", None)
            results.append(d)
        return results

    # ------------------------------------------------------------------
    # GAP-050 — Role-view switcher
    # ------------------------------------------------------------------

    def switch_role_view(
        self,
        org_id: str,
        user_id: str,
        target_role: str,
        duration_seconds: int = 3600,
    ) -> Dict[str, Any]:
        """Temporarily switch user's view to another role. Ends any active override first."""
        if target_role not in ROLES:
            raise ValueError(f"Unknown role '{target_role}'. Valid roles: {list(ROLES)}")
        if not isinstance(duration_seconds, int) or duration_seconds <= 0:
            raise ValueError("duration_seconds must be a positive integer")

        now = datetime.now(timezone.utc)
        now_iso = now.isoformat()
        # End any currently active override for this user+org (one active at a time).
        with self._get_conn() as conn:
            conn.execute(
                """
                UPDATE role_view_overrides
                SET ended_at=?
                WHERE org_id=? AND user_id=? AND ended_at IS NULL
                """,
                (now_iso, org_id, user_id),
            )
            override_id = str(uuid.uuid4())
            expires_at = (now + timedelta(seconds=duration_seconds)).isoformat()
            conn.execute(
                """
                INSERT INTO role_view_overrides
                    (id, org_id, user_id, target_role, started_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (override_id, org_id, user_id, target_role, now_iso, expires_at),
            )

        _logger.info(
            "rbac.switch_role_view",
            override_id=override_id,
            org_id=org_id,
            user_id=user_id,
            target_role=target_role,
            duration_seconds=duration_seconds,
        )

        return {
            "override_id": override_id,
            "org_id": org_id,
            "user_id": user_id,
            "target_role": target_role,
            "started_at": now_iso,
            "expires_at": expires_at,
        }

    def get_active_role_view(
        self, org_id: str, user_id: str
    ) -> Optional[Dict[str, Any]]:
        """Get the currently active (not expired, not ended) role-view override."""
        now_iso = _now_iso()
        with self._get_conn() as conn:
            row = conn.execute(
                """
                SELECT id, org_id, user_id, target_role, started_at, expires_at, ended_at
                FROM role_view_overrides
                WHERE org_id=? AND user_id=? AND ended_at IS NULL AND expires_at > ?
                ORDER BY started_at DESC
                LIMIT 1
                """,
                (org_id, user_id, now_iso),
            ).fetchone()
        if row is None:
            return None
        return dict(row)

    def end_role_view(
        self, org_id: str, override_id: str, user_id: str
    ) -> bool:
        """End an active role-view override. Returns True if ended."""
        now_iso = _now_iso()
        with self._get_conn() as conn:
            cur = conn.execute(
                """
                UPDATE role_view_overrides
                SET ended_at=?
                WHERE id=? AND org_id=? AND user_id=? AND ended_at IS NULL
                """,
                (now_iso, override_id, org_id, user_id),
            )
        ended = cur.rowcount > 0
        if ended:
            _logger.info(
                "rbac.end_role_view",
                override_id=override_id,
                org_id=org_id,
                user_id=user_id,
            )
        return ended


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


__all__ = ["ROLES", "RBACEngine"]
