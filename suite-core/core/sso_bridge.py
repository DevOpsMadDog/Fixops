"""SSO bridge for SAML 2.0 and OIDC authentication."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import sqlite3
import threading
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import structlog

_logger = structlog.get_logger()

_DB_ENV = "FIXOPS_DATA_DIR"
_DEFAULT_DB_DIR = ".fixops_data"
_SESSION_TTL = 86400  # 24 hours


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class SSOUser:
    user_id: str
    email: str
    roles: list[str]
    org_id: str
    provider: str
    raw_claims: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _b64_decode(s: str) -> bytes:
    """Base64url-decode with padding tolerance."""
    # Add padding if needed
    padded = s + "=" * (4 - len(s) % 4) if len(s) % 4 else s
    # Replace URL-safe chars
    padded = padded.replace("-", "+").replace("_", "/")
    return base64.b64decode(padded)


def _parse_jwt(jwt_str: str) -> dict:
    """Decode JWT payload without signature verification."""
    if not jwt_str or not isinstance(jwt_str, str):
        raise ValueError("JWT must be a non-empty string")
    parts = jwt_str.split(".")
    if len(parts) != 3:
        raise ValueError(f"Malformed JWT: expected 3 parts, got {len(parts)}")
    try:
        payload_bytes = _b64_decode(parts[1])
        return json.loads(payload_bytes)
    except Exception as exc:
        raise ValueError(f"Cannot decode JWT payload: {exc}") from exc


# ---------------------------------------------------------------------------
# Bridge
# ---------------------------------------------------------------------------


class SSOBridge:
    """SQLite-backed SSO bridge for SAML 2.0 and OIDC."""

    def __init__(self, db_path: Optional[str] = None) -> None:
        if db_path is None:
            db_dir = os.getenv(_DB_ENV, _DEFAULT_DB_DIR)
            db_path = os.path.join(db_dir, "sso.db")
        self._db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._init_db()

    # ------------------------------------------------------------------
    # Connection
    # ------------------------------------------------------------------

    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self._db_path)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.row_factory = sqlite3.Row
            self._local.conn = conn
        return conn

    def _init_db(self) -> None:
        with self._conn() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS sso_providers (
                    name          TEXT PRIMARY KEY,
                    provider_type TEXT NOT NULL,
                    config        TEXT NOT NULL DEFAULT '{}',
                    created_at    REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS sso_sessions (
                    token         TEXT PRIMARY KEY,
                    user_json     TEXT NOT NULL,
                    expires_at    REAL NOT NULL
                );
            """)

    # ------------------------------------------------------------------
    # Provider management
    # ------------------------------------------------------------------

    def register_provider(self, name: str, provider_type: str, config: dict) -> dict:
        """Register an SSO provider. provider_type: 'saml' or 'oidc'."""
        if provider_type not in ("saml", "oidc"):
            raise ValueError(f"Unsupported provider_type: {provider_type!r}")
        now = time.time()
        with self._conn() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO sso_providers (name, provider_type, config, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (name, provider_type, json.dumps(config), now),
            )
        _logger.info("sso.provider_registered", name=name, type=provider_type)
        return {"name": name, "type": provider_type, "config": config}

    def get_provider_config(self, provider_name: str) -> Optional[dict]:
        """Get provider config by name. Returns None if not found."""
        row = self._conn().execute(
            "SELECT name, provider_type, config FROM sso_providers WHERE name = ?",
            (provider_name,),
        ).fetchone()
        if row is None:
            return None
        return {
            "name": row["name"],
            "type": row["provider_type"],
            "config": json.loads(row["config"]),
        }

    def list_providers(self) -> list[dict]:
        """List all configured providers."""
        rows = self._conn().execute(
            "SELECT name, provider_type, config FROM sso_providers ORDER BY name"
        ).fetchall()
        return [
            {"name": r["name"], "type": r["provider_type"], "config": json.loads(r["config"])}
            for r in rows
        ]

    # ------------------------------------------------------------------
    # OIDC
    # ------------------------------------------------------------------

    def validate_oidc_token(self, jwt_str: str, provider: str = "default") -> SSOUser:
        """Parse and validate an OIDC JWT.

        Accepts any well-formed JWT (no signature verification in initial version).
        Raises ValueError if token is malformed or expired.
        """
        claims = _parse_jwt(jwt_str)

        # Check expiry if present
        exp = claims.get("exp")
        if exp is not None and time.time() > float(exp):
            raise ValueError("OIDC token has expired")

        user_id = claims.get("sub") or claims.get("user_id", "")
        if not user_id:
            raise ValueError("OIDC token missing 'sub' claim")

        email = claims.get("email", f"{user_id}@unknown")
        org_id = claims.get("org_id") or claims.get("tenant_id", "default")

        # roles / groups — accept list or comma-separated string
        raw_roles = claims.get("roles") or claims.get("groups") or []
        if isinstance(raw_roles, str):
            raw_roles = [r.strip() for r in raw_roles.split(",") if r.strip()]
        roles = list(raw_roles)

        _logger.info("sso.oidc_validated", user_id=user_id, provider=provider)
        return SSOUser(
            user_id=user_id,
            email=email,
            roles=roles,
            org_id=org_id,
            provider=provider,
            raw_claims=claims,
        )

    def exchange_code_for_token(
        self, code: str, provider: str, redirect_uri: str = ""
    ) -> dict:
        """Simulate OIDC authorization code exchange. Returns mock token dict."""
        _logger.info("sso.code_exchange", provider=provider)
        # Build a minimal JWT payload for the id_token
        now = int(time.time())
        payload = {
            "sub": f"user_{hashlib.sha256(code.encode()).hexdigest()[:8]}",
            "email": "user@example.com",
            "iat": now,
            "exp": now + 3600,
            "provider": provider,
        }
        encoded = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
        id_token = f"eyJhbGciOiJub25lIn0.{encoded}."
        access_token = f"access_{secrets.token_hex(16)}"
        return {
            "access_token": access_token,
            "id_token": id_token,
            "token_type": "Bearer",
            "expires_in": 3600,
        }

    # ------------------------------------------------------------------
    # SAML
    # ------------------------------------------------------------------

    def validate_saml_assertion(self, xml_str: str) -> SSOUser:
        """Parse SAML response XML. Extract NameID + attributes.

        No signature validation in initial version (TODO: add xmlsec1 verification).
        Raises ValueError if assertion is malformed.
        """
        if not xml_str or not xml_str.strip():
            raise ValueError("SAML assertion XML is empty")

        try:
            root = ET.fromstring(xml_str)
        except ET.ParseError as exc:
            raise ValueError(f"Invalid SAML XML: {exc}") from exc

        # Strip namespace for easier querying
        def _strip_ns(tag: str) -> str:
            return tag.split("}")[-1] if "}" in tag else tag

        def _find_text(node: ET.Element, local_name: str) -> Optional[str]:
            for child in node.iter():
                if _strip_ns(child.tag) == local_name and child.text:
                    return child.text.strip()
            return None

        name_id = _find_text(root, "NameID")
        if not name_id:
            raise ValueError("SAML assertion missing NameID")

        # Collect AttributeStatement values
        attrs: dict[str, list[str]] = {}
        for elem in root.iter():
            if _strip_ns(elem.tag) == "Attribute":
                attr_name = elem.get("Name", "")
                values = [
                    v.text.strip()
                    for v in elem
                    if _strip_ns(v.tag) == "AttributeValue" and v.text
                ]
                if attr_name:
                    attrs[attr_name] = values

        def _first(key: str, default: str = "") -> str:
            return (attrs.get(key) or [default])[0]

        email = _first("email") or _first("emailAddress") or f"{name_id}@saml"
        org_id = _first("org_id") or _first("organizationId", "default")
        roles = attrs.get("roles") or attrs.get("groups") or []

        _logger.info("sso.saml_validated", name_id=name_id)
        return SSOUser(
            user_id=name_id,
            email=email,
            roles=list(roles),
            org_id=org_id,
            provider="saml",
            raw_claims={"name_id": name_id, "attributes": attrs},
        )

    # ------------------------------------------------------------------
    # Session management
    # ------------------------------------------------------------------

    def create_session(self, user: SSOUser) -> str:
        """Create ALDECI session for SSO user. Returns session token."""
        token = "sso_" + secrets.token_hex(24)
        expires_at = time.time() + _SESSION_TTL
        user_json = json.dumps({
            "user_id": user.user_id,
            "email": user.email,
            "roles": user.roles,
            "org_id": user.org_id,
            "provider": user.provider,
            "raw_claims": user.raw_claims,
        })
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO sso_sessions (token, user_json, expires_at) VALUES (?, ?, ?)",
                (token, user_json, expires_at),
            )
        _logger.info("sso.session_created", user_id=user.user_id)
        return token

    def validate_session(self, session_token: str) -> Optional[SSOUser]:
        """Validate a session token. Returns SSOUser or None if invalid/expired."""
        if not session_token:
            return None
        row = self._conn().execute(
            "SELECT user_json, expires_at FROM sso_sessions WHERE token = ?",
            (session_token,),
        ).fetchone()
        if row is None:
            return None
        if time.time() > row["expires_at"]:
            # Clean up expired session
            with self._conn() as conn:
                conn.execute("DELETE FROM sso_sessions WHERE token = ?", (session_token,))
            return None
        data = json.loads(row["user_json"])
        return SSOUser(
            user_id=data["user_id"],
            email=data["email"],
            roles=data["roles"],
            org_id=data["org_id"],
            provider=data["provider"],
            raw_claims=data.get("raw_claims", {}),
        )
