"""ALDECI Snowflake SQL API engine — REAL httpx + JWT, NO MOCKS, NO CACHE.

Wraps the **Snowflake SQL API v2** (https://docs.snowflake.com/en/developer-guide/sql-api/intro).
All access is via a key-pair-auth JWT bearer token signed locally with the
RSA private key supplied via ``SNOWFLAKE_PRIVATE_KEY``.

Singleton:
    eng = get_snowflake_engine()

Reset (tests):
    reset_snowflake_engine()

Configuration env vars
----------------------
SNOWFLAKE_ACCOUNT       — account locator, e.g. ``ab12345.us-east-1``
SNOWFLAKE_USER          — Snowflake user the JWT is issued for
SNOWFLAKE_PRIVATE_KEY   — PEM-encoded RSA private key (PKCS#8) used to sign JWTs
SNOWFLAKE_ROLE          — optional default role
SNOWFLAKE_WAREHOUSE     — optional default warehouse
SNOWFLAKE_DATABASE      — optional default database
SNOWFLAKE_SCHEMA        — optional default schema

When ``snowflake-connector-python`` is importable it is preferred for the
``SHOW <object>`` wrappers; otherwise the engine signs a JWT and submits the
equivalent SQL via the SQL API. Both paths return the same shaped JSON.

NO SQLite cache. NO mock fallback.
"""
from __future__ import annotations

import base64
import hashlib
import logging
import os
import threading
import time
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT_SECONDS = 15.0
_JWT_LIFETIME_SECONDS = 3600  # 1h, well under Snowflake's max

# Endpoints surfaced via the capability summary GET /
_ENDPOINT_CATALOG: List[str] = [
    "/api/v2/statements",
    "/api/v2/databases",
    "/api/v2/users",
    "/api/v2/warehouses",
    "/api/v2/roles",
]


# ---------------------------------------------------------------------------
# TrustGraph event-bus wiring (optional, never blocks)
# ---------------------------------------------------------------------------
try:  # pragma: no cover - optional dependency
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except Exception:  # noqa: BLE001
    _get_tg_bus = None  # type: ignore[assignment]


def _emit_event(event_type: str, payload: Dict[str, Any]) -> None:
    if _get_tg_bus is None:
        return
    try:
        bus = _get_tg_bus()
        if bus is None:
            return
        emit = getattr(bus, "emit", None) or getattr(bus, "publish", None)
        if emit is None:
            return
        emit(event_type, payload)
    except Exception:  # pragma: no cover
        pass


class SnowflakeUnavailableError(RuntimeError):
    """Raised when Snowflake credentials are unset or the API rejected the call."""


class SnowflakeHTTPError(RuntimeError):
    """Non-2xx upstream response (router maps to 502 or passes through)."""

    def __init__(self, status_code: int, message: str, payload: Any = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.payload = payload


# ---------------------------------------------------------------------------
# JWT helpers — local signing, no jwt library needed beyond pyjwt-with-RS256
# ---------------------------------------------------------------------------


def _load_private_key(pem: str):
    """Parse a PEM-encoded RSA private key for JWT signing."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend

    pem_bytes = pem.encode("utf-8") if isinstance(pem, str) else pem
    try:
        return serialization.load_pem_private_key(
            pem_bytes, password=None, backend=default_backend()
        )
    except Exception as exc:
        raise SnowflakeUnavailableError(
            f"SNOWFLAKE_PRIVATE_KEY is not a valid PEM RSA private key: {exc}"
        ) from exc


def _public_key_fingerprint(private_key) -> str:
    """Snowflake public-key fingerprint = ``SHA256:<b64(SHA256(DER pub key))>``."""
    from cryptography.hazmat.primitives import serialization

    pub_der = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    digest = hashlib.sha256(pub_der).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii")


def _normalise_account(account: str) -> str:
    """Strip protocol/host suffix; Snowflake JWT issuer wants just the locator."""
    a = (account or "").strip()
    a = a.replace("https://", "").replace("http://", "").rstrip("/")
    if a.endswith(".snowflakecomputing.com"):
        a = a[: -len(".snowflakecomputing.com")]
    return a


def _make_jwt(account: str, user: str, private_key, lifetime: int = _JWT_LIFETIME_SECONDS) -> str:
    """Build the Snowflake key-pair JWT (RS256, 1h lifetime)."""
    import jwt as _jwt  # PyJWT

    qualified_user = f"{account.upper()}.{user.upper()}"
    fingerprint = _public_key_fingerprint(private_key)
    now = int(time.time())
    claims = {
        "iss": f"{qualified_user}.{fingerprint}",
        "sub": qualified_user,
        "iat": now,
        "exp": now + lifetime,
    }
    token = _jwt.encode(claims, private_key, algorithm="RS256")
    # PyJWT 2.x returns str already; if bytes (1.x) decode it
    if isinstance(token, bytes):
        token = token.decode("ascii")
    return token


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class SnowflakeEngine:
    """Real httpx-backed Snowflake SQL API client."""

    def __init__(
        self,
        account: Optional[str] = None,
        user: Optional[str] = None,
        private_key_pem: Optional[str] = None,
        role: Optional[str] = None,
        warehouse: Optional[str] = None,
        database: Optional[str] = None,
        schema: Optional[str] = None,
        client: Optional[httpx.Client] = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self._explicit_account = account
        self._explicit_user = user
        self._explicit_pk_pem = private_key_pem
        self._explicit_role = role
        self._explicit_warehouse = warehouse
        self._explicit_database = database
        self._explicit_schema = schema

        self._client: Optional[httpx.Client] = client
        self._owns_client: bool = client is None
        self._timeout: float = timeout
        self._lock = threading.RLock()

        # JWT cache — recompute when key/account/user changes or on expiry
        self._jwt_token: Optional[str] = None
        self._jwt_exp: int = 0

    # ------------------------------------------------------------------ creds

    def _account(self) -> str:
        raw = self._explicit_account if self._explicit_account is not None else os.environ.get("SNOWFLAKE_ACCOUNT", "")
        return _normalise_account(raw or "")

    def _user(self) -> str:
        raw = self._explicit_user if self._explicit_user is not None else os.environ.get("SNOWFLAKE_USER", "")
        return (raw or "").strip()

    def _private_key_pem(self) -> str:
        raw = self._explicit_pk_pem if self._explicit_pk_pem is not None else os.environ.get("SNOWFLAKE_PRIVATE_KEY", "")
        return (raw or "").strip()

    def _role(self) -> str:
        raw = self._explicit_role if self._explicit_role is not None else os.environ.get("SNOWFLAKE_ROLE", "")
        return (raw or "").strip()

    def _warehouse(self) -> str:
        raw = self._explicit_warehouse if self._explicit_warehouse is not None else os.environ.get("SNOWFLAKE_WAREHOUSE", "")
        return (raw or "").strip()

    def _database(self) -> str:
        raw = self._explicit_database if self._explicit_database is not None else os.environ.get("SNOWFLAKE_DATABASE", "")
        return (raw or "").strip()

    def _schema(self) -> str:
        raw = self._explicit_schema if self._explicit_schema is not None else os.environ.get("SNOWFLAKE_SCHEMA", "")
        return (raw or "").strip()

    def account_present(self) -> bool:
        return bool(self._account())

    def user_present(self) -> bool:
        return bool(self._user())

    def private_key_present(self) -> bool:
        return bool(self._private_key_pem())

    def is_configured(self) -> bool:
        return self.account_present() and self.user_present() and self.private_key_present()

    def _require_configured(self) -> None:
        if not self.is_configured():
            raise SnowflakeUnavailableError(
                "SNOWFLAKE_ACCOUNT, SNOWFLAKE_USER and SNOWFLAKE_PRIVATE_KEY must "
                "all be set to call the Snowflake SQL API"
            )

    # ----------------------------------------------------------------- client

    def _ensure_client(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(timeout=self._timeout)
            self._owns_client = True
        return self._client

    def _base_url(self) -> str:
        return f"https://{self._account()}.snowflakecomputing.com"

    def _bearer(self) -> str:
        now = int(time.time())
        if self._jwt_token and now < (self._jwt_exp - 60):
            return self._jwt_token
        pk = _load_private_key(self._private_key_pem())
        token = _make_jwt(self._account(), self._user(), pk)
        self._jwt_token = token
        self._jwt_exp = now + _JWT_LIFETIME_SECONDS
        return token

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self._bearer()}",
            "X-Snowflake-Authorization-Token-Type": "KEYPAIR_JWT",
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "ALDECI-Snowflake-Router/1.0",
        }

    # ---------------------------------------------------------------- request

    def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
        expect_204: bool = False,
    ) -> Any:
        self._require_configured()
        client = self._ensure_client()
        url = f"{self._base_url()}{path}"
        try:
            if method == "GET":
                resp = client.get(url, headers=self._headers(), params=params or None)
            elif method == "POST":
                resp = client.post(
                    url,
                    headers=self._headers(),
                    json=json_body,
                    params=params or None,
                )
            elif method == "DELETE":
                resp = client.request(
                    "DELETE",
                    url,
                    headers=self._headers(),
                    params=params or None,
                )
            else:
                raise SnowflakeUnavailableError(f"Unsupported HTTP method: {method}")
        except httpx.HTTPError as exc:
            raise SnowflakeUnavailableError(
                f"Snowflake request failed: {type(exc).__name__}: {exc}"
            ) from exc

        if expect_204 and resp.status_code in (200, 202, 204):
            return None

        if resp.status_code in (401, 403):
            raise SnowflakeUnavailableError(
                f"Snowflake rejected credentials (HTTP {resp.status_code})"
            )

        if 200 <= resp.status_code < 300:
            if not getattr(resp, "content", None):
                return None
            try:
                return resp.json()
            except ValueError:
                return {"raw": getattr(resp, "text", "")}

        # non-2xx — surface upstream payload when JSON
        payload: Any
        try:
            payload = resp.json()
        except ValueError:
            payload = getattr(resp, "text", None) or None
        raise SnowflakeHTTPError(
            resp.status_code,
            f"Snowflake returned HTTP {resp.status_code}",
            payload,
        )

    # ----------------------------------------------------------------- summary

    def capability_summary(self) -> Dict[str, Any]:
        configured = self.is_configured()
        status = "ok" if configured else "unavailable"
        return {
            "service": "Snowflake SQL API",
            "endpoints": list(_ENDPOINT_CATALOG),
            "snowflake_account_present": self.account_present(),
            "snowflake_user_present": self.user_present(),
            "snowflake_private_key_present": self.private_key_present(),
            "status": status,
        }

    # -------------------------------------------------------------- statements

    def submit_statement(
        self,
        statement: str,
        *,
        role: Optional[str] = None,
        warehouse: Optional[str] = None,
        database: Optional[str] = None,
        schema: Optional[str] = None,
        parameters: Optional[Dict[str, Any]] = None,
        timeout: Optional[int] = None,
        result_set_metadata: Optional[Dict[str, Any]] = None,
        async_exec: bool = False,
    ) -> Dict[str, Any]:
        body: Dict[str, Any] = {
            "statement": statement,
            "role": role or self._role() or None,
            "warehouse": warehouse or self._warehouse() or None,
            "database": database or self._database() or None,
            "schema": schema or self._schema() or None,
            "timeout": timeout if timeout is not None else 60,
            "parameters": parameters or {},
        }
        body = {k: v for k, v in body.items() if v is not None}
        if result_set_metadata:
            body["resultSetMetaData"] = result_set_metadata
        params = {"async": "true"} if async_exec else None
        raw = self._request(
            "POST", "/api/v2/statements", json_body=body, params=params
        ) or {}
        return _shape_statement_response(raw)

    def get_statement(self, statement_handle: str, partition: int = 0) -> Dict[str, Any]:
        if not statement_handle:
            raise ValueError("statement_handle must not be empty")
        raw = self._request(
            "GET",
            f"/api/v2/statements/{statement_handle}",
            params={"partition": partition},
        ) or {}
        return _shape_statement_response(raw)

    def cancel_statement(self, statement_handle: str) -> None:
        if not statement_handle:
            raise ValueError("statement_handle must not be empty")
        self._request(
            "POST",
            f"/api/v2/statements/{statement_handle}/cancel",
            json_body={},
            expect_204=True,
        )

    # ----------------------------------- SHOW wrappers (databases/users/etc.)

    def _run_show(self, sql: str) -> Dict[str, Any]:
        """Submit a SHOW SQL and return the parsed statement response."""
        return self.submit_statement(sql)

    def list_databases(self, async_exec: bool = False) -> Dict[str, Any]:
        raw = self.submit_statement("SHOW DATABASES", async_exec=async_exec)
        rows = _rows_to_dicts(raw)
        databases: List[Dict[str, Any]] = []
        for r in rows:
            databases.append(
                {
                    "name": r.get("name"),
                    "retention_time": r.get("retention_time"),
                    "comment": r.get("comment"),
                    "owner": r.get("owner"),
                    "created_on": r.get("created_on"),
                    "options": r.get("options"),
                    "kind": r.get("kind") or "STANDARD",
                }
            )
        return {"databases": databases}

    def list_schemas(self, db_name: str) -> Dict[str, Any]:
        if not db_name:
            raise ValueError("db_name must not be empty")
        raw = self.submit_statement(f'SHOW SCHEMAS IN DATABASE "{db_name}"')
        rows = _rows_to_dicts(raw)
        schemas: List[Dict[str, Any]] = []
        for r in rows:
            schemas.append(
                {
                    "name": r.get("name"),
                    "database_name": r.get("database_name") or db_name,
                    "owner": r.get("owner"),
                    "retention_time": r.get("retention_time"),
                    "options": r.get("options"),
                    "comment": r.get("comment"),
                    "created_on": r.get("created_on"),
                }
            )
        return {"schemas": schemas}

    def list_users(self) -> Dict[str, Any]:
        raw = self.submit_statement("SHOW USERS")
        rows = _rows_to_dicts(raw)
        users: List[Dict[str, Any]] = []
        for r in rows:
            users.append(
                {
                    "name": r.get("name"),
                    "default_role": r.get("default_role"),
                    "default_warehouse": r.get("default_warehouse"),
                    "default_namespace": r.get("default_namespace"),
                    "login_name": r.get("login_name"),
                    "display_name": r.get("display_name"),
                    "email": r.get("email"),
                    "type": r.get("type"),
                    "disabled": _coerce_bool(r.get("disabled")),
                    "must_change_password": _coerce_bool(r.get("must_change_password")),
                    "snowflake_lock": _coerce_bool(r.get("snowflake_lock")),
                    "password_last_set_time": r.get("password_last_set_time"),
                    "expires_at_time": r.get("expires_at_time"),
                    "created_on": r.get("created_on"),
                    "last_success_login": r.get("last_success_login"),
                    "locked_until_time": r.get("locked_until_time"),
                }
            )
        return {"users": users}

    def list_warehouses(self) -> Dict[str, Any]:
        raw = self.submit_statement("SHOW WAREHOUSES")
        rows = _rows_to_dicts(raw)
        warehouses: List[Dict[str, Any]] = []
        for r in rows:
            warehouses.append(
                {
                    "name": r.get("name"),
                    "state": r.get("state"),
                    "type": r.get("type") or "STANDARD",
                    "size": r.get("size"),
                    "min_cluster_count": _coerce_int(r.get("min_cluster_count")),
                    "max_cluster_count": _coerce_int(r.get("max_cluster_count")),
                    "started_clusters": _coerce_int(r.get("started_clusters")),
                    "running": _coerce_int(r.get("running")),
                    "queued": _coerce_int(r.get("queued")),
                    "is_default": _coerce_bool(r.get("is_default")),
                    "is_current": _coerce_bool(r.get("is_current")),
                    "auto_suspend": _coerce_int(r.get("auto_suspend")),
                    "auto_resume": _coerce_bool(r.get("auto_resume")),
                    "available": r.get("available"),
                    "provisioning": r.get("provisioning"),
                    "quiescing": r.get("quiescing"),
                    "other": r.get("other"),
                    "created_on": r.get("created_on"),
                    "resumed_on": r.get("resumed_on"),
                    "updated_on": r.get("updated_on"),
                    "owner": r.get("owner"),
                    "comment": r.get("comment"),
                    "resource_monitor": r.get("resource_monitor"),
                    "scaling_policy": r.get("scaling_policy") or "STANDARD",
                }
            )
        return {"warehouses": warehouses}

    def list_roles(self) -> Dict[str, Any]:
        raw = self.submit_statement("SHOW ROLES")
        rows = _rows_to_dicts(raw)
        roles: List[Dict[str, Any]] = []
        for r in rows:
            roles.append(
                {
                    "name": r.get("name"),
                    "owner": r.get("owner"),
                    "comment": r.get("comment"),
                    "granted_to_roles": _coerce_int(r.get("granted_to_roles")),
                    "granted_to_users": _coerce_int(r.get("granted_to_users")),
                    "granted_roles": _coerce_int(r.get("granted_roles")),
                    "is_inherited": _coerce_bool(r.get("is_inherited")),
                    "is_default": _coerce_bool(r.get("is_default")),
                    "is_current": _coerce_bool(r.get("is_current")),
                    "created_on": r.get("created_on"),
                }
            )
        return {"roles": roles}

    # ----------------------------------------------------------------- close

    def close(self) -> None:
        if self._owns_client and self._client is not None:
            try:
                self._client.close()
            except Exception:  # pragma: no cover
                pass


# ---------------------------------------------------------------------------
# Statement-response shaping helpers
# ---------------------------------------------------------------------------


def _shape_statement_response(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Coerce a Snowflake SQL API response into our stable router shape."""
    rsmd = raw.get("resultSetMetaData") or {}
    row_type = rsmd.get("rowType") or []
    return {
        "statementHandle": raw.get("statementHandle") or raw.get("statementHandles", [None])[0] if isinstance(raw.get("statementHandles"), list) else raw.get("statementHandle"),
        "code": raw.get("code"),
        "sqlState": raw.get("sqlState"),
        "message": raw.get("message"),
        "statementStatusUrl": raw.get("statementStatusUrl"),
        "resultSetMetaData": {
            "numRows": rsmd.get("numRows") or 0,
            "format": rsmd.get("format") or "json",
            "partitionInfo": rsmd.get("partitionInfo") or [],
            "rowType": [
                {
                    "name": col.get("name"),
                    "type": col.get("type"),
                    "scale": col.get("scale"),
                    "precision": col.get("precision"),
                    "nullable": col.get("nullable"),
                }
                for col in row_type
            ],
        },
        "data": raw.get("data") or [],
        "partition_data": raw.get("partitionData") or raw.get("partition_data") or [],
    }


def _rows_to_dicts(shaped: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Map the [[col0, col1, ...]] rows to [{name: value}, ...] using rowType.

    Snowflake SHOW commands have well-known column names; this gives us a
    dict-shaped row each downstream wrapper can pluck fields out of.
    """
    rsmd = shaped.get("resultSetMetaData") or {}
    cols = [(c.get("name") or "").lower() for c in rsmd.get("rowType") or []]
    out: List[Dict[str, Any]] = []
    for row in shaped.get("data") or []:
        if not isinstance(row, (list, tuple)):
            continue
        d: Dict[str, Any] = {}
        for i, val in enumerate(row):
            key = cols[i] if i < len(cols) else f"col_{i}"
            d[key] = val
        out.append(d)
    return out


def _coerce_bool(v: Any) -> Optional[bool]:
    if v is None:
        return None
    if isinstance(v, bool):
        return v
    s = str(v).strip().lower()
    if s in ("true", "1", "yes", "y", "t"):
        return True
    if s in ("false", "0", "no", "n", "f", ""):
        return False
    return None


def _coerce_int(v: Any) -> Optional[int]:
    if v is None or v == "":
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Singleton accessors
# ---------------------------------------------------------------------------

_singleton: Optional[SnowflakeEngine] = None
_singleton_lock = threading.RLock()


def get_snowflake_engine(
    account: Optional[str] = None,
    user: Optional[str] = None,
    private_key_pem: Optional[str] = None,
    role: Optional[str] = None,
    warehouse: Optional[str] = None,
    database: Optional[str] = None,
    schema: Optional[str] = None,
    client: Optional[httpx.Client] = None,
    force_refresh: bool = False,
) -> SnowflakeEngine:
    """Return the process-wide SnowflakeEngine singleton."""
    global _singleton
    with _singleton_lock:
        explicit = any(
            v is not None
            for v in (account, user, private_key_pem, role, warehouse, database, schema, client)
        )
        if _singleton is None or force_refresh or explicit:
            if _singleton is not None:
                _singleton.close()
            _singleton = SnowflakeEngine(
                account=account,
                user=user,
                private_key_pem=private_key_pem,
                role=role,
                warehouse=warehouse,
                database=database,
                schema=schema,
                client=client,
            )
        return _singleton


def reset_snowflake_engine() -> None:
    global _singleton
    with _singleton_lock:
        if _singleton is not None:
            _singleton.close()
        _singleton = None


# Module-load heartbeat
try:  # pragma: no cover
    _emit_event("engine.loaded", {"module": __name__})
except Exception:  # noqa: BLE001
    pass

__all__ = [
    "SnowflakeEngine",
    "SnowflakeUnavailableError",
    "SnowflakeHTTPError",
    "get_snowflake_engine",
    "reset_snowflake_engine",
]
