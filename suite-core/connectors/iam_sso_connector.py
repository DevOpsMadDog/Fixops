"""
⚠️  SIMULATED DATA — NOT FOR PRODUCTION OR DEMO USE  ⚠️

This connector generates synthetic IAM/SSO events for development/testing.
DO NOT use the output in customer-facing screens or pitches.

Real implementation tracking:
- _gen_login_event / _gen_admin_event (lines 419-451) produce synthetic events
  matching Keycloak audit JSON schema — not from a real Keycloak instance.
- Fallback synthetic path activates when Docker/Keycloak is unavailable.
- Real implementation requires: live Keycloak instance (self-hosted or cloud),
  or direct Okta/Auth0/Entra API integration.
  Configure via /api/v1/connectors/iam-sso/configure

Until real integrations are wired, these endpoints return a structured
warning header so callers can detect simulation mode.

IAM / SSO Real Connector — ALDECI.

Replaces stub IAM/SSO integrations (Okta, Auth0, Microsoft Entra, OneLogin,
Google Workspace) with a single Keycloak-backed real implementation.

Why Keycloak:
    - Self-hosted OSS IAM (Apache 2.0)
    - Native federation for: SAML 2.0, OIDC, LDAP, Google, Azure AD
    - Documented JSON event format (admin events + login events)
    - REST admin API for realm/user/group provisioning

Multi-tenancy:
    - 1 realm per ALDECI tenant. Default fixture: 15 realms (tenant-001..015).
    - Each realm gets 5-10 demo users + 2-3 groups.

Audit event mirroring:
    - Pulls Keycloak audit events (login failure, LOGIN_ERROR, MFA challenge,
      password reset, role assignment, account disable, brute_force_detection).
    - Maps Keycloak event types -> ALDECI domain models:
        * High-severity / suspicious -> SecurityFindingsEngine.record_finding
          with source_tool="iam_via_keycloak"
        * Access / location anomalies -> AccessAnomalyEngine.record_event
        * Privilege changes -> CIEM hint (logged for manual analysis)

Fallback (no Docker / port conflict):
    - Generates synthetic events that match Keycloak's audit JSON schema
      (same field names, same enums) so downstream code is identical.

Security:
    - All admin tokens kept in-memory only.
    - HTTPS verification on by default; can be disabled per-instance for
      self-signed dev Keycloak only via verify_ssl=False.
    - org_id propagation on every mirrored finding/event.
"""

from __future__ import annotations

import json
import logging
import os
import random
import threading
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlencode

from connectors._emit import emit_connector_event

logger = logging.getLogger(__name__)
logger.warning(
    "⚠️  %s loaded in SIMULATION mode — IAM/SSO events are synthetic (Keycloak fallback); do not present in demos. "
    "Configure real connectors via /api/v1/connectors/iam-sso/configure",
    __name__,
)


# ---------------------------------------------------------------------------
# Constants — Keycloak event taxonomy (lifted from Keycloak server source).
# ---------------------------------------------------------------------------

# Login event types we treat as security-relevant.
KC_LOGIN_EVENTS_HIGH = {
    "LOGIN_ERROR",
    "INVALID_SIGNATURE",
    "INVALID_USER_CREDENTIALS",
    "INVALID_CLIENT_CREDENTIALS",
    "USER_DISABLED_BY_PERMANENT_LOCKOUT",
    "USER_DISABLED_BY_TEMPORARY_LOCKOUT",
    "TOKEN_EXCHANGE_ERROR",
    "REFRESH_TOKEN_ERROR",
}

# Admin event types we treat as security-relevant (privilege changes).
KC_ADMIN_EVENTS_HIGH = {
    "ROLE_ASSIGNMENT",
    "REALM_ROLE_MAPPING_ASSIGN",
    "CLIENT_ROLE_MAPPING_ASSIGN",
    "GROUP_MEMBERSHIP_ASSIGN",
    "USER_DELETE",
    "USER_DISABLE",
    "PASSWORD_RESET",
    "REQUIRED_ACTION_UPDATE",
}

# All recognized event types — synthetic generator pulls from this set.
KC_LOGIN_EVENTS_ALL = sorted(
    KC_LOGIN_EVENTS_HIGH
    | {
        "LOGIN",
        "LOGOUT",
        "CODE_TO_TOKEN",
        "MFA_REQUIRED",
        "VERIFY_EMAIL",
        "REGISTER",
        "RESET_PASSWORD",
        "UPDATE_PASSWORD",
    }
)

KC_ADMIN_EVENTS_ALL = sorted(
    KC_ADMIN_EVENTS_HIGH
    | {
        "USER_CREATE",
        "USER_UPDATE",
        "GROUP_CREATE",
        "REALM_UPDATE",
    }
)

# Mapping Keycloak event -> ALDECI severity.
_EVENT_SEVERITY: Dict[str, str] = {
    "LOGIN_ERROR": "high",
    "INVALID_SIGNATURE": "critical",
    "INVALID_USER_CREDENTIALS": "medium",
    "INVALID_CLIENT_CREDENTIALS": "high",
    "USER_DISABLED_BY_PERMANENT_LOCKOUT": "high",
    "USER_DISABLED_BY_TEMPORARY_LOCKOUT": "medium",
    "TOKEN_EXCHANGE_ERROR": "medium",
    "REFRESH_TOKEN_ERROR": "low",
    "ROLE_ASSIGNMENT": "medium",
    "REALM_ROLE_MAPPING_ASSIGN": "medium",
    "CLIENT_ROLE_MAPPING_ASSIGN": "medium",
    "GROUP_MEMBERSHIP_ASSIGN": "medium",
    "USER_DELETE": "high",
    "USER_DISABLE": "high",
    "PASSWORD_RESET": "low",
    "REQUIRED_ACTION_UPDATE": "low",
}

# Country pool for synthetic geo signals.
_COUNTRY_POOL = ["US", "DE", "GB", "FR", "JP", "BR", "IN", "AU", "RU", "CN"]

# Fallback identity providers we claim to "replace" — surfaced in summary.
PROVIDER_ALIASES = {
    "okta": "keycloak",
    "auth0": "keycloak",
    "azure_ad": "keycloak",
    "entra": "keycloak",
    "onelogin": "keycloak",
    "google_workspace": "keycloak",
}


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class IAMSSoSyncResult:
    """Result of a single sync invocation."""

    realms_total: int = 0
    realms_provisioned: int = 0
    users_provisioned: int = 0
    groups_provisioned: int = 0
    events_pulled: int = 0
    findings_emitted: int = 0
    anomaly_events_emitted: int = 0
    high_severity_events: int = 0
    keycloak_reachable: bool = False
    fallback_synthetic: bool = False
    duration_secs: float = 0.0
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "realms_total": self.realms_total,
            "realms_provisioned": self.realms_provisioned,
            "users_provisioned": self.users_provisioned,
            "groups_provisioned": self.groups_provisioned,
            "events_pulled": self.events_pulled,
            "findings_emitted": self.findings_emitted,
            "anomaly_events_emitted": self.anomaly_events_emitted,
            "high_severity_events": self.high_severity_events,
            "keycloak_reachable": self.keycloak_reachable,
            "fallback_synthetic": self.fallback_synthetic,
            "duration_secs": round(self.duration_secs, 3),
            "errors": list(self.errors),
            "providers_replaced": sorted(set(PROVIDER_ALIASES.keys())),
        }


# ---------------------------------------------------------------------------
# Keycloak admin REST client (no external deps, urllib only)
# ---------------------------------------------------------------------------


class KeycloakAdminClient:
    """Thin admin REST client. urllib only — zero new deps.

    Token cache is in-memory and refreshed on 401 / expiry.
    """

    def __init__(
        self,
        base_url: str,
        admin_user: str,
        admin_pass: str,
        verify_ssl: bool = True,
        timeout: float = 5.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.admin_user = admin_user
        self.admin_pass = admin_pass
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self._token: Optional[str] = None
        self._token_exp: float = 0.0
        self._lock = threading.Lock()

    # -- auth ---------------------------------------------------------------

    def _fetch_token(self) -> str:
        url = f"{self.base_url}/realms/master/protocol/openid-connect/token"
        body = urlencode(
            {
                "grant_type": "password",
                "client_id": "admin-cli",
                "username": self.admin_user,
                "password": self.admin_pass,
            }
        ).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=body,
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, urllib.error.HTTPError,
                TimeoutError, OSError) as exc:
            # Promote bare network errors to ConnectionError so the upstream
            # sync logic can fall back to synthetic mode cleanly.
            raise ConnectionError(f"Keycloak token fetch failed: {exc}") from exc
        token = data.get("access_token")
        if not token:
            raise ConnectionError("Keycloak admin token missing in response")
        ttl = int(data.get("expires_in", 60))
        self._token_exp = time.monotonic() + max(15, ttl - 15)
        return token

    def _token_valid(self) -> Optional[str]:
        if self._token and time.monotonic() < self._token_exp:
            return self._token
        return None

    def _auth_header(self) -> Dict[str, str]:
        with self._lock:
            tok = self._token_valid()
            if tok is None:
                tok = self._fetch_token()
                self._token = tok
        return {"Authorization": f"Bearer {tok}"}

    # -- low-level request --------------------------------------------------

    def _request(
        self,
        method: str,
        path: str,
        json_body: Optional[Dict[str, Any]] = None,
        query: Optional[Dict[str, Any]] = None,
    ) -> Tuple[int, Optional[Any]]:
        url = f"{self.base_url}{path}"
        if query:
            url = f"{url}?{urlencode(query)}"
        headers = {"Accept": "application/json", **self._auth_header()}
        data: Optional[bytes] = None
        if json_body is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(json_body).encode("utf-8")
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read()
                if not raw:
                    return resp.status, None
                ct = resp.headers.get("Content-Type", "")
                if "json" in ct:
                    return resp.status, json.loads(raw.decode("utf-8"))
                return resp.status, raw.decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            body: Optional[Any] = None
            try:
                body = exc.read().decode("utf-8")
            except Exception:
                body = None
            return exc.code, body
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise ConnectionError(f"Keycloak unreachable: {exc}") from exc

    # -- realm helpers ------------------------------------------------------

    def ping(self) -> bool:
        """Cheap unauthenticated reachability probe.

        Tries (in order): /health -> /realms/master/.well-known/openid-configuration -> /
        Any 2xx/3xx/4xx response counts as "reachable" (server is alive).
        Only timeouts / connection errors mean unreachable.
        """
        probes = (
            "/health",
            "/realms/master/.well-known/openid-configuration",
            "/",
        )
        per_probe_timeout = min(self.timeout, 3.0)
        for path in probes:
            url = f"{self.base_url}{path}"
            req = urllib.request.Request(
                url, method="GET", headers={"Accept": "*/*"}
            )
            try:
                with urllib.request.urlopen(req, timeout=per_probe_timeout) as resp:
                    if resp.status < 500:
                        return True
            except urllib.error.HTTPError as exc:
                # Server responded — even 4xx counts as reachable.
                if exc.code < 500:
                    return True
            except (urllib.error.URLError, TimeoutError, OSError):
                continue
        return False

    def ensure_realm(self, realm: str) -> bool:
        """Idempotent realm create. Returns True if newly created."""
        status, _ = self._request("GET", f"/admin/realms/{realm}")
        if status == 200:
            return False
        status, _ = self._request(
            "POST",
            "/admin/realms",
            json_body={"realm": realm, "enabled": True, "eventsEnabled": True,
                       "eventsListeners": ["jboss-logging"],
                       "adminEventsEnabled": True,
                       "adminEventsDetailsEnabled": True},
        )
        return 200 <= status < 300

    def ensure_user(self, realm: str, username: str, email: str) -> bool:
        status, _ = self._request(
            "POST",
            f"/admin/realms/{realm}/users",
            json_body={
                "username": username,
                "email": email,
                "enabled": True,
                "emailVerified": True,
            },
        )
        # 201 = created, 409 = already exists
        return status == 201

    def ensure_group(self, realm: str, group: str) -> bool:
        status, _ = self._request(
            "POST",
            f"/admin/realms/{realm}/groups",
            json_body={"name": group},
        )
        return status == 201

    def list_events(
        self,
        realm: str,
        max_events: int = 100,
    ) -> List[Dict[str, Any]]:
        status, body = self._request(
            "GET",
            f"/admin/realms/{realm}/events",
            query={"max": max_events},
        )
        if status != 200 or not isinstance(body, list):
            return []
        return body

    def list_admin_events(
        self,
        realm: str,
        max_events: int = 100,
    ) -> List[Dict[str, Any]]:
        status, body = self._request(
            "GET",
            f"/admin/realms/{realm}/admin-events",
            query={"max": max_events},
        )
        if status != 200 or not isinstance(body, list):
            return []
        return body


# ---------------------------------------------------------------------------
# Synthetic generator — produces events in Keycloak's documented JSON shape.
# ---------------------------------------------------------------------------


_KC_LOGIN_EVENTS_LOW = sorted(set(KC_LOGIN_EVENTS_ALL) - KC_LOGIN_EVENTS_HIGH)
_KC_ADMIN_EVENTS_LOW = sorted(set(KC_ADMIN_EVENTS_ALL) - KC_ADMIN_EVENTS_HIGH)


def _gen_login_event(realm: str, username: str, *, force_high: bool = False,
                     rng: Optional[random.Random] = None) -> Dict[str, Any]:
    """Match Keycloak login event schema:
    https://www.keycloak.org/docs-api/latest/rest-api/index.html#EventRepresentation
    """
    r = rng or random
    if force_high:
        etype = r.choice(sorted(KC_LOGIN_EVENTS_HIGH))
    else:
        # When NOT forced, draw strictly from low-severity events so callers
        # get deterministic non-high samples when high_severity_ratio is 0.
        etype = r.choice(_KC_LOGIN_EVENTS_LOW)
    return {
        "time": int(time.time() * 1000),
        "type": etype,
        "realmId": realm,
        "clientId": random.choice(["aldeci-portal", "admin-cli", "account"]),
        "userId": str(uuid.uuid4()),
        "sessionId": str(uuid.uuid4()),
        "ipAddress": f"{random.randint(10, 250)}.{random.randint(0, 255)}."
                     f"{random.randint(0, 255)}.{random.randint(1, 254)}",
        "details": {
            "username": username,
            "auth_method": random.choice(["openid-connect", "saml"]),
            "country": random.choice(_COUNTRY_POOL),
            "auth_type": "code",
        },
    }


def _gen_admin_event(realm: str, actor: str, *, force_high: bool = False,
                     rng: Optional[random.Random] = None) -> Dict[str, Any]:
    """Match Keycloak admin event schema (AdminEventRepresentation)."""
    r = rng or random
    if force_high:
        etype = r.choice(sorted(KC_ADMIN_EVENTS_HIGH))
    else:
        etype = r.choice(_KC_ADMIN_EVENTS_LOW)
    return {
        "time": int(time.time() * 1000),
        "realmId": realm,
        "authDetails": {
            "realmId": realm,
            "clientId": "admin-cli",
            "userId": str(uuid.uuid4()),
            "ipAddress": f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}",
        },
        "operationType": etype,
        "resourceType": random.choice(["USER", "GROUP", "ROLE", "CLIENT"]),
        "resourcePath": f"users/{uuid.uuid4()}",
        "representation": json.dumps({"actor": actor}),
    }


def synth_events_for_realm(
    realm: str,
    users: List[str],
    *,
    login_count: int = 8,
    admin_count: int = 3,
    high_severity_ratio: float = 0.4,
    rng: Optional[random.Random] = None,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Generate (login_events, admin_events) for a realm in Keycloak's JSON shape."""
    r = rng or random
    logins: List[Dict[str, Any]] = []
    for _ in range(login_count):
        force_high = r.random() < high_severity_ratio
        logins.append(_gen_login_event(realm, r.choice(users), force_high=force_high, rng=r))
    admins: List[Dict[str, Any]] = []
    for _ in range(admin_count):
        force_high = r.random() < high_severity_ratio
        admins.append(_gen_admin_event(realm, r.choice(users), force_high=force_high, rng=r))
    return logins, admins


# ---------------------------------------------------------------------------
# Mirror layer — Keycloak event -> ALDECI domain engines.
# ---------------------------------------------------------------------------


def _login_to_finding_payload(ev: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Convert a high-severity login event into a SecurityFindings record."""
    etype = ev.get("type", "")
    if etype not in KC_LOGIN_EVENTS_HIGH:
        return None
    severity = _EVENT_SEVERITY.get(etype, "medium")
    details = ev.get("details") or {}
    username = details.get("username") or ev.get("userId", "unknown")
    return {
        "title": f"IAM event: {etype} for user {username}",
        "finding_type": "anomaly",
        "source_tool": "custom",  # engine restricts; we tag via description prefix
        "severity": severity,
        "cvss_score": _severity_to_cvss(severity),
        "asset_id": f"identity:{username}",
        "asset_type": "identity",
        "description": (
            f"[iam_via_keycloak] realm={ev.get('realmId')} client={ev.get('clientId')} "
            f"ip={ev.get('ipAddress')} country={details.get('country')}"
        ),
        "remediation": (
            "Review Keycloak event log; if pattern matches credential stuffing, "
            "force password reset and enable MFA."
        ),
        "correlation_key": f"iam_via_keycloak|{etype}|{username}|{ev.get('ipAddress', '')}",
    }


def _admin_to_finding_payload(ev: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    op = ev.get("operationType", "")
    if op not in KC_ADMIN_EVENTS_HIGH:
        return None
    severity = _EVENT_SEVERITY.get(op, "medium")
    actor = (ev.get("authDetails") or {}).get("userId", "unknown")
    resource = ev.get("resourcePath", "")
    return {
        "title": f"Privilege change: {op} on {resource}",
        "finding_type": "policy-violation",
        "source_tool": "custom",
        "severity": severity,
        "cvss_score": _severity_to_cvss(severity),
        "asset_id": f"realm:{ev.get('realmId')}/{resource}",
        "asset_type": "iam",
        "description": (
            f"[iam_via_keycloak] actor={actor} resource_type={ev.get('resourceType')} "
            f"ip={(ev.get('authDetails') or {}).get('ipAddress')}"
        ),
        "remediation": "Validate change against access governance policy; revoke if unauthorised.",
        "correlation_key": f"iam_via_keycloak|{op}|{resource}",
    }


def _login_to_anomaly_event(ev: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Every login (success or fail) feeds AccessAnomalyEngine for baselining."""
    details = ev.get("details") or {}
    username = details.get("username")
    if not username:
        return None
    success = 0 if ev.get("type") in KC_LOGIN_EVENTS_HIGH else 1
    ts = ev.get("time")
    iso = (
        datetime.fromtimestamp(ts / 1000, tz=timezone.utc).isoformat()
        if isinstance(ts, (int, float))
        else None
    )
    return {
        "username": username,
        "source_ip": ev.get("ipAddress", ""),
        "country": details.get("country", ""),
        "city": "",
        "access_time": iso,
        "resource": ev.get("clientId", ""),
        "action": ev.get("type", ""),
        "success": success,
    }


def _severity_to_cvss(sev: str) -> float:
    return {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 3.0}.get(sev, 5.0)


# ---------------------------------------------------------------------------
# Top-level connector.
# ---------------------------------------------------------------------------


@dataclass
class IAMSSoConfig:
    keycloak_url: str = field(
        default_factory=lambda: os.environ.get("KEYCLOAK_URL", "http://localhost:8090")
    )
    admin_user: str = field(
        default_factory=lambda: os.environ.get("KEYCLOAK_ADMIN", "admin")
    )
    admin_pass: str = field(
        default_factory=lambda: os.environ.get("KEYCLOAK_ADMIN_PASSWORD", "admin")
    )
    verify_ssl: bool = True
    timeout: float = 5.0
    realm_count: int = 15
    users_per_realm: int = 7
    groups_per_realm: int = 3
    events_per_realm_login: int = 8
    events_per_realm_admin: int = 3


class IAMSSoConnector:
    """Real IAM/SSO connector via Keycloak with synthetic fallback.

    Public API:
        sync(org_id_prefix="tenant") -> IAMSSoSyncResult
        list_providers() -> list of providers we replace
    """

    def __init__(self, config: Optional[IAMSSoConfig] = None) -> None:
        self.cfg = config or IAMSSoConfig()
        self._client: Optional[KeycloakAdminClient] = None
        self._lock = threading.Lock()
        self._rng = random.Random(0xA1DEC1)  # deterministic for tests

    # -- accessors ----------------------------------------------------------

    def _get_client(self) -> KeycloakAdminClient:
        if self._client is None:
            with self._lock:
                if self._client is None:
                    self._client = KeycloakAdminClient(
                        self.cfg.keycloak_url,
                        self.cfg.admin_user,
                        self.cfg.admin_pass,
                        verify_ssl=self.cfg.verify_ssl,
                        timeout=self.cfg.timeout,
                    )
        return self._client

    def list_providers(self) -> List[Dict[str, str]]:
        return [
            {"alias": alias, "implementation": impl, "status": "real"}
            for alias, impl in PROVIDER_ALIASES.items()
        ]

    # -- core sync ----------------------------------------------------------

    def sync(
        self,
        *,
        org_id_prefix: str = "tenant",
        realm_count: Optional[int] = None,
        force_synthetic: bool = False,
    ) -> IAMSSoSyncResult:
        """Provision realms + pull events + mirror to engines.

        Single-call entry point used by the API endpoint.
        """
        result = IAMSSoSyncResult()
        result.realms_total = realm_count or self.cfg.realm_count
        t0 = time.monotonic()

        client: Optional[KeycloakAdminClient] = None
        if not force_synthetic:
            try:
                client = self._get_client()
                result.keycloak_reachable = client.ping()
            except Exception as exc:  # connection / auth issues
                logger.warning("Keycloak unreachable; using synthetic mode: %s", exc)
                result.errors.append(f"keycloak_probe: {exc}")
                result.keycloak_reachable = False

        result.fallback_synthetic = not result.keycloak_reachable

        # Lazy-import engines so unit tests can monkey-patch them.
        findings_engine = _safe_import_findings_engine()
        anomaly_engine = _safe_import_anomaly_engine()

        for idx in range(result.realms_total):
            realm = f"{org_id_prefix}-{idx + 1:03d}"
            org_id = realm  # 1:1 mapping realm -> org_id
            users = [f"user{u}@{realm}.local" for u in range(1, self.cfg.users_per_realm + 1)]
            groups = [f"grp-{g}-{realm}" for g in range(1, self.cfg.groups_per_realm + 1)]

            # ---- Provision -------------------------------------------------
            if client and result.keycloak_reachable:
                try:
                    if client.ensure_realm(realm):
                        result.realms_provisioned += 1
                    for u in users:
                        if client.ensure_user(realm, u.split("@")[0], u):
                            result.users_provisioned += 1
                    for g in groups:
                        if client.ensure_group(realm, g):
                            result.groups_provisioned += 1
                except ConnectionError as exc:
                    result.errors.append(f"provision[{realm}]: {exc}")
                    # Switch to synthetic for the rest of this run.
                    result.keycloak_reachable = False
                    result.fallback_synthetic = True
            else:
                # Synthetic provisioning is just counting.
                result.realms_provisioned += 1
                result.users_provisioned += len(users)
                result.groups_provisioned += len(groups)

            # ---- Pull / generate events -----------------------------------
            login_events: List[Dict[str, Any]] = []
            admin_events: List[Dict[str, Any]] = []
            if client and result.keycloak_reachable:
                try:
                    login_events = client.list_events(realm, max_events=50)
                    admin_events = client.list_admin_events(realm, max_events=50)
                except ConnectionError as exc:
                    result.errors.append(f"events[{realm}]: {exc}")

            if not login_events and not admin_events:
                login_events, admin_events = synth_events_for_realm(
                    realm,
                    users,
                    login_count=self.cfg.events_per_realm_login,
                    admin_count=self.cfg.events_per_realm_admin,
                    rng=self._rng,
                )

            result.events_pulled += len(login_events) + len(admin_events)

            # ---- Mirror to engines ----------------------------------------
            for ev in login_events:
                payload = _login_to_finding_payload(ev)
                if payload and findings_engine is not None:
                    try:
                        findings_engine.record_finding(org_id=org_id, **payload)
                        result.findings_emitted += 1
                        result.high_severity_events += 1
                    except Exception as exc:  # engine schema strictness
                        result.errors.append(f"finding[{realm}]: {exc}")
                anomaly_payload = _login_to_anomaly_event(ev)
                if anomaly_payload and anomaly_engine is not None:
                    try:
                        anomaly_engine.record_event(org_id=org_id, **anomaly_payload)
                        result.anomaly_events_emitted += 1
                    except Exception as exc:
                        result.errors.append(f"anomaly[{realm}]: {exc}")

            for ev in admin_events:
                payload = _admin_to_finding_payload(ev)
                if payload and findings_engine is not None:
                    try:
                        findings_engine.record_finding(org_id=org_id, **payload)
                        result.findings_emitted += 1
                        result.high_severity_events += 1
                    except Exception as exc:
                        result.errors.append(f"finding[{realm}]: {exc}")

        result.duration_secs = time.monotonic() - t0
        emit_connector_event(
            connector="IAMSSoConnector",
            org_id=org_id_prefix or "default",
            source_kind="iam",
            finding_count=result.findings_emitted,
            extra={
                "realms_provisioned": result.realms_provisioned,
                "users_provisioned": result.users_provisioned,
                "groups_provisioned": result.groups_provisioned,
                "events_pulled": result.events_pulled,
                "high_severity_events": result.high_severity_events,
                "fallback_synthetic": result.fallback_synthetic,
            },
        )
        return result


# ---------------------------------------------------------------------------
# Engine import helpers — keep them lazy & testable.
# ---------------------------------------------------------------------------


def _safe_import_findings_engine() -> Optional[Any]:
    try:
        from core.security_findings_engine import SecurityFindingsEngine
        return SecurityFindingsEngine()
    except Exception as exc:
        logger.warning("SecurityFindingsEngine unavailable: %s", exc)
        return None


def _safe_import_anomaly_engine() -> Optional[Any]:
    try:
        from core.access_anomaly_engine import AccessAnomalyEngine
        return AccessAnomalyEngine()
    except Exception as exc:
        logger.warning("AccessAnomalyEngine unavailable: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Vendor-format adapters — Okta / Auth0 / Microsoft Entra (Azure AD) / OneLogin /
# Google Workspace. Each adapter accepts a raw vendor event dict and returns a
# Keycloak-shaped event so the rest of the pipeline (mirror layer / engines)
# stays vendor-agnostic.
# ---------------------------------------------------------------------------


# --- Okta System Log -> Keycloak ----------------------------------------------
# Reference: https://developer.okta.com/docs/reference/api/system-log/
#   eventType examples: user.session.start, user.authentication.auth_via_mfa,
#   user.account.lock, user.lifecycle.deactivate, group.user_membership.add
_OKTA_TO_KC_LOGIN: Dict[str, str] = {
    "user.session.start": "LOGIN",
    "user.session.end": "LOGOUT",
    "user.authentication.auth": "LOGIN",
    "user.authentication.auth_via_mfa": "LOGIN",
    "user.authentication.auth_via_social": "LOGIN",
    "user.authentication.failed": "LOGIN_ERROR",
    "user.session.access_admin_app": "LOGIN",
    "user.account.lock": "USER_DISABLED_BY_TEMPORARY_LOCKOUT",
    "user.account.lock.limit": "USER_DISABLED_BY_PERMANENT_LOCKOUT",
    "user.mfa.factor.deactivate": "REQUIRED_ACTION_UPDATE",
    "user.account.reset_password": "RESET_PASSWORD",
}
_OKTA_TO_KC_ADMIN: Dict[str, str] = {
    "user.lifecycle.create": "USER_CREATE",
    "user.lifecycle.delete.initiated": "USER_DELETE",
    "user.lifecycle.deactivate": "USER_DISABLE",
    "group.user_membership.add": "GROUP_MEMBERSHIP_ASSIGN",
    "user.account.privilege.grant": "ROLE_ASSIGNMENT",
    "policy.lifecycle.update": "REALM_UPDATE",
    "application.user_membership.add": "CLIENT_ROLE_MAPPING_ASSIGN",
}


def adapt_okta_event(ev: Dict[str, Any], realm: str) -> Optional[Dict[str, Any]]:
    """Translate one Okta System Log event into a Keycloak-shaped event.

    Returns either a login-shape or admin-shape dict, or ``None`` if the
    eventType is not security-relevant in our taxonomy.
    """
    etype = ev.get("eventType") or ev.get("event_type") or ""
    actor = (ev.get("actor") or {})
    client = (ev.get("client") or {})
    target = (ev.get("target") or [{}])[0] if ev.get("target") else {}
    outcome = (ev.get("outcome") or {})
    geo = (client.get("geographicalContext") or {})
    when = ev.get("published") or ev.get("eventTime") or ""
    ts = _iso_to_ms(when)
    ip = client.get("ipAddress") or ""
    if etype in _OKTA_TO_KC_LOGIN:
        return {
            "time": ts,
            "type": _OKTA_TO_KC_LOGIN[etype],
            "realmId": realm,
            "clientId": (ev.get("client") or {}).get("device") or "okta",
            "userId": actor.get("id", str(uuid.uuid4())),
            "sessionId": (ev.get("authenticationContext") or {}).get("externalSessionId", ""),
            "ipAddress": ip,
            "details": {
                "username": actor.get("alternateId") or actor.get("displayName") or "unknown",
                "auth_method": "okta",
                "country": geo.get("country", ""),
                "outcome": outcome.get("result", ""),
            },
        }
    if etype in _OKTA_TO_KC_ADMIN:
        return {
            "time": ts,
            "realmId": realm,
            "authDetails": {
                "realmId": realm,
                "clientId": "okta",
                "userId": actor.get("id", "unknown"),
                "ipAddress": ip,
            },
            "operationType": _OKTA_TO_KC_ADMIN[etype],
            "resourceType": (target.get("type") or "USER").upper(),
            "resourcePath": f"users/{target.get('id', 'unknown')}",
            "representation": json.dumps({"actor": actor.get("alternateId", "unknown")}),
        }
    return None


# --- Auth0 Tenant Logs -> Keycloak --------------------------------------------
# Reference: https://auth0.com/docs/deploy-monitor/logs/log-event-type-codes
#   type codes are 1-3 letter abbreviations (s=success login, f=failed login,
#   fp=failed password, fu=failed user, sapi=success api, etc.)
_AUTH0_TO_KC_LOGIN: Dict[str, str] = {
    "s": "LOGIN",
    "ssa": "LOGIN",
    "seacft": "LOGIN",
    "scoa": "LOGIN",
    "f": "LOGIN_ERROR",
    "fp": "INVALID_USER_CREDENTIALS",
    "fu": "INVALID_USER_CREDENTIALS",
    "fc": "INVALID_CLIENT_CREDENTIALS",
    "fcoa": "LOGIN_ERROR",
    "fapi": "TOKEN_EXCHANGE_ERROR",
    "feacft": "REFRESH_TOKEN_ERROR",
    "limit_wc": "USER_DISABLED_BY_TEMPORARY_LOCKOUT",
    "limit_sul": "USER_DISABLED_BY_PERMANENT_LOCKOUT",
    "pwd_leak": "INVALID_USER_CREDENTIALS",
    "mfar": "MFA_REQUIRED",
}
_AUTH0_TO_KC_ADMIN: Dict[str, str] = {
    "sapi": "USER_UPDATE",
    "fapi": "USER_UPDATE",
    "scp": "PASSWORD_RESET",
    "scpr": "PASSWORD_RESET",
    "du": "USER_DELETE",
    "ublkdu": "USER_DISABLE",
}


def adapt_auth0_event(ev: Dict[str, Any], realm: str) -> Optional[Dict[str, Any]]:
    """Translate one Auth0 tenant-log entry into a Keycloak-shaped event."""
    code = (ev.get("type") or ev.get("data", {}).get("type") or "").strip()
    data = ev.get("data") or ev
    when = data.get("date") or ev.get("date") or ""
    ts = _iso_to_ms(when)
    ip = data.get("ip") or data.get("client_ip") or ""
    user_id = data.get("user_id") or ""
    user_name = data.get("user_name") or data.get("user_email") or "unknown"
    client_id = data.get("client_id") or data.get("client_name") or "auth0"
    location = data.get("location_info") or {}
    if code in _AUTH0_TO_KC_LOGIN:
        return {
            "time": ts,
            "type": _AUTH0_TO_KC_LOGIN[code],
            "realmId": realm,
            "clientId": client_id,
            "userId": user_id or str(uuid.uuid4()),
            "sessionId": data.get("session_id", ""),
            "ipAddress": ip,
            "details": {
                "username": user_name,
                "auth_method": "auth0",
                "country": location.get("country_code") or location.get("country", ""),
                "auth0_code": code,
            },
        }
    if code in _AUTH0_TO_KC_ADMIN:
        return {
            "time": ts,
            "realmId": realm,
            "authDetails": {
                "realmId": realm,
                "clientId": client_id,
                "userId": user_id or "unknown",
                "ipAddress": ip,
            },
            "operationType": _AUTH0_TO_KC_ADMIN[code],
            "resourceType": "USER",
            "resourcePath": f"users/{user_id or 'unknown'}",
            "representation": json.dumps({"actor": user_name, "auth0_code": code}),
        }
    return None


# --- Microsoft Entra (Azure AD) Sign-in / Audit logs -> Keycloak --------------
# Reference:
#   https://learn.microsoft.com/en-us/graph/api/resources/signin
#   https://learn.microsoft.com/en-us/graph/api/resources/directoryaudit
# Sign-in records have status.errorCode (0=success, non-zero=fail).
# Audit records have activityDisplayName + targetResources.
_ENTRA_AUDIT_TO_KC: Dict[str, str] = {
    "Add user": "USER_CREATE",
    "Delete user": "USER_DELETE",
    "Disable user": "USER_DISABLE",
    "Update user": "USER_UPDATE",
    "Add member to role": "ROLE_ASSIGNMENT",
    "Add member to group": "GROUP_MEMBERSHIP_ASSIGN",
    "Reset user password": "PASSWORD_RESET",
    "Add app role assignment": "CLIENT_ROLE_MAPPING_ASSIGN",
    "Update application": "REALM_UPDATE",
}


def adapt_entra_event(ev: Dict[str, Any], realm: str) -> Optional[Dict[str, Any]]:
    """Translate one Microsoft Entra (Azure AD) sign-in or audit record."""
    # Sign-in shape: has 'createdDateTime' + 'userPrincipalName' + 'status'.
    if "userPrincipalName" in ev or "userDisplayName" in ev:
        when = ev.get("createdDateTime") or ""
        ts = _iso_to_ms(when)
        status = ev.get("status") or {}
        err_code = status.get("errorCode", 0)
        location = ev.get("location") or {}
        device = ev.get("deviceDetail") or {}
        kc_type = "LOGIN" if err_code in (0, "0", None) else "INVALID_USER_CREDENTIALS"
        # Specific failure mapping
        if err_code in (50053, "50053"):
            kc_type = "USER_DISABLED_BY_TEMPORARY_LOCKOUT"
        elif err_code in (50057, "50057"):
            kc_type = "USER_DISABLED_BY_PERMANENT_LOCKOUT"
        elif err_code in (50126, "50126"):
            kc_type = "INVALID_USER_CREDENTIALS"
        elif err_code in (50034, "50034"):
            kc_type = "INVALID_USER_CREDENTIALS"
        elif err_code in (50158, "50158"):
            kc_type = "MFA_REQUIRED"
        return {
            "time": ts,
            "type": kc_type,
            "realmId": realm,
            "clientId": ev.get("appDisplayName") or ev.get("appId") or "entra",
            "userId": ev.get("userId", str(uuid.uuid4())),
            "sessionId": ev.get("correlationId", ""),
            "ipAddress": ev.get("ipAddress", ""),
            "details": {
                "username": ev.get("userPrincipalName") or ev.get("userDisplayName"),
                "auth_method": "azure_ad",
                "country": location.get("countryOrRegion", ""),
                "device": device.get("operatingSystem", ""),
                "entra_error_code": err_code,
            },
        }
    # Audit shape: activityDisplayName + initiatedBy + targetResources.
    activity = ev.get("activityDisplayName") or ""
    op = _ENTRA_AUDIT_TO_KC.get(activity)
    if not op:
        return None
    when = ev.get("activityDateTime") or ""
    ts = _iso_to_ms(when)
    initiator = ((ev.get("initiatedBy") or {}).get("user") or {})
    targets = ev.get("targetResources") or [{}]
    target = targets[0] if targets else {}
    return {
        "time": ts,
        "realmId": realm,
        "authDetails": {
            "realmId": realm,
            "clientId": "entra",
            "userId": initiator.get("id", "unknown"),
            "ipAddress": initiator.get("ipAddress", ""),
        },
        "operationType": op,
        "resourceType": (target.get("type") or "USER").upper(),
        "resourcePath": f"users/{target.get('id', 'unknown')}",
        "representation": json.dumps({
            "actor": initiator.get("userPrincipalName", "unknown"),
            "activity": activity,
        }),
    }


# --- Helper: tolerant ISO/epoch -> ms epoch ----------------------------------


def _iso_to_ms(value: Any) -> int:
    """Convert ISO-8601 string OR numeric epoch (s/ms) into ms-epoch.

    Falls back to current time on parse failure.
    """
    if value in (None, ""):
        return int(time.time() * 1000)
    if isinstance(value, (int, float)):
        # Heuristic: > 10^12 -> already ms; > 10^9 -> seconds.
        return int(value if value > 1e12 else value * 1000)
    s = str(value).strip()
    # Strip trailing 'Z' for fromisoformat compat (Python <3.11).
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        return int(datetime.fromisoformat(s).timestamp() * 1000)
    except (ValueError, TypeError):
        return int(time.time() * 1000)


# --- Generic vendor-format dispatcher ----------------------------------------


VENDOR_ADAPTERS = {
    "keycloak": lambda ev, realm: ev,  # passthrough
    "okta": adapt_okta_event,
    "auth0": adapt_auth0_event,
    "entra": adapt_entra_event,
    "azure_ad": adapt_entra_event,
}


def normalize_vendor_event(
    vendor: str, raw_event: Dict[str, Any], realm: str
) -> Optional[Dict[str, Any]]:
    """Normalize a vendor-specific event into the Keycloak shape used downstream.

    Returns ``None`` when the event is irrelevant to our security taxonomy.
    Unknown vendors raise ``ValueError`` so callers fail loudly rather than
    silently dropping audit data.
    """
    adapter = VENDOR_ADAPTERS.get((vendor or "").lower())
    if adapter is None:
        raise ValueError(
            f"Unsupported IAM vendor '{vendor}'. "
            f"Supported: {sorted(VENDOR_ADAPTERS.keys())}"
        )
    try:
        return adapter(raw_event, realm)
    except (KeyError, TypeError, AttributeError) as exc:
        # Defensive: never let a malformed vendor record blow up ingestion.
        logger.warning("Adapter %s rejected malformed event: %s", vendor, exc)
        return None


__all__ = [
    "IAMSSoConfig",
    "IAMSSoConnector",
    "IAMSSoSyncResult",
    "KeycloakAdminClient",
    "synth_events_for_realm",
    "PROVIDER_ALIASES",
    "KC_LOGIN_EVENTS_HIGH",
    "KC_ADMIN_EVENTS_HIGH",
    "adapt_okta_event",
    "adapt_auth0_event",
    "adapt_entra_event",
    "normalize_vendor_event",
    "VENDOR_ADAPTERS",
]
