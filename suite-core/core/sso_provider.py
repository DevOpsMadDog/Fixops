"""
Enterprise SSO Provider — SAML 2.0 and OIDC authentication.

Supports Okta, Azure AD, Google Workspace, and generic IdPs.
Uses stdlib xml.etree.ElementTree + defusedxml for SAML (no heavy libs).
Uses PyJWT + httpx for OIDC.

Configuration via environment variables:
    FIXOPS_SSO_ENABLED=1
    FIXOPS_SSO_PROVIDER=okta|azure_ad|google|generic_oidc|generic_saml
    FIXOPS_OIDC_CLIENT_ID=...
    FIXOPS_OIDC_CLIENT_SECRET=...
    FIXOPS_OIDC_ISSUER_URL=https://company.okta.com
    FIXOPS_SSO_ALLOWED_DOMAINS=company.com,subsidiary.com
    FIXOPS_SSO_ROLE_MAPPING={"SecurityTeam":"security_analyst"}
    FIXOPS_SP_ENTITY_ID=https://myaldeci.example.com/sso/sp
"""
from __future__ import annotations

import base64
import ipaddress
import json
import logging
import os
import socket
import time
import urllib.parse
import uuid
import xml.etree.ElementTree as ET  # nosec B405
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Literal, Optional

import defusedxml.ElementTree as defused_ET
import httpx
import jwt
from jwt import PyJWKClient
from pydantic import BaseModel, Field, field_validator, model_validator

from core.exceptions import AuthorizationError, ValidationError

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_OIDC_DISCOVERY_SUFFIX = "/.well-known/openid-configuration"

# Module-level JWKS client cache — keyed by jwks_uri, shared across provider instances
_jwks_clients: dict = {}

# ---------------------------------------------------------------------------
# SSRF protection
# ---------------------------------------------------------------------------

_PRIVATE_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),   # link-local / cloud metadata
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fd00::/8"),
    ipaddress.ip_network("fe80::/10"),
]


def _validate_url_not_private(url: str) -> None:
    """Reject URLs that resolve to private/loopback/cloud-metadata addresses.

    Raises:
        AuthorizationError: If the URL hostname resolves to a private IP range.
    """
    parsed = urllib.parse.urlparse(url)
    scheme = parsed.scheme.lower()
    if scheme not in ("https", "http"):
        raise AuthorizationError(f"SSRF guard: unsupported URL scheme '{scheme}'")

    hostname = parsed.hostname
    if not hostname:
        raise AuthorizationError("SSRF guard: URL has no hostname")

    # Explicit block for cloud metadata endpoints by hostname
    if hostname.lower() in ("169.254.169.254", "metadata.google.internal"):
        raise AuthorizationError(f"SSRF guard: blocked cloud metadata hostname '{hostname}'")

    try:
        # Resolve to all addresses to catch DNS rebinding
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as exc:
        raise AuthorizationError(f"SSRF guard: cannot resolve hostname '{hostname}': {exc}") from exc

    for info in infos:
        addr_str = info[4][0]
        try:
            addr = ipaddress.ip_address(addr_str)
        except ValueError:
            continue
        for net in _PRIVATE_NETWORKS:
            if addr in net:
                raise AuthorizationError(
                    f"SSRF guard: URL '{url}' resolves to private address {addr_str} — blocked"
                )

_PROVIDER_DISCOVERY_URLS: Dict[str, str] = {
    "okta": "{issuer}/.well-known/openid-configuration",
    "azure_ad": "https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid-configuration",
    "google": "https://accounts.google.com/.well-known/openid-configuration",
    "generic_oidc": "{issuer}/.well-known/openid-configuration",
}

_SAML_NS = {
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
}

# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class SSOConfig(BaseModel):
    """SSO provider configuration."""

    provider: Literal["okta", "azure_ad", "google", "generic_oidc", "generic_saml"]
    enabled: bool = True

    # OIDC fields
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    issuer_url: Optional[str] = None

    # SAML fields
    idp_metadata_url: Optional[str] = None
    sp_entity_id: Optional[str] = None

    # Access control
    allowed_domains: List[str] = Field(default_factory=list)
    role_mapping: Dict[str, str] = Field(default_factory=dict)

    # Runtime: populated after discovery
    _discovery_cache: Optional[Dict[str, Any]] = None

    @field_validator("allowed_domains", mode="before")
    @classmethod
    def parse_allowed_domains(cls, v: Any) -> List[str]:
        if isinstance(v, str):
            return [d.strip() for d in v.split(",") if d.strip()]
        return v or []

    @field_validator("role_mapping", mode="before")
    @classmethod
    def parse_role_mapping(cls, v: Any) -> Dict[str, str]:
        if isinstance(v, str):
            try:
                return json.loads(v)
            except json.JSONDecodeError:
                return {}
        return v or {}

    @model_validator(mode="after")
    def check_oidc_fields(self) -> "SSOConfig":
        oidc_providers = {"okta", "azure_ad", "google", "generic_oidc"}
        if self.provider in oidc_providers:
            if not self.client_id:
                raise ValueError(f"client_id required for OIDC provider '{self.provider}'")
            if not self.client_secret:
                raise ValueError(f"client_secret required for OIDC provider '{self.provider}'")
            if self.provider != "google" and not self.issuer_url:
                raise ValueError(f"issuer_url required for provider '{self.provider}'")
        elif self.provider == "generic_saml":
            if not self.idp_metadata_url and not self.sp_entity_id:
                raise ValueError("generic_saml requires idp_metadata_url or sp_entity_id")
        return self

    @classmethod
    def from_env(cls) -> Optional["SSOConfig"]:
        """Build SSOConfig from environment variables. Returns None if SSO is disabled."""
        if os.getenv("FIXOPS_SSO_ENABLED", "").strip() not in ("1", "true", "yes"):
            return None
        provider = os.getenv("FIXOPS_SSO_PROVIDER", "generic_oidc")
        return cls(
            provider=provider,  # type: ignore[arg-type]
            client_id=os.getenv("FIXOPS_OIDC_CLIENT_ID"),
            client_secret=os.getenv("FIXOPS_OIDC_CLIENT_SECRET"),
            issuer_url=os.getenv("FIXOPS_OIDC_ISSUER_URL"),
            idp_metadata_url=os.getenv("FIXOPS_SAML_IDP_METADATA_URL"),
            sp_entity_id=os.getenv("FIXOPS_SP_ENTITY_ID", "https://aldeci.example.com/sso/sp"),
            allowed_domains=os.getenv("FIXOPS_SSO_ALLOWED_DOMAINS", ""),
            role_mapping=os.getenv("FIXOPS_SSO_ROLE_MAPPING", "{}"),
        )


class TokenResponse(BaseModel):
    """OAuth2 token endpoint response."""

    access_token: str
    id_token: Optional[str] = None
    refresh_token: Optional[str] = None
    token_type: str = "Bearer"
    expires_in: int = 3600
    scope: Optional[str] = None


class UserInfo(BaseModel):
    """Normalised user identity from IdP."""

    email: str
    name: str = ""
    groups: List[str] = Field(default_factory=list)
    roles: List[str] = Field(default_factory=list)
    provider: str = ""
    sub: str = ""
    raw_claims: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("email")
    @classmethod
    def email_must_have_at(cls, v: str) -> str:
        if "@" not in v:
            raise ValueError("email must contain @")
        return v.lower().strip()


# ---------------------------------------------------------------------------
# Domain / role helpers
# ---------------------------------------------------------------------------


def check_allowed_domain(email: str, allowed_domains: List[str]) -> bool:
    """Return True if email domain is in allowed_domains (or list is empty = allow all)."""
    if not allowed_domains:
        return True
    domain = email.split("@", 1)[-1].lower()
    return domain in [d.lower() for d in allowed_domains]


def map_groups_to_roles(groups: List[str], role_mapping: Dict[str, str]) -> List[str]:
    """Map IdP groups to ALDECI roles using role_mapping dict."""
    roles: List[str] = []
    for group in groups:
        if group in role_mapping:
            mapped = role_mapping[group]
            if mapped not in roles:
                roles.append(mapped)
    return roles


# ---------------------------------------------------------------------------
# OIDC Provider
# ---------------------------------------------------------------------------


class OIDCProvider:
    """OpenID Connect provider for Okta, Azure AD, Google, or generic OIDC."""

    def __init__(self, config: SSOConfig) -> None:
        if config.provider not in ("okta", "azure_ad", "google", "generic_oidc"):
            raise ValueError(f"OIDCProvider does not support provider '{config.provider}'")
        self.config = config
        self._discovery: Optional[Dict[str, Any]] = None

    # ------------------------------------------------------------------
    # Discovery
    # ------------------------------------------------------------------

    def _discovery_url(self) -> str:
        """Build the OIDC discovery document URL."""
        if self.config.provider == "google":
            return "https://accounts.google.com/.well-known/openid-configuration"
        issuer = (self.config.issuer_url or "").rstrip("/")
        return f"{issuer}/.well-known/openid-configuration"

    def fetch_discovery(self, http_client: Optional[httpx.Client] = None) -> Dict[str, Any]:
        """Fetch and cache OIDC discovery document."""
        if self._discovery is not None:
            return self._discovery
        url = self._discovery_url()
        _validate_url_not_private(url)
        client = http_client or httpx.Client(timeout=10)
        try:
            resp = client.get(url)
            resp.raise_for_status()
            self._discovery = resp.json()
            return self._discovery
        except httpx.HTTPError as exc:
            raise AuthorizationError(f"Failed to fetch OIDC discovery from {url}: {exc}") from exc
        finally:
            if http_client is None:
                client.close()

    def _get_endpoint(self, key: str) -> str:
        """Get an endpoint from the discovery document."""
        if not self._discovery:
            raise AuthorizationError("OIDC discovery not loaded — call fetch_discovery() first")
        url = self._discovery.get(key)
        if not url:
            raise AuthorizationError(f"OIDC discovery missing '{key}' endpoint")
        return url

    # ------------------------------------------------------------------
    # Authorization URL
    # ------------------------------------------------------------------

    def get_authorization_url(
        self,
        state: str,
        nonce: str,
        redirect_uri: str,
        scopes: Optional[List[str]] = None,
    ) -> str:
        """Build the OAuth2 authorization URL to redirect the user to."""
        auth_endpoint = self._get_endpoint("authorization_endpoint")
        scope_str = " ".join(scopes or ["openid", "email", "profile"])
        params = {
            "response_type": "code",
            "client_id": self.config.client_id or "",
            "redirect_uri": redirect_uri,
            "scope": scope_str,
            "state": state,
            "nonce": nonce,
        }
        return f"{auth_endpoint}?{urllib.parse.urlencode(params)}"

    # ------------------------------------------------------------------
    # Code exchange
    # ------------------------------------------------------------------

    def exchange_code(
        self,
        code: str,
        redirect_uri: str,
        http_client: Optional[httpx.Client] = None,
    ) -> TokenResponse:
        """Exchange authorization code for tokens."""
        token_endpoint = self._get_endpoint("token_endpoint")
        payload = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": self.config.client_id or "",
            "client_secret": self.config.client_secret or "",
        }
        client = http_client or httpx.Client(timeout=15)
        try:
            resp = client.post(token_endpoint, data=payload)
            resp.raise_for_status()
            data = resp.json()
            if "error" in data:
                raise AuthorizationError(f"Token exchange error: {data['error']} — {data.get('error_description', '')}")
            return TokenResponse(**{k: v for k, v in data.items() if k in TokenResponse.model_fields})
        except httpx.HTTPError as exc:
            raise AuthorizationError(f"Token exchange HTTP error: {exc}") from exc
        finally:
            if http_client is None:
                client.close()

    # ------------------------------------------------------------------
    # Token validation
    # ------------------------------------------------------------------

    def validate_token(self, id_token: str) -> UserInfo:
        """Validate an OIDC id_token JWT and extract user claims.

        Uses PyJWKClient to fetch the IdP's public key from the JWKS URI and
        verifies the RS256 signature, expiry, audience, and issuer.
        """
        jwks_uri = self._discovery.get("jwks_uri", "")
        if not jwks_uri:
            raise ValueError("No jwks_uri in discovery document")

        if jwks_uri not in _jwks_clients:
            _jwks_clients[jwks_uri] = PyJWKClient(jwks_uri, cache_jwk_set=True, lifespan=300)

        client = _jwks_clients[jwks_uri]
        try:
            signing_key = client.get_signing_key_from_jwt(id_token).key
        except Exception as exc:
            raise AuthorizationError(f"Failed to fetch signing key: {exc}") from exc

        try:
            claims = jwt.decode(
                id_token,
                signing_key,
                algorithms=["RS256"],
                audience=self.config.client_id,
                issuer=self.config.issuer_url,
                options={"verify_exp": True, "verify_aud": True, "verify_iss": True},
            )
        except jwt.ExpiredSignatureError as exc:
            raise AuthorizationError("id_token has expired") from exc
        except jwt.DecodeError as exc:
            raise AuthorizationError(f"Invalid id_token: {exc}") from exc
        except jwt.InvalidTokenError as exc:
            raise AuthorizationError(f"Token validation failed: {exc}") from exc

        exp = claims.get("exp", 0)
        if exp and exp < time.time():
            raise AuthorizationError("id_token has expired")

        email = claims.get("email", "")
        if not email:
            raise AuthorizationError("id_token missing email claim")

        groups = claims.get("groups", claims.get("roles", []))
        if isinstance(groups, str):
            groups = [groups]

        mapped_roles = map_groups_to_roles(groups, self.config.role_mapping)

        return UserInfo(
            email=email,
            name=claims.get("name", claims.get("given_name", "")),
            groups=groups,
            roles=mapped_roles,
            provider=self.config.provider,
            sub=str(claims.get("sub", "")),
            raw_claims=claims,
        )

    # ------------------------------------------------------------------
    # Token refresh
    # ------------------------------------------------------------------

    def refresh_token(
        self,
        refresh_token: str,
        http_client: Optional[httpx.Client] = None,
    ) -> TokenResponse:
        """Use a refresh_token to get a new access_token."""
        token_endpoint = self._get_endpoint("token_endpoint")
        payload = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": self.config.client_id or "",
            "client_secret": self.config.client_secret or "",
        }
        client = http_client or httpx.Client(timeout=15)
        try:
            resp = client.post(token_endpoint, data=payload)
            resp.raise_for_status()
            data = resp.json()
            if "error" in data:
                raise AuthorizationError(f"Refresh error: {data['error']}")
            return TokenResponse(**{k: v for k, v in data.items() if k in TokenResponse.model_fields})
        except httpx.HTTPError as exc:
            raise AuthorizationError(f"Token refresh HTTP error: {exc}") from exc
        finally:
            if http_client is None:
                client.close()

    # ------------------------------------------------------------------
    # UserInfo endpoint
    # ------------------------------------------------------------------

    def get_userinfo(
        self,
        access_token: str,
        http_client: Optional[httpx.Client] = None,
    ) -> UserInfo:
        """Call the OIDC /userinfo endpoint and return a UserInfo object."""
        userinfo_endpoint = self._get_endpoint("userinfo_endpoint")
        client = http_client or httpx.Client(timeout=10)
        try:
            resp = client.get(
                userinfo_endpoint,
                headers={"Authorization": f"Bearer {access_token}"},
            )
            resp.raise_for_status()
            claims = resp.json()
        except httpx.HTTPError as exc:
            raise AuthorizationError(f"Userinfo endpoint error: {exc}") from exc
        finally:
            if http_client is None:
                client.close()

        email = claims.get("email", "")
        if not email:
            raise AuthorizationError("Userinfo missing email claim")

        groups = claims.get("groups", claims.get("roles", []))
        if isinstance(groups, str):
            groups = [groups]
        mapped_roles = map_groups_to_roles(groups, self.config.role_mapping)

        return UserInfo(
            email=email,
            name=claims.get("name", ""),
            groups=groups,
            roles=mapped_roles,
            provider=self.config.provider,
            sub=str(claims.get("sub", "")),
            raw_claims=claims,
        )


# ---------------------------------------------------------------------------
# SAML Provider
# ---------------------------------------------------------------------------


class SAMLProvider:
    """SAML 2.0 service provider for generic SAML IdPs.

    Uses stdlib xml.etree + defusedxml — no python3-saml required.
    Signature verification is intentionally limited; production deployments
    should add a cryptography-backed signature check.
    """

    def __init__(self, config: SSOConfig) -> None:
        if config.provider != "generic_saml":
            raise ValueError(f"SAMLProvider requires provider='generic_saml', got '{config.provider}'")
        self.config = config
        self._idp_metadata: Optional[Dict[str, Any]] = None

    # ------------------------------------------------------------------
    # IdP metadata fetch
    # ------------------------------------------------------------------

    def fetch_idp_metadata(self, http_client: Optional[httpx.Client] = None) -> Dict[str, Any]:
        """Fetch and parse IdP metadata XML."""
        if self._idp_metadata is not None:
            return self._idp_metadata
        if not self.config.idp_metadata_url:
            return {}
        _validate_url_not_private(self.config.idp_metadata_url)
        client = http_client or httpx.Client(timeout=10)
        try:
            resp = client.get(self.config.idp_metadata_url)
            resp.raise_for_status()
            root = defused_ET.fromstring(resp.text)
            sso_url = ""
            # Extract SingleSignOnService HTTP-Redirect binding location
            for el in root.iter("{urn:oasis:names:tc:SAML:2.0:metadata}SingleSignOnService"):
                if "HTTP-Redirect" in el.get("Binding", ""):
                    sso_url = el.get("Location", "")
                    break
            self._idp_metadata = {"sso_url": sso_url}
            return self._idp_metadata
        except httpx.HTTPError as exc:
            raise AuthorizationError(f"Failed to fetch IdP metadata: {exc}") from exc
        except ET.ParseError as exc:
            raise ValidationError(f"Invalid IdP metadata XML: {exc}") from exc
        finally:
            if http_client is None:
                client.close()

    # ------------------------------------------------------------------
    # Login URL (AuthnRequest redirect)
    # ------------------------------------------------------------------

    def get_login_url(self, relay_state: str, sso_url: Optional[str] = None) -> str:
        """Build a SAML AuthnRequest and return the redirect URL."""
        _id = f"_{uuid.uuid4().hex}"
        issue_instant = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        sp_entity = self.config.sp_entity_id or "https://aldeci.example.com/sso/sp"
        acs_url = f"{sp_entity}/acs"

        authn_request = (
            f'<samlp:AuthnRequest'
            f' xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"'
            f' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"'
            f' ID="{_id}"'
            f' Version="2.0"'
            f' IssueInstant="{issue_instant}"'
            f' AssertionConsumerServiceURL="{acs_url}"'
            f' ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">'
            f'<saml:Issuer>{sp_entity}</saml:Issuer>'
            f'</samlp:AuthnRequest>'
        )

        encoded = base64.b64encode(authn_request.encode()).decode()
        target = sso_url or (self._idp_metadata or {}).get("sso_url", "")
        if not target:
            raise AuthorizationError("SAML SSO URL not configured — fetch IdP metadata first")

        params = urllib.parse.urlencode({
            "SAMLRequest": encoded,
            "RelayState": relay_state,
        })
        return f"{target}?{params}"

    # ------------------------------------------------------------------
    # Response processing
    # ------------------------------------------------------------------

    def process_response(self, saml_response: str) -> UserInfo:
        """Decode and parse a base64-encoded SAML Response.

        Extracts NameID (email) and Attribute statements.
        Note: Full XML signature verification requires a cryptography
        integration beyond stdlib scope — validate in production with
        pysaml2 or xmlsec1.
        """
        try:
            xml_bytes = base64.b64decode(saml_response)
            root = defused_ET.fromstring(xml_bytes)
        except (ValueError, ET.ParseError) as exc:
            raise ValidationError(f"Invalid SAML response: {exc}") from exc

        # Status check
        status_code = root.find(
            ".//{urn:oasis:names:tc:SAML:2.0:protocol}StatusCode"
        )
        if status_code is not None:
            value = status_code.get("Value", "")
            if "Success" not in value:
                raise AuthorizationError(f"SAML response status not Success: {value}")

        # NameID — typically the email
        name_id_el = root.find(".//{urn:oasis:names:tc:SAML:2.0:assertion}NameID")
        email = (name_id_el.text or "").strip() if name_id_el is not None else ""
        if not email or "@" not in email:
            raise AuthorizationError("SAML response missing valid email in NameID")

        # Attribute statements
        attrs: Dict[str, List[str]] = {}
        for attr in root.iter("{urn:oasis:names:tc:SAML:2.0:assertion}Attribute"):
            attr_name = attr.get("Name", "")
            values = [
                v.text or ""
                for v in attr.iter("{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue")
            ]
            attrs[attr_name] = values

        name = " ".join(attrs.get("displayName", attrs.get("cn", [""]))).strip()
        groups: List[str] = attrs.get("groups", attrs.get("memberOf", []))
        mapped_roles = map_groups_to_roles(groups, self.config.role_mapping)

        return UserInfo(
            email=email,
            name=name,
            groups=groups,
            roles=mapped_roles,
            provider="generic_saml",
            sub=email,
            raw_claims={"attributes": attrs},
        )

    # ------------------------------------------------------------------
    # SP Metadata
    # ------------------------------------------------------------------

    def get_metadata(self) -> str:
        """Generate SP metadata XML for registration with the IdP."""
        sp_entity = self.config.sp_entity_id or "https://aldeci.example.com/sso/sp"
        acs_url = f"{sp_entity}/acs"
        slo_url = f"{sp_entity}/slo"
        valid_until = (datetime.now(timezone.utc) + timedelta(days=365)).strftime("%Y-%m-%dT%H:%M:%SZ")

        return (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<md:EntityDescriptor'
            ' xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"'
            f' entityID="{sp_entity}"'
            f' validUntil="{valid_until}">\n'
            "  <md:SPSSODescriptor\n"
            '    AuthnRequestsSigned="false"\n'
            '    WantAssertionsSigned="true"\n'
            '    protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">\n'
            "    <md:AssertionConsumerService\n"
            '      Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"\n'
            f'      Location="{acs_url}"\n'
            '      index="1"/>\n'
            "    <md:SingleLogoutService\n"
            '      Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"\n'
            f'      Location="{slo_url}"/>\n'
            "  </md:SPSSODescriptor>\n"
            "</md:EntityDescriptor>"
        )


# ---------------------------------------------------------------------------
# SSO JWT helpers (for SSO-issued session tokens)
# ---------------------------------------------------------------------------

_SSO_JWT_SECRET = os.getenv("FIXOPS_JWT_SECRET", "fixops-dev-secret-change-in-production")
_SSO_JWT_ALGORITHM = "HS256"
_SSO_JWT_EXPIRY_HOURS = int(os.getenv("FIXOPS_JWT_EXPIRY_HOURS", "24"))


def create_sso_jwt(user_info: UserInfo, org_id: str = "default") -> str:
    """Issue a FIXOPS JWT from an SSO UserInfo object."""
    now = datetime.now(timezone.utc)
    payload: Dict[str, Any] = {
        "sub": user_info.sub or user_info.email,
        "email": user_info.email,
        "name": user_info.name,
        "roles": user_info.roles,
        "groups": user_info.groups,
        "provider": user_info.provider,
        "org_id": org_id,
        # Use first mapped role or default "viewer"
        "role": user_info.roles[0] if user_info.roles else "viewer",
        "iat": now,
        "exp": now + timedelta(hours=_SSO_JWT_EXPIRY_HOURS),
        "sso": True,
    }
    return jwt.encode(payload, _SSO_JWT_SECRET, algorithm=_SSO_JWT_ALGORITHM)


def validate_sso_jwt(token: str) -> Dict[str, Any]:
    """Validate an SSO-issued JWT. Raises AuthorizationError on failure."""
    try:
        return jwt.decode(token, _SSO_JWT_SECRET, algorithms=[_SSO_JWT_ALGORITHM])
    except jwt.ExpiredSignatureError as exc:
        raise AuthorizationError("SSO token has expired") from exc
    except jwt.InvalidTokenError as exc:
        raise AuthorizationError(f"Invalid SSO token: {exc}") from exc
