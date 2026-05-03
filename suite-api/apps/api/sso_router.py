"""
Enterprise SSO Router — SAML 2.0 and OIDC authentication endpoints.

Routes:
    GET  /api/v1/auth/sso/providers           — list configured SSO providers
    GET  /api/v1/auth/sso/saml/config         — active SAML SP runtime config
    GET  /api/v1/auth/sso/{provider}/login    — initiate SSO flow
    POST /api/v1/auth/sso/{provider}/callback — IdP callback, issue JWT
    GET  /api/v1/auth/sso/{provider}/metadata — SAML SP metadata
    POST /api/v1/auth/sso/logout              — single logout
    GET  /api/v1/auth/sso/session             — current session info

Auth: These endpoints are intentionally public (no _verify_api_key) because
      they are part of the login flow itself. Session/logout routes validate
      the SSO JWT internally.
"""
from __future__ import annotations

import logging
import os
import secrets
import time
from collections import defaultdict
from threading import Lock
from typing import Any, Dict, List, Optional

from core.exceptions import AuthorizationError, SSRFError, ValidationError
from core.sso_provider import (
    OIDCProvider,
    SAMLProvider,
    SSOConfig,
    UserInfo,
    check_allowed_domain,
    create_sso_jwt,
    validate_sso_jwt,
)
from fastapi import APIRouter, Form, Header, HTTPException, Query, Request
from fastapi.responses import RedirectResponse, Response
from pydantic import BaseModel

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/auth/sso", tags=["sso"])

# ---------------------------------------------------------------------------
# In-memory state store for OIDC state/nonce (replace with Redis in prod)
# ---------------------------------------------------------------------------
_STATE_STORE: Dict[str, Dict[str, str]] = {}

# ---------------------------------------------------------------------------
# Rate limiting for SSO callback (10 req/min per IP)
# ---------------------------------------------------------------------------

_SSO_RATE_LIMIT = 10
_SSO_RATE_WINDOW = 60

_sso_rate_store: Dict[str, List[float]] = defaultdict(list)
_sso_rate_lock = Lock()


def _check_sso_rate_limit(request: Request) -> None:
    """Raise HTTP 429 if the caller IP exceeds the SSO callback rate limit."""
    client_ip = request.client.host if request.client else "unknown"
    now = time.monotonic()
    with _sso_rate_lock:
        cutoff = now - _SSO_RATE_WINDOW
        _sso_rate_store[client_ip] = [t for t in _sso_rate_store[client_ip] if t > cutoff]
        if len(_sso_rate_store[client_ip]) >= _SSO_RATE_LIMIT:
            raise HTTPException(
                status_code=429,
                detail="Rate limit exceeded: max 10 SSO callback requests per minute",
            )
        _sso_rate_store[client_ip].append(now)

# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------


class ProviderInfo(BaseModel):
    name: str
    provider_type: str
    enabled: bool
    login_url: str


class ProviderListResponse(BaseModel):
    providers: List[ProviderInfo]
    count: int


class CallbackResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"
    email: str
    name: str
    roles: List[str]
    groups: List[str]
    provider: str


class SessionResponse(BaseModel):
    authenticated: bool
    email: Optional[str] = None
    name: Optional[str] = None
    roles: List[str] = []
    groups: List[str] = []
    provider: Optional[str] = None
    sub: Optional[str] = None


class LogoutResponse(BaseModel):
    status: str
    message: str


class SAMLSPConfigResponse(BaseModel):
    """Active SAML Service Provider runtime configuration.

    Derived from the live SAMLProvider engine — entity_id, ACS URL, SLO URL,
    and the full SP metadata XML that should be registered with the IdP.
    """

    provider: str
    enabled: bool
    sp_entity_id: str
    acs_url: str
    slo_url: str
    idp_metadata_url: Optional[str]
    allowed_domains: List[str]
    metadata_xml: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_config(provider_name: str) -> SSOConfig:
    """Load SSO config for the requested provider from env.

    In production this would load from a config store; here we read env vars.
    The provider param overrides FIXOPS_SSO_PROVIDER so that URLs like
    /login?provider=okta work without switching env vars.
    """
    # Temporarily override provider env so SSOConfig.from_env picks it up
    original = os.environ.get("FIXOPS_SSO_PROVIDER")
    os.environ["FIXOPS_SSO_PROVIDER"] = provider_name
    os.environ.setdefault("FIXOPS_SSO_ENABLED", "1")
    try:
        cfg = SSOConfig.from_env()
    finally:
        if original is None:
            os.environ.pop("FIXOPS_SSO_PROVIDER", None)
        else:
            os.environ["FIXOPS_SSO_PROVIDER"] = original

    if cfg is None:
        raise HTTPException(status_code=503, detail="SSO is not enabled")
    if cfg.provider != provider_name:
        raise HTTPException(status_code=400, detail=f"Provider mismatch: expected {provider_name}")
    return cfg


def _redirect_uri(request: Request, provider: str) -> str:
    base = str(request.base_url).rstrip("/")
    return f"{base}/api/v1/auth/sso/{provider}/callback"


def _raise_domain_error(email: str) -> None:
    raise HTTPException(
        status_code=403,
        detail=f"Email domain for '{email}' is not allowed by SSO policy",
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("")
@router.get("/")
async def sso_status() -> Dict[str, Any]:
    """SSO status — whether SSO is enabled and which providers are configured."""
    enabled = os.getenv("FIXOPS_SSO_ENABLED", "").strip() in ("1", "true", "yes")
    return {"enabled": enabled, "status": "operational" if enabled else "disabled"}


@router.get("/providers", response_model=ProviderListResponse)
async def list_sso_providers(request: Request) -> ProviderListResponse:
    """List all configured SSO providers."""
    enabled = os.getenv("FIXOPS_SSO_ENABLED", "").strip() in ("1", "true", "yes")
    if not enabled:
        return ProviderListResponse(providers=[], count=0)

    provider_name = os.getenv("FIXOPS_SSO_PROVIDER", "generic_oidc")
    base = str(request.base_url).rstrip("/")
    login_url = f"{base}/api/v1/auth/sso/{provider_name}/login"

    return ProviderListResponse(
        providers=[
            ProviderInfo(
                name=provider_name,
                provider_type="oidc" if provider_name != "generic_saml" else "saml",
                enabled=True,
                login_url=login_url,
            )
        ],
        count=1,
    )


@router.get("/saml/config", response_model=SAMLSPConfigResponse)
async def saml_sp_config() -> SAMLSPConfigResponse:
    """Return the active SAML SP runtime configuration.

    Reads the live SAMLProvider engine configuration derived from env vars
    (FIXOPS_SSO_PROVIDER=generic_saml, FIXOPS_SP_ENTITY_ID, etc.) and returns
    the SP descriptor that must be registered with the IdP — including entity ID,
    ACS URL, SLO URL, and the full metadata XML.

    Returns 503 when SSO is disabled, 400 when the configured provider is not SAML.
    """
    enabled = os.getenv("FIXOPS_SSO_ENABLED", "").strip() in ("1", "true", "yes")
    if not enabled:
        raise HTTPException(status_code=503, detail="SSO is not enabled")

    provider_name = os.getenv("FIXOPS_SSO_PROVIDER", "generic_saml")
    if provider_name != "generic_saml":
        raise HTTPException(
            status_code=400,
            detail=f"Active SSO provider is '{provider_name}', not 'generic_saml'. "
                   "Switch FIXOPS_SSO_PROVIDER=generic_saml to use this endpoint.",
        )

    cfg = _load_config("generic_saml")
    saml = SAMLProvider(cfg)

    sp_entity = cfg.sp_entity_id or "https://aldeci.example.com/sso/sp"
    acs_url = f"{sp_entity}/acs"
    slo_url = f"{sp_entity}/slo"
    metadata_xml = saml.get_metadata()

    return SAMLSPConfigResponse(
        provider="generic_saml",
        enabled=cfg.enabled,
        sp_entity_id=sp_entity,
        acs_url=acs_url,
        slo_url=slo_url,
        idp_metadata_url=cfg.idp_metadata_url,
        allowed_domains=cfg.allowed_domains,
        metadata_xml=metadata_xml,
    )


@router.get("/{provider}/login")
async def sso_login(
    provider: str,
    request: Request,
    relay_state: Optional[str] = Query(None),
) -> RedirectResponse:
    """Initiate SSO flow — redirect user to IdP."""
    cfg = _load_config(provider)

    # Validate relay_state as a redirect target if it is an absolute URL
    if relay_state and relay_state.startswith(("http://", "https://")):
        try:
            from core.ssrf_protection import sanitize_redirect_url
            allowed = list(cfg.allowed_domains) if cfg.allowed_domains else []
            sanitize_redirect_url(relay_state, allowed)
        except SSRFError as exc:
            raise HTTPException(status_code=400, detail=f"Invalid relay_state URL: {exc}")

    if provider == "generic_saml":
        saml = SAMLProvider(cfg)
        try:
            saml.fetch_idp_metadata()
        except (AuthorizationError, ValidationError):
            pass  # SSO URL may be set directly
        sso_url = (saml._idp_metadata or {}).get("sso_url") if saml._idp_metadata else None
        if not sso_url:
            # Fallback: use idp_metadata_url as the SSO URL if it looks like a login page
            sso_url = cfg.idp_metadata_url or ""
        try:
            redirect_url = saml.get_login_url(relay_state=relay_state or "/", sso_url=sso_url or None)
        except AuthorizationError as exc:
            raise HTTPException(status_code=502, detail=str(exc))
        return RedirectResponse(url=redirect_url, status_code=302)

    # OIDC flow
    oidc = OIDCProvider(cfg)
    try:
        oidc.fetch_discovery()
    except AuthorizationError as exc:
        raise HTTPException(status_code=502, detail=f"OIDC discovery failed: {exc}")

    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    _STATE_STORE[state] = {"nonce": nonce, "provider": provider}

    redirect_uri = _redirect_uri(request, provider)
    try:
        auth_url = oidc.get_authorization_url(state=state, nonce=nonce, redirect_uri=redirect_uri)
    except AuthorizationError as exc:
        raise HTTPException(status_code=502, detail=str(exc))

    return RedirectResponse(url=auth_url, status_code=302)


@router.get("/{provider}/callback", response_model=CallbackResponse)
@router.post("/{provider}/callback", response_model=CallbackResponse)
async def sso_callback(
    provider: str,
    request: Request,
    # OIDC params (GET/POST)
    code: Optional[str] = Query(None),
    state: Optional[str] = Query(None),
    # SAML params (POST form)
    SAMLResponse: Optional[str] = Form(None),
    RelayState: Optional[str] = Form(None),
) -> CallbackResponse:
    """Handle IdP callback. Issues an ALDECI JWT on success."""
    # Rate limiting
    _check_sso_rate_limit(request)

    cfg = _load_config(provider)

    # Validate RelayState redirect target (SAML) for SSRF
    if RelayState and RelayState.startswith(("http://", "https://")):
        try:
            from core.ssrf_protection import sanitize_redirect_url
            allowed = list(cfg.allowed_domains) if cfg.allowed_domains else []
            sanitize_redirect_url(RelayState, allowed)
        except SSRFError as exc:
            raise HTTPException(status_code=400, detail=f"Invalid RelayState URL: {exc}")

    # ---- SAML path ----
    if provider == "generic_saml":
        if not SAMLResponse:
            raise HTTPException(status_code=400, detail="Missing SAMLResponse in POST body")
        saml = SAMLProvider(cfg)
        try:
            user_info = saml.process_response(SAMLResponse)
        except (AuthorizationError, ValidationError) as exc:
            raise HTTPException(status_code=401, detail=str(exc))
        if not check_allowed_domain(user_info.email, cfg.allowed_domains):
            _raise_domain_error(user_info.email)
        token = create_sso_jwt(user_info)
        return CallbackResponse(
            access_token=token,
            email=user_info.email,
            name=user_info.name,
            roles=user_info.roles,
            groups=user_info.groups,
            provider=user_info.provider,
        )

    # ---- OIDC path ----
    if not code:
        raise HTTPException(status_code=400, detail="Missing 'code' query parameter")
    if not state or state not in _STATE_STORE:
        raise HTTPException(status_code=400, detail="Invalid or missing state parameter")

    stored = _STATE_STORE.pop(state)
    if stored.get("provider") != provider:
        raise HTTPException(status_code=400, detail="State provider mismatch")

    oidc = OIDCProvider(cfg)
    try:
        oidc.fetch_discovery()
    except AuthorizationError as exc:
        raise HTTPException(status_code=502, detail=str(exc))

    redirect_uri = _redirect_uri(request, provider)
    try:
        tokens = oidc.exchange_code(code=code, redirect_uri=redirect_uri)
    except AuthorizationError as exc:
        raise HTTPException(status_code=401, detail=str(exc))

    # Validate id_token or fall back to userinfo endpoint
    user_info: Optional[UserInfo] = None
    if tokens.id_token:
        try:
            user_info = oidc.validate_token(tokens.id_token)
        except AuthorizationError:
            user_info = None

    if user_info is None:
        try:
            user_info = oidc.get_userinfo(tokens.access_token)
        except AuthorizationError as exc:
            raise HTTPException(status_code=401, detail=str(exc))

    if not check_allowed_domain(user_info.email, cfg.allowed_domains):
        _raise_domain_error(user_info.email)

    token = create_sso_jwt(user_info)
    return CallbackResponse(
        access_token=token,
        email=user_info.email,
        name=user_info.name,
        roles=user_info.roles,
        groups=user_info.groups,
        provider=user_info.provider,
    )


@router.get("/{provider}/metadata")
async def saml_metadata(provider: str) -> Response:
    """Return SAML SP metadata XML. Only valid for generic_saml provider."""
    cfg = _load_config(provider)
    if cfg.provider != "generic_saml":
        raise HTTPException(status_code=400, detail="Metadata endpoint is only for SAML providers")
    saml = SAMLProvider(cfg)
    xml_content = saml.get_metadata()
    return Response(content=xml_content, media_type="application/xml")


@router.post("/logout", response_model=LogoutResponse)
async def sso_logout(
    authorization: Optional[str] = Header(None),
) -> LogoutResponse:
    """Single logout — invalidates the SSO session token client-side.

    Note: True SLO requires back-channel IdP communication. This endpoint
    clears the server-side state and instructs the client to discard the token.
    """
    if authorization and authorization.startswith("Bearer "):
        token = authorization[7:]
        try:
            validate_sso_jwt(token)
        except AuthorizationError:
            pass  # Token already invalid — still return success
    return LogoutResponse(status="logged_out", message="SSO session terminated. Discard your access token.")


@router.get("/session", response_model=SessionResponse)
async def sso_session(
    authorization: Optional[str] = Header(None),
) -> SessionResponse:
    """Return current SSO session info from a Bearer token."""
    if not authorization or not authorization.startswith("Bearer "):
        return SessionResponse(authenticated=False)
    token = authorization[7:]
    try:
        claims = validate_sso_jwt(token)
    except AuthorizationError:
        return SessionResponse(authenticated=False)

    return SessionResponse(
        authenticated=True,
        email=claims.get("email"),
        name=claims.get("name"),
        roles=claims.get("roles", []),
        groups=claims.get("groups", []),
        provider=claims.get("provider"),
        sub=claims.get("sub"),
    )
