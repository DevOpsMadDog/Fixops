from __future__ import annotations

import csv
import hashlib
import importlib.util
import io
import json
import logging
import os
import secrets
import shutil
import threading
import time
import uuid
from contextlib import suppress
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import SpooledTemporaryFile
from types import SimpleNamespace
from typing import Any, Dict, List, Mapping, Optional, Tuple

# Auto-load .env file so FIXOPS_API_TOKEN, FIXOPS_JWT_SECRET etc. are
# available without manual `export` commands.
try:
    from dotenv import load_dotenv

    # Walk up from this file to find the repo-root .env
    _dotenv_path = Path(__file__).resolve().parents[2] / ".env"
    if _dotenv_path.is_file():
        load_dotenv(_dotenv_path, override=False)
    else:
        load_dotenv(override=False)  # searches cwd / parents
except ImportError:
    pass  # python-dotenv not installed — rely on shell env

import jwt
from apps.api.analytics_router import router as analytics_router
from apps.api.audit_router import router as audit_router
from apps.api.auth_router import router as auth_router
from apps.api.bulk_router import router as bulk_router
from apps.api.collaboration_router import router as collaboration_router
from apps.api.fail_router import router as fail_router
from apps.api.sla_router import router as sla_router

# APP_ID Configuration router (app registration, classification, lifecycle)
app_config_router: Optional[APIRouter] = None
try:
    from apps.api.app_config_router import router as app_config_router
    logging.getLogger(__name__).info("Loaded APP_ID Configuration router")
except ImportError as e:
    logging.getLogger(__name__).warning("APP_ID Configuration router not available: %s", e)

# Material Change Detection router (drift, SLA impact, blast radius)
material_change_router: Optional[APIRouter] = None
try:
    from apps.api.material_change_router import router as material_change_router
    logging.getLogger(__name__).info("Loaded Material Change Detection router")
except ImportError as e:
    logging.getLogger(__name__).warning("Material Change Detection router not available: %s", e)

# Universal Connectors router (Jira + GitHub + Slack fan-out)
connectors_router: Optional[APIRouter] = None
try:
    from apps.api.connectors_router import router as connectors_router

    logging.getLogger(__name__).info("Loaded Universal Connectors router")
except ImportError as e:
    logging.getLogger(__name__).warning("Connectors router not available: %s", e)

from apps.api.inventory_router import router as inventory_router
from apps.api.policies_router import router as policies_router
from apps.api.remediation_router import router as remediation_router
from apps.api.reports_router import router as reports_router
from apps.api.admin_router import router as admin_router
from apps.api.system_router import router as system_router
from apps.api.teams_router import router as teams_router
from apps.api.users_router import router as users_router
from apps.api.users_router import public_router as users_public_router
from apps.api.workflows_router import router as workflows_router
from fastapi import (
    APIRouter,
    Body,
    Depends,
    FastAPI,
    File,
    HTTPException,
    Query,
    Request,
    UploadFile,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader

# Validation router - compatibility checking for security tool outputs
validation_router: Optional[APIRouter] = None
try:
    from apps.api.validation_router import router as validation_router
except ImportError:
    logging.getLogger(__name__).warning("Validation router not available")


# Enterprise reachability analysis
reachability_router: Optional[APIRouter] = None
try:
    from risk.reachability.api import router as reachability_router
except ImportError:
    logging.getLogger(__name__).warning("Reachability analysis API not available")

# ---------------------------------------------------------------------------
# Suite-Attack routers (offensive security — from suite-attack/api/)
# ---------------------------------------------------------------------------
_logger = logging.getLogger(__name__)

mpte_router: Optional[APIRouter] = None
try:
    from api.mpte_router import router as mpte_router

    _logger.info("Loaded MPTE (MPTE Enhanced) router from suite-attack")
except ImportError as e:
    _logger.warning("MPTE router not available: %s", e)

micro_pentest_router: Optional[APIRouter] = None
try:
    from api.micro_pentest_router import router as micro_pentest_router

    _logger.info("Loaded Micro Pentest router from suite-attack")
except ImportError as e:
    _logger.warning("Micro Pentest router not available: %s", e)

vuln_discovery_router: Optional[APIRouter] = None
try:
    from api.vuln_discovery_router import router as vuln_discovery_router

    _logger.info("Loaded Vulnerability Discovery router from suite-attack")
except ImportError as e:
    _logger.warning("Vulnerability Discovery router not available: %s", e)

mpte_orchestrator_router: Optional[APIRouter] = None
try:
    from api.mpte_orchestrator_router import router as mpte_orchestrator_router

    _logger.info("Loaded MPTE Orchestrator router from suite-attack")
except ImportError as e:
    _logger.warning("MPTE Orchestrator router not available: %s", e)

secrets_router: Optional[APIRouter] = None
try:
    from api.secrets_router import router as secrets_router

    _logger.info("Loaded Secrets Scanner router from suite-attack")
except ImportError as e:
    _logger.warning("Secrets Scanner router not available: %s", e)

# ---------------------------------------------------------------------------
# Suite-Feeds router (real-time vulnerability intelligence — from suite-feeds/api/)
# ---------------------------------------------------------------------------
feeds_router: Optional[APIRouter] = None
try:
    from api.feeds_router import router as feeds_router

    _logger.info("Loaded Feeds router from suite-feeds")
except ImportError as e:
    _logger.warning("Feeds router not available: %s", e)

# ---------------------------------------------------------------------------
# Scanner Ingest router (25+ scanner parsers — from apps/api/)
# ---------------------------------------------------------------------------
scanner_ingest_router: Optional[APIRouter] = None
try:
    from apps.api.scanner_ingest_router import router as scanner_ingest_router

    _logger.info("Loaded Scanner Ingest router (15 new parsers)")
except ImportError as e:
    _logger.warning("Scanner Ingest router not available: %s", e)

# ---------------------------------------------------------------------------
# Sandbox PoC Verifier router (Docker-isolated exploit verification)
# ---------------------------------------------------------------------------
sandbox_router: Optional[APIRouter] = None
try:
    from core.sandbox_verifier import create_sandbox_router

    sandbox_router = create_sandbox_router()
    _logger.info("Loaded Sandbox PoC Verifier router")
except ImportError as e:
    _logger.warning("Sandbox PoC Verifier router not available: %s", e)

# Enterprise marketplace router
marketplace_router: Optional[APIRouter] = None
try:
    from apps.api.marketplace_router import router as marketplace_router

    logging.getLogger(__name__).info("Loaded enterprise marketplace router")
except ImportError as e:
    logging.getLogger(__name__).warning(
        f"Enterprise marketplace router not available: {e}"
    )

# ---------------------------------------------------------------------------
# Suite-Core routers (intelligence, brain, ML — from suite-core/api/)
# ---------------------------------------------------------------------------
nerve_center_router: Optional[APIRouter] = None
try:
    from api.nerve_center import router as nerve_center_router

    _logger.info("Loaded Nerve Center router from suite-core")
except ImportError as e:
    _logger.warning("Nerve Center router not available: %s", e)

decisions_router: Optional[APIRouter] = None
try:
    from api.decisions import router as decisions_router

    _logger.info("Loaded Decisions router from suite-core")
except ImportError as e:
    _logger.warning("Decisions router not available: %s", e)

deduplication_router: Optional[APIRouter] = None
try:
    from api.deduplication_router import router as deduplication_router

    _logger.info("Loaded Deduplication router from suite-core")
except ImportError as e:
    _logger.warning("Deduplication router not available: %s", e)

ml_router: Optional[APIRouter] = None
try:
    from api.mindsdb_router import router as ml_router

    _logger.info("Loaded ML/MindsDB router from suite-core")
except ImportError as e:
    _logger.warning("ML/MindsDB router not available: %s", e)

autofix_router: Optional[APIRouter] = None
try:
    from api.autofix_router import router as autofix_router

    _logger.info("Loaded AutoFix router from suite-core")
except ImportError as e:
    _logger.warning("AutoFix router not available: %s", e)

autofix_verify_router: Optional[APIRouter] = None
try:
    from api.autofix_verify_router import router as autofix_verify_router

    _logger.info("Loaded AutoFix Verification router from suite-core")
except ImportError as e:
    _logger.warning("AutoFix Verification router not available: %s", e)

# ---------------------------------------------------------------------------
# MPTE Post-Fix Verification (suite-core/api/)
# ---------------------------------------------------------------------------
postfix_verify_router: Optional[APIRouter] = None
try:
    from api.postfix_verify_router import router as postfix_verify_router

    _logger.info("Loaded MPTE Post-Fix Verification router from suite-core")
except ImportError as e:
    _logger.warning("MPTE Post-Fix Verification router not available: %s", e)

# ---------------------------------------------------------------------------
# MITRE ATT&CK Application-Layer Mapping (suite-core/api/)
# ---------------------------------------------------------------------------
mitre_mapper_router: Optional[APIRouter] = None
try:
    from api.mitre_mapper_router import router as mitre_mapper_router

    _logger.info("Loaded MITRE ATT&CK Mapper router from suite-core")
except ImportError as e:
    _logger.warning("MITRE ATT&CK Mapper router not available: %s", e)

# ---------------------------------------------------------------------------
# Air-Gapped / Offline Mode (suite-core/api/)
# ---------------------------------------------------------------------------
airgap_router: Optional[APIRouter] = None
try:
    from api.airgap_router import router as airgap_router

    _logger.info("Loaded Air-Gap Operations router from suite-core")
except ImportError as e:
    _logger.warning("Air-Gap Operations router not available: %s", e)

fuzzy_identity_router: Optional[APIRouter] = None
try:
    from api.fuzzy_identity_router import router as fuzzy_identity_router

    _logger.info("Loaded Fuzzy Identity router from suite-core")
except ImportError as e:
    _logger.warning("Fuzzy Identity router not available: %s", e)

exposure_case_router: Optional[APIRouter] = None
try:
    from api.exposure_case_router import router as exposure_case_router

    _logger.info("Loaded Exposure Case router from suite-core")
except ImportError as e:
    _logger.warning("Exposure Case router not available: %s", e)

pipeline_router: Optional[APIRouter] = None
try:
    from api.pipeline_router import router as pipeline_router

    _logger.info("Loaded Pipeline router from suite-core")
except ImportError as e:
    _logger.warning("Pipeline router not available: %s", e)

copilot_router: Optional[APIRouter] = None
try:
    from api.copilot_router import router as copilot_router

    _logger.info("Loaded Copilot router from suite-core")
except ImportError as e:
    _logger.warning("Copilot router not available: %s", e)

agents_router: Optional[APIRouter] = None
try:
    from api.agents_router import router as agents_router

    _logger.info("Loaded Agents router from suite-core")
except ImportError as e:
    _logger.warning("Agents router not available: %s", e)

predictions_router: Optional[APIRouter] = None
try:
    from api.predictions_router import router as predictions_router

    _logger.info("Loaded Predictions router from suite-core")
except ImportError as e:
    _logger.warning("Predictions router not available: %s", e)

llm_router: Optional[APIRouter] = None
try:
    from api.llm_router import router as llm_router

    _logger.info("Loaded LLM router from suite-core")
except ImportError as e:
    _logger.warning("LLM router not available: %s", e)

algorithmic_router: Optional[APIRouter] = None
try:
    from api.algorithmic_router import router as algorithmic_router

    _logger.info("Loaded Algorithmic router from suite-core")
except ImportError as e:
    _logger.warning("Algorithmic router not available: %s", e)

# intelligent_engine_routes.py deleted — replaced by mindsdb_router.py
intelligent_engine_router: Optional[APIRouter] = None

llm_monitor_router: Optional[APIRouter] = None
try:
    from api.llm_monitor_router import router as llm_monitor_router

    _logger.info("Loaded LLM Monitor router from suite-core")
except ImportError as e:
    _logger.warning("LLM Monitor router not available: %s", e)

streaming_router: Optional[APIRouter] = None
try:
    from api.streaming_router import router as streaming_router

    _logger.info("Loaded Streaming/SSE router from suite-core")
except ImportError as e:
    _logger.warning("Streaming/SSE router not available: %s", e)

code_to_cloud_router: Optional[APIRouter] = None
try:
    from api.code_to_cloud_router import router as code_to_cloud_router

    _logger.info("Loaded Code-to-Cloud router from suite-core")
except ImportError as e:
    _logger.warning("Code-to-Cloud router not available: %s", e)

# ---------------------------------------------------------------------------
# Vision V4-V9 routers (new engines — from suite-core/api/)
# ---------------------------------------------------------------------------
quantum_crypto_router: Optional[APIRouter] = None
try:
    from api.quantum_crypto_router import router as quantum_crypto_router

    _logger.info("Loaded Quantum Crypto router from suite-core (V6)")
except ImportError as e:
    _logger.warning("Quantum Crypto router not available: %s", e)

zero_gravity_router: Optional[APIRouter] = None
try:
    from api.zero_gravity_router import router as zero_gravity_router

    _logger.info("Loaded Zero-Gravity router from suite-core (V9)")
except ImportError as e:
    _logger.warning("Zero-Gravity router not available: %s", e)

single_agent_router: Optional[APIRouter] = None
try:
    from api.single_agent_router import router as single_agent_router

    _logger.info("Loaded Single Agent router from suite-core (V4)")
except ImportError as e:
    _logger.warning("Single Agent router not available: %s", e)

knowledge_graph_router: Optional[APIRouter] = None
try:
    from api.knowledge_graph_router import router as knowledge_graph_router

    _logger.info("Loaded Knowledge Graph router from suite-core (V3)")
except ImportError as e:
    _logger.warning("Knowledge Graph router not available: %s", e)

vllm_router: Optional[APIRouter] = None
try:
    from api.vllm_router import router as vllm_router

    _logger.info("Loaded vLLM Self-Hosted LLM router from suite-core (V9)")
except ImportError as e:
    _logger.warning("vLLM router not available: %s", e)

mcp_protocol_router: Optional[APIRouter] = None
try:
    from api.mcp_protocol_router import router as mcp_protocol_router

    _logger.info("Loaded MCP Protocol router from suite-core (V7)")
except ImportError as e:
    _logger.warning("MCP Protocol router not available: %s", e)

self_learning_router: Optional[APIRouter] = None
try:
    from api.self_learning_router import router as self_learning_router

    _logger.info("Loaded Self-Learning router from suite-core (V8)")
except ImportError as e:
    _logger.warning("Self-Learning router not available: %s", e)

# ---------------------------------------------------------------------------
# Dependency-Track router (SBOM analysis — from suite-core/api/)
# ---------------------------------------------------------------------------
dtrack_router: Optional[APIRouter] = None
try:
    from api.dtrack_router import router as dtrack_router

    _logger.info("Loaded Dependency-Track router from suite-core")
except ImportError as e:
    _logger.warning("Dependency-Track router not available: %s", e)

# ---------------------------------------------------------------------------
# Suite-Attack routers (additional offensive security — from suite-attack/api/)
# ---------------------------------------------------------------------------
attack_sim_router: Optional[APIRouter] = None
try:
    from api.attack_sim_router import router as attack_sim_router

    _logger.info("Loaded Attack Simulation router from suite-attack")
except ImportError as e:
    _logger.warning("Attack Simulation router not available: %s", e)

sast_router: Optional[APIRouter] = None
try:
    from api.sast_router import router as sast_router

    _logger.info("Loaded SAST router from suite-attack")
except ImportError as e:
    _logger.warning("SAST router not available: %s", e)

container_router: Optional[APIRouter] = None
try:
    from api.container_router import router as container_router

    _logger.info("Loaded Container Security router from suite-attack")
except ImportError as e:
    _logger.warning("Container Security router not available: %s", e)

dast_router: Optional[APIRouter] = None
try:
    from api.dast_router import router as dast_router

    _logger.info("Loaded DAST router from suite-attack")
except ImportError as e:
    _logger.warning("DAST router not available: %s", e)

cspm_router: Optional[APIRouter] = None
try:
    from api.cspm_router import router as cspm_router

    _logger.info("Loaded CSPM router from suite-attack")
except ImportError as e:
    _logger.warning("CSPM router not available: %s", e)

api_fuzzer_router: Optional[APIRouter] = None
try:
    from api.api_fuzzer_router import router as api_fuzzer_router

    _logger.info("Loaded API Fuzzer router from suite-attack")
except ImportError as e:
    _logger.warning("API Fuzzer router not available: %s", e)

malware_router: Optional[APIRouter] = None
try:
    from api.malware_router import router as malware_router

    _logger.info("Loaded Malware Analysis router from suite-attack")
except ImportError as e:
    _logger.warning("Malware Analysis router not available: %s", e)

# ---------------------------------------------------------------------------
# Suite-Evidence-Risk routers (compliance, risk, evidence — from suite-evidence-risk/api/)
# ---------------------------------------------------------------------------
evidence_router: Optional[APIRouter] = None
try:
    from api.evidence_router import router as evidence_router

    _logger.info("Loaded Evidence router from suite-evidence-risk")
except ImportError as e:
    _logger.warning("Evidence router not available: %s", e)

risk_router_ext: Optional[APIRouter] = None
try:
    from api.risk_router import router as risk_router_ext

    _logger.info("Loaded Risk router from suite-evidence-risk")
except ImportError as e:
    _logger.warning("Risk router not available: %s", e)

graph_router: Optional[APIRouter] = None
try:
    from api.graph_router import router as graph_router

    _logger.info("Loaded Graph router from suite-evidence-risk")
except ImportError as e:
    _logger.warning("Graph router not available: %s", e)

provenance_router: Optional[APIRouter] = None
try:
    from api.provenance_router import router as provenance_router

    _logger.info("Loaded Provenance router from suite-evidence-risk")
except ImportError as e:
    _logger.warning("Provenance router not available: %s", e)

compliance_engine_router: Optional[APIRouter] = None
try:
    from api.compliance_engine_router import router as compliance_engine_router

    _logger.info("Loaded Compliance Engine router from suite-evidence-risk (V10)")
except ImportError as e:
    _logger.warning("Compliance Engine router not available: %s", e)

biz_ctx_router: Optional[APIRouter] = None
try:
    from api.business_context import router as biz_ctx_router

    _logger.info("Loaded Business Context router from suite-evidence-risk")
except ImportError as e:
    _logger.warning("Business Context router not available: %s", e)

biz_ctx_enhanced_router: Optional[APIRouter] = None
try:
    from api.business_context_enhanced import router as biz_ctx_enhanced_router

    _logger.info("Loaded Business Context Enhanced router from suite-evidence-risk")
except ImportError as e:
    _logger.warning("Business Context Enhanced router not available: %s", e)

# ---------------------------------------------------------------------------
# Suite-Integrations routers (external tools — from suite-integrations/api/)
# ---------------------------------------------------------------------------
integrations_router_ext: Optional[APIRouter] = None
try:
    from api.integrations_router import router as integrations_router_ext

    _logger.info("Loaded Integrations router from suite-integrations")
except ImportError as e:
    _logger.warning("Integrations router not available: %s", e)

webhooks_router: Optional[APIRouter] = None
webhooks_receiver_router: Optional[APIRouter] = None
try:
    from api.webhooks_router import receiver_router as webhooks_receiver_router
    from api.webhooks_router import router as webhooks_router

    _logger.info("Loaded Webhooks routers from suite-integrations")
except ImportError as e:
    _logger.warning("Webhooks routers not available: %s", e)

iac_router: Optional[APIRouter] = None
try:
    from api.iac_router import router as iac_router

    _logger.info("Loaded IaC router from suite-integrations")
except ImportError as e:
    _logger.warning("IaC router not available: %s", e)

ide_router: Optional[APIRouter] = None
try:
    from api.ide_router import router as ide_router

    _logger.info("Loaded IDE router from suite-integrations")
except ImportError as e:
    _logger.warning("IDE router not available: %s", e)

oss_tools_router: Optional[APIRouter] = None
try:
    from api.oss_tools import router as oss_tools_router

    _logger.info("Loaded OSS Tools router from suite-integrations")
except ImportError as e:
    _logger.warning("OSS Tools router not available: %s", e)

mcp_router: Optional[APIRouter] = None
try:
    from api.mcp_router import router as mcp_router  # noqa: F401

    _logger.info("Loaded MCP router from suite-integrations")
except ImportError as e:
    _logger.warning("MCP router not available: %s", e)

# MCP Auto-Discovery router (auto-generates tool catalog from all FastAPI routes)
from apps.api.mcp_router import register_startup_hook as _mcp_register_startup
from apps.api.mcp_router import router as mcp_discovery_router

from core.analytics import AnalyticsStore
from core.configuration import OverlayConfig, load_overlay
from core.enhanced_decision import EnhancedDecisionEngine
from core.feedback import FeedbackRecorder
from core.flags.provider_factory import create_flag_provider
from core.paths import ensure_secure_directory, verify_allowlisted_path
from core.storage import ArtefactArchive
from telemetry import configure as configure_telemetry

try:
    _has_otel_fastapi = importlib.util.find_spec("opentelemetry.instrumentation.fastapi") is not None
except (ModuleNotFoundError, ValueError):
    _has_otel_fastapi = False

if _has_otel_fastapi:
    from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
else:  # pragma: no cover - fallback when instrumentation is unavailable
    from telemetry.fastapi_noop import FastAPIInstrumentor  # type: ignore[assignment]

from .middleware import CorrelationIdMiddleware, RequestLoggingMiddleware, RequestTracingMiddleware, SecurityHeadersMiddleware
from .metrics_middleware import PrometheusMetricsMiddleware, metrics_response

# Security audit logger — logs auth events, permission denials, scanner runs
# Import is lazy-safe: if the module is missing (e.g. sys.path issue) the
# audit logging silently degrades rather than breaking app startup.
try:
    from core.audit_logger import get_audit_logger as _get_audit_logger
    _security_audit = _get_audit_logger()
except (ImportError, AttributeError):  # pragma: no cover
    _security_audit = None  # type: ignore[assignment]
from .org_middleware import OrgIdMiddleware

# ML Learning Middleware — captures all API traffic for anomaly detection & threat scoring
try:
    from core.learning_middleware import LearningMiddleware
except ImportError:
    LearningMiddleware = None  # type: ignore[assignment,misc]
from .normalizers import (
    InputNormalizer,
    NormalizedBusinessContext,
    NormalizedCNAPP,
    NormalizedCVEFeed,
    NormalizedSARIF,
    NormalizedSBOM,
    NormalizedVEX,
)
from .pipeline import PipelineOrchestrator
from .routes.enhanced import router as enhanced_router
from .upload_manager import ChunkUploadManager

logger = logging.getLogger(__name__)

JWT_ALGORITHM = "HS256"
JWT_EXP_MINUTES = int(os.getenv("FIXOPS_JWT_EXP_MINUTES", "120"))
_JWT_SECRET_FILE = Path(os.getenv("FIXOPS_DATA_DIR", ".fixops_data")) / ".jwt_secret"
_MIN_JWT_SECRET_LENGTH = 32
_MAX_TOKEN_LENGTH = 4096

# ---------------------------------------------------------------------------
# Auth brute-force protection — in-memory failed-attempt tracker
# ---------------------------------------------------------------------------
_AUTH_FAIL_TRACKER: Dict[str, List[float]] = {}
_AUTH_FAIL_WINDOW = 300  # 5 minutes
_AUTH_FAIL_MAX = 20  # max failed attempts per IP in window
_AUTH_FAIL_LOCK = threading.Lock()


def _check_auth_rate_limit(client_ip: str) -> bool:
    """Check if client IP has exceeded failed auth attempt limit.

    Returns True if request should be rejected (rate-limited).
    """
    if os.getenv("FIXOPS_DISABLE_RATE_LIMIT") == "1":
        return False
    now = time.monotonic()
    with _AUTH_FAIL_LOCK:
        attempts = _AUTH_FAIL_TRACKER.get(client_ip, [])
        # Clean old attempts outside the window
        attempts = [t for t in attempts if now - t < _AUTH_FAIL_WINDOW]
        _AUTH_FAIL_TRACKER[client_ip] = attempts
        return len(attempts) >= _AUTH_FAIL_MAX


def _record_auth_failure(client_ip: str) -> None:
    """Record a failed auth attempt for brute-force tracking."""
    now = time.monotonic()
    with _AUTH_FAIL_LOCK:
        if client_ip not in _AUTH_FAIL_TRACKER:
            _AUTH_FAIL_TRACKER[client_ip] = []
        _AUTH_FAIL_TRACKER[client_ip].append(now)
        # Prune oldest IP entry to prevent unbounded memory growth (cap at 1000 IPs)
        if len(_AUTH_FAIL_TRACKER) > 1000:
            oldest_ip = min(
                _AUTH_FAIL_TRACKER,
                key=lambda k: _AUTH_FAIL_TRACKER[k][-1]
                if _AUTH_FAIL_TRACKER[k]
                else 0,
            )
            del _AUTH_FAIL_TRACKER[oldest_ip]


def _load_or_generate_jwt_secret() -> str:
    """
    Load JWT secret from environment or generate an ephemeral one for local dev.

    Priority:
    1. FIXOPS_JWT_SECRET environment variable (required for production)
       - Must be at least _MIN_JWT_SECRET_LENGTH (32) characters
       - Weak secrets are rejected with a CRITICAL log and replaced
    2. Generate ephemeral secret for local development (tokens won't survive restarts)

    Returns:
        str: The JWT secret key
    """
    # Priority 1: Environment variable (required for production)
    env_secret = os.getenv("FIXOPS_JWT_SECRET")
    if env_secret:
        if len(env_secret) < _MIN_JWT_SECRET_LENGTH:
            logger.critical(
                "JWT signing key is too short (%d chars, minimum %d). "
                "Weak keys are rejected to prevent "
                "token forgery. Generating a strong ephemeral key instead. "
                "Set a signing key with at least %d characters for production.",
                len(env_secret),
                _MIN_JWT_SECRET_LENGTH,
                _MIN_JWT_SECRET_LENGTH,
            )
            # Fall through to ephemeral generation below
        else:
            logger.info("Using JWT signing key from environment variable")
            return env_secret

    # Priority 2: Generate ephemeral secret for local development
    # Note: We intentionally do NOT persist secrets to disk to avoid clear-text storage
    secret = secrets.token_hex(32)
    logger.warning(
        "JWT signing key not set or rejected — generated ephemeral JWT signing key. "
        "Tokens will be invalid after restart. "
        "For production, set the JWT signing key environment variable (>= %d chars).",
        _MIN_JWT_SECRET_LENGTH,
    )
    return secret


JWT_SECRET = _load_or_generate_jwt_secret()


def generate_access_token(data: Dict[str, Any]) -> str:
    """Generate a signed JWT access token with an expiry and issued-at timestamp."""

    now = datetime.now(timezone.utc)
    exp = now + timedelta(minutes=JWT_EXP_MINUTES)
    payload = {**data, "exp": exp, "iat": now}
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return token


def decode_access_token(token: str) -> Dict[str, Any]:
    """Decode and validate a JWT access token.

    Hardening checks:
    - Max token length (_MAX_TOKEN_LENGTH bytes) to prevent parsing attacks
    - Required ``iat`` (issued-at) claim
    - ``nbf`` (not-before) validated automatically by PyJWT when present
    """

    # Guard: reject oversized tokens before any parsing
    if len(token.encode("utf-8", errors="replace")) > _MAX_TOKEN_LENGTH:
        logger.warning("JWT rejected: token exceeds max length (%d bytes)", _MAX_TOKEN_LENGTH)
        raise HTTPException(status_code=401, detail="Invalid token")

    try:
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[JWT_ALGORITHM],
            options={"require": ["exp", "iat"]},
        )
    except jwt.ExpiredSignatureError as exc:  # pragma: no cover - depends on wall clock
        raise HTTPException(status_code=401, detail="Token expired") from exc
    except jwt.MissingRequiredClaimError as exc:
        logger.warning("JWT rejected: missing required claim — %s", exc.claim)
        raise HTTPException(status_code=401, detail="Invalid token") from exc
    except jwt.InvalidTokenError as exc:
        raise HTTPException(status_code=401, detail="Invalid token") from exc
    return payload


def create_app() -> FastAPI:
    """Create and configure FastAPI application."""
    """Create the FastAPI application with file-upload ingestion endpoints."""

    # Honour FIXOPS_MODE env-var so the overlay config file's "mode: enterprise"
    # can be overridden at runtime (e.g. FIXOPS_MODE=enterprise).
    _mode_env = os.getenv("FIXOPS_MODE", "").strip() or None
    try:
        overlay = load_overlay(
            allow_ephemeral_token_fallback=False,
            mode_override=_mode_env,
        )
    except TypeError:
        overlay = load_overlay()

    flag_provider = create_flag_provider(overlay.raw_config)

    branding = flag_provider.json(
        "fixops.branding",
        default={
            "product_name": "FixOps",
            "short_name": "FixOps",
            "org_name": "FixOps",
            "telemetry_namespace": "fixops",
        },
    )

    configure_telemetry(service_name=f"{branding['telemetry_namespace']}-api")

    # Health router with /api/v1 prefix
    from apps.api.health import router as health_v1_router

    app = FastAPI(
        title=f"{branding['product_name']} Enterprise API",
        description=f"Security decision engine by {branding['org_name']}",
        version="1.0.0",
    )
    FastAPIInstrumentor.instrument_app(app)
    if not hasattr(app, "state"):
        app.state = SimpleNamespace()  # type: ignore[assignment]

    app.state.branding = branding
    app.state.flag_provider = flag_provider

    app.add_middleware(CorrelationIdMiddleware)

    # Request tracing middleware — generates X-Request-ID and mirrors
    # X-Correlation-ID on every response so callers get both IDs for
    # traceability even without a full OpenTelemetry stack.
    app.add_middleware(RequestTracingMiddleware)

    # Security headers middleware — OWASP recommended response headers
    # SOC2 CC6.1, PCI-DSS 6.5.9, OWASP A05:2021
    app.add_middleware(SecurityHeadersMiddleware)

    # Rate-limit middleware — token bucket per client IP
    # Disabled when FIXOPS_DISABLE_RATE_LIMIT=1 (e.g. in CI/test environments)
    if os.getenv("FIXOPS_DISABLE_RATE_LIMIT") != "1":
        try:
            from apps.api.rate_limiter import RateLimitMiddleware

            app.add_middleware(
                RateLimitMiddleware,
                requests_per_minute=120,
                burst_size=20,
                exempt_paths=[
                    "/health",
                    "/metrics",
                    "/api/v1/health",
                    "/api/v1/health/deep",
                    "/api/v1/ready",
                    "/api/v1/version",
                    "/api/v1/metrics",
                    "/api/v1/feeds/refresh",
                ],
            )
            logger.info("RateLimitMiddleware enabled (120 req/min, burst 20)")
        except (OSError, ValueError, KeyError, RuntimeError) as _rl_err:  # narrowed from bare Exception
            logger.warning("RateLimitMiddleware not available: %s", _rl_err)
    else:
        logger.info("RateLimitMiddleware disabled (FIXOPS_DISABLE_RATE_LIMIT=1)")

    app.add_middleware(RequestLoggingMiddleware)

    # Prometheus metrics middleware — tracks request counts, latencies, active
    # connections, and error rates.  Silently no-ops when prometheus_client is
    # not installed (graceful degradation — never breaks the app).
    app.add_middleware(PrometheusMetricsMiddleware)

    # Org ID Middleware — extracts org_id from auth state / headers / query
    # and stores it in a ContextVar so all downstream code can call
    # get_current_org_id() without carrying the Request object.
    # Must be added after auth/correlation middleware so request.state.org_id
    # (set by JWT decode) is already populated when this runs.
    app.add_middleware(OrgIdMiddleware)

    # Detailed Logging Middleware — captures full request/response payloads
    # Disabled by default in production. Set FIXOPS_DETAILED_LOGGING=1 to enable.
    if os.getenv("FIXOPS_DETAILED_LOGGING", "0") == "1":
        try:
            from apps.api.detailed_logging import DetailedLoggingMiddleware

            app.add_middleware(DetailedLoggingMiddleware)
            logger.info("DetailedLoggingMiddleware enabled — full payload capture active")
        except ImportError as _dl_err:
            logger.warning("DetailedLoggingMiddleware not available: %s", _dl_err)
    else:
        logger.info("DetailedLoggingMiddleware disabled (set FIXOPS_DETAILED_LOGGING=1 to enable)")

    # ML Learning Middleware — must be added after logging middleware (outer → inner)
    if LearningMiddleware is not None:
        app.add_middleware(LearningMiddleware)
        logger.info("LearningMiddleware enabled — API traffic will be captured for ML")

    # ── Global exception handler ─────────────────────────────────
    # Catches ALL unhandled exceptions and returns a safe 500 response
    # that never leaks stack traces, file paths, or internal details.
    # Compliance: SOC2 CC6.1, PCI-DSS 6.5.5, OWASP A09:2021
    from fastapi.responses import JSONResponse
    from starlette.exceptions import HTTPException as StarletteHTTPException

    @app.exception_handler(Exception)
    async def _global_exception_handler(request, exc):
        """Catch unhandled exceptions — never leak internal details."""
        correlation_id = getattr(request.state, "correlation_id", "unknown")
        logger.error(
            "unhandled_exception",
            extra={
                "error_type": type(exc).__name__,
                "path": request.url.path,
                "correlation_id": correlation_id,
            },
            exc_info=exc,
        )
        return JSONResponse(
            status_code=500,
            content={
                "detail": "Internal server error",
                "correlation_id": correlation_id,
            },
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http_exception_handler(request, exc):
        """Re-raise HTTP exceptions with correlation ID for traceability."""
        correlation_id = getattr(request.state, "correlation_id", "unknown")
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "detail": exc.detail,
                "correlation_id": correlation_id,
            },
        )

    @app.middleware("http")
    async def add_product_header(request, call_next):
        """Add X-Product-Name header to all responses."""
        response = await call_next(request)
        response.headers["X-Product-Name"] = branding["product_name"]
        response.headers["X-Product-Version"] = "1.0.0"
        return response

    origins_env = os.getenv("FIXOPS_ALLOWED_ORIGINS", "")
    origins = [origin.strip() for origin in origins_env.split(",") if origin.strip()]
    if not origins:
        env_name = os.getenv("ENVIRONMENT", "development")
        if env_name.lower() == "production":
            raise RuntimeError(
                "FIXOPS_ALLOWED_ORIGINS must be set in production. "
                "Refusing to start with default localhost origins."
            )
        origins = [
            "http://localhost:3000",
            "http://localhost:3001",  # Vite dev server (ui/aldeci) - alternate port
            "http://localhost:5173",  # Vite dev server (ui/aldeci)
            "http://localhost:8000",
            "http://127.0.0.1:3000",
            "http://127.0.0.1:3001",  # Vite dev server (ui/aldeci) - alternate port
            "http://127.0.0.1:5173",  # Vite dev server (ui/aldeci)
            "http://127.0.0.1:8000",
        ]
        logger.warning(
            "FIXOPS_ALLOWED_ORIGINS not set. "
            "Using default localhost origins. "
            "Set FIXOPS_ALLOWED_ORIGINS for production deployments."
        )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=[
            "Authorization", "Content-Type", "X-API-Key", "X-Request-ID",
            "X-Correlation-ID", "X-Org-ID", "Accept", "Origin", "Cache-Control",
        ],
    )

    normalizer = InputNormalizer()
    orchestrator = PipelineOrchestrator()

    # API authentication setup
    auth_strategy = overlay.auth.get("strategy", "").lower()
    # Enterprise enforcement: if FIXOPS_API_TOKEN is set in env but overlay
    # doesn't declare a strategy, auto-promote to token-based auth.
    _env_api_token = os.getenv("FIXOPS_API_TOKEN", "").strip()
    if not auth_strategy and _env_api_token:
        auth_strategy = "token"
        logger.info("Auto-promoted auth strategy to 'token' (FIXOPS_API_TOKEN set)")
    header_name = overlay.auth.get(
        "header", "X-API-Key" if auth_strategy != "jwt" else "Authorization"
    )
    api_key_header = APIKeyHeader(name=header_name, auto_error=False)
    # Build expected tokens list from overlay config + env var
    expected_tokens = list(overlay.auth_tokens) if auth_strategy == "token" else []
    if auth_strategy == "token" and _env_api_token and _env_api_token not in expected_tokens:
        expected_tokens.append(_env_api_token)
    expected_tokens = tuple(expected_tokens)

    # Default scopes for token-based auth (service accounts get admin)
    _ALL_SCOPES = [
        "read:sbom",
        "write:sbom",
        "read:findings",
        "write:findings",
        "read:graph",
        "write:graph",
        "read:feeds",
        "read:evidence",
        "write:evidence",
        "read:integrations",
        "write:integrations",
        "attack:execute",
        "admin:all",
    ]

    async def _verify_api_key(
        request: Request,
        api_key: Optional[str] = Depends(api_key_header),
    ) -> None:
        # Determine client IP for brute-force tracking
        client_ip = request.client.host if request.client else "unknown"

        # Check auth rate limit before any validation
        if _check_auth_rate_limit(client_ip):
            logger.warning(
                "Auth rate limit exceeded for IP %s — rejecting request", client_ip
            )
            raise HTTPException(
                status_code=429,
                detail="Too many failed authentication attempts. Try again later.",
            )

        # Also accept token via ?api_key= query parameter (for browser-opened
        # URLs like report view/download where headers cannot be sent).
        if not api_key:
            api_key = request.query_params.get("api_key")

        # Try to extract Authorization header for JWT (frontend sends this after login)
        auth_header = request.headers.get("Authorization", "")

        if auth_strategy == "token":
            # First check X-API-Key token
            if api_key and api_key in expected_tokens:
                request.state.user_role = "admin"
                request.state.user_scopes = _ALL_SCOPES
                return
            # Also accept JWT Bearer tokens (dual auth: API key + JWT login)
            if auth_header.lower().startswith("bearer "):
                jwt_token = auth_header[7:].strip()
                try:
                    claims = decode_access_token(jwt_token)
                    request.state.user_role = claims.get("role", "viewer")
                    request.state.user_scopes = claims.get("scopes", ["read:findings"])
                    return
                except HTTPException:
                    pass  # Fall through to failure
            _record_auth_failure(client_ip)
            logger.warning("Failed token auth attempt from IP %s", client_ip)
            if _security_audit:
                _security_audit.log_login_attempt(
                    client_ip=client_ip,
                    success=False,
                    auth_method="token",
                    correlation_id=getattr(request.state, "correlation_id", None),
                )
            raise HTTPException(
                status_code=401, detail="Invalid or missing API token"
            )
        if auth_strategy == "jwt":
            if not api_key:
                _record_auth_failure(client_ip)
                logger.warning("Missing Authorization header from IP %s", client_ip)
                if _security_audit:
                    _security_audit.log_login_attempt(
                        client_ip=client_ip,
                        success=False,
                        auth_method="jwt",
                        correlation_id=getattr(request.state, "correlation_id", None),
                        details={"reason": "missing_authorization_header"},
                    )
                raise HTTPException(
                    status_code=401, detail="Missing Authorization header"
                )
            token = api_key
            if token.lower().startswith("bearer "):
                token = token[7:].strip()
            try:
                claims = decode_access_token(token)
            except HTTPException:
                _record_auth_failure(client_ip)
                logger.warning("Failed JWT auth attempt from IP %s", client_ip)
                if _security_audit:
                    _security_audit.log_login_attempt(
                        client_ip=client_ip,
                        success=False,
                        auth_method="jwt",
                        correlation_id=getattr(request.state, "correlation_id", None),
                        details={"reason": "invalid_jwt"},
                    )
                raise
            # Extract role/scopes from JWT claims
            request.state.user_role = claims.get("role", "viewer")
            request.state.user_scopes = claims.get("scopes", ["read:findings"])
            return
        # Fallback — no auth strategy → admin (dev mode)
        request.state.user_role = "admin"
        request.state.user_scopes = _ALL_SCOPES

    def _require_scope(scope: str):
        """Factory returning a dependency that checks for a required scope."""

        async def _check(request: Request):
            user_scopes = getattr(request.state, "user_scopes", [])
            if scope not in user_scopes and "admin:all" not in user_scopes:
                if _security_audit:
                    _security_audit.log_permission_denied(
                        client_ip=request.client.host if request.client else None,
                        resource=request.url.path,
                        required_scope=scope,
                        correlation_id=getattr(request.state, "correlation_id", None),
                    )
                raise HTTPException(
                    status_code=403,
                    detail=f"Forbidden — missing required scope: {scope}",
                )

        return _check

    allowlist = overlay.allowed_data_roots or (Path("data").resolve(),)
    for directory in overlay.data_directories.values():
        secure_path = verify_allowlisted_path(directory, allowlist)
        ensure_secure_directory(secure_path)

    archive_dir = overlay.data_directories.get("archive_dir")
    if archive_dir is None:
        root = allowlist[0]
        root = verify_allowlisted_path(root, allowlist)
        archive_dir = (root / "archive" / overlay.mode).resolve()
    archive_dir = verify_allowlisted_path(archive_dir, allowlist)
    archive = ArtefactArchive(archive_dir, allowlist=allowlist)

    analytics_dir = overlay.data_directories.get("analytics_dir")
    if analytics_dir is None:
        root = allowlist[0]
        root = verify_allowlisted_path(root, allowlist)
        analytics_dir = (root / "analytics" / overlay.mode).resolve()
    analytics_dir = verify_allowlisted_path(analytics_dir, allowlist)
    analytics_store = AnalyticsStore(analytics_dir, allowlist=allowlist)

    provenance_dir = overlay.data_directories.get("provenance_dir")
    if provenance_dir is None:
        root = allowlist[0]
        root = verify_allowlisted_path(root, allowlist)
        provenance_dir = (root / "artifacts" / "attestations" / overlay.mode).resolve()
    provenance_dir = verify_allowlisted_path(provenance_dir, allowlist)
    provenance_dir = ensure_secure_directory(provenance_dir)

    risk_dir = overlay.data_directories.get("risk_dir")
    if risk_dir is None:
        root = allowlist[0]
        root = verify_allowlisted_path(root, allowlist)
        risk_dir = (root / "artifacts").resolve()
    risk_dir = verify_allowlisted_path(risk_dir, allowlist)
    risk_dir = ensure_secure_directory(risk_dir)

    app.state.normalizer = normalizer
    app.state.orchestrator = orchestrator
    app.state.artifacts: Dict[str, Any] = {}  # type: ignore[misc]
    app.state.overlay = overlay
    app.state.archive = archive
    app.state.archive_records: Dict[str, Dict[str, Any]] = {}  # type: ignore[misc]
    app.state.analytics_store = analytics_store
    app.state.last_pipeline_result: Optional[Dict[str, Any]] = None  # type: ignore[misc]
    app.state.feedback = (
        FeedbackRecorder(overlay, analytics_store=analytics_store)
        if overlay.toggles.get("capture_feedback")
        else None
    )
    app.state.enhanced_engine = EnhancedDecisionEngine(
        overlay.enhanced_decision_settings
    )
    sbom_dir = overlay.data_directories.get("sbom_dir")
    if sbom_dir is None:
        root = allowlist[0]
        root = verify_allowlisted_path(root, allowlist)
        sbom_dir = (root / "artifacts" / "sbom").resolve()
    sbom_dir = verify_allowlisted_path(sbom_dir, allowlist)
    sbom_dir = ensure_secure_directory(sbom_dir)

    graph_dir = overlay.data_directories.get("graph_dir")
    if graph_dir is None:
        root = allowlist[0]
        root = verify_allowlisted_path(root, allowlist)
        graph_dir = (root / "analysis").resolve()
    graph_dir = verify_allowlisted_path(graph_dir, allowlist)
    graph_dir = ensure_secure_directory(graph_dir)

    evidence_dir = overlay.data_directories.get("evidence_dir")
    if evidence_dir is None:
        root = allowlist[0]
        root = verify_allowlisted_path(root, allowlist)
        evidence_dir = (root / "evidence").resolve()
    evidence_dir = verify_allowlisted_path(evidence_dir, allowlist)
    evidence_dir = ensure_secure_directory(evidence_dir)
    evidence_manifest_dir = ensure_secure_directory(evidence_dir / "manifests")
    evidence_bundle_dir = ensure_secure_directory(evidence_dir / "bundles")

    app.state.provenance_dir = provenance_dir
    app.state.risk_dir = risk_dir
    app.state.sbom_dir = sbom_dir
    app.state.graph_config = {
        "repo_path": Path(".").resolve(),
        "attestation_dir": provenance_dir,
        "sbom_dir": sbom_dir,
        "risk_dir": risk_dir,
        "releases_path": graph_dir / "releases.json",
    }
    app.state.evidence_manifest_dir = evidence_manifest_dir
    app.state.evidence_bundle_dir = evidence_bundle_dir
    uploads_dir = overlay.data_directories.get("uploads_dir")
    if uploads_dir is None:
        root = allowlist[0]
        uploads_dir = (root / "uploads" / overlay.mode).resolve()
    uploads_dir = verify_allowlisted_path(uploads_dir, allowlist)
    upload_manager = ChunkUploadManager(uploads_dir)
    app.state.upload_manager = upload_manager

    app.include_router(health_v1_router)  # Health endpoints with /api/v1 prefix

    # Legacy /health endpoint — required by Dockerfile HEALTHCHECK and
    # scripts/docker-entrypoint.sh readiness probes that poll /health directly.
    @app.get("/health", tags=["health"])
    def legacy_health_check() -> Dict[str, Any]:
        """Legacy health endpoint for backward-compatible probes."""
        return {
            "status": "healthy",
            "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
            "service": "aldeci-api",
        }

    # ------------------------------------------------------------------
    # Prometheus /metrics endpoint
    # No auth required — metrics are not secret and Prometheus scrapers
    # cannot easily send custom headers.  Rate limiting is already exempt
    # for /api/v1/metrics in the RateLimitMiddleware config above.
    # Returns Prometheus text format when prometheus_client is installed,
    # otherwise returns a JSON summary (graceful degradation).
    # ------------------------------------------------------------------
    @app.get("/metrics", tags=["observability"], include_in_schema=True)
    def prometheus_metrics():
        """Prometheus metrics endpoint.

        Exposes:
          - fixops_http_requests_total{method, endpoint, status_code}
          - fixops_http_request_duration_seconds{method, endpoint}
          - fixops_active_connections
          - fixops_pipeline_executions_total{status}
          - fixops_pipeline_duration_seconds
          - fixops_errors_total{error_type}

        Scrape with: ``prometheus.yml`` job ``scrape_configs[].static_configs.targets``
        pointing at ``host:8000``, path ``/metrics``.
        """
        return metrics_response()

    @app.get("/api/v1/status", dependencies=[Depends(_verify_api_key)])
    async def authenticated_status() -> Dict[str, Any]:
        """Authenticated status endpoint."""
        return {
            "status": "ok",
            "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
            "service": "fixops-api",
            "version": os.getenv("FIXOPS_VERSION", "1.0.0"),
        }

    @app.get("/api/v1/search", dependencies=[Depends(_verify_api_key)])
    async def global_search(
        q: str = Query("", description="Search query"),
        entity_types: Optional[str] = Query(
            None,
            description="Comma-separated entity types to search: findings,assets,evidence,tickets. Default: all.",
        ),
        limit: int = Query(50, ge=1, le=200, description="Max results per entity type"),
    ) -> Dict[str, Any]:
        """Cross-entity global search across findings, assets, evidence, and tickets.

        Returns unified results sorted by relevance with type annotations so the
        UI can render heterogeneous result cards in a single list.
        """
        results: list[Dict[str, Any]] = []
        searched_types: list[str] = []
        errors: Dict[str, str] = {}

        if not q:
            return {"query": q, "results": [], "total": 0, "searched_types": []}

        q_lower = q.lower()
        allowed_types = {"findings", "assets", "evidence", "tickets"}
        if entity_types:
            requested = {t.strip().lower() for t in entity_types.split(",")}
            search_types = requested & allowed_types
        else:
            search_types = allowed_types

        def _match(text: str) -> bool:
            return q_lower in text.lower()

        # ── 1. Findings (AnalyticsDB) ──────────────────────────────
        if "findings" in search_types:
            searched_types.append("findings")
            try:
                from core.analytics_db import AnalyticsDB

                adb = AnalyticsDB()
                all_findings = adb.list_findings(limit=500)
                count = 0
                for f in all_findings:
                    fd = f.to_dict() if hasattr(f, "to_dict") else f
                    searchable = " ".join(str(v) for v in fd.values() if v)
                    if _match(searchable):
                        results.append(
                            {
                                "type": "finding",
                                "id": fd.get("id"),
                                "title": fd.get("title", ""),
                                "severity": fd.get("severity", ""),
                                "status": fd.get("status", ""),
                                "source": fd.get("source", ""),
                                "cve_id": fd.get("cve_id", ""),
                                "application_id": fd.get("application_id", ""),
                            }
                        )
                        count += 1
                        if count >= limit:
                            break
            except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
                errors["findings"] = type(exc).__name__

        # ── 2. Assets / Inventory ──────────────────────────────────
        if "assets" in search_types:
            searched_types.append("assets")
            try:
                from core.inventory_db import InventoryDB

                idb = InventoryDB()
                inv_results = idb.search_inventory(q, limit=limit)
                for category, items in inv_results.items():
                    for item in items:
                        results.append(
                            {
                                "type": "asset",
                                "sub_type": category.rstrip("s"),  # applications -> application
                                "id": item.get("id", ""),
                                "name": item.get("name", ""),
                                "description": item.get("description", ""),
                                "status": item.get("status", ""),
                                "criticality": item.get("criticality", ""),
                            }
                        )
            except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
                errors["assets"] = type(exc).__name__

        # ── 3. Evidence bundles ────────────────────────────────────
        if "evidence" in search_types:
            searched_types.append("evidence")
            try:
                import glob as _glob

                evidence_dir = os.path.join("data", "evidence")
                if os.path.isdir(evidence_dir):
                    count = 0
                    for fp in sorted(_glob.glob(os.path.join(evidence_dir, "*.json")))[-500:]:
                        try:
                            with open(fp) as fh:
                                bundle = json.load(fh)
                            searchable = " ".join(
                                str(bundle.get(k, ""))
                                for k in ("id", "type", "framework", "status", "app_id")
                            )
                            if _match(searchable):
                                results.append(
                                    {
                                        "type": "evidence",
                                        "id": bundle.get("id", os.path.basename(fp).replace(".json", "")),
                                        "framework": bundle.get("framework", ""),
                                        "signed": bundle.get("signature") is not None,
                                        "status": bundle.get("status", "sealed"),
                                        "created_at": bundle.get("created_at") or bundle.get("timestamp", ""),
                                    }
                                )
                                count += 1
                                if count >= limit:
                                    break
                        except (OSError, ValueError, RuntimeError):  # narrowed from bare Exception
                            continue
            except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
                errors["evidence"] = type(exc).__name__

        # ── 4. Remediation tickets / tasks ─────────────────────────
        if "tickets" in search_types:
            searched_types.append("tickets")
            try:
                from core.services.remediation import RemediationService

                svc = RemediationService()
                # Search across all orgs — get recent tasks and filter
                import sqlite3 as _sqlite3

                conn = _sqlite3.connect(svc.db_path)
                conn.row_factory = _sqlite3.Row
                try:
                    pattern = f"%{q}%"
                    rows = conn.execute(
                        """SELECT * FROM remediation_tasks
                           WHERE title LIKE ? OR description LIKE ?
                              OR assignee LIKE ? OR ticket_id LIKE ?
                           ORDER BY updated_at DESC LIMIT ?""",
                        (pattern, pattern, pattern, pattern, limit),
                    ).fetchall()
                    for row in rows:
                        task = dict(row)
                        results.append(
                            {
                                "type": "ticket",
                                "id": task.get("task_id", ""),
                                "title": task.get("title", ""),
                                "severity": task.get("severity", ""),
                                "status": task.get("status", ""),
                                "assignee": task.get("assignee", ""),
                                "app_id": task.get("app_id", ""),
                                "ticket_id": task.get("ticket_id", ""),
                            }
                        )
                finally:
                    conn.close()
            except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
                errors["tickets"] = type(exc).__name__

        response: Dict[str, Any] = {
            "query": q,
            "results": results,
            "total": len(results),
            "searched_types": searched_types,
        }
        if errors:
            response["errors"] = errors
        return response

    app.include_router(enhanced_router, dependencies=[Depends(_verify_api_key)])
    # Enterprise reachability analysis API
    if reachability_router:
        app.include_router(reachability_router, dependencies=[Depends(_verify_api_key)])

    app.include_router(inventory_router, dependencies=[Depends(_verify_api_key)])

    # Login endpoint — public (no auth required)
    app.include_router(users_public_router)
    # User management — admin only
    app.include_router(
        users_router,
        dependencies=[Depends(_verify_api_key), Depends(_require_scope("admin:all"))],
    )
    app.include_router(
        teams_router,
        dependencies=[Depends(_verify_api_key), Depends(_require_scope("admin:all"))],
    )
    # Admin-prefixed routes for Platform Admin (Hasan) persona
    app.include_router(
        admin_router,
        dependencies=[Depends(_verify_api_key), Depends(_require_scope("admin:all"))],
    )
    # System administration routes — health, info, config
    app.include_router(
        system_router,
        dependencies=[Depends(_verify_api_key), Depends(_require_scope("admin:all"))],
    )
    app.include_router(
        policies_router,
        dependencies=[
            Depends(_verify_api_key),
            Depends(_require_scope("write:findings")),
        ],
    )

    app.include_router(analytics_router, dependencies=[Depends(_verify_api_key)])

    # FAIL Engine — expanded fault injection, drill grading, neglect zones (Pillar V2)
    app.include_router(fail_router, dependencies=[Depends(_verify_api_key)])

    # APP_ID Configuration — app registry, classification, lifecycle
    if app_config_router:
        app.include_router(
            app_config_router,
            dependencies=[Depends(_verify_api_key)],
        )
        _logger.info("Mounted APP_ID Configuration router")

    # Material Change Detection — drift detection, SLA impact, blast radius
    if material_change_router:
        app.include_router(
            material_change_router,
            dependencies=[Depends(_verify_api_key)],
        )
        _logger.info("Mounted Material Change Detection router")

    # Universal Connectors — Jira + GitHub + Slack fan-out (Pillar V1)
    if connectors_router:
        app.include_router(
            connectors_router,
            dependencies=[Depends(_verify_api_key)],
        )
        _logger.info("Mounted Universal Connectors router")

    app.include_router(reports_router, dependencies=[Depends(_verify_api_key)])
    app.include_router(audit_router, dependencies=[Depends(_verify_api_key)])
    app.include_router(workflows_router, dependencies=[Depends(_verify_api_key)])

    app.include_router(
        auth_router,
        dependencies=[Depends(_verify_api_key), Depends(_require_scope("admin:all"))],
    )
    app.include_router(
        bulk_router,
        dependencies=[
            Depends(_verify_api_key),
            Depends(_require_scope("write:findings")),
        ],
    )

    # Enterprise features - Remediation, Collaboration, SLA
    app.include_router(remediation_router, dependencies=[Depends(_verify_api_key)])
    app.include_router(collaboration_router, dependencies=[Depends(_verify_api_key)])
    app.include_router(sla_router, dependencies=[Depends(_verify_api_key)])

    # Scanner Ingest — 25+ scanner parsers (ZAP, Burp, Nessus, Checkmarx, etc.)
    if scanner_ingest_router:
        app.include_router(
            scanner_ingest_router,
            dependencies=[Depends(_verify_api_key)],
        )
        _logger.info("Mounted Scanner Ingest router")

    # Dependency-Track — SBOM analysis via OWASP Dependency-Track
    if dtrack_router:
        app.include_router(
            dtrack_router,
            dependencies=[Depends(_verify_api_key)],
        )
        _logger.info("Mounted Dependency-Track router")

    # Sandbox PoC Verifier — Docker-isolated exploit verification
    if sandbox_router:
        app.include_router(
            sandbox_router,
            dependencies=[
                Depends(_verify_api_key),
                Depends(_require_scope("attack:execute")),
            ],
        )
        _logger.info("Mounted Sandbox PoC Verifier router")

    # Validation router - compatibility checking for security tool outputs
    if validation_router:
        app.include_router(validation_router, dependencies=[Depends(_verify_api_key)])

    # Enterprise marketplace API
    if marketplace_router:
        app.include_router(
            marketplace_router,
            prefix="/api/v1/marketplace",
            dependencies=[Depends(_verify_api_key)],
        )

    # Suite-Attack routers (offensive security) — require attack:execute scope
    for _r, _name in [
        (mpte_router, "MPTE"),
        (micro_pentest_router, "Micro Pentest"),
        (vuln_discovery_router, "Vulnerability Discovery"),
        (mpte_orchestrator_router, "MPTE Orchestrator"),
        (secrets_router, "Secrets Scanner"),
    ]:
        if _r:
            app.include_router(
                _r,
                dependencies=[
                    Depends(_verify_api_key),
                    Depends(_require_scope("attack:execute")),
                ],
            )

    # Suite-Feeds router (real-time vulnerability intelligence)
    if feeds_router:
        app.include_router(feeds_router, dependencies=[Depends(_verify_api_key)])

    # Knowledge Brain router (central intelligence graph — from suite-core/api/)
    try:
        from api.brain_router import router as brain_router

        app.include_router(brain_router, dependencies=[Depends(_verify_api_key)])
        _logger.info("Loaded Knowledge Brain router from suite-core")
    except ImportError as e:
        _logger.warning("Knowledge Brain router not available: %s", e)

    # -------------------------------------------------------------------
    # Suite-Core routers (intelligence, ML, copilot, pipeline)
    # -------------------------------------------------------------------
    _core_routers = [
        (nerve_center_router, "Nerve Center", None),
        (decisions_router, "Decisions", "/api/v1"),
        (deduplication_router, "Deduplication", None),
        (ml_router, "ML/MindsDB", None),
        (autofix_router, "AutoFix", None),
        (autofix_verify_router, "AutoFix Verification", None),
        (postfix_verify_router, "MPTE Post-Fix Verification", None),
        (mitre_mapper_router, "MITRE ATT&CK Mapper", None),
        (airgap_router, "Air-Gap Operations", None),
        (fuzzy_identity_router, "Fuzzy Identity", None),
        (exposure_case_router, "Exposure Case", None),
        (pipeline_router, "Pipeline", None),
        (copilot_router, "Copilot", None),
        (agents_router, "Agents", None),
        (predictions_router, "Predictions", None),
        (llm_router, "LLM", None),
        (algorithmic_router, "Algorithmic", None),
        # intelligent_engine_router removed — replaced by mindsdb_router
        (llm_monitor_router, "LLM Monitor", None),
        (code_to_cloud_router, "Code-to-Cloud", None),
        (streaming_router, "SSE Streaming", None),
        (quantum_crypto_router, "Quantum Crypto", None),
        (zero_gravity_router, "Zero-Gravity Data", None),
        (single_agent_router, "AI Agent", None),
        (knowledge_graph_router, "Knowledge Graph", None),
        (vllm_router, "Self-Hosted LLM (Air-Gapped)", None),
        (mcp_protocol_router, "MCP Protocol", None),
        (self_learning_router, "Self-Learning", None),
    ]
    for _r, _name, _prefix in _core_routers:
        if _r:
            kwargs: Dict[str, Any] = {"dependencies": [Depends(_verify_api_key)]}
            if _prefix:
                kwargs["prefix"] = _prefix
            app.include_router(_r, **kwargs)
            _logger.info("Mounted %s router from suite-core", _name)

    # -------------------------------------------------------------------
    # Suite-Attack routers (additional offensive security engines)
    # -------------------------------------------------------------------
    _attack_extra_routers = [
        (attack_sim_router, "Attack Simulation"),
        (sast_router, "SAST"),
        (container_router, "Container Security"),
        (dast_router, "DAST"),
        (cspm_router, "CSPM"),
        (api_fuzzer_router, "API Fuzzer"),
        (malware_router, "Malware Analysis"),
    ]
    for _r, _name in _attack_extra_routers:
        if _r:
            app.include_router(
                _r,
                dependencies=[
                    Depends(_verify_api_key),
                    Depends(_require_scope("attack:execute")),
                ],
            )
            _logger.info("Mounted %s router from suite-attack", _name)

    # -------------------------------------------------------------------
    # Suite-Evidence-Risk routers (compliance, risk, evidence, graph)
    # -------------------------------------------------------------------
    _evidence_routers = [
        (evidence_router, "Evidence", "/api/v1"),
        (risk_router_ext, "Risk", "/api/v1"),
        (graph_router, "Graph", "/api/v1"),
        (provenance_router, "Provenance", "/api/v1"),
        (compliance_engine_router, "Compliance Engine", "/api/v1"),
        (biz_ctx_router, "Business Context", "/api/v1"),
        (biz_ctx_enhanced_router, "Business Context Enhanced", "/api/v1"),
    ]
    for _r, _name, _prefix in _evidence_routers:
        if _r:
            app.include_router(
                _r,
                prefix=_prefix,
                dependencies=[
                    Depends(_verify_api_key),
                    Depends(_require_scope("read:evidence")),
                ],
            )
            _logger.info("Mounted %s router from suite-evidence-risk", _name)

    # -------------------------------------------------------------------
    # Suite-Integrations routers (external tools, webhooks, IaC, IDE)
    # -------------------------------------------------------------------
    _integration_routers = [
        (integrations_router_ext, "Integrations"),
        (webhooks_router, "Webhooks"),
        (iac_router, "IaC"),
        (ide_router, "IDE"),
        # Legacy mcp_router removed — superseded by MCP Auto-Discovery
        # router (apps.api.mcp_router) which auto-generates tools from
        # all FastAPI routes instead of 9 hard-coded definitions.
        # Client management endpoints (/clients, /manifest, /config)
        # are preserved via the new router's broader coverage.
    ]
    for _r, _name in _integration_routers:
        if _r:
            app.include_router(
                _r,
                dependencies=[
                    Depends(_verify_api_key),
                    Depends(_require_scope("write:integrations")),
                ],
            )
            _logger.info("Mounted %s router from suite-integrations", _name)

    # Webhooks receiver — no API key auth (uses signature verification)
    if webhooks_receiver_router:
        app.include_router(webhooks_receiver_router)
        _logger.info("Mounted Webhooks Receiver router (no API key auth)")

    # OSS Tools — needs /api/v1 prefix normalization
    if oss_tools_router:
        app.include_router(
            oss_tools_router, prefix="/api/v1", dependencies=[Depends(_verify_api_key)]
        )
        _logger.info("Mounted OSS Tools router from suite-integrations")

    # Detailed Logging REST API — query/stream/clear logs
    try:
        from apps.api.detailed_logging import logs_router as detailed_logs_router

        app.include_router(
            detailed_logs_router,
            prefix="/api/v1",
            dependencies=[Depends(_verify_api_key)],
        )
        _logger.info("Mounted Detailed Logs router at /api/v1/logs")
    except (ValueError, KeyError, RuntimeError, TypeError, AttributeError) as _lr_err:
        _logger.warning("Detailed Logs router not available: %s", _lr_err)

    _CHUNK_SIZE = 1024 * 1024
    _RAW_BYTES_THRESHOLD = 4 * 1024 * 1024

    async def _read_limited(
        file: UploadFile, stage: str
    ) -> Tuple[SpooledTemporaryFile, int]:
        """Stream an upload into a spooled file respecting the configured limit."""

        limit = overlay.upload_limit(stage)
        total = 0
        try:
            buffer = SpooledTemporaryFile(max_size=_CHUNK_SIZE, mode="w+b")
            while total < limit:
                remaining = limit - total
                chunk = await file.read(min(_CHUNK_SIZE, remaining))
                if not chunk:
                    break
                if total + len(chunk) > limit:
                    buffer.close()
                    raise HTTPException(
                        status_code=413,
                        detail={
                            "message": f"Upload for stage '{stage}' exceeded limit",
                            "max_bytes": limit,
                            "received_bytes": total + len(chunk),
                        },
                    )
                buffer.write(chunk)
                total += len(chunk)
        except HTTPException:
            raise
        except (ValueError, KeyError, RuntimeError, TypeError, AttributeError):
            buffer.close()
            raise
        buffer.seek(0)
        return buffer, total

    def _maybe_materialise_raw(
        buffer: SpooledTemporaryFile,
        total: int,
        *,
        threshold: int = _RAW_BYTES_THRESHOLD,
    ) -> Optional[bytes]:
        if total > threshold:
            return None
        buffer.seek(0)
        data = buffer.read()
        buffer.seek(0)
        return data

    def _validate_content_type(file: UploadFile, expected: tuple[str, ...]) -> None:
        if file.content_type and file.content_type not in expected:
            raise HTTPException(
                status_code=415,
                detail={
                    "message": "Unsupported content type",
                    "received": file.content_type,
                    "expected": list(expected),
                },
            )

    def _store(
        stage: str,
        payload: Any,
        *,
        original_filename: Optional[str] = None,
        raw_bytes: Optional[bytes] = None,
    ) -> None:
        logger.debug("Storing stage %s", stage)
        app.state.artifacts[stage] = payload
        try:
            record = app.state.archive.persist(
                stage,
                payload,
                original_filename=original_filename,
                raw_bytes=raw_bytes,
            )
        except (
            Exception
        ) as exc:  # pragma: no cover - persistence must not break ingestion
            logger.exception("Failed to persist artefact stage %s", stage)
            record = {"stage": stage, "error": str(exc)}
        app.state.archive_records[stage] = record

    supported_stages = {
        "design",
        "sbom",
        "sarif",
        "cve",
        "vex",
        "cnapp",
        "context",
    }

    def _process_design(
        buffer: SpooledTemporaryFile, total: int, filename: str
    ) -> Dict[str, Any]:
        text_stream = io.TextIOWrapper(
            buffer, encoding="utf-8", errors="ignore", newline=""  # type: ignore[arg-type]
        )
        try:
            reader = csv.DictReader(text_stream)
            rows = [
                row
                for row in reader
                if any((value or "").strip() for value in row.values())
            ]
            columns = reader.fieldnames or []
        finally:
            buffer = text_stream.detach()  # type: ignore[assignment]
        if not rows:
            raise HTTPException(status_code=400, detail="Design CSV contained no rows")

        overlay: OverlayConfig = app.state.overlay
        strict_validation = overlay.toggles.get("strict_validation", False)

        if strict_validation:
            required_columns = {
                "component",
                "subcomponent",
                "owner",
                "data_class",
                "description",
                "control_scope",
            }
            missing_columns = required_columns - set(columns)
            if missing_columns:
                raise HTTPException(
                    status_code=422,
                    detail={
                        "message": "Design CSV missing required columns (strict mode)",
                        "missing_columns": sorted(missing_columns),
                        "required_columns": sorted(required_columns),
                    },
                )

        dataset = {"columns": columns, "rows": rows}
        raw_bytes = _maybe_materialise_raw(buffer, total)
        _store("design", dataset, original_filename=filename, raw_bytes=raw_bytes)
        return {
            "status": "ok",
            "stage": "design",
            "input_filename": filename,
            "row_count": len(rows),
            "columns": columns,
            "data": dataset,
        }

    def _process_sbom(
        buffer: SpooledTemporaryFile, total: int, filename: str
    ) -> Dict[str, Any]:
        buffer.seek(0)
        try:
            sbom_data = json.load(buffer)
        except json.JSONDecodeError as exc:
            raise HTTPException(
                status_code=400, detail=f"Invalid JSON in SBOM: {exc}"
            ) from exc

        overlay: OverlayConfig = app.state.overlay
        strict_validation = overlay.toggles.get("strict_validation", False)

        bom_format = sbom_data.get("bomFormat")
        if bom_format and bom_format not in ("CycloneDX", "SPDX"):
            if strict_validation:
                raise HTTPException(
                    status_code=422,
                    detail={
                        "message": f"Unsupported SBOM format: {bom_format}",
                        "supported_formats": ["CycloneDX", "SPDX"],
                    },
                )
            else:
                logger.warning(
                    "SBOM has unsupported bomFormat: %s, continuing with provider fallback",
                    bom_format,
                )

        if not bom_format:
            components = sbom_data.get("components")
            detected_manifests = sbom_data.get("detectedManifests")
            artifacts = sbom_data.get("artifacts")
            descriptor = sbom_data.get("descriptor")

            has_known_format = (
                isinstance(components, list)
                or isinstance(detected_manifests, dict)
                or isinstance(artifacts, list)
                or isinstance(descriptor, dict)
            )

            if not has_known_format and strict_validation:
                raise HTTPException(
                    status_code=422,
                    detail={
                        "message": "SBOM missing bomFormat and has unrecognized structure",
                        "hint": "Provide bomFormat field or use a known format (CycloneDX, GitHub dependency snapshot, Syft)",
                    },
                )

        buffer.seek(0)
        try:
            sbom: NormalizedSBOM = normalizer.load_sbom(buffer)
        except (json.JSONDecodeError, ValueError, KeyError) as exc:
            logger.warning("SBOM normalisation failed: %s", type(exc).__name__)
            raise HTTPException(
                status_code=400, detail=f"Failed to parse SBOM: {type(exc).__name__}"
            ) from exc
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            logger.exception("SBOM normalisation failed")
            raise HTTPException(
                status_code=400, detail=f"Failed to parse SBOM: {type(exc).__name__}"
            ) from exc
        raw_bytes = _maybe_materialise_raw(buffer, total)
        _store("sbom", sbom, original_filename=filename, raw_bytes=raw_bytes)

        # ── Forward SBOM to Dependency-Track (fire-and-forget) ──────
        dtrack_status = None
        try:
            from core.security_connectors import DependencyTrackConnector

            dtrack = DependencyTrackConnector()
            if dtrack.configured:
                project_name = (
                    sbom_data.get("metadata", {}).get("component", {}).get("name")
                    or os.path.splitext(filename)[0]
                    or "fixops-upload"
                )
                sbom_json = json.dumps(sbom_data)
                outcome = dtrack.upload_sbom(
                    project_name=project_name,
                    sbom_content=sbom_json,
                )
                dtrack_status = outcome.status
                if outcome.success:
                    logger.info(
                        "SBOM forwarded to Dependency-Track: project=%s token=%s",
                        project_name,
                        outcome.details.get("token", ""),
                    )
                else:
                    logger.warning(
                        "Dependency-Track SBOM upload returned: %s",
                        outcome.details.get("error", "unknown"),
                    )
        except ImportError:
            pass  # DTrack connector not available
        except Exception:
            logger.debug("Dependency-Track forwarding skipped (not configured or unavailable)")

        result: Dict[str, Any] = {
            "status": "ok",
            "stage": "sbom",
            "input_filename": filename,
            "metadata": sbom.metadata,
            "component_preview": [
                component.to_dict() for component in sbom.components[:5]
            ],
            "format": sbom.format,
        }
        if dtrack_status:
            result["dependency_track"] = {"status": dtrack_status}
        return result

    def _process_cve(
        buffer: SpooledTemporaryFile, total: int, filename: str
    ) -> Dict[str, Any]:
        try:
            cve_feed: NormalizedCVEFeed = normalizer.load_cve_feed(buffer)
        except (json.JSONDecodeError, ValueError, KeyError) as exc:
            logger.warning("CVE feed normalisation failed: %s", type(exc).__name__)
            raise HTTPException(
                status_code=400, detail=f"Failed to parse CVE feed: {type(exc).__name__}"
            ) from exc
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            logger.exception("CVE feed normalisation failed")
            raise HTTPException(
                status_code=400, detail=f"Failed to parse CVE feed: {type(exc).__name__}"
            ) from exc

        overlay: OverlayConfig = app.state.overlay
        strict_validation = overlay.toggles.get("strict_validation", False)

        if cve_feed.errors and strict_validation:
            raise HTTPException(
                status_code=422,
                detail={
                    "message": "CVE feed contains validation errors (strict mode)",
                    "record_count": cve_feed.metadata.get("record_count", 0),
                    "validation_errors": cve_feed.errors[:10],
                    "total_errors": len(cve_feed.errors),
                    "hint": "Use official CVE JSON 5.1.1 format or ensure all required fields are present",
                },
            )

        raw_bytes = _maybe_materialise_raw(buffer, total)
        _store("cve", cve_feed, original_filename=filename, raw_bytes=raw_bytes)
        return {
            "status": "ok",
            "stage": "cve",
            "input_filename": filename,
            "record_count": cve_feed.metadata.get("record_count", 0),
            "validation_errors": cve_feed.errors,
        }

    def _process_vex(
        buffer: SpooledTemporaryFile, total: int, filename: str
    ) -> Dict[str, Any]:
        try:
            vex_doc: NormalizedVEX = normalizer.load_vex(buffer)
        except (json.JSONDecodeError, ValueError, KeyError) as exc:
            logger.warning("VEX normalisation failed: %s", type(exc).__name__)
            raise HTTPException(
                status_code=400, detail=f"Failed to parse VEX document: {type(exc).__name__}"
            ) from exc
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            logger.exception("VEX normalisation failed")
            raise HTTPException(
                status_code=400, detail=f"Failed to parse VEX document: {type(exc).__name__}"
            ) from exc
        raw_bytes = _maybe_materialise_raw(buffer, total)
        _store("vex", vex_doc, original_filename=filename, raw_bytes=raw_bytes)
        return {
            "status": "ok",
            "stage": "vex",
            "input_filename": filename,
            "assertions": vex_doc.metadata.get("assertion_count", 0),
            "not_affected": len(vex_doc.suppressed_refs),
        }

    def _process_cnapp(
        buffer: SpooledTemporaryFile, total: int, filename: str
    ) -> Dict[str, Any]:
        try:
            cnapp_payload: NormalizedCNAPP = normalizer.load_cnapp(buffer)
        except (json.JSONDecodeError, ValueError, KeyError) as exc:
            logger.warning("CNAPP normalisation failed: %s", type(exc).__name__)
            raise HTTPException(
                status_code=400, detail=f"Failed to parse CNAPP payload: {type(exc).__name__}"
            ) from exc
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            logger.exception("CNAPP normalisation failed")
            raise HTTPException(
                status_code=400, detail=f"Failed to parse CNAPP payload: {type(exc).__name__}"
            ) from exc
        raw_bytes = _maybe_materialise_raw(buffer, total)
        _store("cnapp", cnapp_payload, original_filename=filename, raw_bytes=raw_bytes)
        return {
            "status": "ok",
            "stage": "cnapp",
            "input_filename": filename,
            "asset_count": cnapp_payload.metadata.get(
                "asset_count", len(cnapp_payload.assets)
            ),
            "finding_count": cnapp_payload.metadata.get(
                "finding_count", len(cnapp_payload.findings)
            ),
        }

    def _process_sarif(
        buffer: SpooledTemporaryFile, total: int, filename: str
    ) -> Dict[str, Any]:
        try:
            sarif: NormalizedSARIF = normalizer.load_sarif(buffer)
        except (json.JSONDecodeError, ValueError, KeyError) as exc:
            logger.warning("SARIF normalisation failed: %s", type(exc).__name__)
            raise HTTPException(
                status_code=400, detail=f"Failed to parse SARIF: {type(exc).__name__}"
            ) from exc
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            logger.exception("SARIF normalisation failed")
            raise HTTPException(
                status_code=400, detail=f"Failed to parse SARIF: {type(exc).__name__}"
            ) from exc
        raw_bytes = _maybe_materialise_raw(buffer, total)
        _store("sarif", sarif, original_filename=filename, raw_bytes=raw_bytes)
        return {
            "status": "ok",
            "stage": "sarif",
            "input_filename": filename,
            "metadata": sarif.metadata,
            "tools": sarif.tool_names,
        }

    def _process_context(
        buffer: SpooledTemporaryFile,
        total: int,
        filename: str,
        content_type: Optional[str] = None,
    ) -> Dict[str, Any]:
        try:
            context: NormalizedBusinessContext = normalizer.load_business_context(
                buffer, content_type=content_type
            )
        except (json.JSONDecodeError, ValueError, KeyError) as exc:
            logger.warning("Business context normalisation failed: %s", type(exc).__name__)
            raise HTTPException(
                status_code=400, detail=f"Failed to parse business context: {type(exc).__name__}"
            ) from exc
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            logger.exception("Business context normalisation failed")
            raise HTTPException(
                status_code=400, detail=f"Failed to parse business context: {type(exc).__name__}"
            ) from exc
        raw_bytes = _maybe_materialise_raw(buffer, total)
        _store("context", context, original_filename=filename, raw_bytes=raw_bytes)
        return {
            "status": "ok",
            "stage": "context",
            "input_filename": filename,
            "format": context.format,
            "ssvc_factors": context.ssvc,
            "components": context.components,
        }

    def _process_from_buffer(
        stage: str,
        buffer: SpooledTemporaryFile,
        total: int,
        filename: str,
        content_type: Optional[str] = None,
    ) -> Dict[str, Any]:
        if stage == "design":
            return _process_design(buffer, total, filename)
        if stage == "sbom":
            return _process_sbom(buffer, total, filename)
        if stage == "cve":
            return _process_cve(buffer, total, filename)
        if stage == "vex":
            return _process_vex(buffer, total, filename)
        if stage == "cnapp":
            return _process_cnapp(buffer, total, filename)
        if stage == "sarif":
            return _process_sarif(buffer, total, filename)
        if stage == "context":
            return _process_context(buffer, total, filename, content_type)
        raise HTTPException(status_code=400, detail=f"Unsupported stage '{stage}'")

    def _process_from_path(
        stage: str, path: Path, filename: str, content_type: Optional[str] = None
    ) -> Dict[str, Any]:
        buffer = SpooledTemporaryFile(max_size=_CHUNK_SIZE, mode="w+b")
        try:
            with path.open("rb") as handle:
                shutil.copyfileobj(handle, buffer)  # type: ignore[misc]
            total = buffer.tell()
            buffer.seek(0)
            return _process_from_buffer(stage, buffer, total, filename, content_type)
        finally:
            with suppress(Exception):
                buffer.close()

    @app.post("/inputs/design", dependencies=[Depends(_verify_api_key)])
    async def ingest_design(file: UploadFile = File(...)) -> Dict[str, Any]:
        _validate_content_type(
            file, ("text/csv", "application/vnd.ms-excel", "application/csv")
        )
        buffer, total = await _read_limited(file, "design")
        try:
            return _process_design(buffer, total, file.filename or "design.csv")
        finally:
            with suppress(Exception):
                buffer.close()

    @app.post("/inputs/sbom", dependencies=[Depends(_verify_api_key)])
    async def ingest_sbom(file: UploadFile = File(...)) -> Dict[str, Any]:
        _validate_content_type(
            file,
            (
                "application/json",
                "text/json",
                "application/zip",
                "application/x-zip-compressed",
                "application/gzip",
            ),
        )
        buffer, total = await _read_limited(file, "sbom")
        try:
            # Validate JSON structure if content-type is JSON
            if file.content_type in ("application/json", "text/json"):
                buffer.seek(0)
                try:
                    json.load(buffer)
                    buffer.seek(0)
                except json.JSONDecodeError as exc:
                    raise HTTPException(
                        status_code=422,
                        detail=f"Invalid JSON payload: {exc}",
                    ) from exc
            return _process_sbom(buffer, total, file.filename or "sbom.json")
        finally:
            with suppress(Exception):
                buffer.close()

    @app.post("/inputs/cve", dependencies=[Depends(_verify_api_key)])
    async def ingest_cve(file: UploadFile = File(...)) -> Dict[str, Any]:
        _validate_content_type(
            file,
            (
                "application/json",
                "text/json",
                "application/zip",
                "application/x-zip-compressed",
                "application/gzip",
            ),
        )
        buffer, total = await _read_limited(file, "cve")
        try:
            return _process_cve(buffer, total, file.filename or "cve.json")
        finally:
            with suppress(Exception):
                buffer.close()

    @app.post("/inputs/vex", dependencies=[Depends(_verify_api_key)])
    async def ingest_vex(file: UploadFile = File(...)) -> Dict[str, Any]:
        _validate_content_type(file, ("application/json", "text/json"))
        buffer, total = await _read_limited(file, "vex")
        try:
            return _process_vex(buffer, total, file.filename or "vex.json")
        finally:
            with suppress(Exception):
                buffer.close()

    @app.post("/inputs/cnapp", dependencies=[Depends(_verify_api_key)])
    async def ingest_cnapp(file: UploadFile = File(...)) -> Dict[str, Any]:
        _validate_content_type(file, ("application/json", "text/json"))
        buffer, total = await _read_limited(file, "cnapp")
        try:
            return _process_cnapp(buffer, total, file.filename or "cnapp.json")
        finally:
            with suppress(Exception):
                buffer.close()

    @app.post("/inputs/sarif", dependencies=[Depends(_verify_api_key)])
    async def ingest_sarif(file: UploadFile = File(...)) -> Dict[str, Any]:
        _validate_content_type(
            file,
            (
                "application/json",
                "text/json",
                "application/zip",
                "application/x-zip-compressed",
                "application/gzip",
            ),
        )
        buffer, total = await _read_limited(file, "sarif")
        try:
            return _process_sarif(buffer, total, file.filename or "scan.sarif")
        finally:
            with suppress(Exception):
                buffer.close()

    @app.post("/inputs/context", dependencies=[Depends(_verify_api_key)])
    async def ingest_context(file: UploadFile = File(...)) -> Dict[str, Any]:
        _validate_content_type(
            file,
            (
                "application/json",
                "text/json",
                "application/x-yaml",
                "text/yaml",
                "application/yaml",
                "text/plain",
            ),
        )
        buffer, total = await _read_limited(file, "context")
        try:
            return _process_context(
                buffer, total, file.filename or "context.yaml", file.content_type
            )
        finally:
            with suppress(Exception):
                buffer.close()

    @app.post("/api/v1/ingest/multipart", dependencies=[Depends(_verify_api_key)])
    async def ingest_multipart(
        files: List[UploadFile] = File(...),
        format_hint: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Scanner-agnostic multipart ingestion endpoint.

        Accepts multiple files in various formats (SARIF, CycloneDX, SPDX, VEX, CNAPP,
        dark web intel, etc.) and normalizes them into a unified Finding model.

        Features:
        - Auto-detection of format variants
        - Parallel processing for multiple files
        - Format drift handling with lenient parsing
        - Performance: 10K findings in <2 min

        Args:
            files: One or more files to ingest
            format_hint: Optional format hint (sarif, cyclonedx, spdx, vex, cnapp, dark_web_intel)

        Returns:
            Ingestion results with normalized findings and asset inventory
        """
        import asyncio

        from apps.api.ingestion import get_ingestion_service

        service = get_ingestion_service()

        # Limit concurrent file processing to prevent resource exhaustion
        MAX_CONCURRENT_FILES = 10
        semaphore = asyncio.Semaphore(MAX_CONCURRENT_FILES)

        async def process_file(file: UploadFile) -> Dict[str, Any]:
            """Process a single file and return result dict."""
            async with semaphore:
                try:
                    buffer, total = await _read_limited(file, "sarif")
                    buffer.seek(0)
                    content = buffer.read()
                    buffer.close()
                    result = await service.ingest(
                        content=content,
                        filename=file.filename,
                        content_type=file.content_type,
                        format_hint=format_hint,
                    )
                    return {
                        "filename": file.filename,
                        "status": result.status,
                        "format_detected": result.format_detected,
                        "detection_confidence": result.detection_confidence,
                        "findings_count": result.findings_count,
                        "assets_count": result.assets_count,
                        "processing_time_ms": result.processing_time_ms,
                        "errors": result.errors,
                        "warnings": result.warnings,
                        "_findings_count": result.findings_count,
                        "_assets_count": result.assets_count,
                        "_errors": result.errors,
                    }
                except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
                    logger.error("Failed to ingest %s: %s", file.filename, type(e).__name__)
                    error_type = type(e).__name__
                    safe_error = f"Ingestion failed: {error_type}"
                    return {
                        "filename": file.filename,
                        "status": "error",
                        "error": safe_error,
                        "_findings_count": 0,
                        "_assets_count": 0,
                        "_errors": [f"{file.filename}: {safe_error}"],
                    }

        # Process all files in parallel using asyncio.gather
        raw_results = await asyncio.gather(*[process_file(f) for f in files])

        # Aggregate results
        results = []
        total_findings = 0
        total_assets = 0
        errors = []

        for raw in raw_results:
            total_findings += raw.pop("_findings_count", 0)
            total_assets += raw.pop("_assets_count", 0)
            file_errors = raw.pop("_errors", [])
            if file_errors:
                errors.extend(file_errors)
            results.append(raw)

        return {
            "status": "success" if not errors else "partial",
            "files_processed": len(files),
            "total_findings": total_findings,
            "total_assets": total_assets,
            "results": results,
            "errors": errors,
        }

    @app.get("/api/v1/ingest/assets", dependencies=[Depends(_verify_api_key)])
    async def get_asset_inventory() -> Dict[str, Any]:
        """
        Get the dynamic asset inventory.

        Returns all discovered assets from ingested security data.
        """
        from apps.api.ingestion import get_ingestion_service

        service = get_ingestion_service()
        assets = service.get_asset_inventory()

        return {
            "total": len(assets),
            "assets": [asset.model_dump() for asset in assets],
        }

    @app.get("/api/v1/ingest/formats", dependencies=[Depends(_verify_api_key)])
    async def list_supported_formats() -> Dict[str, Any]:
        """
        List all supported ingestion formats.

        Returns the available normalizers and their configuration.
        """
        from apps.api.ingestion import get_registry

        registry = get_registry()
        normalizers = []

        for name in registry.list_normalizers():
            normalizer = registry.get_normalizer(name)
            if normalizer:
                normalizers.append(
                    {
                        "name": name,
                        "enabled": normalizer.enabled,
                        "priority": normalizer.priority,
                        "description": normalizer.config.description,
                        "supported_versions": normalizer.config.supported_versions,
                    }
                )

        return {
            "total": len(normalizers),
            "normalizers": normalizers,
        }

    @app.post("/inputs/{stage}/chunks/start", dependencies=[Depends(_verify_api_key)])
    async def initialise_chunk_upload(
        stage: str, payload: Dict[str, Any] = Body(...)
    ) -> Dict[str, Any]:
        if stage not in supported_stages:
            raise HTTPException(
                status_code=404, detail=f"Stage '{stage}' not recognised"
            )
        filename = str(
            payload.get("file_name") or payload.get("filename") or f"{stage}.bin"
        )
        try:
            total_bytes = (
                int(payload.get("total_size"))  # type: ignore[arg-type]
                if payload.get("total_size") is not None
                else None
            )
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="total_size must be an integer")
        checksum = payload.get("checksum")
        content_type = payload.get("content_type")
        session = upload_manager.create_session(
            stage,
            filename=filename,
            total_bytes=total_bytes,
            checksum=checksum,
            content_type=content_type,
        )
        return {"status": "initialised", "session": session.to_dict()}

    @app.put(
        "/inputs/{stage}/chunks/{session_id}", dependencies=[Depends(_verify_api_key)]
    )
    async def upload_chunk(
        stage: str,
        session_id: str,
        chunk: UploadFile = File(...),
        offset: Optional[int] = None,
    ) -> Dict[str, Any]:
        if stage not in supported_stages:
            raise HTTPException(
                status_code=404, detail=f"Stage '{stage}' not recognised"
            )

        # Validate offset parameter
        if offset is not None and offset < 0:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid offset: {offset}. Offset must be non-negative.",
            )

        data = await chunk.read()
        try:
            session = upload_manager.append_chunk(session_id, data, offset=offset)
        except KeyError:
            raise HTTPException(status_code=404, detail="Upload session not found")
        except ValueError as exc:
            logger.warning("upload.append_chunk.invalid: %s", type(exc).__name__)
            raise HTTPException(status_code=400, detail="Invalid chunk data")
        return {"status": "chunk_received", "session": session.to_dict()}

    @app.post(
        "/inputs/{stage}/chunks/{session_id}/complete",
        dependencies=[Depends(_verify_api_key)],
    )
    async def complete_upload(stage: str, session_id: str) -> Dict[str, Any]:
        if stage not in supported_stages:
            raise HTTPException(
                status_code=404, detail=f"Stage '{stage}' not recognised"
            )
        try:
            session = upload_manager.finalise(session_id)
        except KeyError:
            raise HTTPException(status_code=404, detail="Upload session not found")
        except ValueError as exc:
            logger.warning("upload.complete.invalid: %s", type(exc).__name__)
            raise HTTPException(status_code=400, detail="Invalid upload state")
        path = session.path
        if path is None:
            raise HTTPException(status_code=500, detail="Upload payload missing")
        response = _process_from_path(
            stage, path, session.filename, session.content_type
        )
        response["upload_session"] = session.to_dict()
        return response

    @app.get(
        "/inputs/{stage}/chunks/{session_id}", dependencies=[Depends(_verify_api_key)]
    )
    async def upload_status(stage: str, session_id: str) -> Dict[str, Any]:
        if stage not in supported_stages:
            raise HTTPException(
                status_code=404, detail=f"Stage '{stage}' not recognised"
            )
        try:
            session = upload_manager.status(session_id)
        except KeyError:
            raise HTTPException(status_code=404, detail="Upload session not found")
        return {"status": "ok", "session": session.to_dict()}

    async def _run_legacy_pipeline_impl() -> Dict[str, Any]:
        overlay: OverlayConfig = app.state.overlay
        required = overlay.required_inputs
        missing = [stage for stage in required if stage not in app.state.artifacts]
        if missing:
            raise HTTPException(
                status_code=400,
                detail={"message": "Missing required artefacts", "missing": missing},
            )

        if overlay.toggles.get("enforce_ticket_sync") and not overlay.jira.get(
            "project_key"
        ):
            raise HTTPException(
                status_code=500,
                detail={
                    "message": "Ticket synchronisation enforced but Jira project_key missing",
                    "integration": overlay.jira,
                },
            )

        run_id = uuid.uuid4().hex

        try:
            result = orchestrator.run(
                design_dataset=app.state.artifacts.get(
                    "design", {"columns": [], "rows": []}
                ),
                sbom=app.state.artifacts["sbom"],
                sarif=app.state.artifacts["sarif"],
                cve=app.state.artifacts["cve"],
                overlay=overlay,
                vex=app.state.artifacts.get("vex"),
                cnapp=app.state.artifacts.get("cnapp"),
                context=app.state.artifacts.get("context"),
            )
        except Exception as exc:
            import traceback as _tb
            tb_str = _tb.format_exc()
            logger.exception("Pipeline orchestrator failed: %s\n%s", exc, tb_str)
            raise HTTPException(
                status_code=500,
                detail={
                    "message": "Pipeline execution failed",
                    "error": str(exc),
                    "error_type": type(exc).__name__,
                    "traceback": tb_str[-2000:],
                },
            )
        result["run_id"] = run_id

        severity_overview = result.get("severity_overview", {})
        guardrail_evaluation = result.get("guardrail_evaluation", {})
        result["highest_severity"] = severity_overview.get("highest")
        result["guardrail_status"] = guardrail_evaluation.get("status")
        analytics_store = getattr(app.state, "analytics_store", None)
        if analytics_store is not None:
            try:
                persistence = analytics_store.persist_run(run_id, result)
            except (
                Exception
            ):  # pragma: no cover - analytics persistence must not block pipeline
                logger.exception(
                    "Failed to persist analytics artefacts for run %s", run_id
                )
                persistence = {}
            if persistence:
                result["analytics_persistence"] = persistence
                analytics_section = result.get("analytics")
                if isinstance(analytics_section, dict):
                    analytics_section["persistence"] = persistence
        if app.state.archive_records:
            result["artifact_archive"] = ArtefactArchive.summarise(
                app.state.archive_records
            )
            app.state.archive_records = {}
        if overlay.toggles.get("auto_attach_overlay_metadata", True):
            result["overlay"] = overlay.to_sanitised_dict()
            result["overlay"]["required_inputs"] = list(required)

        app.state.last_pipeline_result = result

        return result

    @app.get("/pipeline/run", dependencies=[Depends(_verify_api_key)])
    async def get_legacy_pipeline_run() -> Dict[str, Any]:
        """Legacy pipeline trigger (GET)."""
        return await _run_legacy_pipeline_impl()

    @app.post("/pipeline/run", dependencies=[Depends(_verify_api_key)])
    async def post_legacy_pipeline_run() -> Dict[str, Any]:
        """Legacy pipeline trigger (POST)."""
        return await _run_legacy_pipeline_impl()

    @app.get("/api/v1/triage", dependencies=[Depends(_verify_api_key)])
    async def get_triage(
        view: str = "events",
        cluster_status: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Transform last pipeline result into triage inbox format.

        Args:
            view: View mode - 'events' (individual findings) or 'clusters' (deduplicated groups)
            cluster_status: Filter clusters by status (only applies when view=clusters)

        Returns:
            Triage data with rows and summary. When view=clusters, rows represent
            deduplicated finding groups with event counts.
        """
        last_result = app.state.last_pipeline_result

        if last_result is None:
            raise HTTPException(
                status_code=404,
                detail="No pipeline results available. Run /api/v1/brain/pipeline/run first.",
            )

        # If view=clusters, return deduplicated cluster view
        if view == "clusters":
            return await _get_triage_clusters(cluster_status)

        rows = []
        crosswalk = last_result.get("crosswalk", [])
        evidence_bundle = last_result.get("evidence_bundle", {})
        compliance_status = last_result.get("compliance_status", {})
        exploitability_insights = last_result.get("exploitability_insights", {})

        retention_days = 2555

        for idx, entry in enumerate(crosswalk):
            design_row = entry.get("design_row", {})
            findings = entry.get("findings", [])
            cves = entry.get("cves", [])

            component_name = design_row.get("component", "unknown")
            exposure = design_row.get("exposure", "internal")
            internet_facing = exposure == "internet"

            for finding in findings:
                rule_id = finding.get("rule_id", "unknown")
                message = finding.get("message", "No description")
                level = finding.get("level", "warning")
                file_path = finding.get("file", "")
                line = finding.get("line", 0)

                severity_map = {"error": "high", "warning": "medium", "note": "low"}
                severity = severity_map.get(level, "medium")

                location = f"{file_path}:{line}" if file_path else component_name

                row_id = f"sarif-{idx}-{rule_id}"

                rows.append(
                    {
                        "id": row_id,
                        "severity": severity,
                        "title": f"{rule_id} - {message[:80]}",
                        "source": "SAST",
                        "repo": component_name,
                        "location": location,
                        "exploitability": {"kev": False, "epss": 0.0},
                        "age_days": 0,
                        "internet_facing": internet_facing,
                        "description": message,
                        "remediation": f"Review and fix {rule_id} in {location}",
                        "evidence_bundle": {
                            "id": evidence_bundle.get("bundle_id", "unknown"),
                            "signature_algorithm": "RSA-SHA256",
                            "retention_days": retention_days,
                            "retained_until": (
                                datetime.now(timezone.utc)
                                + timedelta(days=retention_days)
                            ).strftime("%m/%d/%Y"),
                            "sha256": hashlib.sha256(
                                evidence_bundle.get("bundle_id", "unknown").encode()
                            ).hexdigest(),
                        },
                        "decision": {
                            "verdict": "review" if severity == "high" else "allow",
                            "confidence": 0.75,
                            "ssvc_outcome": "scheduled",
                            "rationale": f"SAST finding with {severity} severity in {component_name}",
                            "signals": {
                                "severity": severity,
                                "internet_facing": internet_facing,
                                "source": "SAST",
                            },
                        },
                        "compliance_mappings": _get_compliance_mappings(
                            compliance_status, "SAST"
                        ),
                    }
                )

            for cve in cves:
                cve_id = cve.get("cve_id", "unknown")
                cve_severity = cve.get("severity", "medium")
                exploited = cve.get("exploited", False)
                raw_cve = cve.get("raw", {})
                short_desc = raw_cve.get("shortDescription", "No description")

                epss_score = 0.0
                if exploitability_insights:
                    epss_data = exploitability_insights.get("epss", {})
                    epss_score = epss_data.get(cve_id, 0.0)

                age_days = 7

                verdict = (
                    "block"
                    if (exploited or epss_score > 0.7) and cve_severity == "critical"
                    else "review"
                )
                ssvc_outcome = "immediate" if verdict == "block" else "scheduled"

                row_id = f"cve-{idx}-{cve_id}"

                rows.append(
                    {
                        "id": row_id,
                        "severity": cve_severity,
                        "title": f"{cve_id} - {short_desc[:80]}",
                        "source": "CVE",
                        "repo": component_name,
                        "location": component_name,
                        "exploitability": {"kev": exploited, "epss": epss_score},
                        "age_days": age_days,
                        "internet_facing": internet_facing,
                        "description": short_desc,
                        "remediation": f"Update {component_name} to patch {cve_id}",
                        "evidence_bundle": {
                            "id": evidence_bundle.get("bundle_id", "unknown"),
                            "signature_algorithm": "RSA-SHA256",
                            "retention_days": retention_days,
                            "retained_until": (
                                datetime.now(timezone.utc)
                                + timedelta(days=retention_days)
                            ).strftime("%m/%d/%Y"),
                            "sha256": hashlib.sha256(
                                evidence_bundle.get("bundle_id", "unknown").encode()
                            ).hexdigest(),
                        },
                        "decision": {
                            "verdict": verdict,
                            "confidence": 0.95 if exploited else 0.80,
                            "ssvc_outcome": ssvc_outcome,
                            "rationale": f"CVE with {cve_severity} severity, KEV={exploited}, EPSS={epss_score:.2f}",
                            "signals": {
                                "kev": exploited,
                                "epss": epss_score,
                                "severity": cve_severity,
                                "internet_facing": internet_facing,
                                "age_days": age_days,
                            },
                        },
                        "compliance_mappings": _get_compliance_mappings(
                            compliance_status, "CVE"
                        ),
                    }
                )

        new_7d = sum(1 for r in rows if r["age_days"] <= 7)
        high_critical = sum(1 for r in rows if r["severity"] in ["high", "critical"])
        exploitable = sum(
            1
            for r in rows
            if r["exploitability"]["kev"] or r["exploitability"]["epss"] > 0.7
        )
        internet_facing_count = sum(1 for r in rows if r["internet_facing"])

        return {
            "rows": rows,
            "summary": {
                "total": len(rows),
                "new_7d": new_7d,
                "high_critical": high_critical,
                "exploitable": exploitable,
                "internet_facing": internet_facing_count,
            },
        }

    @app.get("/api/v1/triage/export", dependencies=[Depends(_verify_api_key)])
    async def export_triage(format: str = "csv") -> Any:
        """Export triage data as CSV or JSON."""
        last_result = app.state.last_pipeline_result

        if last_result is None:
            raise HTTPException(
                status_code=404,
                detail="No pipeline results available. Run /api/v1/brain/pipeline/run first.",
            )

        triage_data = await get_triage()
        rows = triage_data["rows"]

        if format == "json":
            from fastapi.responses import JSONResponse

            return JSONResponse(
                content={"data": rows, "summary": triage_data["summary"]},
                headers={
                    "Content-Disposition": 'attachment; filename="fixops-triage-export.json"',
                    "Access-Control-Expose-Headers": "Content-Disposition",
                },
            )
        elif format == "csv":
            import io

            from fastapi.responses import StreamingResponse

            output = io.StringIO()
            if rows:
                fieldnames = [
                    "id",
                    "severity",
                    "title",
                    "source",
                    "repo",
                    "location",
                    "age_days",
                    "internet_facing",
                ]
                writer = csv.DictWriter(output, fieldnames=fieldnames)
                writer.writeheader()
                for row in rows:
                    writer.writerow(
                        {
                            "id": row["id"],
                            "severity": row["severity"],
                            "title": row["title"],
                            "source": row["source"],
                            "repo": row["repo"],
                            "location": row["location"],
                            "age_days": row["age_days"],
                            "internet_facing": row["internet_facing"],
                        }
                    )

            output.seek(0)
            return StreamingResponse(
                iter([output.getvalue()]),
                media_type="text/csv",
                headers={
                    "Content-Disposition": 'attachment; filename="fixops-triage-export.csv"',
                    "Access-Control-Expose-Headers": "Content-Disposition",
                },
            )
        else:
            raise HTTPException(
                status_code=400, detail="Invalid format. Use 'csv' or 'json'."
            )

    async def _get_triage_clusters(
        cluster_status: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Get triage data in cluster (deduplicated) view.

        Returns finding clusters instead of individual events, showing
        deduplicated groups with event counts and representative info.
        """
        from pathlib import Path

        from core.services.deduplication import DeduplicationService

        db_path = (
            Path(os.environ.get("FIXOPS_DATA_DIR", "data"))
            / "deduplication"
            / "dedup.db"
        )
        dedup_service = DeduplicationService(db_path=db_path)
        clusters = dedup_service.get_clusters(
            org_id="default",
            status=cluster_status,
            limit=1000,
            offset=0,
        )

        # Batch fetch events for all clusters to avoid N+1 query pattern
        cluster_ids = [c["cluster_id"] for c in clusters]
        events_by_cluster = dedup_service.get_events_for_clusters(
            cluster_ids, limit_per_cluster=100
        )

        rows = []
        for cluster in clusters:
            # Get events for this cluster from the batch result
            events: List[Dict[str, Any]] = events_by_cluster.get(
                cluster["cluster_id"], []
            )

            # Compute severity (highest among events, fallback to cluster metadata)
            severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
            max_severity = cluster.get("severity", "low")
            for event in events:
                event_severity = event.get("severity", "low")
                if severity_order.get(event_severity, 0) > severity_order.get(
                    max_severity, 0
                ):
                    max_severity = event_severity

            # Compute exploitability (any KEV or max EPSS)
            has_kev = any(event.get("kev", False) for event in events)
            max_epss = max((event.get("epss", 0.0) for event in events), default=0.0)

            # Get representative event for title/description
            representative = events[0] if events else {}

            rows.append(
                {
                    "id": cluster["cluster_id"],
                    "cluster_id": cluster["cluster_id"],
                    "severity": max_severity,
                    "title": cluster.get(
                        "title", representative.get("title", "Unknown")
                    ),
                    "source": cluster.get(
                        "source", representative.get("source", "Unknown")
                    ),
                    "event_count": cluster.get("event_count", len(events)),
                    "first_seen": cluster.get("first_seen"),
                    "last_seen": cluster.get("last_seen"),
                    "status": cluster.get("status", "open"),
                    "exploitability": {"kev": has_kev, "epss": max_epss},
                    "correlation_key": cluster.get("correlation_key"),
                    "fingerprint": cluster.get("fingerprint"),
                    "stages": list(set(e.get("stage", "unknown") for e in events)),
                    "locations": list(
                        set(e.get("location", "") for e in events if e.get("location"))
                    ),
                }
            )

        # Compute summary
        high_critical = sum(1 for r in rows if r["severity"] in ["high", "critical"])
        exploitable = sum(
            1
            for r in rows
            if r["exploitability"]["kev"] or r["exploitability"]["epss"] > 0.7
        )
        open_count = sum(1 for r in rows if r["status"] == "open")

        return {
            "view": "clusters",
            "rows": rows,
            "summary": {
                "total_clusters": len(rows),
                "total_events": sum(r["event_count"] for r in rows),
                "high_critical": high_critical,
                "exploitable": exploitable,
                "open": open_count,
                "noise_reduction": f"{(1 - len(rows) / max(sum(r['event_count'] for r in rows), 1)) * 100:.1f}%"
                if rows
                else "0%",
            },
        }

    def _get_compliance_mappings(
        compliance_status: Dict[str, Any], source_type: str
    ) -> list:
        """Extract compliance mappings from compliance_status."""
        mappings = []
        frameworks = compliance_status.get("frameworks", [])

        for framework in frameworks[:3]:
            framework_name = framework.get("name", "")
            controls = framework.get("controls", [])

            if source_type == "CVE" and controls:
                for control in controls[:2]:
                    mappings.append(
                        {
                            "framework": framework_name,
                            "control": control.get("id", ""),
                            "description": control.get("title", ""),
                        }
                    )
            elif source_type == "SAST" and controls:
                for control in controls[:1]:
                    mappings.append(
                        {
                            "framework": framework_name,
                            "control": control.get("id", ""),
                            "description": control.get("title", ""),
                        }
                    )

        return mappings

    @app.get("/api/v1/graph", dependencies=[Depends(_verify_api_key)])
    async def get_graph() -> Dict[str, Any]:
        """Transform last pipeline result into interactive graph format."""
        last_result = app.state.last_pipeline_result

        if last_result is None:
            raise HTTPException(
                status_code=404,
                detail="No pipeline results available. Run /api/v1/brain/pipeline/run first.",
            )

        nodes = []
        edges = []
        crosswalk = last_result.get("crosswalk", [])
        context_summary = last_result.get("context_summary", {})
        exploitability_insights = last_result.get("exploitability_insights", {})

        services_seen = set()
        components_seen = set()

        context_components = {}
        for comp in context_summary.get("components", []):
            name = comp.get("component", "")
            if name:
                context_components[name] = comp

        for idx, entry in enumerate(crosswalk):
            design_row = entry.get("design_row", {})
            findings = entry.get("findings", [])
            cves = entry.get("cves", [])

            component_name = design_row.get("component", f"component-{idx}")
            service_name = design_row.get("service", component_name)
            exposure = design_row.get("exposure", "internal")

            context = context_components.get(component_name, {})
            criticality = context.get("criticality", "standard")
            data_classification = context.get("data_classification", [])

            if service_name not in services_seen:
                services_seen.add(service_name)
                nodes.append(
                    {
                        "id": f"service-{service_name}",
                        "type": "service",
                        "label": service_name,
                        "criticality": criticality,
                        "exposure": exposure,
                        "internet_facing": exposure == "internet",
                        "has_pii": "pii" in data_classification,
                    }
                )

            if component_name not in components_seen:
                components_seen.add(component_name)
                nodes.append(
                    {
                        "id": f"component-{component_name}",
                        "type": "component",
                        "label": component_name,
                        "criticality": criticality,
                        "exposure": exposure,
                        "internet_facing": exposure == "internet",
                        "has_pii": "pii" in data_classification,
                    }
                )

                edges.append(
                    {
                        "id": f"edge-service-{service_name}-{component_name}",
                        "source": f"service-{service_name}",
                        "target": f"component-{component_name}",
                        "type": "contains",
                    }
                )

            for finding_idx, finding in enumerate(findings):
                rule_id = finding.get("rule_id", f"finding-{finding_idx}")
                level = finding.get("level", "warning")
                message = finding.get("message", "No description")
                file_path = finding.get("file", "")

                severity_map = {"error": "high", "warning": "medium", "note": "low"}
                severity = severity_map.get(level, "medium")

                finding_id = f"finding-{component_name}-{rule_id}-{finding_idx}"
                nodes.append(
                    {
                        "id": finding_id,
                        "type": "finding",
                        "label": rule_id,
                        "severity": severity,
                        "message": message[:100],
                        "file": file_path,
                        "source": "SAST",
                        "kev": False,
                        "epss": 0.0,
                    }
                )

                edges.append(
                    {
                        "id": f"edge-{component_name}-{finding_id}",
                        "source": f"component-{component_name}",
                        "target": finding_id,
                        "type": "has_issue",
                    }
                )

            for cve_idx, cve in enumerate(cves):
                cve_id = cve.get("cve_id", f"cve-{cve_idx}")
                cve_severity = cve.get("severity", "medium")
                exploited = cve.get("exploited", False)
                raw_cve = cve.get("raw", {})
                short_desc = raw_cve.get("shortDescription", "No description")

                epss_score = 0.0
                if exploitability_insights:
                    epss_data = exploitability_insights.get("epss", {})
                    epss_score = epss_data.get(cve_id, 0.0)

                cve_node_id = f"cve-{component_name}-{cve_id}"
                nodes.append(
                    {
                        "id": cve_node_id,
                        "type": "cve",
                        "label": cve_id,
                        "severity": cve_severity,
                        "message": short_desc[:100],
                        "source": "CVE",
                        "kev": exploited,
                        "epss": epss_score,
                    }
                )

                edges.append(
                    {
                        "id": f"edge-{component_name}-{cve_node_id}",
                        "source": f"component-{component_name}",
                        "target": cve_node_id,
                        "type": "has_issue",
                    }
                )

        return {
            "nodes": nodes,
            "edges": edges,
            "summary": {
                "services": len(services_seen),
                "components": len(components_seen),
                "issues": len([n for n in nodes if n["type"] in ["finding", "cve"]]),
                "kev_count": len([n for n in nodes if n.get("kev", False)]),
            },
        }

    @app.get("/analytics/dashboard", dependencies=[Depends(_verify_api_key)])
    async def analytics_dashboard(limit: int = 10) -> Dict[str, Any]:
        store: Optional[AnalyticsStore] = getattr(app.state, "analytics_store", None)
        if store is None:
            raise HTTPException(
                status_code=404,
                detail="Analytics persistence disabled for this profile",
            )
        try:
            return store.load_dashboard(limit=limit)
        except ValueError as exc:  # pragma: no cover - defensive guard
            logger.warning("analytics.dashboard.invalid: %s", type(exc).__name__)
            raise HTTPException(status_code=400, detail="Invalid analytics request") from exc

    @app.get("/analytics/runs/{run_id}", dependencies=[Depends(_verify_api_key)])
    async def analytics_run(run_id: str) -> Dict[str, Any]:
        store: Optional[AnalyticsStore] = getattr(app.state, "analytics_store", None)
        if store is None:
            raise HTTPException(
                status_code=404,
                detail="Analytics persistence disabled for this profile",
            )
        try:
            data = store.load_run(run_id)
        except ValueError as exc:
            logger.warning("analytics.run.invalid: %s", type(exc).__name__)
            raise HTTPException(status_code=400, detail="Invalid run ID") from exc
        has_content = bool(
            data.get("forecasts")
            or data.get("exploit_snapshots")
            or data.get("ticket_metrics")
        )
        feedback_section = data.get("feedback")
        if isinstance(feedback_section, Mapping):
            has_content = has_content or bool(
                feedback_section.get("events") or feedback_section.get("outcomes")
            )
        if not has_content:
            raise HTTPException(
                status_code=404, detail="No analytics persisted for run"
            )
        return data

    @app.post("/feedback", dependencies=[Depends(_verify_api_key)])
    async def submit_feedback(payload: Dict[str, Any]) -> Dict[str, Any]:
        recorder: Optional[FeedbackRecorder] = app.state.feedback
        if recorder is None:
            raise HTTPException(
                status_code=400, detail="Feedback capture disabled in this profile"
            )
        try:
            entry = recorder.record(payload)
        except ValueError as exc:
            logger.warning("feedback.invalid: %s", type(exc).__name__)
            raise HTTPException(status_code=400, detail="Invalid feedback payload") from exc
        return entry

    # ------------------------------------------------------------------
    # MCP Auto-Discovery router (must be mounted after all other routers
    # so that the startup hook can introspect the full route table)
    # ------------------------------------------------------------------
    app.include_router(
        mcp_discovery_router,
        dependencies=[Depends(_verify_api_key)],
    )
    _mcp_register_startup(app)
    _logger.info("Mounted MCP Auto-Discovery router at /api/v1/mcp")

    # ------------------------------------------------------------------
    # Startup hooks: database, EventBus, route logging
    # ------------------------------------------------------------------
    @app.on_event("startup")
    async def _init_enterprise_db():
        """Initialize the enterprise DatabaseManager (PostgreSQL / SQLite)."""
        try:
            from core.db.enterprise.session import DatabaseManager

            await DatabaseManager.initialize()
            _logger.info("Enterprise DatabaseManager initialized")
        except ImportError as exc:
            _logger.warning("Enterprise DB init skipped: %s", exc)

    @app.on_event("shutdown")
    async def _close_enterprise_db():
        """Gracefully close the enterprise database pool."""
        try:
            from core.db.enterprise.session import DatabaseManager

            await DatabaseManager.close()
            _logger.info("Enterprise DatabaseManager closed")
        except (ImportError, AttributeError):
            pass  # DB manager not available in this deployment
        except ImportError as exc:
            _logger.debug("Enterprise DB close error: %s", type(exc).__name__)

    @app.on_event("startup")
    async def _wire_event_subscribers():
        """Register EventBus subscribers so emitted events trigger handlers."""
        try:
            from core.event_subscribers import register_all_subscribers

            count = register_all_subscribers()
            _logger.info("EventBus: %d subscribers registered at startup", count)
        except ImportError as exc:
            _logger.warning("EventBus subscriber registration failed: %s", exc)

        # Wire activity feed persistence (P3 Vision Gap)
        try:
            from apps.api.gap_router import record_activity_event
            from core.event_bus import get_event_bus

            bus = get_event_bus()

            async def _activity_feed_recorder(event):
                """Persist every event to the activity feed SQLite DB."""
                et = event.event_type.value if hasattr(event.event_type, "value") else str(event.event_type)
                record_activity_event(et, event.source, event.data, event.org_id)

            bus.subscribe_all(_activity_feed_recorder)
            _logger.info("Activity feed recorder wired to EventBus (wildcard)")
        except (ValueError, KeyError, RuntimeError, TypeError, AttributeError) as exc:
            _logger.warning("Activity feed recorder wiring failed: %s", exc)

    @app.on_event("startup")
    async def _python_compat_check():
        """Warn if running on Python 3.14 (dataclasses slots bug)."""
        import sys as _sys
        if _sys.version_info[:2] == (3, 14):
            _logger.warning(
                "Python %s detected — known dataclasses slots bug (cpython#142214). "
                "A runtime patch is applied but Python 3.11-3.13 is recommended "
                "for production. Docker images use Python 3.11.",
                _sys.version,
            )

    @app.on_event("startup")
    async def _log_mounted_routes():
        """Log all mounted routes and optionally fail-fast if critical routes missing."""
        routes = [r for r in app.routes if hasattr(r, "path")]
        prefixes = {
            "/".join(r.path.split("/")[:4])
            for r in routes
            if r.path.startswith("/api/")
        }
        _logger.info(
            "API startup complete: %d routes mounted across %d prefixes",
            len(routes),
            len(prefixes),
        )

        # Critical prefixes that must exist for a functional deployment
        critical = [
            "/api/v1/nerve-center",
            "/api/v1/copilot",
            "/api/v1/brain",
            "/api/v1/attack-sim",
            "/api/v1/feeds",
            "/api/v1/evidence",
            "/api/v1/risk",
            "/api/v1/stream",
        ]
        missing = [p for p in critical if p not in prefixes]

        if missing:
            _logger.warning("MISSING CRITICAL PREFIXES: %s", missing)
            if os.getenv("FIXOPS_FAIL_FAST", "").lower() in ("1", "true", "yes"):
                _logger.error("FAIL_FAST enabled — aborting due to missing routes")
                import sys

                sys.exit(1)
        else:
            _logger.info("All %d critical route prefixes verified OK", len(critical))

    # -----------------------------------------------------------------------
    # OpenTelemetry — OTLP exporter + custom spans for critical operations
    # -----------------------------------------------------------------------
    # FastAPIInstrumentor is already applied above (auto-spans for all HTTP
    # requests). Here we:
    #   1. Configure OTLP exporter when OTEL_EXPORTER_OTLP_ENDPOINT is set.
    #   2. Add a middleware that emits dedicated named spans for the three
    #      highest-value operations: Brain Pipeline, AutoFix, and MPTE.
    #
    # The telemetry.configure() call above already wires up TracerProvider +
    # MeterProvider — we only need to attach the custom span middleware here.

    _OTEL_CUSTOM_PATHS: Dict[str, str] = {
        "/api/v1/brain/pipeline/run": "brain_pipeline.run",
        "/api/v1/brain/pipeline": "brain_pipeline.run",
        "/api/v1/autofix/apply": "autofix.apply",
        "/api/v1/autofix/generate": "autofix.generate",
        "/api/v1/autofix": "autofix.operation",
        "/api/v1/mpte/scan": "mpte.scan",
        "/api/v1/mpte/run": "mpte.run",
        "/api/v1/mpte": "mpte.operation",
        "/api/v1/micro-pentest/run": "mpte.micro_pentest",
        "/api/v1/micro-pentest": "mpte.micro_pentest",
    }

    @app.middleware("http")
    async def _otel_custom_span_middleware(request, call_next):
        """
        Emit named OpenTelemetry spans for Brain Pipeline, AutoFix, and MPTE
        operations — enriched with HTTP method, correlation ID, and response
        status so Grafana Tempo / Jaeger can visualise critical code paths.
        """
        try:
            from telemetry import get_tracer
            path = request.url.path
            span_name = None
            for prefix, name in _OTEL_CUSTOM_PATHS.items():
                if path.startswith(prefix):
                    span_name = name
                    break

            if span_name:
                tracer = get_tracer("fixops.operations")
                correlation_id = getattr(request.state, "correlation_id", None)
                with tracer.start_as_current_span(span_name) as span:
                    span.set_attribute("http.method", request.method)
                    span.set_attribute("http.url", str(request.url))
                    span.set_attribute("http.path", path)
                    if correlation_id:
                        span.set_attribute("fixops.correlation_id", str(correlation_id))
                    client_ip = (request.client.host if request.client else "unknown")
                    span.set_attribute("net.peer.ip", client_ip)

                    response = await call_next(request)

                    span.set_attribute("http.status_code", response.status_code)
                    if response.status_code >= 500:
                        span.set_status(
                            # import kept inside try to avoid hard dep
                            __import__(
                                "opentelemetry.trace", fromlist=["StatusCode"]
                            ).StatusCode.ERROR,
                            f"HTTP {response.status_code}",
                        )
                    return response
        except (OSError, ValueError, RuntimeError):  # narrowed from bare Exception
            pass  # OTel must never break request handling

        return await call_next(request)

    # -----------------------------------------------------------------------
    # Gap Router — bridges missing API endpoints for the frontend
    # -----------------------------------------------------------------------
    try:
        from apps.api.gap_router import ALL_GAP_ROUTERS
        for _gap_r in ALL_GAP_ROUTERS:
            app.include_router(_gap_r, dependencies=[Depends(_verify_api_key)])
        _logger.info("Mounted %d gap routers for frontend coverage", len(ALL_GAP_ROUTERS))
    except ImportError as _gap_err:
        _logger.warning("Failed to mount gap routers: %s", _gap_err)

    # -----------------------------------------------------------------------
    # Serve React frontend — prefer aldeci-ui-new, fall back to aldeci
    # -----------------------------------------------------------------------
    _repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
    _ui_dist_new = os.path.join(_repo_root, "suite-ui", "aldeci-ui-new", "dist")
    _ui_dist_legacy = os.path.join(_repo_root, "suite-ui", "aldeci", "dist")
    _ui_dist = _ui_dist_new if os.path.isdir(_ui_dist_new) else _ui_dist_legacy
    if os.path.isdir(_ui_dist):
        from starlette.staticfiles import StaticFiles
        from starlette.responses import FileResponse

        # Serve /assets/* (JS/CSS bundles)
        _assets_dir = os.path.join(_ui_dist, "assets")
        if os.path.isdir(_assets_dir):
            app.mount("/assets", StaticFiles(directory=_assets_dir), name="ui-assets")

        # SPA fallback: any non-API, non-asset path → index.html
        from starlette.responses import JSONResponse as _SpaJsonResp

        @app.get("/{full_path:path}", include_in_schema=False)
        async def _spa_fallback(full_path: str):
            # NEVER serve index.html for API paths — return 404 JSON
            if full_path.startswith("api/"):
                return _SpaJsonResp(
                    {"detail": "Not Found", "path": f"/{full_path}"},
                    status_code=404,
                )
            # If the exact file exists in dist, serve it (e.g., vite.svg, favicon)
            candidate = os.path.join(_ui_dist, full_path)
            if full_path and os.path.isfile(candidate):
                return FileResponse(candidate)
            return FileResponse(os.path.join(_ui_dist, "index.html"))

        _logger.info("Mounted React SPA from %s", _ui_dist)
    else:
        _logger.warning("React UI dist not found at %s — SPA not served", _ui_dist)

    return app


app = create_app()
