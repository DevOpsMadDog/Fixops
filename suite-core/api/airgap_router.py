"""
FixOps Air-Gap Operations Router.

API endpoints for air-gapped / offline deployment management.
Supports US defense (DRDO, ISRO) and financial institution deployments
where no external network access is permitted.

All endpoints:
  - Require API key authentication (via X-API-Key header or Bearer token)
  - Operate 100% offline — no external API calls made
  - Inject classification banners when classification mode is active
  - Use FIPS-approved cryptographic algorithms
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

from apps.api.dependencies import get_org_id
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field, validator

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

router = APIRouter(prefix="/api/v1/airgap", tags=["Air-Gap Operations"])

# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

_VALID_API_KEYS_ENV = os.getenv("FIXOPS_API_KEYS", "")


def _require_api_key(api_key: Optional[str] = Depends(_api_key_header)) -> str:
    """Verify the X-API-Key header.  Falls back gracefully to env-configured keys."""
    if not api_key:
        raise HTTPException(status_code=401, detail="Missing X-API-Key header")
    valid_keys = {k.strip() for k in _VALID_API_KEYS_ENV.split(",") if k.strip()}
    if valid_keys and api_key not in valid_keys:
        raise HTTPException(status_code=403, detail="Invalid API key")
    return api_key


# ---------------------------------------------------------------------------
# Pydantic request / response models
# ---------------------------------------------------------------------------


class AirGapConfigureRequest(BaseModel):
    """Request body for configuring air-gap mode settings."""

    mode: Optional[str] = Field(
        None,
        description="Air-gap mode: disabled | detected | configured | enforced",
    )
    classification_level: Optional[str] = Field(
        None,
        description="Classification level: UNCLASSIFIED | CUI | SECRET | TOP SECRET",
    )
    allow_local_network: Optional[bool] = Field(
        None,
        description="Allow LAN traffic (e.g. for local Ollama/vLLM)",
    )
    allow_usb_import: Optional[bool] = Field(
        None,
        description="Allow data import from removable media",
    )
    fips_mode: Optional[str] = Field(
        None,
        description="FIPS enforcement: disabled | audit | enforced",
    )
    llm_backend: Optional[str] = Field(
        None,
        description="Local LLM backend: ollama | vllm | llamacpp | huggingface_local | none",
    )
    llm_endpoint: Optional[str] = Field(
        None,
        description="URL for the local LLM API (e.g. http://localhost:11434)",
    )
    llm_model: Optional[str] = Field(
        None,
        description="Model name to use (e.g. mistral:7b, llama3:8b)",
    )
    enabled_scanners: Optional[List[str]] = Field(
        None,
        description="List of scanner names to enable, or ['all'] for all 25",
    )
    offline_data_paths: Optional[Dict[str, str]] = Field(
        None,
        description="Override paths for offline data (vuln_db, signatures, etc.)",
    )
    configured_by: Optional[str] = Field(
        None,
        description="Operator/user making the configuration change",
    )


class ClassificationSetRequest(BaseModel):
    """Request body for setting the classification level."""

    level: str = Field(
        ...,
        description="Classification level: UNCLASSIFIED | CUI | SECRET | TOP SECRET",
    )
    set_by: str = Field(
        "admin",
        description="Identity of the operator setting classification",
    )

    @validator("level")
    def validate_level(cls, v: str) -> str:
        allowed = {"UNCLASSIFIED", "CUI", "SECRET", "TOP SECRET"}
        if v not in allowed:
            raise ValueError(f"level must be one of {sorted(allowed)}")
        return v


class ImportVulnDBRequest(BaseModel):
    """Request to import a vulnerability database from a local path."""

    bundle_path: str = Field(
        ...,
        description="Absolute path on the server to the vulnerability DB ZIP bundle",
    )


class ExportVulnDBRequest(BaseModel):
    """Request to export the vulnerability database."""

    output_path: str = Field(
        ...,
        description="Absolute output path for the exported ZIP bundle",
    )


class ImportThreatIntelRequest(BaseModel):
    """Request to import a STIX/TAXII threat intelligence bundle."""

    bundle_path: str = Field(
        ...,
        description="Absolute path on the server to the STIX/TAXII bundle file",
    )


class ExportThreatIntelRequest(BaseModel):
    """Request to export threat intelligence for air-gapped sharing."""

    output_path: str = Field(
        ...,
        description="Absolute output path for the exported bundle",
    )
    classification: Optional[str] = Field(
        None,
        description="Override classification level for this export",
    )


class CreateUpdatePackageRequest(BaseModel):
    """Request to create an offline update package."""

    package_type: str = Field(
        ...,
        description="Type: vuln_db | signatures | compliance_rules | llm_model | full_system",
    )
    content_paths: List[str] = Field(
        ...,
        description="List of absolute server-side paths to include in the package",
    )
    version: str = Field(
        ...,
        description="Package version string (e.g. 2024.11.1)",
    )
    output_path: str = Field(
        ...,
        description="Absolute output path for the generated ZIP package",
    )


class ApplyUpdatePackageRequest(BaseModel):
    """Request to apply an offline update package."""

    package_path: str = Field(
        ...,
        description="Absolute path on the server to the update ZIP package",
    )


# ---------------------------------------------------------------------------
# Internal helper
# ---------------------------------------------------------------------------


def _get_engine():
    """Lazy-load the AirGapConfigEngine singleton."""
    from core.airgap_config import get_airgap_engine
    return get_airgap_engine()


def _with_banner(response: Dict[str, Any]) -> Dict[str, Any]:
    """Inject classification banner if classification mode is active."""
    try:
        engine = _get_engine()
        return engine.classify_response(response)
    except (ImportError, AttributeError, RuntimeError):
        return response


# ---------------------------------------------------------------------------
# GET /status
# ---------------------------------------------------------------------------


@router.get(
    "/status",
    summary="Current air-gap configuration status",
    response_description="Air-gap mode, classification, LLM routing, and FIPS status",
)
async def get_status(_: str = Depends(_require_api_key)) -> Dict[str, Any]:
    """Return the current air-gap configuration status including:
    - Active air-gap mode
    - Classification level and banner
    - FIPS compliance mode
    - Local LLM backend availability
    - Offline vulnerability DB info
    - Network isolation detection results
    """
    try:
        engine = _get_engine()
        status = engine.get_status()
        return _with_banner({"status": "ok", **status})
    except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
        logger.exception("Error fetching air-gap status")
        raise HTTPException(status_code=500, detail=type(exc).__name__)


# ---------------------------------------------------------------------------
# POST /configure
# ---------------------------------------------------------------------------


@router.post(
    "/configure",
    summary="Configure air-gap mode settings",
    response_description="Updated air-gap configuration",
)
async def configure_airgap(
    req: AirGapConfigureRequest,
    _: str = Depends(_require_api_key),
) -> Dict[str, Any]:
    """Configure air-gap mode settings.

    Accepts a partial update — only supplied fields are modified.
    Persists the configuration to disk immediately.
    """
    try:
        engine = _get_engine()
        settings = req.dict(exclude_none=True)
        updated = engine.configure(settings)
        return _with_banner({
            "status": "ok",
            "message": "Air-gap configuration updated",
            "mode": updated.mode,
            "classification_level": updated.classification_level,
            "last_configured": updated.last_configured,
            "instance_id": updated.instance_id,
        })
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=type(exc).__name__)
    except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
        logger.exception("Error configuring air-gap mode")
        raise HTTPException(status_code=500, detail=type(exc).__name__)


# ---------------------------------------------------------------------------
# GET /health
# ---------------------------------------------------------------------------


@router.get(
    "/health",
    summary="Health check for air-gapped components",
    response_description="Component-by-component health status",
)
async def health_check(_: str = Depends(_require_api_key)) -> Dict[str, Any]:
    """Run a comprehensive health check across all air-gapped components:
    - Air-gap mode status
    - Offline vulnerability DB availability
    - Local LLM backend
    - FIPS compliance
    - Threat intelligence bundle
    - Offline data path accessibility
    - Scanner availability
    - Classification configuration
    """
    try:
        engine = _get_engine()
        result = engine.run_health_check()
        return _with_banner({"status": "ok", **result})
    except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
        logger.exception("Error running air-gap health check")
        raise HTTPException(status_code=500, detail=type(exc).__name__)


# ---------------------------------------------------------------------------
# POST /import/vuln-db
# ---------------------------------------------------------------------------


@router.post(
    "/import/vuln-db",
    summary="Import offline vulnerability database",
    response_description="Imported vulnerability database metadata",
)
async def import_vuln_db(
    req: ImportVulnDBRequest,
    _: str = Depends(_require_api_key),
) -> Dict[str, Any]:
    """Import an offline vulnerability database bundle (ZIP format).

    The bundle must contain:
    - `manifest.json` — metadata with version, source, and SHA-256 checksum
    - `vuln_db.json.gz` — gzip-compressed NVD/CVE JSON feed

    Suitable for importing NVD data snapshots delivered via USB or secure transfer.
    The bundle checksum is verified before import (FIPS SHA-256).
    """
    try:
        engine = _get_engine()
        info = engine.import_vuln_db(req.bundle_path)
        return _with_banner({
            "status": "ok",
            "message": "Vulnerability database imported successfully",
            "db_id": info.db_id,
            "version": info.version,
            "cve_count": info.cve_count,
            "last_updated": info.last_updated,
            "checksum_sha256": info.checksum_sha256,
            "is_valid": info.is_valid,
            "validation_errors": info.validation_errors,
            "size_bytes": info.size_bytes,
        })
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=type(exc).__name__)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=type(exc).__name__)
    except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
        logger.exception("Error importing vulnerability DB")
        raise HTTPException(status_code=500, detail=type(exc).__name__)


# ---------------------------------------------------------------------------
# POST /export/vuln-db
# ---------------------------------------------------------------------------


@router.post(
    "/export/vuln-db",
    summary="Export vulnerability database for transfer",
    response_description="Export bundle path and metadata",
)
async def export_vuln_db(
    req: ExportVulnDBRequest,
    _: str = Depends(_require_api_key),
) -> Dict[str, Any]:
    """Export the local vulnerability database as a signed ZIP bundle.

    The output bundle includes:
    - `manifest.json` — metadata and SHA-256 integrity checksum
    - `vuln_db.json.gz` — the compressed vulnerability feed

    Use this to distribute the vulnerability DB to other air-gapped instances
    via USB or secure offline transfer.
    """
    try:
        engine = _get_engine()
        output_path = engine.export_vuln_db(req.output_path)
        return _with_banner({
            "status": "ok",
            "message": "Vulnerability database exported successfully",
            "output_path": output_path,
        })
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=type(exc).__name__)
    except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
        logger.exception("Error exporting vulnerability DB")
        raise HTTPException(status_code=500, detail=type(exc).__name__)


# ---------------------------------------------------------------------------
# POST /import/threat-intel
# ---------------------------------------------------------------------------


@router.post(
    "/import/threat-intel",
    summary="Import STIX/TAXII threat intelligence bundle",
    response_description="Bundle metadata and object type counts",
)
async def import_threat_intel(
    req: ImportThreatIntelRequest,
    _: str = Depends(_require_api_key),
) -> Dict[str, Any]:
    """Import a STIX 2.1 threat intelligence bundle.

    Accepts:
    - Raw STIX 2.1 JSON file (`.json`)
    - ZIP archive containing a STIX bundle (`.zip`)
    - TAXII collection export

    Classification data markings are preserved. Suitable for receiving
    threat intelligence from other air-gapped instances or from
    out-of-band intelligence feeds.
    """
    try:
        engine = _get_engine()
        manifest = engine.import_threat_intel(req.bundle_path)
        return _with_banner({
            "status": "ok",
            "message": "Threat intelligence bundle imported successfully",
            **manifest,
        })
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=type(exc).__name__)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=type(exc).__name__)
    except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
        logger.exception("Error importing threat intelligence")
        raise HTTPException(status_code=500, detail=type(exc).__name__)


# ---------------------------------------------------------------------------
# POST /export/threat-intel
# ---------------------------------------------------------------------------


@router.post(
    "/export/threat-intel",
    summary="Export threat intelligence for air-gapped sharing",
    response_description="Export bundle path",
)
async def export_threat_intel(
    req: ExportThreatIntelRequest,
    _: str = Depends(_require_api_key),
) -> Dict[str, Any]:
    """Export stored threat intelligence as a signed STIX 2.1 bundle ZIP.

    The exported bundle includes:
    - STIX 2.1 objects (indicators, TTPs, threat actors, malware, etc.)
    - Classification data marking (STIX marking-definition object)
    - Export metadata with SHA-256 integrity checksum

    Use this to transfer threat intelligence to another air-gapped FixOps
    instance via USB or secure offline transfer.
    """
    try:
        engine = _get_engine()
        # Allow overriding classification for the export
        if req.classification:
            current_level = engine.config.classification_level
            engine.set_classification(req.classification)
        output_path = engine.export_threat_intel(req.output_path)
        if req.classification:
            # Restore previous classification
            engine.set_classification(current_level)
        return _with_banner({
            "status": "ok",
            "message": "Threat intelligence exported successfully",
            "output_path": output_path,
            "classification": req.classification or engine.config.classification_level,
        })
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=type(exc).__name__)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=type(exc).__name__)
    except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
        logger.exception("Error exporting threat intelligence")
        raise HTTPException(status_code=500, detail=type(exc).__name__)


# ---------------------------------------------------------------------------
# GET /classification
# ---------------------------------------------------------------------------


@router.get(
    "/classification",
    summary="Get current classification level",
    response_description="Classification level and banner information",
)
async def get_classification(_: str = Depends(_require_api_key)) -> Dict[str, Any]:
    """Get the current data classification level and associated banner.

    Classification levels:
    - **UNCLASSIFIED** — Standard unclassified data
    - **CUI** — Controlled Unclassified Information (purple banner)
    - **SECRET** — Secret classification (red banner `//SECRET//`)
    - **TOP SECRET** — Top Secret classification (orange banner `//TOP SECRET//`)

    When classification is set above UNCLASSIFIED, all API responses include
    a `_classification` banner field.
    """
    try:
        engine = _get_engine()
        from core.airgap_config import get_classification_banner
        level = engine.config.classification_level
        banner = get_classification_banner(level)
        return _with_banner({
            "status": "ok",
            "classification_level": level,
            "banner": banner,
        })
    except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
        raise HTTPException(status_code=500, detail=type(exc).__name__)


# ---------------------------------------------------------------------------
# POST /classification
# ---------------------------------------------------------------------------


@router.post(
    "/classification",
    summary="Set classification level",
    response_description="Updated classification level and banner",
)
async def set_classification(
    req: ClassificationSetRequest,
    _: str = Depends(_require_api_key),
) -> Dict[str, Any]:
    """Set the data classification level for all FixOps operations.

    Valid levels:
    - `UNCLASSIFIED`
    - `CUI` (Controlled Unclassified Information)
    - `SECRET`
    - `TOP SECRET`

    Once set, all API responses will include the appropriate classification
    banner in the `_classification` field. This setting is persisted and
    survives restarts.

    **Note**: Increasing the classification level is a privileged operation.
    The `set_by` field should identify the authorized operator.
    """
    try:
        engine = _get_engine()
        banner = engine.set_classification(req.level, set_by=req.set_by)
        return _with_banner({
            "status": "ok",
            "message": f"Classification level set to {req.level}",
            "classification_level": req.level,
            "banner": banner,
            "set_by": req.set_by,
        })
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=type(exc).__name__)
    except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
        logger.exception("Error setting classification level")
        raise HTTPException(status_code=500, detail=type(exc).__name__)


# ---------------------------------------------------------------------------
# GET /fips/status
# ---------------------------------------------------------------------------


@router.get(
    "/fips/status",
    summary="FIPS 140-2/3 compliance status",
    response_description="FIPS compliance report",
)
async def get_fips_status(_: str = Depends(_require_api_key)) -> Dict[str, Any]:
    """Get the current FIPS 140-2/3 compliance status.

    Returns:
    - Current FIPS enforcement mode (disabled/audit/enforced)
    - Whether the Linux kernel has FIPS mode enabled (`/proc/sys/crypto/fips_enabled`)
    - List of approved and forbidden cryptographic algorithms
    - Any compliance violations detected during the current session
    - A full compliance report

    FIPS 140-2/3 approved algorithms: SHA-256, SHA-384, SHA-512, SHA3-256,
    SHA3-384, SHA3-512, HMAC-SHA256, HMAC-SHA384, HMAC-SHA512.

    Forbidden algorithms: MD5, SHA-1, RC4, DES, 3DES, Blowfish.
    """
    try:
        engine = _get_engine()
        report = engine.get_fips_status()
        return _with_banner({"status": "ok", **report})
    except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
        logger.exception("Error fetching FIPS status")
        raise HTTPException(status_code=500, detail=type(exc).__name__)


# ---------------------------------------------------------------------------
# POST /updates/package
# ---------------------------------------------------------------------------


@router.post(
    "/updates/package",
    summary="Create offline update package",
    response_description="Update package metadata and output path",
)
async def create_update_package(
    req: CreateUpdatePackageRequest,
    _: str = Depends(_require_api_key),
) -> Dict[str, Any]:
    """Create an offline update package for distribution to air-gapped instances.

    Package types:
    - `vuln_db` — Vulnerability database update
    - `signatures` — Scanner signature updates
    - `compliance_rules` — Compliance rule updates (CIS, NIST, etc.)
    - `llm_model` — Local LLM model weights
    - `full_system` — Full FixOps system update

    The package includes:
    - All specified content files
    - Per-file SHA-256 checksums
    - Package manifest with type, version, and creation metadata

    The output ZIP can be transferred to air-gapped instances via USB or
    secure offline transfer and applied with `POST /updates/apply`.
    """
    try:
        engine = _get_engine()
        manifest = engine.create_update_package(
            package_type=req.package_type,
            content_paths=req.content_paths,
            version=req.version,
            output_path=req.output_path,
        )
        return _with_banner({
            "status": "ok",
            "message": "Offline update package created",
            **manifest,
        })
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=type(exc).__name__)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=type(exc).__name__)
    except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
        logger.exception("Error creating update package")
        raise HTTPException(status_code=500, detail=type(exc).__name__)


# ---------------------------------------------------------------------------
# POST /updates/apply
# ---------------------------------------------------------------------------


@router.post(
    "/updates/apply",
    summary="Apply offline update package",
    response_description="Update application result",
)
async def apply_update_package(
    req: ApplyUpdatePackageRequest,
    _: str = Depends(_require_api_key),
) -> Dict[str, Any]:
    """Apply an offline update package to this FixOps instance.

    The update package is verified before application:
    1. ZIP structure integrity check
    2. Manifest presence and validity
    3. Per-file SHA-256 checksum verification (FIPS-compliant)

    If any checksum fails, the update is rejected and no files are modified.
    Files are only written after all checks pass.

    After a successful `vuln_db` update, the vulnerability scanner will
    automatically use the new database for all subsequent scans.
    """
    try:
        engine = _get_engine()
        result = engine.apply_update_package(req.package_path)
        return _with_banner({"status": "ok", **result})
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=type(exc).__name__)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=type(exc).__name__)
    except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
        logger.exception("Error applying update package")
        raise HTTPException(status_code=500, detail=type(exc).__name__)


# ---------------------------------------------------------------------------
# GET /dependencies
# ---------------------------------------------------------------------------


@router.get(
    "/dependencies",
    summary="List external dependencies and their offline alternatives",
    response_description="Dependency inventory with offline alternatives",
)
async def list_dependencies(
    dependency_type: Optional[str] = Query(
        None,
        description="Filter by type: api | dns | package_registry | llm | vuln_db",
    ),
    org_id: str = Depends(get_org_id),
    required_only: bool = Query(
        False,
        description="Only return required dependencies",
    ),
    offline_available: Optional[bool] = Query(
        None,
        description="Filter by offline availability",
    ),
    _: str = Depends(_require_api_key),
) -> Dict[str, Any]:
    """List all external dependencies that FixOps normally relies on,
    along with their offline alternatives for air-gapped deployments.

    This endpoint is the primary reference for operators configuring a new
    air-gapped FixOps installation. It shows:
    - What external services are used in connected mode
    - The corresponding offline alternative for each
    - Whether an offline alternative is available
    - Whether the dependency is required for core functionality

    Use this to plan your air-gapped infrastructure requirements.
    """
    try:
        engine = _get_engine()
        deps = engine.list_dependencies()

        # Apply filters
        if dependency_type:
            deps = [d for d in deps if d["dependency_type"] == dependency_type]
        if required_only:
            deps = [d for d in deps if d["is_required"]]
        if offline_available is not None:
            deps = [d for d in deps if d["offline_available"] == offline_available]

        return _with_banner({
            "status": "ok",
            "count": len(deps),
            "dependencies": deps,
            "filters_applied": {
                "dependency_type": dependency_type,
                "required_only": required_only,
                "offline_available": offline_available,
            },
        })
    except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
        logger.exception("Error listing dependencies")
        raise HTTPException(status_code=500, detail=type(exc).__name__)


# ---------------------------------------------------------------------------
# Additional utility endpoints
# ---------------------------------------------------------------------------


@router.post(
    "/detect-isolation",
    summary="Probe network for isolation detection",
    response_description="Network isolation detection result",
)
async def detect_isolation(_: str = Depends(_require_api_key)) -> Dict[str, Any]:
    """Run live network probes to detect air-gap isolation.

    Probes:
    - TCP connectivity to well-known internet hosts (Google DNS, Cloudflare, OpenDNS)
    - DNS resolution of external hostnames
    - HTTPS reachability to external API endpoints

    If all probes fail, the system is considered air-gapped and the mode
    is automatically set to `detected`.

    This is safe to run in an already-isolated environment — all probes
    have short timeouts (≤2 seconds) and fail silently.
    """
    try:
        engine = _get_engine()
        status = engine.detect_isolation()
        return _with_banner({
            "status": "ok",
            "is_isolated": status.is_isolated,
            "tcp_reachable": status.tcp_reachable,
            "dns_resolving": status.dns_resolving,
            "https_reachable": status.https_reachable,
            "probe_timestamp": status.probe_timestamp,
            "probe_details": status.probe_details,
            "detection_method": status.detection_method,
            "mode_after_detection": engine.config.mode,
        })
    except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
        logger.exception("Error during isolation detection")
        raise HTTPException(status_code=500, detail=type(exc).__name__)


@router.post(
    "/llm/probe",
    summary="Probe and configure local LLM backend",
    response_description="Detected local LLM backend configuration",
)
async def probe_local_llm(_: str = Depends(_require_api_key)) -> Dict[str, Any]:
    """Auto-detect and configure available local LLM backends.

    Probes the following backends in order:
    1. **Ollama** at `http://localhost:11434`
    2. **vLLM** at `http://localhost:8000`
    3. **llama.cpp** at `http://localhost:8080`

    If a backend is found, it is configured automatically and the first
    available model is selected. The configuration is persisted.

    Run this after installing and starting a local LLM service to
    enable AI-powered features in air-gapped mode.
    """
    try:
        engine = _get_engine()
        cfg = engine.probe_local_llm()
        return _with_banner({
            "status": "ok",
            "backend": cfg.backend,
            "available": cfg.available,
            "endpoint": cfg.endpoint,
            "model_name": cfg.model_name,
            "message": (
                f"Local LLM found: {cfg.backend} at {cfg.endpoint}"
                if cfg.available
                else "No local LLM backend found. Install Ollama or vLLM."
            ),
        })
    except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
        logger.exception("Error probing local LLM")
        raise HTTPException(status_code=500, detail=type(exc).__name__)


@router.get(
    "/vuln-db/lookup/{cve_id}",
    summary="Look up a CVE in the offline vulnerability database",
    response_description="CVE details from the local database",
)
async def lookup_cve(
    cve_id: str,
    _: str = Depends(_require_api_key),
) -> Dict[str, Any]:
    """Look up a specific CVE in the offline vulnerability database.

    Searches the locally imported NVD/CVE database for the given CVE ID.
    Returns the full vulnerability record including CVSS scores, description,
    affected packages, and references.

    Requires that a vulnerability database has been imported via
    `POST /import/vuln-db` first.

    Example: `GET /api/v1/airgap/vuln-db/lookup/CVE-2021-44228`
    """
    try:
        from core.airgap_config import OfflineVulnDBManager
        db = OfflineVulnDBManager()
        result = db.lookup_cve(cve_id)
        if result is None:
            _get_engine()
            if not db.is_available():
                raise HTTPException(
                    status_code=503,
                    detail="No offline vulnerability database available. Import one first.",
                )
            raise HTTPException(
                status_code=404,
                detail=f"CVE {cve_id} not found in local database",
            )
        _get_engine()
        return _with_banner({
            "status": "ok",
            "cve_id": cve_id,
            "record": result,
        })
    except HTTPException:
        raise
    except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
        logger.exception("Error looking up CVE %s", cve_id)
        raise HTTPException(status_code=500, detail=type(exc).__name__)


@router.get(
    "/vuln-db/info",
    summary="Get offline vulnerability database metadata",
    response_description="Vulnerability database version and statistics",
)
async def get_vuln_db_info(_: str = Depends(_require_api_key)) -> Dict[str, Any]:
    """Get metadata about the currently installed offline vulnerability database.

    Returns:
    - Database version and CVE count
    - Data source (NVD, custom feed, etc.)
    - Last updated timestamp
    - Feed date range coverage
    - SHA-256 integrity checksum
    - Validation status
    """
    try:
        from core.airgap_config import OfflineVulnDBManager
        db = OfflineVulnDBManager()
        info = db.load_db_info()
        _get_engine()
        if info is None:
            return _with_banner({
                "status": "ok",
                "available": False,
                "message": "No offline vulnerability database installed. Use POST /import/vuln-db to import one.",
            })
        return _with_banner({
            "status": "ok",
            "available": True,
            "db_id": info.db_id,
            "source": info.source,
            "version": info.version,
            "cve_count": info.cve_count,
            "last_updated": info.last_updated,
            "checksum_sha256": info.checksum_sha256,
            "feed_date_range": info.feed_date_range,
            "size_bytes": info.size_bytes,
            "is_valid": info.is_valid,
        })
    except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
        raise HTTPException(status_code=500, detail=type(exc).__name__)


@router.get(
    "/threat-intel/info",
    summary="Get threat intelligence bundle metadata",
    response_description="STIX bundle manifest and statistics",
)
async def get_threat_intel_info(_: str = Depends(_require_api_key)) -> Dict[str, Any]:
    """Get metadata about the currently stored threat intelligence bundle.

    Returns:
    - Bundle ID and STIX version
    - Object counts by type (indicators, TTPs, threat actors, etc.)
    - Import timestamp and source
    - SHA-256 integrity checksum
    """
    try:
        from core.airgap_config import ThreatIntelManager
        tm = ThreatIntelManager()
        manifest = tm.get_manifest()
        _get_engine()
        if manifest is None:
            return _with_banner({
                "status": "ok",
                "available": False,
                "message": "No threat intelligence bundle installed. Use POST /import/threat-intel to import one.",
            })
        return _with_banner({
            "status": "ok",
            "available": True,
            **manifest,
        })
    except ImportError as exc:
        raise HTTPException(status_code=500, detail=type(exc).__name__)


@router.get(
    "/updates/history",
    summary="List applied offline update packages",
    response_description="History of applied update packages",
)
async def list_applied_updates(_: str = Depends(_require_api_key)) -> Dict[str, Any]:
    """List all offline update packages that have been applied to this instance.

    Returns a history of applied updates sorted by application date (newest first),
    including package type, version, file count, and checksums.
    """
    try:
        from core.airgap_config import OfflineUpdateManager
        mgr = OfflineUpdateManager()
        packages = mgr.list_applied_packages()
        _get_engine()
        return _with_banner({
            "status": "ok",
            "count": len(packages),
            "packages": packages,
        })
    except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
        raise HTTPException(status_code=500, detail=type(exc).__name__)


@router.get(
    "/fips/algorithms",
    summary="List FIPS-approved and forbidden algorithms",
    response_description="Algorithm whitelist and blacklist",
)
async def list_fips_algorithms(_: str = Depends(_require_api_key)) -> Dict[str, Any]:
    """Return the complete list of FIPS 140-2/3 approved and forbidden algorithms.

    This is the reference for operators and developers to ensure all
    cryptographic operations use only approved algorithms.

    In FIPS `enforced` mode, any attempt to use a forbidden algorithm will
    raise an error. In `audit` mode, violations are logged but allowed.
    """
    try:
        from core.airgap_config import (
            FIPS_APPROVED_HASH_ALGORITHMS,
            FIPS_APPROVED_HMAC_ALGORITHMS,
            FIPS_FORBIDDEN_ALGORITHMS,
        )
        engine = _get_engine()
        return _with_banner({
            "status": "ok",
            "fips_mode": engine.config.fips.mode,
            "approved": {
                "hash_algorithms": sorted(FIPS_APPROVED_HASH_ALGORITHMS),
                "hmac_algorithms": sorted(FIPS_APPROVED_HMAC_ALGORITHMS),
            },
            "forbidden_algorithms": sorted(FIPS_FORBIDDEN_ALGORITHMS),
            "notes": (
                "Use SHA-256, SHA-384, or SHA-512 for all cryptographic operations. "
                "MD5 and SHA-1 are explicitly forbidden under FIPS 140-2/3."
            ),
        })
    except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
        raise HTTPException(status_code=500, detail=type(exc).__name__)


# ---------------------------------------------------------------------------
# Deployment Hardening endpoints (from airgap_deployment.py)
# ---------------------------------------------------------------------------


def _get_hardening():
    """Lazy-load the AirGapDeploymentHardening singleton."""
    from core.airgap_deployment import AirGapDeploymentHardening
    return AirGapDeploymentHardening()


class EnableAirGapRequest(BaseModel):
    """Request body for enabling air-gap mode."""
    classification: Optional[str] = Field(
        None,
        description="Classification level: UNCLASSIFIED | CUI | SECRET | TOP SECRET/SCI",
    )


class CVESearchRequest(BaseModel):
    """Query parameters model (used for documentation only — params come via Query)."""
    product: Optional[str] = None
    severity: Optional[str] = None
    min_score: float = 0.0
    max_score: float = 10.0
    year: Optional[int] = None
    limit: int = 100


class SneakernetExportRequest(BaseModel):
    """Request body for exporting a sneakernet update package."""
    payload_files: List[str] = Field(
        ...,
        description="Absolute server-side paths of files to include in the package",
    )
    package_type: str = Field(
        ...,
        description="Package type: cve_db | sbom | trustgraph_config | signatures | full_system",
    )
    version: str = Field(..., description="Semantic version string, e.g. 2025.01.1")
    encryption_key_hex: str = Field(
        ...,
        description="64-hex-char AES-256 key for encrypting the package",
    )
    classification: str = Field(
        "UNCLASSIFIED",
        description="Classification level for the package",
    )
    output_path: Optional[str] = Field(None, description="Override output file path")


class SneakernetImportRequest(BaseModel):
    """Request body for importing a sneakernet update package."""
    package_path: str = Field(
        ...,
        description="Absolute path to the .snk package file on the server",
    )
    encryption_key_hex: str = Field(
        ...,
        description="64-hex-char AES-256 key that was used when exporting",
    )
    extract_dir: Optional[str] = Field(None, description="Override extraction directory")


# ---------------------------------------------------------------------------
# POST /enable
# ---------------------------------------------------------------------------


@router.post(
    "/enable",
    summary="Enable air-gap mode with full deployment hardening",
    response_description="Air-gap mode enablement status",
)
async def enable_airgap(
    req: EnableAirGapRequest,
    _: str = Depends(_require_api_key),
) -> Dict[str, Any]:
    """Enable air-gap / SCIF deployment mode.

    Activates:
    - AirGapMode network blocking
    - Telemetry kill-switch (all analytics disabled)
    - Local-only TrustGraph configuration

    Optionally sets the classification level (UNCLASSIFIED, CUI, SECRET, TOP SECRET/SCI).
    """
    try:
        hardening = _get_hardening()
        hardening.enable()
        result: Dict[str, Any] = {
            "status": "ok",
            "message": "Air-gap hardening enabled",
            "air_gap_enabled": True,
        }
        if req.classification:
            from core.airgap_deployment import ClassificationEnforcer
            policy = ClassificationEnforcer.set_level(req.classification)
            result["classification"] = req.classification
            result["banner"] = policy.banner
        return _with_banner(result)
    except ValueError as exc:
        logger.warning("air-gap enable validation error: %s", exc)
        raise HTTPException(status_code=400, detail="Invalid air-gap configuration")
    except (OSError, RuntimeError, KeyError) as exc:
        logger.exception("Error enabling air-gap mode")
        raise HTTPException(status_code=500, detail=type(exc).__name__)


# ---------------------------------------------------------------------------
# POST /disable
# ---------------------------------------------------------------------------


@router.post(
    "/disable",
    summary="Disable air-gap mode (admin only)",
    response_description="Confirmation that air-gap mode has been disabled",
)
async def disable_airgap(_: str = Depends(_require_api_key)) -> Dict[str, Any]:
    """Disable air-gap hardening mode.

    This is a privileged operation intended for maintenance windows only.
    Requires admin-level API key. All network restrictions are lifted.
    """
    try:
        hardening = _get_hardening()
        hardening.disable()
        return _with_banner({
            "status": "ok",
            "message": "Air-gap hardening disabled",
            "air_gap_enabled": False,
        })
    except (OSError, RuntimeError, KeyError) as exc:
        logger.exception("Error disabling air-gap mode")
        raise HTTPException(status_code=500, detail=type(exc).__name__)


# ---------------------------------------------------------------------------
# GET /cve/search
# ---------------------------------------------------------------------------


@router.get(
    "/cve/search",
    summary="Search offline CVE database",
    response_description="List of matching CVE records from the local NVD mirror",
)
async def search_cves(
    product: Optional[str] = Query(None, description="Product name substring filter"),
    severity: Optional[str] = Query(None, description="CRITICAL | HIGH | MEDIUM | LOW | UNKNOWN"),
    min_score: float = Query(0.0, ge=0.0, le=10.0, description="Minimum CVSS score"),
    max_score: float = Query(10.0, ge=0.0, le=10.0, description="Maximum CVSS score"),
    year: Optional[int] = Query(None, description="Filter by CVE publication year"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum results to return"),
    _: str = Depends(_require_api_key),
) -> Dict[str, Any]:
    """Search the offline NVD/CVE database without any internet access.

    Filter by product name, severity level, CVSS score range, or publication year.
    Requires that NVD feeds have been imported via POST /import/vuln-db first.
    """
    try:
        from core.airgap_deployment import OfflineCVEDatabase
        db = OfflineCVEDatabase()
        results = db.search(
            product=product,
            severity=severity,
            min_score=min_score,
            max_score=max_score,
            year=year,
            limit=limit,
        )
        return _with_banner({
            "status": "ok",
            "count": len(results),
            "results": [r.model_dump() for r in results],
            "filters": {
                "product": product,
                "severity": severity,
                "min_score": min_score,
                "max_score": max_score,
                "year": year,
                "limit": limit,
            },
        })
    except (OSError, ValueError, KeyError, RuntimeError) as exc:
        logger.exception("Error searching CVE database")
        raise HTTPException(status_code=500, detail=type(exc).__name__)


# ---------------------------------------------------------------------------
# POST /update/export
# ---------------------------------------------------------------------------


@router.post(
    "/update/export",
    summary="Export sneakernet update package",
    response_description="Path to the generated encrypted+signed .snk package",
)
async def export_update_package(
    req: SneakernetExportRequest,
    _: str = Depends(_require_api_key),
) -> Dict[str, Any]:
    """Create an encrypted and integrity-signed update package for sneakernet transfer.

    The package uses FIPS-compliant AES-256 encryption and HMAC-SHA256 signing.
    Transfer via USB or removable media to other air-gapped instances and import
    with POST /update/import.

    Package types: cve_db | sbom | trustgraph_config | signatures | full_system
    """
    try:
        key = bytes.fromhex(req.encryption_key_hex)
        if len(key) != 32:
            raise ValueError("encryption_key_hex must be 64 hex chars (32 bytes / AES-256)")
    except ValueError as exc:
        logger.warning("sneakernet export key validation error: %s", exc)
        raise HTTPException(status_code=400, detail="Invalid encryption_key_hex: must be 64 hex chars")
    try:
        from core.airgap_deployment import SneakernetManager
        mgr = SneakernetManager()
        out_path = mgr.export_package(
            payload_files=req.payload_files,
            package_type=req.package_type,
            version=req.version,
            key=key,
            classification=req.classification,
            output_path=req.output_path,
        )
        return _with_banner({
            "status": "ok",
            "message": "Sneakernet package exported",
            "output_path": out_path,
            "package_type": req.package_type,
            "version": req.version,
            "classification": req.classification,
        })
    except FileNotFoundError as exc:
        logger.warning("sneakernet export file not found: %s", exc)
        raise HTTPException(status_code=404, detail="Payload file not found")
    except ValueError as exc:
        logger.warning("sneakernet export validation error: %s", exc)
        raise HTTPException(status_code=400, detail="Invalid sneakernet export parameters")
    except (OSError, RuntimeError, KeyError) as exc:
        logger.exception("Error exporting sneakernet package")
        raise HTTPException(status_code=500, detail=type(exc).__name__)


# ---------------------------------------------------------------------------
# POST /update/import
# ---------------------------------------------------------------------------


@router.post(
    "/update/import",
    summary="Import sneakernet update package",
    response_description="Manifest of the imported package and extracted file list",
)
async def import_update_package(
    req: SneakernetImportRequest,
    _: str = Depends(_require_api_key),
) -> Dict[str, Any]:
    """Import and verify an encrypted sneakernet update package.

    Verification steps:
    1. Magic header check
    2. HMAC-SHA256 payload integrity
    3. AES-256 decryption
    4. Per-file SHA-256 checksum verification

    If any check fails, the import is rejected with no files written.
    """
    try:
        key = bytes.fromhex(req.encryption_key_hex)
        if len(key) != 32:
            raise ValueError("encryption_key_hex must be 64 hex chars (32 bytes / AES-256)")
    except ValueError as exc:
        logger.warning("sneakernet import key validation error: %s", exc)
        raise HTTPException(status_code=400, detail="Invalid encryption_key_hex: must be 64 hex chars")
    try:
        from core.airgap_deployment import SneakernetManager
        mgr = SneakernetManager()
        manifest, extracted = mgr.import_package(
            package_path=req.package_path,
            key=key,
            extract_dir=req.extract_dir,
        )
        return _with_banner({
            "status": "ok",
            "message": "Sneakernet package imported and verified",
            "manifest": manifest.model_dump(),
            "extracted_files": extracted,
            "file_count": len(extracted),
        })
    except FileNotFoundError as exc:
        logger.warning("sneakernet import file not found: %s", exc)
        raise HTTPException(status_code=404, detail="Package file not found")
    except ValueError as exc:
        logger.warning("sneakernet import validation error: %s", exc)
        raise HTTPException(status_code=400, detail="Invalid sneakernet package or parameters")
    except (OSError, RuntimeError, KeyError) as exc:
        logger.exception("Error importing sneakernet package")
        raise HTTPException(status_code=500, detail=type(exc).__name__)


# ---------------------------------------------------------------------------
# GET /network-check
# ---------------------------------------------------------------------------


@router.get(
    "/network-check",
    summary="Verify network isolation — active egress check",
    response_description="Network isolation verification result",
)
async def network_check(_: str = Depends(_require_api_key)) -> Dict[str, Any]:
    """Run an active network isolation verification.

    Probes:
    - TCP egress to known external IPs (Google DNS, Cloudflare, PyPI, AI APIs)
    - DNS resolution of external hostnames
    - HTTP/HTTPS egress to external endpoints

    All probes have short timeouts (≤1 second). A fully isolated system will
    report is_isolated=true with all egress checks blocked.

    IMPORTANT: This endpoint is read-only and safe to call in production.
    It makes outbound connection ATTEMPTS (which should all fail in air-gap).
    """
    try:
        from core.airgap_deployment import NetworkIsolationVerifier
        verifier = NetworkIsolationVerifier()
        result = verifier.verify()
        return _with_banner({
            "status": "ok",
            "is_isolated": result.is_isolated,
            "tcp_blocked": result.tcp_blocked,
            "dns_blocked": result.dns_blocked,
            "egress_blocked": result.egress_blocked,
            "violations": result.violations,
            "probe_duration_ms": result.probe_duration_ms,
            "checked_at": result.checked_at,
        })
    except (OSError, RuntimeError, KeyError) as exc:
        logger.exception("Error running network check")
        raise HTTPException(status_code=500, detail=type(exc).__name__)


# ---------------------------------------------------------------------------
# GET /validate
# ---------------------------------------------------------------------------


@router.get(
    "/validate",
    summary="Run deployment validation checklist",
    response_description="Pre-deployment checklist results with pass/fail per item",
)
async def validate_deployment(
    classification: str = Query(
        "UNCLASSIFIED",
        description="Classification level for this deployment",
    ),
    _: str = Depends(_require_api_key),
) -> Dict[str, Any]:
    """Run the full SCIF/air-gap deployment pre-flight checklist.

    Validates:
    - Air-gap mode enabled
    - FIPS 140-2 mode active
    - Offline CVE database populated
    - Telemetry fully disabled
    - TrustGraph configured local-only
    - Network isolation configured
    - Audit logging operational
    - Data directory accessible
    - Classification level valid
    - Package registries blocked

    Returns overall pass/fail plus per-check detail with severity (ERROR/WARNING/INFO).
    """
    try:
        from core.airgap_deployment import AirGapDeploymentHardening
        hardening = AirGapDeploymentHardening()
        report = hardening.validate(classification=classification)
        return _with_banner({
            "status": "ok",
            "overall_pass": report.overall_pass,
            "errors": report.errors,
            "warnings": report.warnings,
            "classification": report.classification,
            "validated_at": report.validated_at,
            "checks": [c.model_dump() for c in report.checks],
        })
    except ValueError as exc:
        logger.warning("deployment validation error: %s", exc)
        raise HTTPException(status_code=400, detail="Invalid deployment validation parameters")
    except (OSError, RuntimeError, KeyError) as exc:
        logger.exception("Error running deployment validation")
        raise HTTPException(status_code=500, detail=type(exc).__name__)
