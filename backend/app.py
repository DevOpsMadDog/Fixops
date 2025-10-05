from __future__ import annotations

import base64
import csv
import hashlib
import hmac
import io
import json
import logging
import time
from typing import Any, Dict, Iterable, Mapping, Optional

import requests
from fastapi import Depends, FastAPI, File, Header, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader

from fixops.configuration import OverlayConfig, load_overlay
from fixops.paths import ensure_secure_directory
from fixops.storage import ArtefactArchive
from fixops.feedback import FeedbackRecorder

from .normalizers import InputNormalizer, NormalizedCVEFeed, NormalizedSARIF, NormalizedSBOM
from .pipeline import PipelineOrchestrator

logger = logging.getLogger(__name__)


def create_app() -> FastAPI:
    """Create the FastAPI application with file-upload ingestion endpoints."""

    app = FastAPI(title="FixOps Ingestion Demo API", version="0.1.0")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    normalizer = InputNormalizer()
    orchestrator = PipelineOrchestrator()
    overlay = load_overlay()

    # API authentication and authorisation setup
    auth_strategy = overlay.auth.get("strategy", "").lower()
    api_header_name = overlay.auth.get("header", "X-API-Key")
    tenant_header_name = overlay.auth.get("tenant_header", "X-FixOps-Tenant")
    default_tenant = overlay.auth.get("default_tenant", "default")
    api_key_header = APIKeyHeader(name=api_header_name, auto_error=False)
    expected_tokens = overlay.auth_tokens if auth_strategy == "token" else tuple()
    jwks_cache: Dict[str, list[Dict[str, Any]]] = {}

    def _normalise_sequence(value: Any) -> list[str]:
        if value is None:
            return []
        if isinstance(value, str):
            return [item for item in value.replace(",", " ").split() if item]
        if isinstance(value, Iterable):
            items: list[str] = []
            for entry in value:
                if isinstance(entry, str):
                    candidate = entry.strip()
                    if candidate:
                        items.append(candidate)
                elif entry is not None:
                    items.append(str(entry))
            return list(dict.fromkeys(items))
        return [str(value)]

    def _b64url_decode(data: str) -> bytes:
        padded = data + "=" * (-len(data) % 4)
        return base64.urlsafe_b64decode(padded.encode("ascii"))

    def _load_jwks(provider_id: str, provider: Mapping[str, Any]) -> list[Dict[str, Any]]:
        cached = jwks_cache.get(provider_id)
        if cached is not None:
            return cached

        keys: list[Dict[str, Any]] = []
        jwks = provider.get("jwks") if isinstance(provider, Mapping) else None
        if isinstance(jwks, Mapping):
            raw_keys = jwks.get("keys")
            if isinstance(raw_keys, Iterable):
                for entry in raw_keys:
                    if isinstance(entry, Mapping):
                        keys.append(dict(entry))
        elif isinstance(jwks, Iterable):
            for entry in jwks:
                if isinstance(entry, Mapping):
                    keys.append(dict(entry))
        elif isinstance(provider, Mapping) and provider.get("jwks_url"):
            try:
                response = requests.get(str(provider["jwks_url"]), timeout=5)
                response.raise_for_status()
                data = response.json()
            except requests.RequestException as exc:  # pragma: no cover - network instability is environment specific
                raise HTTPException(status_code=503, detail="Failed to fetch identity provider keys") from exc
            else:
                raw_keys = data.get("keys")
                if isinstance(raw_keys, Iterable):
                    for entry in raw_keys:
                        if isinstance(entry, Mapping):
                            keys.append(dict(entry))
        if not keys:
            raise HTTPException(status_code=500, detail="Identity provider does not expose any keys")
        jwks_cache[provider_id] = keys
        return keys

    def _select_jwk(keys: Iterable[Mapping[str, Any]], kid: Optional[str], algorithm: str) -> Mapping[str, Any]:
        candidates: list[Mapping[str, Any]] = []
        for key in keys:
            if kid and key.get("kid") != kid:
                continue
            key_alg = key.get("alg")
            if key_alg and key_alg != algorithm:
                continue
            candidates.append(key)
        if not candidates:
            for key in keys:
                key_alg = key.get("alg")
                if key_alg and key_alg != algorithm:
                    continue
                candidates.append(key)
                break
        if not candidates:
            raise HTTPException(status_code=401, detail="No matching signing key found for token")
        return dict(candidates[0])

    def _verify_hs256_signature(key: Mapping[str, Any], signing_input: bytes, signature: bytes) -> None:
        secret = key.get("k")
        if not isinstance(secret, str):
            raise HTTPException(status_code=500, detail="Invalid symmetric key configuration")
        expected = hmac.new(_b64url_decode(secret), signing_input, hashlib.sha256).digest()
        if not hmac.compare_digest(expected, signature):
            raise HTTPException(status_code=401, detail="Invalid token signature")

    def _verify_rs256_signature(key: Mapping[str, Any], signing_input: bytes, signature: bytes) -> None:
        modulus_b64 = key.get("n")
        exponent_b64 = key.get("e", "AQAB")
        if not isinstance(modulus_b64, str) or not isinstance(exponent_b64, str):
            raise HTTPException(status_code=500, detail="Invalid RSA key material")
        modulus = int.from_bytes(_b64url_decode(modulus_b64), "big")
        exponent = int.from_bytes(_b64url_decode(exponent_b64), "big")
        if modulus <= 0 or exponent <= 0:
            raise HTTPException(status_code=500, detail="Invalid RSA key material")
        signature_int = int.from_bytes(signature, "big")
        key_size = (modulus.bit_length() + 7) // 8
        if len(signature) != key_size:
            signature_int = int.from_bytes(signature.rjust(key_size, b"\x00"), "big")
        decrypted = pow(signature_int, exponent, modulus)
        decrypted_bytes = decrypted.to_bytes(key_size, "big")
        digest = hashlib.sha256(signing_input).digest()
        digestinfo_prefix = bytes.fromhex("3031300d060960864801650304020105000420")
        padding_len = key_size - len(digestinfo_prefix) - len(digest) - 3
        if padding_len < 8:
            raise HTTPException(status_code=401, detail="Invalid token signature")
        expected = b"\x00\x01" + b"\xff" * padding_len + b"\x00" + digestinfo_prefix + digest
        if decrypted_bytes != expected:
            raise HTTPException(status_code=401, detail="Invalid token signature")

    def _decode_and_verify_jwt(token: str, provider_id: str, provider: Mapping[str, Any]) -> Dict[str, Any]:
        try:
            header_segment, payload_segment, signature_segment = token.split(".")
        except ValueError as exc:
            raise HTTPException(status_code=401, detail="Malformed bearer token") from exc

        try:
            header = json.loads(_b64url_decode(header_segment))
        except json.JSONDecodeError as exc:
            raise HTTPException(status_code=401, detail="Invalid token header") from exc

        algorithm = header.get("alg")
        if not isinstance(algorithm, str):
            raise HTTPException(status_code=401, detail="Token missing algorithm")

        signing_input = f"{header_segment}.{payload_segment}".encode("ascii")
        try:
            signature = _b64url_decode(signature_segment)
        except Exception as exc:  # pragma: no cover - unexpected encoding errors
            raise HTTPException(status_code=401, detail="Malformed token signature") from exc

        keys = _load_jwks(provider_id, provider)
        key = _select_jwk(keys, header.get("kid"), algorithm)

        if algorithm == "HS256":
            _verify_hs256_signature(key, signing_input, signature)
        elif algorithm == "RS256":
            _verify_rs256_signature(key, signing_input, signature)
        else:
            raise HTTPException(status_code=400, detail=f"Unsupported JWT algorithm '{algorithm}'")

        try:
            payload = json.loads(_b64url_decode(payload_segment))
        except json.JSONDecodeError as exc:
            raise HTTPException(status_code=401, detail="Invalid token payload") from exc

        exp = payload.get("exp")
        if isinstance(exp, (int, float)) and time.time() > float(exp):
            raise HTTPException(status_code=401, detail="Token has expired")

        nbf = payload.get("nbf")
        if isinstance(nbf, (int, float)) and time.time() < float(nbf):
            raise HTTPException(status_code=401, detail="Token not yet valid")

        return payload

    def _extract_roles(claims: Mapping[str, Any]) -> set[str]:
        roles: set[str] = set()
        for key in ("roles", "role", "groups", "permissions"):
            roles.update(_normalise_sequence(claims.get(key)))
        for key in ("scope", "scp"):
            roles.update(_normalise_sequence(claims.get(key)))
        return roles

    def _verify_oidc_token(token: str, tenant_id: str) -> Dict[str, Any]:
        tenant = overlay.get_tenant(tenant_id)
        if not tenant:
            raise HTTPException(status_code=403, detail="Unknown tenant")
        identity = tenant.get("identity") if isinstance(tenant.get("identity"), Mapping) else {}
        provider_id = identity.get("provider") if isinstance(identity, Mapping) else None
        if not provider_id:
            defaults = overlay.tenancy_settings.get("defaults")
            if isinstance(defaults, Mapping):
                provider_id = defaults.get("identity_provider")
        if not provider_id:
            raise HTTPException(status_code=403, detail="Tenant does not have an identity provider configured")
        provider = overlay.tenant_identity_providers.get(str(provider_id))
        if not provider:
            raise HTTPException(status_code=403, detail="Identity provider configuration missing")

        claims = _decode_and_verify_jwt(token, str(provider_id), provider)

        issuer = provider.get("issuer")
        if issuer and claims.get("iss") != issuer:
            raise HTTPException(status_code=401, detail="Token issuer mismatch")

        allowed_audiences = set(_normalise_sequence(provider.get("allowed_audiences")))
        tenant_audiences = identity.get("allowed_audiences") if isinstance(identity, Mapping) else None
        allowed_audiences.update(_normalise_sequence(tenant_audiences))
        if allowed_audiences:
            token_audience = claims.get("aud")
            token_audiences: set[str] = set()
            if isinstance(token_audience, str):
                token_audiences = {token_audience}
            elif isinstance(token_audience, Iterable):
                token_audiences = {str(entry) for entry in token_audience}
            if not token_audiences & allowed_audiences:
                raise HTTPException(status_code=403, detail="Token audience not permitted for tenant")

        return {
            "tenant_id": tenant_id,
            "claims": claims,
            "tenant": tenant,
            "identity": identity,
            "provider": provider,
        }

    def _enforce_rbac(action: str, context: Mapping[str, Any]) -> None:
        identity = context.get("identity")
        if not isinstance(identity, Mapping):
            return
        roles_config = identity.get("roles")
        if not isinstance(roles_config, Mapping):
            return
        required = roles_config.get(action)
        if required is None:
            fallback_map = {
                "upload": ("uploads", "ingest", "write"),
                "pipeline": ("run", "execute", "pipeline_run"),
                "feedback": ("feedback",),
            }
            for candidate in fallback_map.get(action, ()):  # pragma: no cover - defensive mapping
                candidate_roles = roles_config.get(candidate)
                if candidate_roles is not None:
                    required = candidate_roles
                    break
        required_roles = set(_normalise_sequence(required))
        if not required_roles:
            return
        token_roles = _extract_roles(context.get("claims", {}))
        if not token_roles.intersection(required_roles):
            raise HTTPException(status_code=403, detail=f"Missing required role for '{action}'")

    def _resolve_archive(tenant_id: str) -> ArtefactArchive:
        archives: Dict[str, ArtefactArchive] = app.state.tenant_archives
        archive = archives.get(tenant_id)
        if archive is not None:
            return archive
        archive_dir = overlay.tenant_archive_directory(tenant_id)
        archive = ArtefactArchive(archive_dir)
        archives[tenant_id] = archive
        return archive

    def _tenant_state(tenant_id: str) -> tuple[Dict[str, Any], Dict[str, Any], ArtefactArchive]:
        artifact_map: Dict[str, Dict[str, Any]] = app.state.artifacts
        tenant_artifacts = artifact_map.setdefault(tenant_id, {})
        archive_records_map: Dict[str, Dict[str, Any]] = app.state.archive_records
        tenant_records = archive_records_map.setdefault(tenant_id, {})
        archive = _resolve_archive(tenant_id)
        return tenant_artifacts, tenant_records, archive

    async def _authorise_request(
        action: str,
        *,
        api_key: Optional[str],
        tenant_id: Optional[str],
        authorization: Optional[str],
    ) -> Dict[str, Any]:
        if auth_strategy == "token":
            if not api_key or api_key not in expected_tokens:
                raise HTTPException(status_code=401, detail="Invalid or missing API token")
            return {"tenant_id": default_tenant, "claims": {"token": api_key}}
        if auth_strategy == "oidc":
            if not tenant_id:
                raise HTTPException(status_code=400, detail="Missing tenant header")
            if not authorization or not authorization.lower().startswith("bearer "):
                raise HTTPException(status_code=401, detail="Missing bearer token")
            token = authorization.split(" ", 1)[1].strip()
            context = _verify_oidc_token(token, tenant_id)
            _enforce_rbac(action, context)
            return context
        # Default to a permissive mode for demo deployments without explicit auth
        return {"tenant_id": default_tenant, "claims": {}}

    for directory in overlay.data_directories.values():
        ensure_secure_directory(directory)

    app.state.normalizer = normalizer
    app.state.orchestrator = orchestrator
    app.state.artifacts: Dict[str, Dict[str, Any]] = {}
    app.state.overlay = overlay
    app.state.tenant_archives: Dict[str, ArtefactArchive] = {}
    app.state.archive_records: Dict[str, Dict[str, Any]] = {}
    app.state.feedback = (
        FeedbackRecorder(overlay)
        if overlay.toggles.get("capture_feedback")
        else None
    )
    app.state.auth_strategy = auth_strategy
    app.state.tenant_header = tenant_header_name

    if auth_strategy != "oidc":
        _resolve_archive(default_tenant)

    async def _read_limited(file: UploadFile, stage: str) -> bytes:
        limit = overlay.upload_limit(stage)
        total = 0
        chunks: list[bytes] = []
        while True:
            remaining = limit - total
            if remaining <= 0:
                break
            chunk = await file.read(min(1024 * 1024, remaining))
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                raise HTTPException(
                    status_code=413,
                    detail={
                        "message": f"Upload for stage '{stage}' exceeded limit",
                        "max_bytes": limit,
                    },
                )
            chunks.append(chunk)
            if total == limit:
                break
        return b"".join(chunks)

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
        tenant_id: str,
        original_filename: Optional[str] = None,
        raw_bytes: Optional[bytes] = None,
    ) -> None:
        logger.debug("Storing stage %s for tenant %s", stage, tenant_id)
        tenant_artifacts, tenant_records, archive = _tenant_state(tenant_id)
        tenant_artifacts[stage] = payload
        try:
            record = archive.persist(
                stage,
                payload,
                original_filename=original_filename,
                raw_bytes=raw_bytes,
            )
        except Exception as exc:  # pragma: no cover - persistence must not break ingestion
            logger.exception("Failed to persist artefact stage %s", stage)
            record = {"stage": stage, "error": str(exc)}
        tenant_records[stage] = dict(record)

    @app.post("/inputs/design")
    async def ingest_design(
        request: Request,
        file: UploadFile = File(...),
        authorization: Optional[str] = Header(None, alias="Authorization"),
        api_key: Optional[str] = Depends(api_key_header),
        tenant_id: Optional[str] = Header(None, alias=tenant_header_name),
    ) -> Dict[str, Any]:
        auth_context = await _authorise_request(
            "upload", api_key=api_key, tenant_id=tenant_id, authorization=authorization
        )
        request.state.tenant_id = auth_context["tenant_id"]

        _validate_content_type(
            file,
            (
                "text/csv",
                "application/vnd.ms-excel",
                "application/csv",
                "text/plain",
            ),
        )
        raw_bytes = await _read_limited(file, "design")
        text = raw_bytes.decode("utf-8", errors="ignore")
        reader = csv.DictReader(io.StringIO(text))
        rows = [row for row in reader if any((value or "").strip() for value in row.values())]

        if not rows:
            raise HTTPException(status_code=400, detail="Design CSV contained no rows")

        dataset = {"columns": reader.fieldnames or [], "rows": rows, "row_count": len(rows)}
        _store(
            "design",
            dataset,
            tenant_id=auth_context["tenant_id"],
            original_filename=file.filename,
            raw_bytes=raw_bytes,
        )
        return {
            "stage": "design",
            "input_filename": file.filename,
            "row_count": len(rows),
            "columns": dataset["columns"],
            "data": dataset,
        }

    @app.post("/inputs/sbom")
    async def ingest_sbom(
        request: Request,
        file: UploadFile = File(...),
        authorization: Optional[str] = Header(None, alias="Authorization"),
        api_key: Optional[str] = Depends(api_key_header),
        tenant_id: Optional[str] = Header(None, alias=tenant_header_name),
    ) -> Dict[str, Any]:
        auth_context = await _authorise_request(
            "upload", api_key=api_key, tenant_id=tenant_id, authorization=authorization
        )
        request.state.tenant_id = auth_context["tenant_id"]

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
        raw_bytes = await _read_limited(file, "sbom")
        try:
            sbom: NormalizedSBOM = normalizer.load_sbom(raw_bytes)
        except Exception as exc:  # pragma: no cover - FastAPI will serialise the message
            logger.exception("SBOM normalisation failed")
            raise HTTPException(status_code=400, detail=f"Failed to parse SBOM: {exc}") from exc

        _store(
            "sbom",
            sbom,
            tenant_id=auth_context["tenant_id"],
            original_filename=file.filename,
            raw_bytes=raw_bytes,
        )
        return {
            "stage": "sbom",
            "input_filename": file.filename,
            "metadata": sbom.metadata,
            "component_preview": [
                component.to_dict() for component in sbom.components[:5]
            ],
        }

    @app.post("/inputs/cve")
    async def ingest_cve(
        request: Request,
        file: UploadFile = File(...),
        authorization: Optional[str] = Header(None, alias="Authorization"),
        api_key: Optional[str] = Depends(api_key_header),
        tenant_id: Optional[str] = Header(None, alias=tenant_header_name),
    ) -> Dict[str, Any]:
        auth_context = await _authorise_request(
            "upload", api_key=api_key, tenant_id=tenant_id, authorization=authorization
        )
        request.state.tenant_id = auth_context["tenant_id"]

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
        raw_bytes = await _read_limited(file, "cve")
        try:
            cve_feed: NormalizedCVEFeed = normalizer.load_cve_feed(raw_bytes)
        except Exception as exc:  # pragma: no cover - FastAPI will serialise the message
            logger.exception("CVE feed normalisation failed")
            raise HTTPException(status_code=400, detail=f"Failed to parse CVE feed: {exc}") from exc

        _store(
            "cve",
            cve_feed,
            tenant_id=auth_context["tenant_id"],
            original_filename=file.filename,
            raw_bytes=raw_bytes,
        )
        return {
            "stage": "cve",
            "input_filename": file.filename,
            "record_count": cve_feed.metadata.get("record_count", 0),
            "validation_errors": cve_feed.errors,
        }

    @app.post("/inputs/sarif")
    async def ingest_sarif(
        request: Request,
        file: UploadFile = File(...),
        authorization: Optional[str] = Header(None, alias="Authorization"),
        api_key: Optional[str] = Depends(api_key_header),
        tenant_id: Optional[str] = Header(None, alias=tenant_header_name),
    ) -> Dict[str, Any]:
        auth_context = await _authorise_request(
            "upload", api_key=api_key, tenant_id=tenant_id, authorization=authorization
        )
        request.state.tenant_id = auth_context["tenant_id"]

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
        raw_bytes = await _read_limited(file, "sarif")
        try:
            sarif: NormalizedSARIF = normalizer.load_sarif(raw_bytes)
        except Exception as exc:  # pragma: no cover - FastAPI will serialise the message
            logger.exception("SARIF normalisation failed")
            raise HTTPException(status_code=400, detail=f"Failed to parse SARIF: {exc}") from exc

        _store(
            "sarif",
            sarif,
            tenant_id=auth_context["tenant_id"],
            original_filename=file.filename,
            raw_bytes=raw_bytes,
        )
        return {
            "stage": "sarif",
            "input_filename": file.filename,
            "metadata": sarif.metadata,
            "tools": sarif.tool_names,
        }

    @app.post("/pipeline/run")
    async def run_pipeline(
        request: Request,
        authorization: Optional[str] = Header(None, alias="Authorization"),
        api_key: Optional[str] = Depends(api_key_header),
        tenant_id: Optional[str] = Header(None, alias=tenant_header_name),
    ) -> Dict[str, Any]:
        auth_context = await _authorise_request(
            "pipeline", api_key=api_key, tenant_id=tenant_id, authorization=authorization
        )
        request.state.tenant_id = auth_context["tenant_id"]

        overlay_config: OverlayConfig = app.state.overlay
        required = overlay_config.required_inputs
        tenant_artifacts = app.state.artifacts.get(auth_context["tenant_id"], {})
        missing = [stage for stage in required if stage not in tenant_artifacts]
        if missing:
            raise HTTPException(
                status_code=400,
                detail={"message": "Missing required artefacts", "missing": missing},
            )

        if overlay_config.toggles.get("enforce_ticket_sync") and not overlay_config.jira.get("project_key"):
            raise HTTPException(
                status_code=500,
                detail={
                    "message": "Ticket synchronisation enforced but Jira project_key missing",
                    "integration": overlay_config.jira,
                },
            )

        result = orchestrator.run(
            design_dataset=tenant_artifacts.get("design", {"columns": [], "rows": []}),
            sbom=tenant_artifacts["sbom"],
            sarif=tenant_artifacts["sarif"],
            cve=tenant_artifacts["cve"],
            overlay=overlay_config,
        )
        tenant_records = app.state.archive_records.get(auth_context["tenant_id"], {})
        if tenant_records:
            result["artifact_archive"] = ArtefactArchive.summarise(tenant_records)
            app.state.archive_records[auth_context["tenant_id"]] = {}
        if overlay_config.toggles.get("auto_attach_overlay_metadata", True):
            result["overlay"] = overlay_config.to_sanitised_dict()
            result["overlay"]["required_inputs"] = list(required)
        return result

    @app.post("/feedback")
    async def submit_feedback(
        payload: Dict[str, Any],
        authorization: Optional[str] = Header(None, alias="Authorization"),
        api_key: Optional[str] = Depends(api_key_header),
        tenant_id: Optional[str] = Header(None, alias=tenant_header_name),
    ) -> Dict[str, Any]:
        await _authorise_request(
            "feedback", api_key=api_key, tenant_id=tenant_id, authorization=authorization
        )
        recorder: Optional[FeedbackRecorder] = app.state.feedback
        if recorder is None:
            raise HTTPException(status_code=400, detail="Feedback capture disabled in this profile")
        try:
            entry = recorder.record(payload)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return entry

    return app
