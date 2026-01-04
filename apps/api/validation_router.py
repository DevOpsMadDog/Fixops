"""
Validation Router for FixOps Compatibility Checking

This router provides dry-run validation endpoints that test whether
security tool outputs can be successfully ingested by FixOps without
actually persisting the data. This is useful for:

1. Customer pre-deployment validation
2. Tool version compatibility testing
3. Schema drift detection
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import logging
from datetime import datetime
from tempfile import SpooledTemporaryFile
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, File, HTTPException, UploadFile
from pydantic import BaseModel

from .normalizers import (
    InputNormalizer,
    NormalizedCNAPP,
    NormalizedCVEFeed,
    NormalizedSARIF,
    NormalizedSBOM,
    NormalizedVEX,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/validate", tags=["validation"])

# Shared normalizer instance
_normalizer = InputNormalizer()

# Maximum file size for validation (8MB)
MAX_VALIDATION_SIZE = 8 * 1024 * 1024


class ValidationResult(BaseModel):
    """Result of validating a security tool output."""

    valid: bool
    input_type: str
    detected_format: Optional[str] = None
    detected_version: Optional[str] = None
    tool_name: Optional[str] = None
    findings_count: int = 0
    components_count: int = 0
    warnings: List[str] = []
    errors: List[str] = []
    metadata: Dict[str, Any] = {}
    file_info: Dict[str, Any] = {}
    compatibility: Dict[str, Any] = {}


class CompatibilityReport(BaseModel):
    """Detailed compatibility report for customer validation."""

    timestamp: str
    fixops_version: str = "1.0.0"
    validation_results: List[ValidationResult]
    overall_compatible: bool
    recommendations: List[str] = []


async def _read_file_content(file: UploadFile) -> tuple[bytes, str]:
    """Read file content with size limit.

    Checks file size before fully loading into memory to prevent
    memory exhaustion from oversized uploads.
    """
    # Check content-length header first if available to avoid loading large files
    if file.size is not None and file.size > MAX_VALIDATION_SIZE:
        raise HTTPException(
            status_code=413,
            detail=f"File too large. Maximum size is {MAX_VALIDATION_SIZE // (1024*1024)}MB",
        )

    # Read in chunks to handle streaming uploads and enforce size limit
    chunks = []
    total_size = 0
    chunk_size = 64 * 1024  # 64KB chunks

    while True:
        chunk = await file.read(chunk_size)
        if not chunk:
            break
        total_size += len(chunk)
        if total_size > MAX_VALIDATION_SIZE:
            raise HTTPException(
                status_code=413,
                detail=f"File too large. Maximum size is {MAX_VALIDATION_SIZE // (1024*1024)}MB",
            )
        chunks.append(chunk)

    content = b"".join(chunks)
    file_hash = hashlib.sha256(content).hexdigest()
    return content, file_hash


def _detect_input_type(content: bytes, filename: str) -> str:
    """Detect the type of security tool output."""
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        # Check if it's CSV
        if filename.endswith(".csv") or b"," in content[:1000]:
            return "design"
        return "unknown"

    # SARIF detection
    if data.get("$schema") and "sarif" in str(data.get("$schema", "")).lower():
        return "sarif"
    if data.get("version") == "2.1.0" and "runs" in data:
        return "sarif"

    # CycloneDX SBOM detection
    if data.get("bomFormat") == "CycloneDX":
        return "sbom"
    if data.get("spdxVersion"):
        return "sbom"

    # Snyk detection (will be converted to SARIF)
    if "vulnerabilities" in data and (
        "snyk" in str(data).lower() or "packageManager" in data
    ):
        return "sarif"  # Snyk is converted to SARIF

    # Trivy detection
    if data.get("SchemaVersion") and "Results" in data:
        return "cve"

    # Grype detection
    if "matches" in data and "source" in data:
        return "cve"

    # VEX detection
    if data.get("@context") and "openvex" in str(data.get("@context", "")).lower():
        return "vex"
    if "statements" in data and any(
        "vulnerability" in str(s) for s in data.get("statements", [])
    ):
        return "vex"

    # CNAPP detection
    if "findings" in data and ("provider" in data or "cloudProvider" in data):
        return "cnapp"

    # CVE feed detection
    if isinstance(data, list) and data and "cveId" in str(data[0]):
        return "cve"
    if "CVE_Items" in data or "cve_items" in data:
        return "cve"

    # Checkov/IaC detection
    if "check_type" in data or "passed_checks" in data or "failed_checks" in data:
        return "cve"  # Treat as CVE/findings feed

    # SonarQube detection
    if "issues" in data and "paging" in data:
        return "sarif"  # Will need conversion

    # ZAP detection
    if "site" in data and isinstance(data.get("site"), list):
        return "sarif"  # Will need conversion

    # Generic SBOM indicators
    if "components" in data or "packages" in data or "dependencies" in data:
        return "sbom"

    return "unknown"


def _detect_tool_info(content: bytes, input_type: str) -> Dict[str, Any]:
    """Extract tool name and version from the content."""
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return {}

    tool_info = {}

    if input_type == "sarif":
        runs = data.get("runs", [])
        if runs:
            tool = runs[0].get("tool", {}).get("driver", {})
            tool_info["tool_name"] = tool.get("name")
            tool_info["tool_version"] = tool.get("version")
            tool_info["sarif_version"] = data.get("version")

    elif input_type == "sbom":
        tool_info["format"] = (
            data.get("bomFormat") or "SPDX" if data.get("spdxVersion") else "unknown"
        )
        tool_info["spec_version"] = data.get("specVersion") or data.get("spdxVersion")
        metadata = data.get("metadata", {})
        if metadata.get("tools"):
            tools = metadata["tools"]
            if isinstance(tools, list) and tools:
                tool_info["tool_name"] = tools[0].get("name")
                tool_info["tool_version"] = tools[0].get("version")

    elif input_type == "cve":
        # Trivy
        if data.get("SchemaVersion"):
            tool_info["tool_name"] = "Trivy"
            tool_info["schema_version"] = data.get("SchemaVersion")
        # Grype
        elif "matches" in data:
            tool_info["tool_name"] = "Grype"
            if data.get("descriptor"):
                tool_info["tool_version"] = data["descriptor"].get("version")

    return tool_info


@router.post("/input", response_model=ValidationResult)
async def validate_input(
    file: UploadFile = File(...),
    input_type: Optional[str] = None,
) -> ValidationResult:
    """
    Validate a security tool output without persisting it.

    This endpoint tests whether FixOps can successfully parse and normalize
    the provided file. Use this to verify compatibility before deployment.

    Args:
        file: The security tool output file to validate
        input_type: Optional hint for input type (sarif, sbom, cve, vex, cnapp)

    Returns:
        ValidationResult with parsing status, detected format, and any warnings
    """
    content, file_hash = await _read_file_content(file)
    filename = file.filename or "unknown"

    # Detect input type if not provided
    detected_type = input_type or _detect_input_type(content, filename)

    result = ValidationResult(
        valid=False,
        input_type=detected_type,
        file_info={
            "filename": filename,
            "size_bytes": len(content),
            "sha256": file_hash,
            "content_type": file.content_type,
        },
    )

    if detected_type == "unknown":
        result.errors.append(
            "Could not detect input type. Supported: sarif, sbom, cve, vex, cnapp"
        )
        return result

    # Extract tool info
    tool_info = _detect_tool_info(content, detected_type)
    result.tool_name = tool_info.get("tool_name")
    result.detected_version = tool_info.get("tool_version") or tool_info.get(
        "spec_version"
    )
    result.detected_format = tool_info.get("format")
    result.metadata = tool_info

    # Create a buffer for the normalizer
    buffer = SpooledTemporaryFile(max_size=1024 * 1024, mode="w+b")
    try:
        buffer.write(content)
        buffer.seek(0)

        # Attempt to normalize based on detected type
        if detected_type == "sarif":
            try:
                sarif: NormalizedSARIF = _normalizer.load_sarif(buffer)
                result.valid = True
                result.findings_count = len(sarif.findings)
                result.detected_format = f"SARIF {sarif.version}"
                result.metadata["tool_names"] = sarif.tool_names
                result.metadata["schema_uri"] = sarif.schema_uri
                if not sarif.findings:
                    result.warnings.append("SARIF contains no findings (empty results)")
            except Exception as exc:
                result.errors.append(f"SARIF parsing failed: {exc}")

        elif detected_type == "sbom":
            try:
                sbom: NormalizedSBOM = _normalizer.load_sbom(buffer)
                result.valid = True
                result.components_count = len(sbom.components)
                result.detected_format = sbom.format
                result.metadata["vulnerabilities_count"] = len(sbom.vulnerabilities)
                if not sbom.components:
                    result.warnings.append("SBOM contains no components")
            except Exception as exc:
                result.errors.append(f"SBOM parsing failed: {exc}")

        elif detected_type == "cve":
            try:
                cve_feed: NormalizedCVEFeed = _normalizer.load_cve_feed(buffer)
                result.valid = True
                result.findings_count = len(cve_feed.records)
                result.metadata["record_count"] = cve_feed.metadata.get(
                    "record_count", 0
                )
                if cve_feed.errors:
                    result.warnings.extend(cve_feed.errors[:5])
                if not cve_feed.records:
                    result.warnings.append("CVE feed contains no records")
            except Exception as exc:
                result.errors.append(f"CVE feed parsing failed: {exc}")

        elif detected_type == "vex":
            try:
                vex: NormalizedVEX = _normalizer.load_vex(buffer)
                result.valid = True
                result.findings_count = len(vex.assertions)
                result.metadata["suppressed_count"] = len(vex.suppressed_refs)
                if not vex.assertions:
                    result.warnings.append("VEX document contains no assertions")
            except Exception as exc:
                result.errors.append(f"VEX parsing failed: {exc}")

        elif detected_type == "cnapp":
            try:
                cnapp: NormalizedCNAPP = _normalizer.load_cnapp(buffer)
                result.valid = True
                result.findings_count = len(cnapp.findings)
                result.components_count = len(cnapp.assets)
                if not cnapp.findings:
                    result.warnings.append("CNAPP payload contains no findings")
            except Exception as exc:
                result.errors.append(f"CNAPP parsing failed: {exc}")

        elif detected_type == "design":
            # Design files are CSV files containing threat models, design artifacts
            try:
                buffer.seek(0)
                text_content = buffer.read().decode("utf-8")
                csv_reader = csv.reader(io.StringIO(text_content))
                rows = list(csv_reader)
                if rows:
                    result.valid = True
                    result.detected_format = "CSV"
                    result.metadata["columns"] = rows[0] if rows else []
                    result.metadata["row_count"] = len(rows) - 1  # Exclude header
                    if len(rows) <= 1:
                        result.warnings.append("Design CSV contains no data rows")
                else:
                    result.errors.append("Design CSV is empty")
            except UnicodeDecodeError as exc:
                result.errors.append(f"Design CSV encoding error: {exc}")
            except csv.Error as exc:
                result.errors.append(f"Design CSV parsing failed: {exc}")

    finally:
        buffer.close()

    # Add compatibility info
    result.compatibility = {
        "fixops_compatible": result.valid,
        "ingestion_endpoint": f"/inputs/{detected_type}"
        if detected_type != "unknown"
        else None,
        "requires_conversion": detected_type in ["sarif"]
        and result.tool_name in ["Snyk", "SonarQube", "ZAP"],
    }

    return result


@router.post("/batch", response_model=CompatibilityReport)
async def validate_batch(
    files: List[UploadFile] = File(...),
) -> CompatibilityReport:
    """
    Validate multiple security tool outputs at once.

    Use this to test a complete set of tool outputs before deployment.
    """
    results = []
    for file in files:
        try:
            result = await validate_input(file)
            results.append(result)
        except HTTPException as exc:
            results.append(
                ValidationResult(
                    valid=False,
                    input_type="unknown",
                    errors=[str(exc.detail)],
                    file_info={"filename": file.filename},
                )
            )

    overall_compatible = all(r.valid for r in results)

    recommendations = []
    if not overall_compatible:
        failed = [r for r in results if not r.valid]
        for f in failed:
            if f.errors:
                recommendations.append(
                    f"Fix {f.file_info.get('filename', 'unknown')}: {f.errors[0]}"
                )

    return CompatibilityReport(
        timestamp=datetime.utcnow().isoformat() + "Z",
        validation_results=results,
        overall_compatible=overall_compatible,
        recommendations=recommendations,
    )


@router.get("/supported-formats")
async def get_supported_formats() -> Dict[str, Any]:
    """
    List all supported input formats and their versions.
    """
    return {
        "formats": {
            "sarif": {
                "versions": ["2.1.0"],
                "tools": [
                    "ESLint",
                    "Semgrep",
                    "CodeQL",
                    "Checkmarx",
                    "SonarQube (converted)",
                    "Snyk (converted)",
                ],
                "endpoint": "/inputs/sarif",
            },
            "sbom": {
                "versions": [
                    "CycloneDX 1.2-1.5",
                    "SPDX 2.2-2.3",
                    "Syft",
                    "GitHub Dependency Snapshot",
                ],
                "tools": [
                    "CycloneDX Maven/Gradle/NPM",
                    "Syft",
                    "Trivy SBOM",
                    "SPDX tools",
                ],
                "endpoint": "/inputs/sbom",
            },
            "cve": {
                "versions": [
                    "CVE JSON 5.0",
                    "NVD JSON 1.1",
                    "Trivy JSON",
                    "Grype JSON",
                    "KEV",
                ],
                "tools": ["Trivy", "Grype", "NVD feeds", "CISA KEV"],
                "endpoint": "/inputs/cve",
            },
            "vex": {
                "versions": ["OpenVEX 0.2.0", "CycloneDX VEX", "CSAF VEX"],
                "tools": ["vexctl", "CycloneDX tools"],
                "endpoint": "/inputs/vex",
            },
            "cnapp": {
                "versions": [
                    "AWS Security Hub",
                    "Azure Defender",
                    "GCP Security Command Center",
                ],
                "tools": ["Cloud-native security platforms"],
                "endpoint": "/inputs/cnapp",
            },
            "design": {
                "versions": ["CSV"],
                "tools": ["Threat modeling tools", "Design documentation"],
                "endpoint": "/inputs/design",
            },
        },
        "validation_endpoint": "/api/v1/validate/input",
        "batch_endpoint": "/api/v1/validate/batch",
    }
