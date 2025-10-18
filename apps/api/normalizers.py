from __future__ import annotations

import base64
import binascii
import gzip
import io
import json
import logging
import sys
import zipfile
from contextlib import suppress
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Iterable, List, Literal, Mapping, Optional, Tuple

from pydantic import (
    BaseModel,
    ConfigDict,
    StrictInt,
    StrictStr,
    ValidationError,
    field_validator,
)

try:  # Optional dependency for YAML parsing
    import yaml
except Exception:  # pragma: no cover - optional dependency
    yaml = None  # type: ignore[assignment]

try:  # Optional dependency for rich SBOM parsing
    from lib4sbom import parser as sbom_parser  # type: ignore
except ImportError as exc:  # pragma: no cover - optional runtime dependency
    sbom_parser = None  # type: ignore[assignment]
    LIB4SBOM_IMPORT_ERROR: Exception | None = exc
else:
    LIB4SBOM_IMPORT_ERROR = None


def _resolve_sbom_parser_state() -> tuple[Any | None, Exception | None]:
    module = sys.modules.get("backend.normalizers")
    parser = getattr(module, "sbom_parser", sbom_parser) if module else sbom_parser
    import_error = (
        getattr(module, "LIB4SBOM_IMPORT_ERROR", LIB4SBOM_IMPORT_ERROR)
        if module
        else LIB4SBOM_IMPORT_ERROR
    )
    return parser, import_error


try:  # Optional dependency for CVE schema validation
    from cvelib.cve_api import CveRecord, CveRecordValidationError
except ImportError:  # pragma: no cover - library is declared but optional at runtime
    CveRecord = None  # type: ignore[assignment]
    CveRecordValidationError = Exception  # type: ignore[assignment]

try:  # Optional converter for Snyk JSON → SARIF
    from snyk_to_sarif import converter as snyk_converter  # type: ignore
except Exception:  # pragma: no cover - the package may require manual installation
    snyk_converter = None

try:
    from sarif_om import SarifLog
except (
    ImportError
) as exc:  # pragma: no cover - sarif-om is declared but highlight failure early
    raise RuntimeError("sarif-om must be available to normalise SARIF inputs.") from exc

SUPPORTED_SARIF_SCHEMAS = {
    "https://json.schemastore.org/sarif-2.1.0.json",
    "http://json.schemastore.org/sarif-2.1.0.json",
    "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
}


logger = logging.getLogger(__name__)

DEFAULT_MAX_DOCUMENT_BYTES = 8 * 1024 * 1024

_SNYK_SEVERITY_TO_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "moderate": "warning",
    "low": "note",
    "info": "note",
}


def _extract_first_identifier(payload: Mapping[str, Any] | None) -> Optional[str]:
    """Return the first interesting identifier from a Snyk issue payload."""

    if not isinstance(payload, Mapping):
        return None

    for key in ("CVE", "GHSA", "CWE", "OSV"):
        values = payload.get(key)
        if isinstance(values, Iterable) and not isinstance(
            values, (str, bytes, bytearray)
        ):
            for value in values:
                if isinstance(value, str) and value.strip():
                    return f"{key}:{value}" if not value.startswith(key) else value
    return None


def _derive_snyk_location(issue: Mapping[str, Any]) -> str:
    """Best-effort derivation of a SARIF location from a Snyk issue."""

    dependency_path = issue.get("from")
    if isinstance(dependency_path, Iterable) and not isinstance(
        dependency_path, (str, bytes, bytearray)
    ):
        for candidate in reversed(list(dependency_path)):
            if isinstance(candidate, str) and candidate.strip():
                return candidate

    for candidate_key in ("file", "path", "targetFile", "packageName", "projectName"):
        candidate = issue.get(candidate_key)
        if isinstance(candidate, str) and candidate.strip():
            return candidate

    package_manager = issue.get("packageManager")
    package_name = issue.get("package") or issue.get("packageName")
    if isinstance(package_name, str) and package_name.strip():
        if isinstance(package_manager, str) and package_manager.strip():
            return f"{package_manager}:{package_name}"
        return package_name

    return "dependency"


def _collect_snyk_issues(payload: Mapping[str, Any]) -> List[dict[str, Any]]:
    """Gather issues from the many Snyk JSON representations."""

    issues: List[dict[str, Any]] = []
    catalogue = payload.get("issues")

    if isinstance(catalogue, Mapping):
        for category, entries in catalogue.items():
            if isinstance(entries, Iterable) and not isinstance(
                entries, (str, bytes, bytearray)
            ):
                for entry in entries:
                    if isinstance(entry, Mapping):
                        issue = dict(entry)
                        issue.setdefault("_category", category)
                        issues.append(issue)
    elif isinstance(catalogue, Iterable) and not isinstance(
        catalogue, (str, bytes, bytearray)
    ):
        for entry in catalogue:
            if isinstance(entry, Mapping):
                issues.append(dict(entry))

    for key in (
        "vulnerabilities",
        "licenses",
        "securityIssues",
        "codeIssues",
        "infrastructureAsCodeIssues",
    ):
        entries = payload.get(key)
        if isinstance(entries, Iterable) and not isinstance(
            entries, (str, bytes, bytearray)
        ):
            for entry in entries:
                if isinstance(entry, Mapping):
                    issue = dict(entry)
                    issue.setdefault("_category", key)
                    issues.append(issue)

    return issues


def _convert_snyk_payload_to_sarif(
    payload: Mapping[str, Any]
) -> Optional[dict[str, Any]]:
    """Fallback conversion when `snyk-to-sarif` is unavailable."""

    issues = _collect_snyk_issues(payload)
    results: List[dict[str, Any]] = []

    for issue in issues:
        severity = str(issue.get("severity") or "").lower()
        level = _SNYK_SEVERITY_TO_LEVEL.get(severity, "warning")
        rule_id = issue.get("id") or issue.get("issueId") or issue.get("issueType")
        if not isinstance(rule_id, str) or not rule_id.strip():
            rule_id = (
                _extract_first_identifier(issue.get("identifiers")) or "SNYK-ISSUE"
            )

        message = issue.get("title") or issue.get("message") or issue.get("description")
        if not isinstance(message, str) or not message.strip():
            message = "Snyk vulnerability detected"

        location = _derive_snyk_location(issue)

        properties: dict[str, Any] = {}
        for key in (
            "severity",
            "packageManager",
            "packageName",
            "identifiers",
            "cvssScore",
            "exploitMaturity",
            "isPatchable",
            "isFixable",
            "isUpgradable",
        ):
            value = issue.get(key)
            if value is not None:
                properties[key] = value

        dependency_path = issue.get("from")
        if isinstance(dependency_path, Iterable) and not isinstance(
            dependency_path, (str, bytes, bytearray)
        ):
            properties["dependency_path"] = list(dependency_path)

        category = issue.get("_category")
        if isinstance(category, str) and category:
            properties["category"] = category

        result: dict[str, Any] = {
            "ruleId": rule_id,
            "level": level,
            "message": {"text": message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": location},
                        "region": {"startLine": 1},
                    }
                }
            ],
        }

        if properties:
            result["properties"] = properties

        results.append(result)

    if not results:
        return None

    tool: dict[str, Any] = {
        "driver": {
            "name": "Snyk",
            "informationUri": "https://snyk.io",
        }
    }

    snyk_version = payload.get("snykVersion") or payload.get("snykCliVersion")
    if isinstance(snyk_version, str) and snyk_version.strip():
        tool["driver"]["version"] = snyk_version

    run_properties: dict[str, Any] = {}
    for key, alias in (("projectName", "project"), ("org", "organisation")):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            run_properties[alias] = value

    run: dict[str, Any] = {
        "tool": tool,
        "results": results,
    }

    if run_properties:
        run["properties"] = run_properties

    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [run],
    }


@dataclass
class SBOMComponent:
    """A minimal view of a component extracted from an SBOM."""

    name: str
    version: Optional[str] = None
    purl: Optional[str] = None
    licenses: List[str] = field(default_factory=list)
    supplier: Optional[str] = None
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        # Avoid duplicating the raw data when serialising for responses
        payload["raw"] = self.raw
        return payload


@dataclass
class NormalizedSBOM:
    """Result of normalising an SBOM document."""

    format: str
    document: dict[str, Any]
    components: List[SBOMComponent]
    relationships: List[Any]
    services: List[Any]
    vulnerabilities: List[Any]
    metadata: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": self.format,
            "document": self.document,
            "components": [component.to_dict() for component in self.components],
            "relationships": self.relationships,
            "services": self.services,
            "vulnerabilities": self.vulnerabilities,
            "metadata": self.metadata,
        }


@dataclass
class CVERecordSummary:
    """Reduced representation of a CVE or KEV record."""

    cve_id: str
    title: Optional[str]
    severity: Optional[str]
    exploited: bool
    raw: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class NormalizedCVEFeed:
    """Validated and simplified CVE feed content."""

    records: List[CVERecordSummary]
    errors: List[str]
    metadata: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "records": [record.to_dict() for record in self.records],
            "errors": self.errors,
            "metadata": self.metadata,
        }


@dataclass
class VEXAssertion:
    """Individual VEX assertion mapped to a component reference."""

    vulnerability_id: str
    ref: str
    status: str
    detail: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "vulnerability_id": self.vulnerability_id,
            "ref": self.ref,
            "status": self.status,
        }
        if self.detail:
            payload["detail"] = self.detail
        return payload


@dataclass
class NormalizedVEX:
    """Simplified CycloneDX VEX representation."""

    assertions: List[VEXAssertion]
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def suppressed_refs(self) -> set[str]:
        return {
            assertion.ref
            for assertion in self.assertions
            if assertion.status == "not_affected"
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "assertions": [assertion.to_dict() for assertion in self.assertions],
            "metadata": self.metadata,
        }


@dataclass
class CNAPPAsset:
    """Asset metadata derived from CNAPP findings."""

    asset_id: str
    attributes: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.asset_id, **self.attributes}


@dataclass
class CNAPPFinding:
    """Normalised CNAPP finding with consistent severity semantics."""

    asset: str
    finding_type: str
    severity: str
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "asset": self.asset,
            "type": self.finding_type,
            "severity": self.severity,
            "raw": self.raw,
        }


@dataclass
class NormalizedCNAPP:
    """Structured CNAPP payload with assets and findings."""

    assets: List[CNAPPAsset]
    findings: List[CNAPPFinding]
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "assets": [asset.to_dict() for asset in self.assets],
            "findings": [finding.to_dict() for finding in self.findings],
            "metadata": self.metadata,
        }


@dataclass
class NormalizedBusinessContext:
    """Business context payload supporting FixOps, OTM and SSVC formats."""

    format: str
    components: List[Dict[str, Any]] = field(default_factory=list)
    ssvc: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    raw: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "format": self.format,
            "components": self.components,
            "ssvc": self.ssvc,
            "metadata": self.metadata,
        }


@dataclass
class SarifFinding:
    """Summarised SARIF result."""

    rule_id: Optional[str]
    message: Optional[str]
    level: Optional[str]
    file: Optional[str]
    line: Optional[int]
    raw: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class NormalizedSARIF:
    """Parsed SARIF log enriched with quick statistics."""

    version: str
    schema_uri: Optional[str]
    tool_names: List[str]
    findings: List[SarifFinding]
    metadata: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "schema_uri": self.schema_uri,
            "tool_names": self.tool_names,
            "findings": [finding.to_dict() for finding in self.findings],
            "metadata": self.metadata,
        }


class SarifFindingSchema(BaseModel):
    """Strict validator for normalised SARIF findings."""

    model_config = ConfigDict(extra="forbid")

    rule_id: StrictStr | None = None
    message: StrictStr | None = None
    level: Literal["error", "warning", "note", "none"] | None = None
    file: StrictStr | None = None
    line: StrictInt | None = None

    @field_validator("rule_id")
    @classmethod
    def _reject_empty_rule_ids(cls, value: StrictStr | None) -> StrictStr | None:
        if value is not None and not value.strip():
            raise ValueError("rule_id must not be empty")
        return value


class NormalizedSarifSchema(BaseModel):
    """Strict validator for the SARIF summary emitted by the normalizer."""

    model_config = ConfigDict(extra="forbid")

    version: StrictStr
    schema_uri: StrictStr | None = None
    tool_names: List[StrictStr]
    findings: List[SarifFindingSchema]
    metadata: Dict[str, Any]


class InputNormalizer:
    """Normalise artefacts using dedicated OSS parsers."""

    def __init__(
        self, sbom_type: str = "auto", *, max_document_bytes: int | None = None
    ) -> None:
        self.sbom_type = sbom_type
        self.max_document_bytes = (
            max_document_bytes
            if max_document_bytes is not None
            else DEFAULT_MAX_DOCUMENT_BYTES
        )

    @staticmethod
    def _ensure_bytes(content: Any) -> bytes:
        if isinstance(content, (bytes, bytearray)):
            return bytes(content)
        if isinstance(content, memoryview):
            return content.tobytes()
        if hasattr(content, "read"):
            handle = content  # type: ignore[assignment]
            chunk_size = 1024 * 1024
            data = bytearray()
            start = None
            try:
                start = handle.tell()  # type: ignore[attr-defined]
            except Exception:  # pragma: no cover - not all streams support tell
                start = None
            while True:
                chunk = handle.read(chunk_size)
                if not chunk:
                    break
                if isinstance(chunk, str):
                    chunk = chunk.encode("utf-8")
                elif isinstance(chunk, memoryview):
                    chunk = chunk.tobytes()
                elif not isinstance(chunk, (bytes, bytearray)):
                    chunk = str(chunk).encode("utf-8")
                data.extend(chunk)
            if start is not None:
                with suppress(Exception):  # pragma: no cover - best effort reset
                    handle.seek(start)  # type: ignore[attr-defined]
            return bytes(data)
        if isinstance(content, str):
            return content.encode("utf-8")
        return str(content).encode("utf-8")

    @staticmethod
    def _maybe_decode_base64(data: bytes) -> bytes:
        stripped = data.strip()
        if not stripped or len(stripped) % 4 != 0:
            return data
        try:
            decoded = base64.b64decode(stripped, validate=True)
        except (binascii.Error, ValueError):
            return data
        return decoded or data

    @staticmethod
    def _maybe_decompress(data: bytes) -> bytes:
        if data.startswith(b"\x1f\x8b"):
            try:
                return gzip.decompress(data)
            except OSError:
                return data
        buffer = io.BytesIO(data)
        if zipfile.is_zipfile(buffer):
            with zipfile.ZipFile(buffer) as archive:
                names = [name for name in archive.namelist() if not name.endswith("/")]
                priority = (
                    ".json",
                    ".sarif",
                    ".cdx",
                    ".spdx.json",
                    ".xml",
                )
                chosen: Optional[str] = None
                for suffix in priority:
                    for name in names:
                        if name.lower().endswith(suffix):
                            chosen = name
                            break
                    if chosen:
                        break
                if not chosen and names:
                    chosen = names[0]
                if chosen:
                    return archive.read(chosen)
        return data

    def _prepare_text(self, raw: Any) -> str:
        data = self._ensure_bytes(raw)
        data = self._maybe_decode_base64(data)
        data = self._maybe_decompress(data)
        if self.max_document_bytes and len(data) > self.max_document_bytes:
            raise ValueError(
                f"Input document exceeds maximum allowed size of {self.max_document_bytes} bytes"
            )
        return data.decode("utf-8", errors="ignore")

    def load_sbom(self, raw: Any) -> NormalizedSBOM:
        """Normalise an SBOM using lib4sbom or provider fallbacks."""

        payload = self._prepare_text(raw)
        last_error: Exception | None = None

        active_parser, import_error = _resolve_sbom_parser_state()
        if active_parser is not None:
            try:
                return self._load_sbom_with_lib4sbom(payload, active_parser)
            except Exception as exc:  # pragma: no cover - surface provider fallback
                last_error = exc

        provider_result = self._load_sbom_from_provider(payload)
        if provider_result is not None:
            logger.debug(
                "Normalised SBOM via provider parser",
                extra={
                    "metadata": provider_result.metadata,
                    "format": provider_result.format,
                },
            )
            return provider_result

        if active_parser is None:
            error_detail = "lib4sbom is not installed"
            if import_error is not None:
                error_detail = f"{error_detail}: {import_error}"
            raise RuntimeError(
                f"SBOM_PARSER_MISSING: Unable to parse SBOM without lib4sbom ({error_detail})."
            )

        if last_error is not None:
            raise last_error
        raise ValueError("Failed to parse SBOM document")

    def _load_sbom_with_lib4sbom(
        self, payload: str, parser_module: Any
    ) -> NormalizedSBOM:
        if parser_module is None:  # pragma: no cover - defensive guard
            raise RuntimeError("lib4sbom is not available")

        parser = parser_module.SBOMParser(self.sbom_type)
        parser.parse_string(payload)

        packages = parser.get_packages() or []
        components = []
        append_component = components.append
        for package in packages:
            licenses: Iterable[Any] = package.get("licenses", [])
            license_values = [
                item.get("license") if isinstance(item, dict) else str(item)
                for item in licenses
            ]
            supplier = package.get("supplier")
            if isinstance(supplier, dict):
                supplier_name = supplier.get("name")
            else:
                supplier_name = supplier

            append_component(
                SBOMComponent(
                    name=package.get("name", "unknown"),
                    version=package.get("version"),
                    purl=package.get("package_url") or package.get("purl"),
                    licenses=license_values,
                    supplier=supplier_name,
                    raw=package,
                )
            )

        relationships = parser.get_relationships() or []
        services = parser.get_services() or []
        vulnerabilities = parser.get_vulnerabilities() or []

        metadata = {
            "component_count": len(components),
            "relationship_count": len(relationships),
            "service_count": len(services),
            "vulnerability_count": len(vulnerabilities),
        }

        normalized = NormalizedSBOM(
            format=parser.get_type(),
            document=parser.get_document() or {},
            components=components,
            relationships=relationships,
            services=services,
            vulnerabilities=vulnerabilities,
            metadata=metadata,
        )
        logger.debug("Normalised SBOM", extra={"metadata": metadata})
        return normalized

    def _load_sbom_from_provider(self, payload: str) -> NormalizedSBOM | None:
        try:
            document = json.loads(
                payload
            )  # TODO: streaming parse for very large SBOM documents.
        except json.JSONDecodeError:
            return None

        for parser in (self._parse_github_dependency_snapshot, self._parse_syft_json):
            result = parser(document)
            if result is not None:
                return result
        return None

    def _parse_github_dependency_snapshot(
        self, document: dict[str, Any]
    ) -> NormalizedSBOM | None:
        manifests = document.get("detectedManifests")
        if not isinstance(manifests, dict) or not manifests:
            return None

        components: list[SBOMComponent] = []
        manifest_count = 0
        for manifest in manifests.values():
            if not isinstance(manifest, dict):
                continue
            manifest_count += 1
            resolved = manifest.get("resolved")
            if not isinstance(resolved, dict):
                continue
            for entry in resolved.values():
                if not isinstance(entry, dict):
                    continue
                name = (
                    entry.get("name")
                    or entry.get("packageName")
                    or entry.get("package")
                    or entry.get("packageIdentifier")
                )
                if not name:
                    continue
                version = entry.get("version") or entry.get("packageVersion")
                purl = entry.get("packageUrl") or entry.get("packageURL")

                licenses: Iterable[Any]
                license_value = entry.get("licenses") or entry.get("license")
                if isinstance(license_value, list):
                    licenses = [str(item) for item in license_value]
                elif license_value:
                    licenses = [str(license_value)]
                else:
                    licenses = []

                supplier_info = entry.get("source") or entry.get("publisher")
                supplier = None
                if isinstance(supplier_info, dict):
                    supplier = supplier_info.get("name")
                elif supplier_info:
                    supplier = str(supplier_info)

                components.append(
                    SBOMComponent(
                        name=str(name),
                        version=str(version) if version is not None else None,
                        purl=str(purl) if purl else None,
                        licenses=list(licenses),
                        supplier=supplier,
                        raw=entry,
                    )
                )

        if not components:
            return None

        metadata = {
            "component_count": len(components),
            "manifest_count": manifest_count,
            "parser": "github-dependency-snapshot",
        }
        return NormalizedSBOM(
            format="github-dependency-snapshot",
            document=document,
            components=components,
            relationships=[],
            services=[],
            vulnerabilities=document.get("vulnerabilities") or [],
            metadata=metadata,
        )

    def _parse_syft_json(self, document: dict[str, Any]) -> NormalizedSBOM | None:
        artifacts = document.get("artifacts")
        if not isinstance(artifacts, list) or not artifacts:
            return None

        components: list[SBOMComponent] = []
        for artifact in artifacts:
            if not isinstance(artifact, dict):
                continue
            name = artifact.get("name")
            if not name:
                continue
            version = artifact.get("version")
            purl = artifact.get("purl") or artifact.get("packageURL")

            licenses_raw = artifact.get("licenses")
            licenses: list[str] = []
            if isinstance(licenses_raw, list):
                for item in licenses_raw:
                    if isinstance(item, dict):
                        license_name = (
                            item.get("value")
                            or item.get("spdx-id")
                            or item.get("spdxId")
                        )
                        if license_name:
                            licenses.append(str(license_name))
                    elif item:
                        licenses.append(str(item))
            elif licenses_raw:
                licenses.append(str(licenses_raw))

            supplier = artifact.get("supplier") or artifact.get("origin")
            if isinstance(supplier, dict):
                supplier = supplier.get("name")

            components.append(
                SBOMComponent(
                    name=str(name),
                    version=str(version) if version is not None else None,
                    purl=str(purl) if purl else None,
                    licenses=licenses,
                    supplier=str(supplier) if supplier else None,
                    raw=artifact,
                )
            )

        if not components:
            return None

        relationships = document.get("artifactRelationships")
        if not isinstance(relationships, list):
            relationships = []

        vulnerabilities = document.get("vulnerabilities")
        if not isinstance(vulnerabilities, list):
            vulnerabilities = []

        metadata = {
            "component_count": len(components),
            "relationship_count": len(relationships),
            "parser": "syft-json",
        }
        if descriptor := document.get("descriptor"):
            if isinstance(descriptor, dict):
                metadata["descriptor_name"] = descriptor.get("name")
                metadata["descriptor_version"] = descriptor.get("version")

        return NormalizedSBOM(
            format="syft-json",
            document=document,
            components=components,
            relationships=relationships,
            services=[],
            vulnerabilities=vulnerabilities,
            metadata=metadata,
        )

    def load_cve_feed(self, raw: Any) -> NormalizedCVEFeed:
        """Normalise CVE/KEV feeds using cvelib for schema validation."""

        payload = self._prepare_text(raw)
        data = json.loads(payload)

        if isinstance(data, dict):
            entries = (
                data.get("vulnerabilities")
                or data.get("cves")
                or data.get("data")
                or []
            )
        elif isinstance(data, list):
            entries = data
        else:
            raise ValueError("Unsupported CVE feed structure")

        records: List[CVERecordSummary] = []
        errors: List[str] = []

        for entry in entries:
            if not isinstance(entry, dict):
                errors.append(f"Skipping non-dict entry: {entry!r}")
                continue

            validation_error: Optional[str] = None
            if CveRecord:
                try:
                    # Accept either CNA container or full CVE document
                    record = entry
                    if "containers" in entry:
                        record = entry
                    elif "cnaContainer" in entry:
                        record = {"containers": {"cna": entry["cnaContainer"]}}
                    CveRecord.validate(record)  # type: ignore[arg-type]
                except CveRecordValidationError as exc:  # type: ignore[misc]
                    validation_error = str(exc)
                except Exception as exc:  # pragma: no cover - defensive guard
                    validation_error = str(exc)

            if validation_error:
                errors.append(validation_error)

            cve_id = (
                entry.get("cveID")
                or entry.get("cve_id")
                or entry.get("id")
                or entry.get("cve", {}).get("cveId")
                or "UNKNOWN"
            )
            title = (
                entry.get("shortDescription")
                or entry.get("title")
                or entry.get("summary")
                or entry.get("cve", {}).get("descriptions", [{}])[0].get("value")
                if isinstance(entry.get("cve"), dict)
                else None
            )
            severity = entry.get("severity") or entry.get("cvssV3Severity")
            if not severity:
                impact = entry.get("impact", {})
                if isinstance(impact, dict):
                    metric = impact.get("baseMetricV3", {})
                    if isinstance(metric, dict):
                        severity = metric.get("baseSeverity")
            exploited = bool(
                entry.get("knownRansomwareCampaignUse")
                or entry.get("knownExploited")
                or entry.get("exploited")
            )

            records.append(
                CVERecordSummary(
                    cve_id=cve_id,
                    title=title,
                    severity=severity,
                    exploited=exploited,
                    raw=entry,
                )
            )

        metadata = {"record_count": len(records)}
        if errors:
            metadata["validation_errors"] = len(errors)

        normalized = NormalizedCVEFeed(
            records=records, errors=errors, metadata=metadata
        )
        logger.debug("Normalised CVE feed", extra={"metadata": metadata})
        return normalized

    def load_sarif(self, raw: Any) -> NormalizedSARIF:
        """Normalise SARIF logs via sarif-om with optional Snyk conversion."""

        payload = self._prepare_text(raw)
        data = json.loads(
            payload
        )  # TODO: support streaming parse for very large SARIF inputs.
        original_data = data

        runs = data.get("runs") if isinstance(data, dict) else None
        schema_uri = data.get("$schema") if isinstance(data, dict) else None

        if (not runs) and isinstance(data, dict):
            for key in ("sarif", "sarifLog", "sarif_log"):
                if key not in data:
                    continue
                embedded = data[key]
                if isinstance(embedded, str):
                    try:
                        embedded = json.loads(embedded)
                    except json.JSONDecodeError:
                        logger.debug(
                            "Failed to parse embedded SARIF payload",
                            extra={"source_key": key},
                        )
                        continue
                if isinstance(embedded, dict):
                    data = embedded
                    runs = data.get("runs")
                    schema_uri = schema_uri or data.get("$schema")
                    break

        if (not runs) and snyk_converter is not None:
            convert = getattr(snyk_converter, "convert", None) or getattr(
                snyk_converter, "to_sarif", None
            )
            if convert:
                data = convert(original_data)  # type: ignore[misc]
                runs = data.get("runs") if isinstance(data, dict) else None
                if not schema_uri and isinstance(data, dict):
                    schema_uri = data.get("$schema")

        if (not runs) and isinstance(original_data, Mapping):
            fallback_document = _convert_snyk_payload_to_sarif(original_data)
            if fallback_document:
                data = fallback_document
                runs = data.get("runs") if isinstance(data, Mapping) else None
                if not schema_uri and isinstance(data, Mapping):
                    schema_uri = data.get("$schema")
                result_count = 0
                if isinstance(runs, list):
                    for run in runs:
                        if isinstance(run, Mapping):
                            entries = run.get("results")
                            if isinstance(entries, list):
                                result_count += len(entries)
                logger.info(
                    "Converted Snyk JSON payload via built-in fallback",
                    extra={"finding_count": result_count},
                )

        if not runs:
            if isinstance(original_data, dict) and snyk_converter is None:
                snyk_markers = {
                    "issues",
                    "vulnerabilities",
                    "applications",
                    "projects",
                    "ok",
                }
                matched = snyk_markers.intersection(original_data.keys())
                if matched:
                    logger.error(
                        "Snyk JSON payload detected but snyk-to-sarif is not installed. "
                        "Install it via `pip install snyk-to-sarif` or upload SARIF directly.",
                        extra={"markers": sorted(matched)},
                    )
            raise ValueError("The provided document is not a valid SARIF log")

        sarif_log = SarifLog(
            runs=runs,
            version=data.get("version", "2.1.0"),
            schema_uri=schema_uri or data.get("$schema"),
            properties=data.get("properties"),
        )

        findings: List[SarifFinding] = []
        validated_findings: List[SarifFindingSchema] = []
        tool_names: List[str] = []

        for run in runs:
            tool = (
                (run.get("tool") or {}).get("driver", {})
                if isinstance(run, dict)
                else {}
            )
            tool_name = tool.get("name")
            if isinstance(tool_name, str) and tool_name.strip():
                tool_names.append(tool_name.strip())

            results = run.get("results") if isinstance(run, dict) else None
            for result in results or []:
                rule_id_value = result.get("ruleId")
                rule_id: str | None = None
                if isinstance(rule_id_value, str):
                    rule_id = rule_id_value.strip()
                elif rule_id_value is not None:
                    rule_id = str(rule_id_value).strip()

                message = None
                if "message" in result:
                    raw_message = result["message"]
                    if isinstance(raw_message, Mapping):
                        candidate_text = raw_message.get("text")
                        if isinstance(candidate_text, str):
                            message = candidate_text
                    elif raw_message is not None:
                        message = str(raw_message)

                location = (result.get("locations") or [{}])[0]
                physical = location.get("physicalLocation", {})
                artifact = physical.get("artifactLocation", {})
                region = physical.get("region", {})
                level_value = result.get("level")
                level = level_value.lower() if isinstance(level_value, str) else None

                file_path = artifact.get("uri")
                if file_path is not None and not isinstance(file_path, str):
                    file_path = str(file_path)

                line_value = region.get("startLine")
                line_number: int | None = None
                if isinstance(line_value, int):
                    line_number = line_value
                elif isinstance(line_value, str):
                    stripped_line = line_value.strip()
                    if stripped_line.isdigit():
                        line_number = int(stripped_line)

                try:
                    validated = SarifFindingSchema(
                        rule_id=rule_id,
                        message=message,
                        level=level,
                        file=file_path,
                        line=line_number,
                    )
                except ValidationError as exc:
                    raise ValueError("SARIF result failed validation") from exc

                validated_findings.append(validated)
                findings.append(
                    SarifFinding(
                        rule_id=validated.rule_id,
                        message=validated.message,
                        level=validated.level,
                        file=validated.file,
                        line=validated.line,
                        raw=result,
                    )
                )

        metadata = {
            "run_count": len(runs),
            "finding_count": len(findings),
        }
        schema_key = sarif_log.schema_uri
        if isinstance(schema_key, str):
            metadata["supported_schema"] = schema_key.lower() in SUPPORTED_SARIF_SCHEMAS
        if tool_names:
            metadata["tool_count"] = len(tool_names)

        try:
            NormalizedSarifSchema(
                version=str(sarif_log.version),
                schema_uri=(
                    str(sarif_log.schema_uri)
                    if isinstance(sarif_log.schema_uri, str)
                    else None
                ),
                tool_names=tool_names,
                findings=validated_findings,
                metadata=metadata,
            )
        except ValidationError as exc:
            raise ValueError("Normalised SARIF payload failed validation") from exc

        normalized = NormalizedSARIF(
            version=str(sarif_log.version),
            schema_uri=(
                str(sarif_log.schema_uri)
                if isinstance(sarif_log.schema_uri, str)
                else sarif_log.schema_uri
            ),
            tool_names=tool_names,
            findings=findings,
            metadata=metadata,
        )
        logger.debug("Normalised SARIF", extra={"metadata": metadata})
        return normalized

    def load_vex(self, raw: Any) -> NormalizedVEX:
        """Parse a CycloneDX VEX document and extract actionable assertions."""

        payload = self._prepare_text(raw)
        try:
            document = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise ValueError("The provided VEX document is not valid JSON") from exc

        vulnerabilities = document.get("vulnerabilities")
        assertions: List[VEXAssertion] = []
        if isinstance(vulnerabilities, Iterable):
            for entry in vulnerabilities:
                if not isinstance(entry, Mapping):
                    continue
                vuln_id = str(
                    entry.get("id") or entry.get("vulnerability") or "unknown"
                )
                analysis = (
                    entry.get("analysis")
                    if isinstance(entry.get("analysis"), Mapping)
                    else {}
                )
                state = str(
                    analysis.get("state") or analysis.get("status") or "unknown"
                ).lower()
                detail = analysis.get("detail")
                affects = entry.get("affects")
                if not isinstance(affects, Iterable):
                    affects = []
                for target in affects:
                    ref = None
                    if isinstance(target, Mapping):
                        ref = target.get("ref") or target.get("name")
                    elif target:
                        ref = str(target)
                    if not ref:
                        continue
                    assertions.append(
                        VEXAssertion(
                            vulnerability_id=vuln_id,
                            ref=str(ref),
                            status=state,
                            detail=str(detail) if detail else None,
                        )
                    )

        metadata = {
            "assertion_count": len(assertions),
            "not_affected_count": sum(
                1 for assertion in assertions if assertion.status == "not_affected"
            ),
        }
        return NormalizedVEX(assertions=assertions, metadata=metadata)

    def load_cnapp(self, raw: Any) -> NormalizedCNAPP:
        """Normalise CNAPP asset inventory and findings payloads."""

        payload = self._prepare_text(raw)
        try:
            document = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise ValueError("The provided CNAPP document is not valid JSON") from exc

        raw_assets = document.get("assets") if isinstance(document, Mapping) else None
        assets: List[CNAPPAsset] = []
        if isinstance(raw_assets, Iterable):
            for entry in raw_assets:
                if not isinstance(entry, Mapping):
                    continue
                asset_id = entry.get("id") or entry.get("asset")
                if not asset_id:
                    continue
                attributes = {
                    key: value
                    for key, value in entry.items()
                    if key not in {"id", "asset"}
                }
                assets.append(CNAPPAsset(asset_id=str(asset_id), attributes=attributes))

        raw_findings = (
            document.get("findings") if isinstance(document, Mapping) else None
        )
        findings: List[CNAPPFinding] = []
        if isinstance(raw_findings, Iterable):
            for entry in raw_findings:
                if not isinstance(entry, Mapping):
                    continue
                asset = entry.get("asset") or entry.get("target")
                severity = str(
                    entry.get("sev") or entry.get("severity") or "low"
                ).lower()
                finding_type = entry.get("type") or entry.get("category") or "finding"
                if not asset:
                    continue
                findings.append(
                    CNAPPFinding(
                        asset=str(asset),
                        finding_type=str(finding_type),
                        severity=severity,
                        raw=dict(entry),
                    )
                )

        metadata = {
            "asset_count": len(assets),
            "finding_count": len(findings),
        }
        return NormalizedCNAPP(assets=assets, findings=findings, metadata=metadata)

    def _parse_business_payload(
        self, text: str, content_type: Optional[str]
    ) -> Tuple[Any, str]:
        """Return the decoded document and detected format."""

        preferred_type = (content_type or "").lower()
        document: Any = None
        source = "unknown"
        try:
            document = json.loads(text)
            source = "json"
        except json.JSONDecodeError:
            if yaml is None:
                raise ValueError(
                    "Business context payload is not valid JSON and PyYAML is unavailable"
                )
            document = yaml.safe_load(text)
            source = "yaml"
        if document is None:
            raise ValueError("Business context payload was empty")
        if preferred_type:
            source = preferred_type.split(";")[0]
        if isinstance(document, list) and document:
            document = document[0]
        if not isinstance(document, Mapping):
            raise ValueError("Business context payload must decode to a mapping")
        return document, source

    @staticmethod
    def _normalise_ssvc(mapping: Mapping[str, Any]) -> Dict[str, Any]:
        defaults = {
            "exploitation": "none",
            "exposure": "controlled",
            "utility": "efficient",
            "safety_impact": "negligible",
            "mission_impact": "degraded",
        }
        ssvc: Dict[str, Any] = dict(defaults)
        for key in defaults:
            value = mapping.get(key)
            if isinstance(value, str) and value.strip():
                ssvc[key] = value.strip().lower()
        return ssvc

    def _from_fixops_context(
        self, document: Mapping[str, Any], source: str
    ) -> NormalizedBusinessContext:
        components = []
        for entry in document.get("components", []) or []:
            if isinstance(entry, Mapping):
                components.append({k: v for k, v in entry.items() if v is not None})
        ssvc_payload = (
            document.get("ssvc") if isinstance(document.get("ssvc"), Mapping) else {}
        )
        ssvc = self._normalise_ssvc(ssvc_payload)
        metadata = {
            "component_count": len(components),
            "source": source,
            "profile": document.get("profile"),
        }
        return NormalizedBusinessContext(
            format="fixops.yaml" if source.endswith("yaml") else "fixops.json",
            components=components,
            ssvc=ssvc,
            metadata=metadata,
            raw=dict(document),
        )

    def _from_otm(
        self, document: Mapping[str, Any], source: str
    ) -> NormalizedBusinessContext:
        components = []
        otm_components = (
            document.get("components")
            if isinstance(document.get("components"), Iterable)
            else []
        )
        for entry in otm_components:
            if not isinstance(entry, Mapping):
                continue
            node = {
                "name": entry.get("name"),
                "type": entry.get("type"),
                "trust_zone": (
                    entry.get("parent", {}).get("trustZone")
                    if isinstance(entry.get("parent"), Mapping)
                    else None
                ),
                "tags": entry.get("tags"),
            }
            data_assets = (
                entry.get("data") if isinstance(entry.get("data"), Iterable) else []
            )
            if data_assets:
                classifications = []
                for asset in data_assets:
                    if isinstance(asset, Mapping) and asset.get("classification"):
                        classifications.append(asset["classification"])
                if classifications:
                    node["data_classification"] = ",".join(
                        str(value) for value in classifications
                    )
            components.append({k: v for k, v in node.items() if v is not None})

        trust_zones = (
            document.get("trustZones")
            if isinstance(document.get("trustZones"), Iterable)
            else []
        )
        highest_trust = 0
        for zone in trust_zones:
            if not isinstance(zone, Mapping):
                continue
            rating = (
                zone.get("risk", {}).get("trustRating")
                if isinstance(zone.get("risk"), Mapping)
                else None
            )
            try:
                rating_value = int(rating)
            except (TypeError, ValueError):
                continue
            highest_trust = max(highest_trust, rating_value)
        ssvc = self._normalise_ssvc(
            {
                "exposure": "open" if highest_trust <= 3 else "controlled",
                "mission_impact": "mev" if highest_trust <= 3 else "degraded",
            }
        )
        metadata = {
            "component_count": len(components),
            "trust_zones": len(list(trust_zones)),
            "source": source,
        }
        return NormalizedBusinessContext(
            format="otm.json",
            components=components,
            ssvc=ssvc,
            metadata=metadata,
            raw=dict(document),
        )

    def _from_ssvc(
        self, document: Mapping[str, Any], source: str
    ) -> NormalizedBusinessContext:
        ssvc = self._normalise_ssvc(document)
        metadata = {"source": source}
        return NormalizedBusinessContext(
            format="ssvc.yaml" if source.endswith("yaml") else "ssvc.json",
            components=[],
            ssvc=ssvc,
            metadata=metadata,
            raw=dict(document),
        )

    def load_business_context(
        self, raw: Any, *, content_type: Optional[str] = None
    ) -> NormalizedBusinessContext:
        """Parse FixOps business context, OTM JSON, or SSVC YAML inputs."""

        payload = self._prepare_text(raw)
        document, source = self._parse_business_payload(payload, content_type)
        if "otm" in (document.get("format") or "").lower() or document.get(
            "otmVersion"
        ):
            return self._from_otm(document, source)
        if document.get("components") and document.get("ssvc"):
            return self._from_fixops_context(document, source)
        required_ssvc_keys = {
            "exploitation",
            "exposure",
            "utility",
            "safety_impact",
            "mission_impact",
        }
        if required_ssvc_keys.intersection(document.keys()) == required_ssvc_keys:
            return self._from_ssvc(document, source)
        # Attempt to coerce legacy FixOps structures
        if document.get("business_context"):
            nested = document.get("business_context")
            if isinstance(nested, Mapping):
                return self._from_fixops_context(nested, source)
        raise ValueError(
            "Unsupported business context document; expected FixOps, OTM, or SSVC payload"
        )
