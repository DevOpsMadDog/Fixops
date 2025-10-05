from __future__ import annotations

from __future__ import annotations

import base64
import binascii
import gzip
import io
import json
import logging
import zipfile
from dataclasses import dataclass, field, asdict
from typing import Any, Iterable, List, Optional

from lib4sbom import parser as sbom_parser

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
except ImportError as exc:  # pragma: no cover - sarif-om is declared but highlight failure early
    raise RuntimeError(
        "sarif-om must be available to normalise SARIF inputs."
    ) from exc

SUPPORTED_SARIF_SCHEMAS = {
    "https://json.schemastore.org/sarif-2.1.0.json",
    "http://json.schemastore.org/sarif-2.1.0.json",
    "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
}


logger = logging.getLogger(__name__)


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


class InputNormalizer:
    """Normalise artefacts using dedicated OSS parsers."""

    def __init__(self, sbom_type: str = "auto") -> None:
        self.sbom_type = sbom_type

    @staticmethod
    def _ensure_bytes(content: Any) -> bytes:
        if isinstance(content, bytes):
            return content
        if hasattr(content, "read"):
            data = content.read()
            if isinstance(data, bytes):
                return data
            return str(data).encode("utf-8")
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
        return data.decode("utf-8", errors="ignore")

    def load_sbom(self, raw: Any) -> NormalizedSBOM:
        """Normalise an SBOM using lib4sbom."""

        payload = self._prepare_text(raw)
        parser = sbom_parser.SBOMParser(self.sbom_type)
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
                or entry.get("cve", {})
                .get("descriptions", [{}])[0]
                .get("value")
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

        normalized = NormalizedCVEFeed(records=records, errors=errors, metadata=metadata)
        logger.debug("Normalised CVE feed", extra={"metadata": metadata})
        return normalized

    def load_sarif(self, raw: Any) -> NormalizedSARIF:
        """Normalise SARIF logs via sarif-om with optional Snyk conversion."""

        payload = self._prepare_text(raw)
        data = json.loads(payload)
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
                            "Failed to parse embedded SARIF payload", extra={"source_key": key}
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

        if not runs:
            if isinstance(original_data, dict) and snyk_converter is None:
                snyk_markers = {"issues", "vulnerabilities", "applications", "projects", "ok"}
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
        tool_names: List[str] = []

        for run in runs:
            tool = (run.get("tool") or {}).get("driver", {}) if isinstance(run, dict) else {}
            tool_name = tool.get("name")
            if tool_name:
                tool_names.append(tool_name)

            results = run.get("results") if isinstance(run, dict) else None
            for result in results or []:
                message = None
                if "message" in result:
                    if isinstance(result["message"], dict):
                        message = result["message"].get("text")
                    else:
                        message = str(result["message"])

                location = (result.get("locations") or [{}])[0]
                physical = location.get("physicalLocation", {})
                artifact = physical.get("artifactLocation", {})
                region = physical.get("region", {})

                findings.append(
                    SarifFinding(
                        rule_id=result.get("ruleId"),
                        message=message,
                        level=result.get("level"),
                        file=artifact.get("uri"),
                        line=region.get("startLine"),
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

        normalized = NormalizedSARIF(
            version=sarif_log.version,
            schema_uri=sarif_log.schema_uri,
            tool_names=tool_names,
            findings=findings,
            metadata=metadata,
        )
        logger.debug("Normalised SARIF", extra={"metadata": metadata})
        return normalized
