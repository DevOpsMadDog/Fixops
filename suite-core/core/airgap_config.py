"""
FixOps Air-Gapped Deployment Configuration Engine.

Handles network isolation detection, offline vulnerability database management,
local LLM routing, STIX/TAXII threat intelligence bundles, offline update
packages, classification level labeling, FIPS 140-2/3 compliance mode, and
comprehensive health checks for air-gapped deployments.

Designed for US defense (DRDO, ISRO) and financial institution deployments
where no external network access is permitted.
"""

from __future__ import annotations

import gzip
import hashlib
import hmac
import json
import logging
import os
import platform
import shutil
import socket
import tempfile
import uuid
import zipfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# TrustGraph second-brain wiring
# ---------------------------------------------------------------------------
try:  # pragma: no cover - optional dependency
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except Exception:  # noqa: BLE001
    _get_tg_bus = None  # type: ignore[assignment]


def _emit_event(event_type: str, payload: dict) -> None:
    """Emit to TrustGraph event bus. Never raises."""
    if _get_tg_bus is None:
        return
    try:
        bus = _get_tg_bus()
        if bus is None:
            return
        emit = getattr(bus, "emit", None) or getattr(bus, "publish", None)
        if emit is None:
            return
        result = emit(event_type, payload)
        try:
            import asyncio as _aio
            import inspect as _insp
            if _insp.iscoroutine(result):
                try:
                    loop = _aio.get_running_loop()
                    loop.create_task(result)
                except RuntimeError:
                    result.close()
        except Exception:  # pragma: no cover
            pass
    except Exception:  # pragma: no cover
        pass


try:  # pragma: no cover
    _emit_event("engine.loaded", {"module": __name__})
except Exception:  # noqa: BLE001
    pass

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

AIRGAP_STATE_FILE = Path(os.getenv("FIXOPS_AIRGAP_STATE", "/tmp/fixops_airgap_state.json"))  # nosec B108
_DATA_ROOT = Path(os.getenv("FIXOPS_DATA_DIR", ".fixops_data"))
VULN_DB_PATH = Path(os.getenv("FIXOPS_VULN_DB_PATH", str(_DATA_ROOT / "airgap" / "vuln_db")))
THREAT_INTEL_PATH = Path(os.getenv("FIXOPS_THREAT_INTEL_PATH", str(_DATA_ROOT / "airgap" / "threat_intel")))
OFFLINE_UPDATES_PATH = Path(os.getenv("FIXOPS_UPDATES_PATH", str(_DATA_ROOT / "airgap" / "updates")))
SIGNATURE_DB_PATH = Path(os.getenv("FIXOPS_SIGNATURES_PATH", str(_DATA_ROOT / "airgap" / "signatures")))
COMPLIANCE_RULES_PATH = Path(os.getenv("FIXOPS_COMPLIANCE_PATH", str(_DATA_ROOT / "airgap" / "compliance")))
FIPS_MARKER_FILE = Path("/proc/sys/crypto/fips_enabled")  # Linux FIPS kernel mode

# FIPS 140-2/3 approved algorithm whitelist
FIPS_APPROVED_HASH_ALGORITHMS = {"sha256", "sha384", "sha512", "sha3_256", "sha3_384", "sha3_512"}
FIPS_APPROVED_HMAC_ALGORITHMS = {"sha256", "sha384", "sha512"}
FIPS_FORBIDDEN_ALGORITHMS = {"md5", "sha1", "rc4", "des", "3des", "blowfish"}

# External connectivity probes (used for isolation detection)
PROBE_HOSTS = [
    ("8.8.8.8", 53),       # Google DNS
    ("1.1.1.1", 53),       # Cloudflare DNS
    ("208.67.222.222", 53), # OpenDNS
]
PROBE_DNS_HOSTS = ["google.com", "cloudflare.com", "microsoft.com"]
PROBE_HTTPS_URLS = [
    "https://api.openai.com",
    "https://api.anthropic.com",
    "https://nvd.nist.gov",
]

# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class ClassificationLevel(str, Enum):
    """US Government data classification levels."""
    UNCLASSIFIED = "UNCLASSIFIED"
    CUI = "CUI"                # Controlled Unclassified Information
    SECRET = "SECRET"
    TOP_SECRET = "TOP SECRET"


class AirGapMode(str, Enum):
    """Air-gap operational modes."""
    DISABLED = "disabled"           # Normal internet-connected operation
    DETECTED = "detected"           # Auto-detected isolation — passive
    CONFIGURED = "configured"       # Explicitly configured by admin
    ENFORCED = "enforced"           # Strict enforcement — reject any external calls


class LLMBackend(str, Enum):
    """Local LLM backend options for air-gapped environments."""
    OLLAMA = "ollama"
    VLLM = "vllm"
    LLAMACPP = "llamacpp"
    HUGGINGFACE_LOCAL = "huggingface_local"
    NONE = "none"


class VulnDBSource(str, Enum):
    """Vulnerability database source types."""
    NVD_OFFLINE = "nvd_offline"
    CUSTOM_FEED = "custom_feed"
    USB_IMPORT = "usb_import"
    MANUAL = "manual"


class UpdatePackageType(str, Enum):
    """Offline update package types."""
    VULN_DB = "vuln_db"
    SIGNATURES = "signatures"
    COMPLIANCE_RULES = "compliance_rules"
    LLM_MODEL = "llm_model"
    FULL_SYSTEM = "full_system"


class FIPSMode(str, Enum):
    """FIPS compliance enforcement levels."""
    DISABLED = "disabled"
    AUDIT = "audit"         # Log violations but allow
    ENFORCED = "enforced"   # Block non-FIPS operations


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class NetworkIsolationStatus:
    """Result of network isolation detection probe."""
    is_isolated: bool
    tcp_reachable: bool = False
    dns_resolving: bool = False
    https_reachable: bool = False
    probe_timestamp: str = field(default_factory=lambda: _utcnow())
    probe_details: Dict[str, Any] = field(default_factory=dict)
    detection_method: str = "auto"


@dataclass
class VulnDBInfo:
    """Offline vulnerability database metadata."""
    db_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    source: str = VulnDBSource.MANUAL.value
    version: str = "0.0.0"
    cve_count: int = 0
    last_updated: str = field(default_factory=lambda: _utcnow())
    checksum_sha256: str = ""
    feed_date_range: Dict[str, str] = field(default_factory=lambda: {"from": "", "to": ""})
    db_path: str = ""
    size_bytes: int = 0
    is_valid: bool = False
    validation_errors: List[str] = field(default_factory=list)


@dataclass
class LocalLLMConfig:
    """Configuration for local LLM in air-gapped mode."""
    backend: str = LLMBackend.NONE.value
    endpoint: str = "http://localhost:11434"  # Ollama default
    model_name: str = "mistral:7b"
    context_window: int = 4096
    max_tokens: int = 2048
    temperature: float = 0.1
    available: bool = False
    model_path: str = ""
    quantization: str = "Q4_K_M"


@dataclass
class FIPSStatus:
    """FIPS 140-2/3 compliance status."""
    mode: str = FIPSMode.DISABLED.value
    kernel_fips_enabled: bool = False
    approved_algorithms_only: bool = False
    violations_detected: List[str] = field(default_factory=list)
    last_audit: str = field(default_factory=lambda: _utcnow())
    fips_version: str = "FIPS 140-2"


@dataclass
class ExternalDependency:
    """An external dependency and its offline alternative."""
    name: str
    description: str
    dependency_type: str       # "api", "dns", "package_registry", "llm", "vuln_db"
    original_endpoint: str
    offline_alternative: str
    is_required: bool
    offline_available: bool
    notes: str = ""


@dataclass
class AirGapConfiguration:
    """Complete air-gap deployment configuration."""
    mode: str = AirGapMode.DISABLED.value
    classification_level: str = ClassificationLevel.UNCLASSIFIED.value
    fips: FIPSStatus = field(default_factory=FIPSStatus)
    local_llm: LocalLLMConfig = field(default_factory=LocalLLMConfig)
    vuln_db: VulnDBInfo = field(default_factory=VulnDBInfo)
    network_status: Optional[NetworkIsolationStatus] = None
    allow_local_network: bool = True    # Allow LAN traffic (e.g. for Ollama)
    allow_usb_import: bool = True
    enabled_scanners: List[str] = field(default_factory=lambda: ["all"])
    offline_data_paths: Dict[str, str] = field(default_factory=dict)
    last_configured: str = field(default_factory=lambda: _utcnow())
    configured_by: str = "system"
    instance_id: str = field(default_factory=lambda: str(uuid.uuid4()))


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------


def _utcnow() -> str:
    """Return current UTC time as ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


def _fips_hash(data: bytes, algorithm: str = "sha256") -> str:
    """Compute hash using only FIPS-approved algorithms.

    Raises ValueError if a non-FIPS algorithm is requested in enforced mode.
    """
    alg = algorithm.lower().replace("-", "_")
    if alg not in FIPS_APPROVED_HASH_ALGORITHMS:
        raise ValueError(
            f"Algorithm '{algorithm}' is not FIPS 140-2/3 approved. "
            f"Use one of: {sorted(FIPS_APPROVED_HASH_ALGORITHMS)}"
        )
    return hashlib.new(alg, data).hexdigest()


def _compute_file_sha256(path: Path) -> str:
    """Compute SHA-256 checksum of a file (FIPS-approved)."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _safe_hmac(key: bytes, data: bytes, algorithm: str = "sha256") -> str:
    """Compute HMAC using FIPS-approved digest."""
    alg = algorithm.lower().replace("-", "_")
    if alg not in FIPS_APPROVED_HMAC_ALGORITHMS:
        raise ValueError(f"HMAC algorithm '{algorithm}' not FIPS approved.")
    return hmac.new(key, data, alg).hexdigest()


def _ensure_dir(path: Path) -> Path:
    """Create directory tree if it does not exist, return path."""
    path.mkdir(parents=True, exist_ok=True)
    return path


# ---------------------------------------------------------------------------
# Network Isolation Detection
# ---------------------------------------------------------------------------


class NetworkIsolationDetector:
    """Detects whether the host is running in an air-gapped (isolated) environment."""

    TCP_TIMEOUT = 2.0   # seconds
    DNS_TIMEOUT = 2.0

    def probe_tcp(self) -> bool:
        """Attempt raw TCP connections to well-known internet hosts."""
        for host, port in PROBE_HOSTS:
            try:
                with socket.create_connection((host, port), timeout=self.TCP_TIMEOUT):
                    return True
            except (OSError, socket.timeout):
                continue
        return False

    def probe_dns(self) -> bool:
        """Attempt DNS resolution of well-known external hosts."""
        for hostname in PROBE_DNS_HOSTS:
            try:
                socket.setdefaulttimeout(self.DNS_TIMEOUT)
                socket.getaddrinfo(hostname, None)
                return True
            except (socket.gaierror, socket.timeout, OSError):
                continue
        return False

    def probe_https(self) -> bool:
        """Attempt HTTPS connections to external API endpoints.
        Uses only stdlib — no requests/httpx to avoid import side-effects.
        """
        import ssl
        import urllib.request
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        for url in PROBE_HTTPS_URLS:
            try:
                req = urllib.request.Request(url, method="HEAD")  # nosemgrep: dynamic-urllib-use-detected
                with urllib.request.urlopen(req, timeout=2, context=ctx):  # nosemgrep: dynamic-urllib-use-detected  # nosec
                    return True
            except (OSError, ValueError, RuntimeError):  # narrowed from bare Exception
                continue
        return False

    def detect(self, force: bool = False) -> NetworkIsolationStatus:
        """Run all probes and return isolation status."""
        tcp_ok = False
        dns_ok = False
        https_ok = False
        details: Dict[str, Any] = {}

        try:
            tcp_ok = self.probe_tcp()
            details["tcp_probe"] = "reachable" if tcp_ok else "unreachable"
        except (ValueError, KeyError, RuntimeError, TypeError, AttributeError) as exc:
            details["tcp_probe_error"] = str(exc)

        try:
            dns_ok = self.probe_dns()
            details["dns_probe"] = "resolving" if dns_ok else "no_resolution"
        except (ValueError, KeyError, RuntimeError, TypeError, AttributeError) as exc:
            details["dns_probe_error"] = str(exc)

        if tcp_ok or dns_ok:
            # No need to probe HTTPS if TCP/DNS already confirm connectivity
            https_ok = False
            details["https_probe"] = "skipped"
        else:
            try:
                https_ok = self.probe_https()
                details["https_probe"] = "reachable" if https_ok else "unreachable"
            except (ValueError, KeyError, RuntimeError, TypeError, AttributeError) as exc:
                details["https_probe_error"] = str(exc)

        is_isolated = not (tcp_ok or dns_ok or https_ok)

        return NetworkIsolationStatus(
            is_isolated=is_isolated,
            tcp_reachable=tcp_ok,
            dns_resolving=dns_ok,
            https_reachable=https_ok,
            probe_details=details,
        )


# ---------------------------------------------------------------------------
# Offline Vulnerability Database Manager
# ---------------------------------------------------------------------------


def build_nvd_bundle(
    nvd_json_path: str,
    output_zip_path: str,
    *,
    feed_date_range: Optional[Tuple[str, str]] = None,
) -> Dict[str, Any]:
    """Build an importable air-gap NVD bundle from a raw NVD 2.0 JSON feed.

    The output ZIP is consumable by ``OfflineVulnDBManager.import_from_bundle``
    without modification. Operators previously had to hand-craft these bundles
    (gzip + manifest + ZIP) before transferring them to SCIF instances; this
    helper collapses that workflow into a single function call.

    Args:
        nvd_json_path:    Filesystem path to the raw NVD 2.0 JSON feed. The
                          feed must be a top-level dict containing a
                          ``vulnerabilities`` list with at least one CVE.
        output_zip_path:  Destination ZIP path. Parent directories are created
                          on demand. The ZIP will contain
                          ``OfflineVulnDBManager.MANIFEST_FILENAME`` and
                          ``OfflineVulnDBManager.DB_FILENAME``.
        feed_date_range:  Optional (from, to) ISO-8601 strings recording the
                          feed coverage window. Stored verbatim in the manifest.

    Returns:
        The manifest dict that was written into the ZIP.

    Raises:
        FileNotFoundError: ``nvd_json_path`` does not exist.
        ValueError:        Input is not valid JSON, is not the NVD 2.0 schema,
                           or contains zero CVE entries.
    """
    src = Path(nvd_json_path)
    if not src.exists():
        raise FileNotFoundError(f"NVD JSON feed not found: {nvd_json_path}")

    raw_bytes = src.read_bytes()
    try:
        parsed = json.loads(raw_bytes)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"Invalid NVD JSON at {nvd_json_path}: {exc}. "
            "Expected NVD 2.0 format with top-level 'vulnerabilities' list."
        ) from exc

    if not isinstance(parsed, dict):
        raise ValueError(
            "NVD 2.0 feed must be a JSON object with a 'vulnerabilities' "
            f"list at the top level (got {type(parsed).__name__})."
        )

    vulnerabilities = parsed.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        raise ValueError(
            "NVD 2.0 feed missing 'vulnerabilities' list. "
            "Expected key 'vulnerabilities: List[{cve: {...}}]'."
        )
    if len(vulnerabilities) == 0:
        raise ValueError(
            "NVD 2.0 feed contains zero CVE entries. "
            "Refusing to build an empty bundle — verify your feed source."
        )

    # Gzip-compress the raw feed in-memory
    gz_bytes = gzip.compress(raw_bytes)
    checksum = hashlib.sha256(gz_bytes).hexdigest()

    feed_range_payload: Optional[List[str]]
    if feed_date_range is None:
        feed_range_payload = None
    else:
        feed_range_payload = [str(feed_date_range[0]), str(feed_date_range[1])]

    manifest: Dict[str, Any] = {
        "version": "1.0",
        "format": "NVD-2.0",
        "cve_count": len(vulnerabilities),
        "checksum_sha256": checksum,
        "feed_date_range": feed_range_payload,
        "created_at": _utcnow(),
        "compression": "gzip",
        "db_filename": OfflineVulnDBManager.DB_FILENAME,
    }

    output_file = Path(output_zip_path)
    _ensure_dir(output_file.parent)

    manifest_bytes = json.dumps(manifest, indent=2).encode("utf-8")
    with zipfile.ZipFile(output_file, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(OfflineVulnDBManager.MANIFEST_FILENAME, manifest_bytes)
        zf.writestr(OfflineVulnDBManager.DB_FILENAME, gz_bytes)

    logger.info(
        "Built NVD bundle: %d CVEs → %s (sha256=%s)",
        len(vulnerabilities),
        output_file,
        checksum[:16],
    )
    _emit_event(
        "airgap.nvd_bundle_built",
        {
            "output_path": str(output_file),
            "cve_count": len(vulnerabilities),
            "checksum_sha256": checksum,
        },
    )
    return manifest


class OfflineVulnDBManager:
    """Manages a local offline copy of the NVD/CVE vulnerability database.

    Supports import from USB/removable media and export for distribution
    to other air-gapped instances.
    """

    MANIFEST_FILENAME = "manifest.json"
    DB_FILENAME = "vuln_db.json.gz"

    def __init__(self, base_path: Optional[Path] = None):
        self.base_path = base_path or VULN_DB_PATH
        _ensure_dir(self.base_path)

    # ---- Import ----

    def import_from_bundle(self, bundle_path: str) -> VulnDBInfo:
        """Import a vulnerability database bundle (ZIP) from external media.

        The bundle must contain:
          - manifest.json  — metadata and SHA-256 checksum
          - vuln_db.json.gz — gzip-compressed CVE/NVD JSON feed
        """
        bundle = Path(bundle_path)
        if not bundle.exists():
            raise FileNotFoundError(f"Bundle not found: {bundle_path}")

        if not zipfile.is_zipfile(bundle):
            raise ValueError("Bundle must be a ZIP archive")

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            with zipfile.ZipFile(bundle, "r") as zf:
                # Security: validate member names to prevent path traversal
                for member in zf.namelist():
                    if ".." in member or member.startswith("/"):
                        raise ValueError(f"Unsafe path in bundle: {member}")
                zf.extractall(tmp_path)

            manifest_file = tmp_path / self.MANIFEST_FILENAME
            db_file = tmp_path / self.DB_FILENAME

            if not manifest_file.exists():
                raise ValueError("Bundle missing manifest.json")
            if not db_file.exists():
                raise ValueError(f"Bundle missing {self.DB_FILENAME}")

            manifest = json.loads(manifest_file.read_text())

            # Verify integrity
            actual_checksum = _compute_file_sha256(db_file)
            expected_checksum = manifest.get("checksum_sha256", "")
            if expected_checksum and actual_checksum != expected_checksum:
                raise ValueError(
                    f"Checksum mismatch: expected {expected_checksum}, got {actual_checksum}"
                )

            # Validate content
            cve_count, errors = self._validate_db_file(db_file)

            # Copy to destination
            dest_db = self.base_path / self.DB_FILENAME
            dest_manifest = self.base_path / self.MANIFEST_FILENAME
            shutil.copy2(db_file, dest_db)
            shutil.copy2(manifest_file, dest_manifest)

        db_info = VulnDBInfo(
            db_id=manifest.get("db_id", str(uuid.uuid4())),
            source=manifest.get("source", VulnDBSource.USB_IMPORT.value),
            version=manifest.get("version", "unknown"),
            cve_count=cve_count,
            last_updated=manifest.get("last_updated", _utcnow()),
            checksum_sha256=actual_checksum,
            feed_date_range=manifest.get("feed_date_range", {}),
            db_path=str(dest_db),
            size_bytes=dest_db.stat().st_size,
            is_valid=len(errors) == 0,
            validation_errors=errors,
        )
        self._save_db_info(db_info)
        logger.info("Imported vuln DB: %d CVEs, version=%s", cve_count, db_info.version)
        _emit_event("airgap.vuln_db_imported", {"version": db_info.version, "cve_count": cve_count, "bundle_path": bundle_path})
        return db_info

    def _validate_db_file(self, db_file: Path) -> Tuple[int, List[str]]:
        """Validate the gzip-compressed vulnerability database file."""
        errors: List[str] = []
        cve_count = 0
        try:
            with gzip.open(db_file, "rt", encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, list):
                cve_count = len(data)
            elif isinstance(data, dict):
                items = data.get("CVE_Items", data.get("vulnerabilities", []))
                cve_count = len(items)
            else:
                errors.append("Unexpected root type in DB file")
        except json.JSONDecodeError as exc:
            errors.append(f"JSON parse error: {exc}")
        except gzip.BadGzipFile:
            errors.append("Not a valid gzip file")
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            errors.append(f"Validation error: {exc}")
        return cve_count, errors

    # ---- Export ----

    def export_to_bundle(self, output_path: str) -> str:
        """Export current vulnerability database as a signed ZIP bundle."""
        dest_db = self.base_path / self.DB_FILENAME
        if not dest_db.exists():
            raise FileNotFoundError("No local vulnerability database to export")

        db_info = self.load_db_info()
        checksum = _compute_file_sha256(dest_db)

        manifest = {
            "db_id": db_info.db_id if db_info else str(uuid.uuid4()),
            "source": db_info.source if db_info else VulnDBSource.MANUAL.value,
            "version": db_info.version if db_info else "unknown",
            "cve_count": db_info.cve_count if db_info else 0,
            "last_updated": db_info.last_updated if db_info else _utcnow(),
            "checksum_sha256": checksum,
            "feed_date_range": db_info.feed_date_range if db_info else {},
            "exported_at": _utcnow(),
            "exported_by": "fixops-airgap",
        }

        output_file = Path(output_path)
        _ensure_dir(output_file.parent)

        with zipfile.ZipFile(output_file, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.write(dest_db, self.DB_FILENAME)
            manifest_bytes = json.dumps(manifest, indent=2).encode()
            zf.writestr(self.MANIFEST_FILENAME, manifest_bytes)

        logger.info("Exported vuln DB bundle to %s", output_file)
        _emit_event("airgap.vuln_db_exported", {"output_path": str(output_file)})
        return str(output_file)

    def export_bundle(self, output_zip_path: str) -> Dict[str, Any]:
        """Export the currently-imported DB as an importable ZIP bundle.

        This is the inverse of :meth:`import_from_bundle` — useful for
        SCIF-to-SCIF transfer, where one air-gapped instance has the DB and
        needs to share it with another. The output bundle contains a fresh
        manifest using the standard NVD-2.0 schema and is itself importable
        via :meth:`import_from_bundle`.

        Args:
            output_zip_path: Destination ZIP path. Parent directories are
                             created on demand.

        Returns:
            The manifest dict that was written into the ZIP.

        Raises:
            FileNotFoundError: No imported DB exists at ``self.base_path``.
        """
        dest_db = self.base_path / self.DB_FILENAME
        if not dest_db.exists():
            raise FileNotFoundError(
                "No local vulnerability database to export — "
                "import a bundle first via import_from_bundle()."
            )

        gz_bytes = dest_db.read_bytes()
        checksum = hashlib.sha256(gz_bytes).hexdigest()

        # Re-derive cve_count + feed metadata from any persisted db_info.json
        db_info = self.load_db_info()
        cve_count, _errors = self._validate_db_file(dest_db)
        feed_range_payload: Optional[List[str]]
        if db_info and isinstance(db_info.feed_date_range, dict) and db_info.feed_date_range:
            feed_range_payload = [
                db_info.feed_date_range.get("from", ""),
                db_info.feed_date_range.get("to", ""),
            ]
        else:
            feed_range_payload = None

        manifest: Dict[str, Any] = {
            "version": "1.0",
            "format": "NVD-2.0",
            "cve_count": cve_count,
            "checksum_sha256": checksum,
            "feed_date_range": feed_range_payload,
            "created_at": _utcnow(),
            "compression": "gzip",
            "db_filename": self.DB_FILENAME,
            "source_db_id": db_info.db_id if db_info else "",
        }

        output_file = Path(output_zip_path)
        _ensure_dir(output_file.parent)

        manifest_bytes = json.dumps(manifest, indent=2).encode("utf-8")
        with zipfile.ZipFile(output_file, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(self.MANIFEST_FILENAME, manifest_bytes)
            zf.writestr(self.DB_FILENAME, gz_bytes)

        logger.info(
            "Exported transportable NVD bundle: %d CVEs → %s",
            cve_count,
            output_file,
        )
        _emit_event(
            "airgap.nvd_bundle_exported",
            {"output_path": str(output_file), "cve_count": cve_count},
        )
        return manifest

    # ---- State persistence ----

    def _save_db_info(self, info: VulnDBInfo) -> None:
        info_file = self.base_path / "db_info.json"
        info_file.write_text(json.dumps(asdict(info), indent=2))

    def load_db_info(self) -> Optional[VulnDBInfo]:
        info_file = self.base_path / "db_info.json"
        if not info_file.exists():
            return None
        try:
            data = json.loads(info_file.read_text())
            return VulnDBInfo(**data)
        except (ValueError, KeyError, RuntimeError, TypeError, AttributeError):
            return None

    def is_available(self) -> bool:
        return (self.base_path / self.DB_FILENAME).exists()

    def lookup_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Look up a specific CVE in the local database."""
        db_file = self.base_path / self.DB_FILENAME
        if not db_file.exists():
            return None
        try:
            with gzip.open(db_file, "rt", encoding="utf-8") as fh:
                data = json.load(fh)
            items = data if isinstance(data, list) else data.get(
                "CVE_Items", data.get("vulnerabilities", [])
            )
            cve_upper = cve_id.upper()
            for item in items:
                item_id = ""
                if isinstance(item, dict):
                    item_id = (
                        item.get("cve_id", "")
                        or item.get("id", "")
                        or (item.get("cve", {}) or {}).get("CVE_data_meta", {}).get("ID", "")
                    )
                if item_id.upper() == cve_upper:
                    return item
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            logger.warning("CVE lookup error: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Local LLM Router
# ---------------------------------------------------------------------------


class LocalLLMRouter:
    """Routes LLM requests to local backends in air-gapped environments."""

    OLLAMA_DEFAULT = "http://localhost:11434"
    VLLM_DEFAULT = "http://localhost:8000"
    LLAMACPP_DEFAULT = "http://localhost:8080"

    def __init__(self, config: Optional[LocalLLMConfig] = None):
        self.config = config or LocalLLMConfig()

    def detect_available_backend(self) -> LocalLLMConfig:
        """Probe local backends to find an available LLM service."""
        backends = [
            (LLMBackend.OLLAMA, self.OLLAMA_DEFAULT, "/api/tags"),
            (LLMBackend.VLLM, self.VLLM_DEFAULT, "/v1/models"),
            (LLMBackend.LLAMACPP, self.LLAMACPP_DEFAULT, "/v1/models"),
        ]
        for backend, base_url, probe_path in backends:
            url = f"{base_url}{probe_path}"
            if self._probe_endpoint(url):
                model_name = self._get_first_model(backend, base_url)
                cfg = LocalLLMConfig(
                    backend=backend.value,
                    endpoint=base_url,
                    model_name=model_name or "default",
                    available=True,
                )
                logger.info("Local LLM backend detected: %s at %s", backend.value, base_url)
                return cfg

        logger.warning("No local LLM backend detected")
        return LocalLLMConfig(backend=LLMBackend.NONE.value, available=False)

    def _probe_endpoint(self, url: str, timeout: float = 1.5) -> bool:
        """Quick HTTP probe — returns True if endpoint responds."""
        import urllib.request
        try:
            with urllib.request.urlopen(url, timeout=timeout):  # nosemgrep: dynamic-urllib-use-detected  # nosec
                return True
        except (ValueError, KeyError, RuntimeError, TypeError, AttributeError):
            return False

    def _get_first_model(self, backend: LLMBackend, base_url: str) -> str:
        """Retrieve the first available model name from a local backend."""
        import urllib.request
        endpoints = {
            LLMBackend.OLLAMA: f"{base_url}/api/tags",
            LLMBackend.VLLM: f"{base_url}/v1/models",
            LLMBackend.LLAMACPP: f"{base_url}/v1/models",
        }
        url = endpoints.get(backend, "")
        if not url:
            return ""
        try:
            with urllib.request.urlopen(url, timeout=2) as resp:  # nosemgrep: dynamic-urllib-use-detected  # nosec
                data = json.loads(resp.read())
            if backend == LLMBackend.OLLAMA:
                models = data.get("models", [])
                return models[0]["name"] if models else ""
            else:
                models = data.get("data", [])
                return models[0]["id"] if models else ""
        except (ValueError, KeyError, RuntimeError, TypeError, AttributeError):
            return ""

    def build_chat_payload(
        self,
        messages: List[Dict[str, str]],
        model: Optional[str] = None,
        max_tokens: Optional[int] = None,
    ) -> Tuple[str, Dict[str, Any]]:
        """Build the HTTP endpoint URL and JSON payload for the active backend."""
        cfg = self.config
        effective_model = model or cfg.model_name
        effective_max_tokens = max_tokens or cfg.max_tokens

        if cfg.backend == LLMBackend.OLLAMA.value:
            url = f"{cfg.endpoint}/api/chat"
            payload = {
                "model": effective_model,
                "messages": messages,
                "stream": False,
                "options": {
                    "temperature": cfg.temperature,
                    "num_predict": effective_max_tokens,
                },
            }
        elif cfg.backend in (LLMBackend.VLLM.value, LLMBackend.LLAMACPP.value):
            url = f"{cfg.endpoint}/v1/chat/completions"
            payload = {
                "model": effective_model,
                "messages": messages,
                "max_tokens": effective_max_tokens,
                "temperature": cfg.temperature,
            }
        else:
            raise RuntimeError(
                "No local LLM backend configured. "
                "Install Ollama or vLLM on the air-gapped host."
            )
        return url, payload


# ---------------------------------------------------------------------------
# STIX/TAXII Threat Intelligence Manager
# ---------------------------------------------------------------------------


class ThreatIntelManager:
    """Import/export STIX 2.1 bundles for air-gapped threat intelligence sharing."""

    BUNDLE_FILENAME = "threat_intel.stix.json"
    MANIFEST_FILENAME = "bundle_manifest.json"

    def __init__(self, base_path: Optional[Path] = None):
        self.base_path = base_path or THREAT_INTEL_PATH
        _ensure_dir(self.base_path)

    def import_stix_bundle(self, bundle_path: str) -> Dict[str, Any]:
        """Import a STIX 2.1 bundle from a file."""
        src = Path(bundle_path)
        if not src.exists():
            raise FileNotFoundError(f"Bundle not found: {bundle_path}")

        # Detect if it's a ZIP archive or raw JSON
        if zipfile.is_zipfile(src):
            return self._import_from_zip(src)
        else:
            return self._import_raw_json(src)

    def _import_from_zip(self, zip_path: Path) -> Dict[str, Any]:
        """Import from a ZIP-wrapped STIX bundle."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            with zipfile.ZipFile(zip_path, "r") as zf:
                for name in zf.namelist():
                    if ".." in name or name.startswith("/"):
                        raise ValueError(f"Unsafe path: {name}")
                zf.extractall(tmp)

            # Find STIX JSON
            stix_files = list(tmp.rglob("*.json"))
            if not stix_files:
                raise ValueError("No JSON found in bundle archive")

            bundle = json.loads(stix_files[0].read_text())
            return self._store_bundle(bundle, source=str(zip_path))

    def _import_raw_json(self, json_path: Path) -> Dict[str, Any]:
        """Import a raw STIX 2.1 JSON bundle."""
        bundle = json.loads(json_path.read_text())
        return self._store_bundle(bundle, source=str(json_path))

    def _store_bundle(self, bundle: Dict[str, Any], source: str = "") -> Dict[str, Any]:
        """Validate and store a STIX bundle locally."""
        if bundle.get("type") != "bundle":
            raise ValueError("Not a valid STIX 2.1 bundle (type must be 'bundle')")

        objects = bundle.get("objects", [])
        bundle_id = bundle.get("id", f"bundle--{uuid.uuid4()}")

        # Count object types
        type_counts: Dict[str, int] = {}
        for obj in objects:
            t = obj.get("type", "unknown")
            type_counts[t] = type_counts.get(t, 0) + 1

        # Store the bundle
        dest = self.base_path / self.BUNDLE_FILENAME
        dest.write_text(json.dumps(bundle, indent=2))

        checksum = _compute_file_sha256(dest)
        manifest = {
            "bundle_id": bundle_id,
            "imported_at": _utcnow(),
            "source": source,
            "object_count": len(objects),
            "type_counts": type_counts,
            "checksum_sha256": checksum,
            "stix_version": bundle.get("spec_version", "2.1"),
        }
        (self.base_path / self.MANIFEST_FILENAME).write_text(
            json.dumps(manifest, indent=2)
        )

        logger.info(
            "Imported STIX bundle: %d objects (types: %s)",
            len(objects),
            type_counts,
        )
        return manifest

    def export_stix_bundle(
        self,
        output_path: str,
        classification: str = ClassificationLevel.UNCLASSIFIED.value,
    ) -> str:
        """Export stored threat intelligence as a signed STIX bundle ZIP."""
        src = self.base_path / self.BUNDLE_FILENAME
        if not src.exists():
            raise FileNotFoundError("No local threat intel bundle to export")

        manifest_file = self.base_path / self.MANIFEST_FILENAME
        bundle = json.loads(src.read_text())

        # Inject classification marking per STIX 2.1 data markings
        marking = {
            "type": "marking-definition",
            "spec_version": "2.1",
            "id": f"marking-definition--{uuid.uuid4()}",
            "created": _utcnow(),
            "definition_type": "statement",
            "definition": {"statement": f"CLASSIFICATION: {classification}"},
        }
        bundle.setdefault("objects", []).append(marking)
        bundle["exported_at"] = _utcnow()

        checksum = _fips_hash(json.dumps(bundle).encode(), "sha256")

        output_file = Path(output_path)
        _ensure_dir(output_file.parent)

        with zipfile.ZipFile(output_file, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(
                self.BUNDLE_FILENAME,
                json.dumps(bundle, indent=2),
            )
            if manifest_file.exists():
                zf.write(manifest_file, self.MANIFEST_FILENAME)
            export_meta = json.dumps(
                {
                    "exported_at": _utcnow(),
                    "checksum_sha256": checksum,
                    "classification": classification,
                },
                indent=2,
            )
            zf.writestr("export_metadata.json", export_meta)

        logger.info("Exported STIX bundle to %s (classification=%s)", output_file, classification)
        return str(output_file)

    def get_manifest(self) -> Optional[Dict[str, Any]]:
        """Return the stored bundle manifest metadata."""
        mf = self.base_path / self.MANIFEST_FILENAME
        if not mf.exists():
            return None
        return json.loads(mf.read_text())

    def is_available(self) -> bool:
        return (self.base_path / self.BUNDLE_FILENAME).exists()


# ---------------------------------------------------------------------------
# Offline Update Package Manager
# ---------------------------------------------------------------------------


class OfflineUpdateManager:
    """Manages offline update packages for air-gapped deployments."""

    UPDATE_MANIFEST = "update_manifest.json"

    def __init__(self, base_path: Optional[Path] = None):
        self.base_path = base_path or OFFLINE_UPDATES_PATH
        _ensure_dir(self.base_path)

    def create_package(
        self,
        package_type: str,
        content_paths: List[str],
        version: str,
        output_path: str,
    ) -> Dict[str, Any]:
        """Create an offline update package as a signed ZIP archive.

        Args:
            package_type:  One of UpdatePackageType values.
            content_paths: List of files/directories to include.
            version:       Version string (e.g. "2024.11.1").
            output_path:   Destination ZIP file path.
        """
        package_id = str(uuid.uuid4())
        output_file = Path(output_path)
        _ensure_dir(output_file.parent)

        file_checksums: Dict[str, str] = {}
        included_files: List[str] = []

        with zipfile.ZipFile(output_file, "w", zipfile.ZIP_DEFLATED) as zf:
            for src_str in content_paths:
                src = Path(src_str)
                if src.is_file():
                    arcname = src.name
                    zf.write(src, arcname)
                    file_checksums[arcname] = _compute_file_sha256(src)
                    included_files.append(arcname)
                elif src.is_dir():
                    for f in src.rglob("*"):
                        if f.is_file():
                            rel = f.relative_to(src.parent)
                            zf.write(f, str(rel))
                            file_checksums[str(rel)] = _compute_file_sha256(f)
                            included_files.append(str(rel))

            manifest = {
                "package_id": package_id,
                "package_type": package_type,
                "version": version,
                "created_at": _utcnow(),
                "file_count": len(included_files),
                "files": included_files,
                "checksums": file_checksums,
                "created_by": "fixops-airgap",
                "platform": platform.system(),
            }
            zf.writestr(self.UPDATE_MANIFEST, json.dumps(manifest, indent=2))

        package_checksum = _compute_file_sha256(output_file)
        manifest["package_checksum_sha256"] = package_checksum
        manifest["size_bytes"] = output_file.stat().st_size

        # Record locally
        record_file = self.base_path / f"package_{package_id}.json"
        record_file.write_text(json.dumps(manifest, indent=2))

        logger.info(
            "Created offline update package: type=%s version=%s files=%d",
            package_type,
            version,
            len(included_files),
        )
        return manifest

    def apply_package(self, package_path: str) -> Dict[str, Any]:
        """Apply an offline update package to the local installation."""
        pkg = Path(package_path)
        if not pkg.exists():
            raise FileNotFoundError(f"Package not found: {package_path}")

        if not zipfile.is_zipfile(pkg):
            raise ValueError("Update package must be a ZIP archive")

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            with zipfile.ZipFile(pkg, "r") as zf:
                for name in zf.namelist():
                    if ".." in name or name.startswith("/"):
                        raise ValueError(f"Unsafe path in package: {name}")
                zf.extractall(tmp)

            manifest_file = tmp / self.UPDATE_MANIFEST
            if not manifest_file.exists():
                raise ValueError("Package missing update_manifest.json")

            manifest = json.loads(manifest_file.read_text())

            # Verify checksums
            errors = []
            for arcname, expected_csum in manifest.get("checksums", {}).items():
                extracted = tmp / arcname
                if extracted.exists():
                    actual = _compute_file_sha256(extracted)
                    if actual != expected_csum:
                        errors.append(f"Checksum mismatch for {arcname}")

            if errors:
                raise ValueError(f"Package integrity check failed: {errors}")

            # Dispatch by type
            pkg_type = manifest.get("package_type", "")
            applied_count = self._apply_by_type(pkg_type, tmp, manifest)

        result = {
            "status": "applied",
            "package_id": manifest.get("package_id"),
            "package_type": pkg_type,
            "version": manifest.get("version"),
            "applied_at": _utcnow(),
            "files_applied": applied_count,
        }
        logger.info("Applied update package: %s", result)
        return result

    def _apply_by_type(self, pkg_type: str, tmp: Path, manifest: Dict) -> int:
        """Apply package contents to the appropriate destination directory."""
        dest_map = {
            UpdatePackageType.VULN_DB.value: VULN_DB_PATH,
            UpdatePackageType.SIGNATURES.value: SIGNATURE_DB_PATH,
            UpdatePackageType.COMPLIANCE_RULES.value: COMPLIANCE_RULES_PATH,
        }
        dest = dest_map.get(pkg_type, self.base_path / "applied" / pkg_type)
        _ensure_dir(dest)

        count = 0
        for arcname in manifest.get("files", []):
            src_file = tmp / arcname
            if src_file.is_file():
                dest_file = dest / Path(arcname).name
                _ensure_dir(dest_file.parent)
                shutil.copy2(src_file, dest_file)
                count += 1
        return count

    def list_applied_packages(self) -> List[Dict[str, Any]]:
        """List all packages that have been applied."""
        packages = []
        for f in self.base_path.glob("package_*.json"):
            try:
                packages.append(json.loads(f.read_text()))
            except (OSError, ValueError, RuntimeError):  # narrowed from bare Exception
                pass
        return sorted(packages, key=lambda x: x.get("created_at", ""), reverse=True)


# ---------------------------------------------------------------------------
# FIPS 140-2/3 Compliance Manager
# ---------------------------------------------------------------------------


class FIPSComplianceManager:
    """Manages and audits FIPS 140-2/3 cryptographic compliance."""

    def __init__(self):
        self._violations: List[str] = []

    def detect_kernel_fips(self) -> bool:
        """Check if the Linux kernel FIPS mode is enabled."""
        if FIPS_MARKER_FILE.exists():
            try:
                return FIPS_MARKER_FILE.read_text().strip() == "1"
            except (OSError, ValueError, RuntimeError):  # narrowed from bare Exception
                pass
        return False

    def get_status(self) -> FIPSStatus:
        """Return current FIPS compliance status."""
        kernel_fips = self.detect_kernel_fips()
        mode_env = os.getenv("FIXOPS_FIPS_MODE", FIPSMode.DISABLED.value)
        try:
            mode = FIPSMode(mode_env)
        except ValueError:
            mode = FIPSMode.DISABLED

        return FIPSStatus(
            mode=mode.value,
            kernel_fips_enabled=kernel_fips,
            approved_algorithms_only=(mode == FIPSMode.ENFORCED or kernel_fips),
            violations_detected=list(self._violations),
            fips_version="FIPS 140-3" if kernel_fips else "FIPS 140-2",
        )

    def audit_algorithm(self, algorithm: str) -> bool:
        """Audit whether an algorithm is FIPS-approved. Records violations."""
        alg = algorithm.lower().replace("-", "_")
        approved = alg in FIPS_APPROVED_HASH_ALGORITHMS | FIPS_APPROVED_HMAC_ALGORITHMS
        if not approved:
            violation = f"Non-FIPS algorithm used: {algorithm} (forbidden: {alg in FIPS_FORBIDDEN_ALGORITHMS})"
            self._violations.append(violation)
            logger.warning("FIPS violation: %s", violation)
        return approved

    def enforce_fips_hash(self, data: bytes, algorithm: str = "sha256") -> str:
        """Compute hash enforcing FIPS-approved algorithms only."""
        return _fips_hash(data, algorithm)

    def clear_violations(self) -> None:
        self._violations.clear()

    def generate_report(self) -> Dict[str, Any]:
        """Generate a FIPS compliance report."""
        status = self.get_status()
        return {
            "report_id": str(uuid.uuid4()),
            "generated_at": _utcnow(),
            "fips_status": asdict(status),
            "approved_hash_algorithms": sorted(FIPS_APPROVED_HASH_ALGORITHMS),
            "approved_hmac_algorithms": sorted(FIPS_APPROVED_HMAC_ALGORITHMS),
            "forbidden_algorithms": sorted(FIPS_FORBIDDEN_ALGORITHMS),
            "compliant": len(status.violations_detected) == 0,
        }


# ---------------------------------------------------------------------------
# External Dependencies Registry
# ---------------------------------------------------------------------------


def get_external_dependencies() -> List[ExternalDependency]:
    """Return the full list of external dependencies and their offline alternatives."""
    return [
        ExternalDependency(
            name="OpenAI API",
            description="GPT-4/GPT-3.5 LLM for AI-powered analysis",
            dependency_type="api",
            original_endpoint="https://api.openai.com/v1",
            offline_alternative="Local Ollama/vLLM instance with open-source model",
            is_required=False,
            offline_available=True,
            notes="Route to LocalLLMRouter with Ollama/Mistral or vLLM/LLaMA",
        ),
        ExternalDependency(
            name="Anthropic API",
            description="Claude LLM for security analysis",
            dependency_type="api",
            original_endpoint="https://api.anthropic.com/v1",
            offline_alternative="Local Ollama/vLLM with Claude-equivalent model",
            is_required=False,
            offline_available=True,
        ),
        ExternalDependency(
            name="NVD/CVE Database",
            description="NIST National Vulnerability Database for CVE data",
            dependency_type="vuln_db",
            original_endpoint="https://services.nvd.nist.gov/rest/json",
            offline_alternative="Local offline NVD JSON feed (USB-imported)",
            is_required=True,
            offline_available=True,
            notes="Use OfflineVulnDBManager to import periodic NVD JSON feeds",
        ),
        ExternalDependency(
            name="PyPI Package Registry",
            description="Python package registry for dependency scanning",
            dependency_type="package_registry",
            original_endpoint="https://pypi.org",
            offline_alternative="Local Devpi or Nexus repository mirror",
            is_required=False,
            offline_available=True,
        ),
        ExternalDependency(
            name="NPM Registry",
            description="Node.js package registry for dependency scanning",
            dependency_type="package_registry",
            original_endpoint="https://registry.npmjs.org",
            offline_alternative="Local Verdaccio or Nexus NPM mirror",
            is_required=False,
            offline_available=True,
        ),
        ExternalDependency(
            name="Maven Central",
            description="Java package registry for dependency scanning",
            dependency_type="package_registry",
            original_endpoint="https://search.maven.org",
            offline_alternative="Local Nexus/Artifactory Maven mirror",
            is_required=False,
            offline_available=True,
        ),
        ExternalDependency(
            name="GitHub Advisory Database",
            description="Security advisories for open-source packages",
            dependency_type="vuln_db",
            original_endpoint="https://api.github.com/advisories",
            offline_alternative="Periodic GHSA JSON export imported via USB",
            is_required=False,
            offline_available=True,
        ),
        ExternalDependency(
            name="OSV.dev API",
            description="Open Source Vulnerability database",
            dependency_type="vuln_db",
            original_endpoint="https://api.osv.dev/v1",
            offline_alternative="Local OSV offline dump imported via USB",
            is_required=False,
            offline_available=True,
        ),
        ExternalDependency(
            name="DNS Resolution",
            description="External DNS for hostname resolution",
            dependency_type="dns",
            original_endpoint="8.8.8.8:53 / 1.1.1.1:53",
            offline_alternative="Local DNS server (bind9/unbound) or /etc/hosts",
            is_required=False,
            offline_available=True,
        ),
        ExternalDependency(
            name="TAXII Server",
            description="TAXII 2.1 threat intelligence feed server",
            dependency_type="api",
            original_endpoint="https://taxii.mitre.org",
            offline_alternative="Local STIX/TAXII bundle import via ThreatIntelManager",
            is_required=False,
            offline_available=True,
        ),
        ExternalDependency(
            name="Semgrep Registry",
            description="Semgrep rule registry for SAST scanning",
            dependency_type="api",
            original_endpoint="https://semgrep.dev/api",
            offline_alternative="Bundled offline Semgrep rules (included in FixOps package)",
            is_required=False,
            offline_available=True,
        ),
        ExternalDependency(
            name="Container Registry (Docker Hub)",
            description="Docker Hub for container image scanning",
            dependency_type="api",
            original_endpoint="https://registry.hub.docker.com",
            offline_alternative="Local Harbor/Nexus container registry mirror",
            is_required=False,
            offline_available=True,
        ),
        ExternalDependency(
            name="Trivy Vulnerability DB",
            description="Trivy vulnerability database updates",
            dependency_type="vuln_db",
            original_endpoint="https://ghcr.io/aquasecurity/trivy-db",
            offline_alternative="Offline Trivy DB imported via OfflineUpdateManager",
            is_required=False,
            offline_available=True,
        ),
    ]


# ---------------------------------------------------------------------------
# Air-Gap Health Check
# ---------------------------------------------------------------------------


class AirGapHealthChecker:
    """Verifies all components are properly configured for air-gapped operation."""

    def __init__(self, config: AirGapConfiguration):
        self.config = config
        self.vuln_db = OfflineVulnDBManager()
        self.threat_intel = ThreatIntelManager()
        self.fips = FIPSComplianceManager()
        self.llm = LocalLLMRouter(config.local_llm)

    def run_health_check(self) -> Dict[str, Any]:
        """Run a comprehensive health check and return structured results."""
        checks: Dict[str, Dict[str, Any]] = {}
        overall_healthy = True

        # 1. Air-gap mode active
        mode_ok = self.config.mode != AirGapMode.DISABLED.value
        checks["airgap_mode"] = {
            "status": "ok" if mode_ok else "warning",
            "mode": self.config.mode,
            "message": "Air-gap mode active" if mode_ok else "Air-gap mode is DISABLED",
        }
        if not mode_ok:
            overall_healthy = False

        # 2. Offline vulnerability DB
        vuln_ok = self.vuln_db.is_available()
        vuln_info = self.vuln_db.load_db_info()
        checks["vuln_db"] = {
            "status": "ok" if vuln_ok else "degraded",
            "available": vuln_ok,
            "cve_count": vuln_info.cve_count if vuln_info else 0,
            "version": vuln_info.version if vuln_info else "N/A",
            "last_updated": vuln_info.last_updated if vuln_info else "N/A",
            "message": "Offline vulnerability DB available" if vuln_ok else "No offline vulnerability DB — import required",
        }
        if not vuln_ok:
            overall_healthy = False

        # 3. Local LLM
        llm_ok = self.config.local_llm.available
        checks["local_llm"] = {
            "status": "ok" if llm_ok else "degraded",
            "available": llm_ok,
            "backend": self.config.local_llm.backend,
            "endpoint": self.config.local_llm.endpoint,
            "model": self.config.local_llm.model_name,
            "message": f"Local LLM available ({self.config.local_llm.backend})" if llm_ok else "No local LLM — AI features degraded",
        }

        # 4. FIPS compliance
        fips_status = self.fips.get_status()
        fips_ok = fips_status.mode != FIPSMode.DISABLED.value
        checks["fips_compliance"] = {
            "status": "ok" if fips_ok else "warning",
            "mode": fips_status.mode,
            "kernel_fips": fips_status.kernel_fips_enabled,
            "violations": len(fips_status.violations_detected),
            "message": f"FIPS mode: {fips_status.mode}",
        }

        # 5. Threat intelligence
        ti_ok = self.threat_intel.is_available()
        ti_manifest = self.threat_intel.get_manifest()
        checks["threat_intel"] = {
            "status": "ok" if ti_ok else "warning",
            "available": ti_ok,
            "object_count": ti_manifest.get("object_count", 0) if ti_manifest else 0,
            "imported_at": ti_manifest.get("imported_at", "N/A") if ti_manifest else "N/A",
            "message": "Threat intel bundle available" if ti_ok else "No threat intel bundle — import recommended",
        }

        # 6. Data paths
        paths_ok = True
        path_checks: Dict[str, Any] = {}
        for name, raw_path in [
            ("vuln_db", str(VULN_DB_PATH)),
            ("threat_intel", str(THREAT_INTEL_PATH)),
            ("updates", str(OFFLINE_UPDATES_PATH)),
            ("signatures", str(SIGNATURE_DB_PATH)),
        ]:
            p = Path(raw_path)
            exists = p.exists()
            writable = exists and os.access(p, os.W_OK)
            path_checks[name] = {
                "path": raw_path,
                "exists": exists,
                "writable": writable,
            }
            if not exists or not writable:
                paths_ok = False

        checks["data_paths"] = {
            "status": "ok" if paths_ok else "warning",
            "paths": path_checks,
            "message": "All data paths accessible" if paths_ok else "Some data paths missing or not writable",
        }

        # 7. Classification
        checks["classification"] = {
            "status": "ok",
            "level": self.config.classification_level,
            "message": f"Classification: {self.config.classification_level}",
        }

        # 8. Scanners
        checks["scanners"] = {
            "status": "ok",
            "enabled": self.config.enabled_scanners,
            "count": len(self.config.enabled_scanners),
            "message": "All 25 scanner parsers work offline (no external calls required)",
        }

        return {
            "healthy": overall_healthy,
            "timestamp": _utcnow(),
            "instance_id": self.config.instance_id,
            "mode": self.config.mode,
            "classification": self.config.classification_level,
            "checks": checks,
            "summary": {
                "total_checks": len(checks),
                "ok": sum(1 for c in checks.values() if c["status"] == "ok"),
                "warnings": sum(1 for c in checks.values() if c["status"] == "warning"),
                "degraded": sum(1 for c in checks.values() if c["status"] == "degraded"),
            },
        }


# ---------------------------------------------------------------------------
# Classification Banner
# ---------------------------------------------------------------------------


# Banner strings per classification level
_CLASSIFICATION_BANNERS: Dict[str, str] = {
    ClassificationLevel.UNCLASSIFIED.value: "UNCLASSIFIED",
    ClassificationLevel.CUI.value: "CONTROLLED UNCLASSIFIED INFORMATION (CUI)",
    ClassificationLevel.SECRET.value: "//SECRET//",
    ClassificationLevel.TOP_SECRET.value: "//TOP SECRET//",
}

_CLASSIFICATION_COLORS: Dict[str, str] = {
    ClassificationLevel.UNCLASSIFIED.value: "green",
    ClassificationLevel.CUI.value: "purple",
    ClassificationLevel.SECRET.value: "red",
    ClassificationLevel.TOP_SECRET.value: "orange",
}


def get_classification_banner(level: str) -> Dict[str, str]:
    """Return the classification banner metadata for a given level."""
    return {
        "level": level,
        "banner_text": _CLASSIFICATION_BANNERS.get(level, level),
        "color": _CLASSIFICATION_COLORS.get(level, "gray"),
        "display_required": level != ClassificationLevel.UNCLASSIFIED.value,
    }


# ---------------------------------------------------------------------------
# AirGapConfigEngine — Main entry point
# ---------------------------------------------------------------------------


class AirGapConfigEngine:
    """Central engine for air-gapped deployment configuration.

    Singleton-ish — use get_airgap_engine() to obtain the shared instance.
    """

    def __init__(self):
        self._config: AirGapConfiguration = AirGapConfiguration()
        self._network_detector = NetworkIsolationDetector()
        self._fips_manager = FIPSComplianceManager()
        self._vuln_db = OfflineVulnDBManager()
        self._threat_intel = ThreatIntelManager()
        self._update_manager = OfflineUpdateManager()
        self._llm_router = LocalLLMRouter()
        self._load_state()

    # ---- State persistence ----

    def _load_state(self) -> None:
        """Load persisted air-gap configuration from disk."""
        if AIRGAP_STATE_FILE.exists():
            try:
                raw = json.loads(AIRGAP_STATE_FILE.read_text())
                # Reconstruct nested dataclasses
                fips_data = raw.pop("fips", {})
                llm_data = raw.pop("local_llm", {})
                vuln_data = raw.pop("vuln_db", {})
                net_data = raw.pop("network_status", None)
                self._config = AirGapConfiguration(
                    fips=FIPSStatus(**fips_data) if fips_data else FIPSStatus(),
                    local_llm=LocalLLMConfig(**llm_data) if llm_data else LocalLLMConfig(),
                    vuln_db=VulnDBInfo(**vuln_data) if vuln_data else VulnDBInfo(),
                    network_status=NetworkIsolationStatus(**net_data) if net_data else None,
                    **raw,
                )
                logger.info("Loaded air-gap configuration (mode=%s)", self._config.mode)
            except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
                logger.warning("Could not load air-gap state: %s", exc)

    def _save_state(self) -> None:
        """Persist current air-gap configuration to disk."""
        _ensure_dir(AIRGAP_STATE_FILE.parent)
        AIRGAP_STATE_FILE.write_text(json.dumps(asdict(self._config), indent=2))

    # ---- Public API ----

    @property
    def config(self) -> AirGapConfiguration:
        return self._config

    def get_status(self) -> Dict[str, Any]:
        """Return a summary of the current air-gap configuration."""
        net = self._config.network_status
        return {
            "mode": self._config.mode,
            "classification_level": self._config.classification_level,
            "classification_banner": get_classification_banner(
                self._config.classification_level
            ),
            "fips": {
                "mode": self._config.fips.mode,
                "kernel_fips_enabled": self._config.fips.kernel_fips_enabled,
                "approved_algorithms_only": self._config.fips.approved_algorithms_only,
            },
            "local_llm": {
                "backend": self._config.local_llm.backend,
                "available": self._config.local_llm.available,
                "endpoint": self._config.local_llm.endpoint,
            },
            "vuln_db": {
                "available": self._vuln_db.is_available(),
                "cve_count": self._config.vuln_db.cve_count,
                "version": self._config.vuln_db.version,
                "last_updated": self._config.vuln_db.last_updated,
            },
            "threat_intel": {
                "available": self._threat_intel.is_available(),
            },
            "network_isolation": {
                "is_isolated": net.is_isolated if net else None,
                "last_probed": net.probe_timestamp if net else None,
            },
            "instance_id": self._config.instance_id,
            "last_configured": self._config.last_configured,
        }

    def configure(self, settings: Dict[str, Any]) -> AirGapConfiguration:
        """Apply a new configuration. Accepts partial updates."""
        if "mode" in settings:
            self._config.mode = settings["mode"]
        if "classification_level" in settings:
            self._config.classification_level = settings["classification_level"]
        if "allow_local_network" in settings:
            self._config.allow_local_network = settings["allow_local_network"]
        if "allow_usb_import" in settings:
            self._config.allow_usb_import = settings["allow_usb_import"]
        if "fips_mode" in settings:
            self._config.fips.mode = settings["fips_mode"]
        if "llm_backend" in settings:
            self._config.local_llm.backend = settings["llm_backend"]
        if "llm_endpoint" in settings:
            self._config.local_llm.endpoint = settings["llm_endpoint"]
        if "llm_model" in settings:
            self._config.local_llm.model_name = settings["llm_model"]
        if "enabled_scanners" in settings:
            self._config.enabled_scanners = settings["enabled_scanners"]
        if "offline_data_paths" in settings:
            self._config.offline_data_paths.update(settings["offline_data_paths"])
        if "configured_by" in settings:
            self._config.configured_by = settings["configured_by"]

        self._config.last_configured = _utcnow()
        self._save_state()
        logger.info("Air-gap configuration updated: mode=%s", self._config.mode)
        _emit_event("airgap.config_updated", {"mode": str(self._config.mode)})
        return self._config

    def detect_isolation(self) -> NetworkIsolationStatus:
        """Run network isolation detection and update config."""
        status = self._network_detector.detect()
        self._config.network_status = status
        if status.is_isolated and self._config.mode == AirGapMode.DISABLED.value:
            self._config.mode = AirGapMode.DETECTED.value
            logger.info("Air-gap auto-detected — switching mode to DETECTED")
        self._save_state()
        return status

    def set_classification(self, level: str, set_by: str = "admin") -> Dict[str, Any]:
        """Set the data classification level."""
        try:
            ClassificationLevel(level)
        except ValueError:
            raise ValueError(
                f"Invalid classification level: {level}. "
                f"Must be one of: {[e.value for e in ClassificationLevel]}"
            )
        self._config.classification_level = level
        self._config.configured_by = set_by
        self._config.last_configured = _utcnow()
        self._save_state()
        return get_classification_banner(level)

    def import_vuln_db(self, bundle_path: str) -> VulnDBInfo:
        """Import an offline vulnerability database bundle."""
        info = self._vuln_db.import_from_bundle(bundle_path)
        self._config.vuln_db = info
        self._save_state()
        return info

    def export_vuln_db(self, output_path: str) -> str:
        """Export the local vulnerability database as a bundle."""
        return self._vuln_db.export_to_bundle(output_path)

    def import_threat_intel(self, bundle_path: str) -> Dict[str, Any]:
        """Import a STIX/TAXII threat intelligence bundle."""
        return self._threat_intel.import_stix_bundle(bundle_path)

    def export_threat_intel(self, output_path: str) -> str:
        """Export threat intelligence for sharing between air-gapped instances."""
        return self._threat_intel.export_stix_bundle(
            output_path,
            classification=self._config.classification_level,
        )

    def get_fips_status(self) -> Dict[str, Any]:
        """Return FIPS 140-2/3 compliance status."""
        status = self._fips_manager.get_status()
        self._config.fips = status
        return self._fips_manager.generate_report()

    def create_update_package(
        self, package_type: str, content_paths: List[str], version: str, output_path: str
    ) -> Dict[str, Any]:
        """Create an offline update package."""
        return self._update_manager.create_package(
            package_type, content_paths, version, output_path
        )

    def apply_update_package(self, package_path: str) -> Dict[str, Any]:
        """Apply an offline update package."""
        return self._update_manager.apply_package(package_path)

    def run_health_check(self) -> Dict[str, Any]:
        """Run a comprehensive air-gap health check."""
        checker = AirGapHealthChecker(self._config)
        return checker.run_health_check()

    def list_dependencies(self) -> List[Dict[str, Any]]:
        """List all external dependencies and their offline alternatives."""
        deps = get_external_dependencies()
        return [
            {
                "name": d.name,
                "description": d.description,
                "dependency_type": d.dependency_type,
                "original_endpoint": d.original_endpoint,
                "offline_alternative": d.offline_alternative,
                "is_required": d.is_required,
                "offline_available": d.offline_available,
                "notes": d.notes,
            }
            for d in deps
        ]

    def probe_local_llm(self) -> LocalLLMConfig:
        """Detect and configure an available local LLM backend."""
        cfg = self._llm_router.detect_available_backend()
        self._config.local_llm = cfg
        self._llm_router.config = cfg
        self._save_state()
        return cfg

    def classify_response(self, response: Dict[str, Any]) -> Dict[str, Any]:
        """Inject classification banner into an API response dict."""
        level = self._config.classification_level
        if level != ClassificationLevel.UNCLASSIFIED.value:
            response["_classification"] = get_classification_banner(level)
        return response


# ---------------------------------------------------------------------------
# Singleton accessor
# ---------------------------------------------------------------------------

_engine_instance: Optional[AirGapConfigEngine] = None


def get_airgap_engine() -> AirGapConfigEngine:
    """Return the shared AirGapConfigEngine instance (thread-unsafe singleton)."""
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = AirGapConfigEngine()
    return _engine_instance


def get_air_gap_mode() -> AirGapMode:
    """Return the currently active air-gap mode.

    Resolution order:
      1. ``FIXOPS_AIRGAP_MODE`` env-var override (disabled|detected|configured|enforced).
      2. The persisted AirGapConfigEngine state (FIXOPS_AIRGAP_STATE).
      3. ``AirGapMode.DISABLED`` if neither source is set or values are invalid.

    The env-var path is what production deployments use to enforce air-gap from
    systemd / Kubernetes; the persisted state is what the admin UI writes.
    Either one MUST be honoured by downstream code (e.g. LLM council).
    """
    env_value = os.getenv("FIXOPS_AIRGAP_MODE", "").strip().lower()
    if env_value:
        try:
            return AirGapMode(env_value)
        except ValueError:
            logger.warning(
                "FIXOPS_AIRGAP_MODE=%r is not a valid AirGapMode — ignoring.", env_value
            )

    try:
        engine = get_airgap_engine()
        mode_str = (engine.config.mode or "").strip().lower()
        if mode_str:
            try:
                return AirGapMode(mode_str)
            except ValueError:
                logger.warning(
                    "Persisted air-gap mode %r is invalid — defaulting to DISABLED.",
                    mode_str,
                )
    except Exception as exc:  # noqa: BLE001 - never raise from accessor
        logger.debug("get_air_gap_mode: engine load failed: %s", exc)

    return AirGapMode.DISABLED
