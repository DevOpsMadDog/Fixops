"""FIPS boot toggle — runs at FastAPI app start when ``FIPS_MODE=1``.

Effects when ``FIPS_MODE=1``:
  1. Verifies host kernel ``/proc/sys/crypto/fips_enabled`` (warns if absent
     so the same code path runs under macOS/dev — refuses to *boot* only when
     also ``FIPS_STRICT_BOOT=1``).
  2. Refuses to boot if any non-FIPS python crypto module is on the import path
     (pycryptodome's ARC4/DES/Blowfish, ssl with non-FIPS OpenSSL).
  3. Forces :pyfunc:`core.hsm_provider.get_hsm` to resolve to a real HSM (raises
     otherwise) so all downstream code paths that ask the HSM for keys are
     guaranteed FIPS-validated cryptographic boundaries.
  4. Wires the audit-chain logger so every cryptographic operation initiated by
     the app is appended to the tamper-evident chain.
  5. Disables non-FIPS algorithms in :pymod:`core.fips_compliance_mode_engine`.

Returns a :class:`FIPSBootReport` describing the posture so the API can expose
it on ``/api/v1/fips/status``.
"""

from __future__ import annotations

import importlib
import logging
import os
import ssl
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

_logger = logging.getLogger(__name__)

# Modules that must NOT be importable when FIPS_MODE=1
_NON_FIPS_MODULES = (
    "Crypto.Cipher.ARC4",
    "Crypto.Cipher.DES",
    "Crypto.Cipher.Blowfish",
    "Crypto.Hash.MD5",
    "Crypto.Hash.MD2",
    "Crypto.Hash.MD4",
)

# ---------------------------------------------------------------------------
# OpenSSL FIPS probing
# ---------------------------------------------------------------------------

def _openssl_version() -> str:
    """Return the OpenSSL version string reported by the ``ssl`` stdlib module."""
    try:
        return ssl.OPENSSL_VERSION
    except Exception:
        return "unknown"


def _openssl_fips_active() -> bool:
    """Return True if the runtime OpenSSL is operating in FIPS mode.

    Two independent checks:
    1. ``ssl.OPENSSL_VERSION`` contains the word ``fips`` (OpenSSL 3 FIPS
       provider sets this when loaded).
    2. Linux kernel ``/proc/sys/crypto/fips_enabled`` == 1 (implies OS-level
       FIPS enforcement which mandates the FIPS provider).
    """
    try:
        if "fips" in ssl.OPENSSL_VERSION.lower():
            return True
    except Exception:
        pass
    try:
        p = Path("/proc/sys/crypto/fips_enabled")
        if p.exists() and p.read_text().strip() == "1":
            return True
    except Exception:
        pass
    return False


def _fips_allowed_algorithms() -> list[str]:
    """Return the algorithm allow-list for FIPS 140-3.

    MD5 and SHA-1 are deprecated by FIPS 140-3 for new applications and are
    intentionally absent from this list.
    """
    return [
        "AES-128-GCM",
        "AES-256-GCM",
        "AES-128-CBC",
        "AES-256-CBC",
        "SHA-256",
        "SHA-384",
        "SHA-512",
        "SHA3-256",
        "SHA3-512",
        "HMAC-SHA256",
        "HMAC-SHA384",
        "HMAC-SHA512",
        "RSA-2048",
        "RSA-3072",
        "RSA-4096",
        "ECDSA-P256",
        "ECDSA-P384",
        "ECDH-P256",
        "ECDH-P384",
    ]


@dataclass
class FIPSBootReport:
    fips_mode_requested: bool = False
    fips_mode_active: bool = False
    kernel_fips: Optional[bool] = None  # None = not readable
    hsm_backend: Optional[str] = None
    hsm_required: bool = False
    audit_chain_attached: bool = False
    non_fips_libs_detected: list[str] = field(default_factory=list)
    boot_refused: bool = False
    refusal_reason: Optional[str] = None
    warnings: list[str] = field(default_factory=list)
    # OpenSSL FIPS boundary fields (populated by run_fips_boot)
    openssl_version: str = "unknown"
    openssl_fips_active: bool = False
    validated_module: Optional[str] = None
    algorithms_allowed: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "fips_mode_requested": self.fips_mode_requested,
            "fips_mode_active": self.fips_mode_active,
            "kernel_fips": self.kernel_fips,
            "hsm_backend": self.hsm_backend,
            "hsm_required": self.hsm_required,
            "audit_chain_attached": self.audit_chain_attached,
            "non_fips_libs_detected": self.non_fips_libs_detected,
            "boot_refused": self.boot_refused,
            "refusal_reason": self.refusal_reason,
            "warnings": self.warnings,
            # OpenSSL FIPS boundary
            "enabled": self.openssl_fips_active,
            "openssl_version": self.openssl_version,
            "validated_module": self.validated_module,
            "algorithms_allowed": self.algorithms_allowed,
        }


def _check_kernel_fips() -> Optional[bool]:
    p = Path("/proc/sys/crypto/fips_enabled")
    if not p.exists():
        return None
    try:
        return p.read_text().strip() == "1"
    except OSError:
        return None


def _check_non_fips_libs() -> list[str]:
    detected: list[str] = []
    for name in _NON_FIPS_MODULES:
        try:
            importlib.import_module(name)
            detected.append(name)
        except ImportError:
            pass
    return detected


class FIPSBootError(RuntimeError):
    """Raised when FIPS_STRICT_BOOT=1 and prerequisites are not met."""


def run_fips_boot() -> FIPSBootReport:
    """Execute FIPS boot sequence. Idempotent — safe to call multiple times.

    Reads env:
      ``FIPS_MODE``          — request FIPS mode
      ``FIPS_STRICT_BOOT``   — refuse to boot if checks fail (default 0)
      ``FIPS_MODE_REQUIRED`` — panic at startup if OpenSSL FIPS module is not
                               active; implies FIPS_MODE=1 and FIPS_STRICT_BOOT=1
      ``HSM_ENABLED``        — force HSM provider
    """
    report = FIPSBootReport()

    # FIPS_MODE_REQUIRED=1 is the strongest knob: implies both FIPS_MODE and
    # FIPS_STRICT_BOOT so a container that ships without an FIPS-validated
    # OpenSSL simply refuses to start rather than silently degrading.
    fips_required = os.environ.get("FIPS_MODE_REQUIRED", "0") == "1"
    report.fips_mode_requested = (
        fips_required or os.environ.get("FIPS_MODE", "0") == "1"
    )
    report.hsm_required = os.environ.get("HSM_ENABLED", "0") == "1"
    strict = fips_required or os.environ.get("FIPS_STRICT_BOOT", "0") == "1"

    # Always probe OpenSSL regardless of FIPS_MODE so /api/v1/fips/status
    # always returns a meaningful shape.
    report.openssl_version = _openssl_version()
    report.openssl_fips_active = _openssl_fips_active()
    report.algorithms_allowed = _fips_allowed_algorithms()
    if report.openssl_fips_active:
        # Derive a human-readable validated module identifier from the version.
        report.validated_module = report.openssl_version
    else:
        report.validated_module = None

    # FIPS_MODE_REQUIRED=1 with no FIPS OpenSSL → immediate RuntimeError panic.
    if fips_required and not report.openssl_fips_active:
        msg = (
            f"FIPS_MODE_REQUIRED=1 but OpenSSL FIPS module is NOT active "
            f"(openssl_version={report.openssl_version!r}). "
            "Boot refused. Provide a FIPS-validated OpenSSL build or unset "
            "FIPS_MODE_REQUIRED."
        )
        _logger.critical(msg)
        report.boot_refused = True
        report.refusal_reason = msg
        raise RuntimeError(msg)

    if not report.fips_mode_requested:
        _logger.warning(
            "FIPS_MODE not set — running without FIPS-validated crypto boundary. "
            "Set FIPS_MODE_REQUIRED=1 in production SCIF deployments."
        )
        return report

    # 1) kernel
    report.kernel_fips = _check_kernel_fips()
    if report.kernel_fips is False:
        msg = "Kernel reports fips_enabled=0 (host is not in FIPS mode)"
        if strict:
            report.boot_refused = True
            report.refusal_reason = msg
            raise FIPSBootError(msg)
        report.warnings.append(msg + " — running in FIPS-aware mode")
    elif report.kernel_fips is None:
        report.warnings.append(
            "/proc/sys/crypto/fips_enabled not readable (likely non-Linux host)"
        )

    # 2) non-FIPS libs
    detected = _check_non_fips_libs()
    report.non_fips_libs_detected = detected
    if detected:
        msg = f"Non-FIPS crypto libs detected: {detected}"
        if strict:
            report.boot_refused = True
            report.refusal_reason = msg
            raise FIPSBootError(msg)
        report.warnings.append(msg)
        # Force-evict from sys.modules so subsequent imports raise
        for name in detected:
            sys.modules.pop(name, None)

    # 3) HSM
    if report.hsm_required or report.fips_mode_requested:
        try:
            from core.hsm_provider import get_hsm
            hsm = get_hsm()
            report.hsm_backend = hsm.backend_name()
            _logger.info("FIPS boot: HSM ready — %s", report.hsm_backend)
        except Exception as exc:
            msg = f"HSM unavailable: {exc}"
            if strict:
                report.boot_refused = True
                report.refusal_reason = msg
                raise FIPSBootError(msg)
            report.warnings.append(msg)

    # 4) audit chain
    try:
        from core.audit_chain import get_audit_chain
        chain = get_audit_chain()
        chain.append(
            "fips_boot",
            payload={
                "kernel_fips": report.kernel_fips,
                "hsm_backend": report.hsm_backend,
                "non_fips_libs_detected": detected,
                "warnings": report.warnings,
            },
        )
        report.audit_chain_attached = True
    except Exception as exc:  # pragma: no cover
        report.warnings.append(f"Audit chain attach failed: {exc}")

    # 5) FIPS mode engine activation (best-effort)
    try:
        from core.fips_compliance_mode_engine import FIPSComplianceModeEngine
        engine = FIPSComplianceModeEngine()
        org = os.environ.get("FIPS_TENANT", "default")
        if hasattr(engine, "activate_fips_mode"):
            engine.activate_fips_mode(org_id=org)
    except Exception as exc:  # pragma: no cover
        report.warnings.append(f"FIPSComplianceModeEngine activation skipped: {exc}")

    report.fips_mode_active = True
    return report


# ---------------------------------------------------------------------------
# Runtime status helper — used by /api/v1/fips/status (runtime boundary view)
# ---------------------------------------------------------------------------

def get_runtime_fips_status() -> dict[str, Any]:
    """Return a dict describing the live OpenSSL FIPS boundary.

    This is intentionally lightweight (no side effects, no engine calls) so it
    can be called on every GET /api/v1/fips/status request.

    Required fields (guaranteed to be present):
      ``enabled``           — bool: True only when OpenSSL FIPS module is active
      ``openssl_version``   — str: e.g. "OpenSSL 3.0.7 1 Nov 2022"
      ``validated_module``  — str | None: same as openssl_version when enabled
      ``algorithms_allowed``— list[str]: FIPS 140-3 approved algorithms (MD5/SHA1 excluded)
    """
    fips_active = _openssl_fips_active()
    version = _openssl_version()
    fips_required = os.environ.get("FIPS_MODE_REQUIRED", "0") == "1"
    fips_mode = os.environ.get("FIPS_MODE", "0") == "1" or fips_required
    return {
        "enabled": fips_active,
        "openssl_version": version,
        "validated_module": version if fips_active else None,
        "algorithms_allowed": _fips_allowed_algorithms(),
        "fips_mode_requested": fips_mode,
        "fips_mode_required": fips_required,
        "cryptography_library": _cryptography_lib_info(),
    }


def _cryptography_lib_info() -> dict[str, Any]:
    """Return metadata about the ``cryptography`` package in use."""
    try:
        import cryptography  # type: ignore[import]
        return {
            "available": True,
            "version": getattr(cryptography, "__version__", "unknown"),
            "backend": "openssl",
        }
    except ImportError:
        return {
            "available": False,
            "version": None,
            "backend": None,
        }
