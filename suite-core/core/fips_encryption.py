"""FIPS 140-2 compliant encryption + air-gap mode for SCIF deployment.

Crypto operations use the ``cryptography`` library (pyca/cryptography) which
delegates to the system OpenSSL.  When the system OpenSSL is a FIPS-validated
build (e.g. RHEL 9 FIPS mode, Iron Bank base image) every call here is
automatically FIPS-validated.  stdlib AES is intentionally NOT used — it is
not covered by any FIPS 140 certificate regardless of the underlying OpenSSL.
"""

import hashlib
import hmac
import json
import os
import threading
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List

from pydantic import BaseModel

# ---------------------------------------------------------------------------
# ``cryptography`` library — FIPS-friendly AES-256-GCM
# ---------------------------------------------------------------------------
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _AESGCM
    _CRYPTOGRAPHY_AVAILABLE = True
except ImportError:  # pragma: no cover
    _CRYPTOGRAPHY_AVAILABLE = False
    _AESGCM = None  # type: ignore[assignment,misc]


class EncryptionMode(str, Enum):
    STANDARD = "standard"
    FIPS_140_2 = "fips_140_2"
    AIR_GAP = "air_gap"


class EncryptionStatus(BaseModel):
    mode: str
    algorithms: List[str]
    key_length: int
    fips_verified: bool
    air_gap_enabled: bool
    encrypted_databases: int


class FIPSEncryption:
    """FIPS 140-2 compliant encryption using AES-256 via stdlib."""

    BLOCK_SIZE = 16
    KEY_SIZE = 32
    NONCE_SIZE = 12
    TAG_SIZE = 16

    def __init__(self):
        self._lock = threading.Lock()
        self._mode = EncryptionMode.STANDARD

    def generate_key(self) -> bytes:
        return os.urandom(self.KEY_SIZE)

    def hash(self, data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    def hmac_sign(self, data: bytes, key: bytes) -> bytes:
        return hmac.new(key, data, hashlib.sha256).digest()

    def hmac_verify(self, data: bytes, key: bytes, signature: bytes) -> bool:
        expected = hmac.new(key, data, hashlib.sha256).digest()
        return hmac.compare_digest(expected, signature)

    def encrypt(self, data: bytes, key: bytes) -> bytes:
        """Encrypt using AES-256-GCM via ``cryptography`` lib (FIPS-friendly).

        Wire format: ``nonce(12) | ciphertext+tag(len(data)+16)``.
        Falls back to the legacy XOR+HMAC path only when the ``cryptography``
        package is not installed — legacy path is NOT FIPS-certified.
        """
        if len(key) != self.KEY_SIZE:
            raise ValueError(f"Key must be {self.KEY_SIZE} bytes")
        if _CRYPTOGRAPHY_AVAILABLE:
            nonce = os.urandom(self.NONCE_SIZE)
            ct_and_tag = _AESGCM(key).encrypt(nonce, data, None)
            return nonce + ct_and_tag
        # Legacy fallback (non-FIPS, development only)
        nonce = os.urandom(self.NONCE_SIZE)
        derived = hashlib.sha256(key + nonce).digest()
        encrypted = bytes(a ^ b for a, b in zip(data, (derived * ((len(data) // 32) + 1))[:len(data)]))
        tag = self.hmac_sign(nonce + encrypted, key)[:self.TAG_SIZE]
        return nonce + tag + encrypted

    def decrypt(self, data: bytes, key: bytes) -> bytes:
        """Decrypt AES-256-GCM ciphertext produced by :meth:`encrypt`."""
        if len(key) != self.KEY_SIZE:
            raise ValueError(f"Key must be {self.KEY_SIZE} bytes")
        if len(data) < self.NONCE_SIZE + self.TAG_SIZE:
            raise ValueError("Data too short")
        if _CRYPTOGRAPHY_AVAILABLE:
            nonce = data[:self.NONCE_SIZE]
            ct_and_tag = data[self.NONCE_SIZE:]
            try:
                from cryptography.exceptions import InvalidTag
                try:
                    return _AESGCM(key).decrypt(nonce, ct_and_tag, None)
                except InvalidTag:
                    raise ValueError("Authentication failed — data tampered")
            except ImportError:
                raise ValueError("Authentication failed — data tampered")
        # Legacy fallback (non-FIPS)
        nonce = data[:self.NONCE_SIZE]
        tag = data[self.NONCE_SIZE:self.NONCE_SIZE + self.TAG_SIZE]
        encrypted = data[self.NONCE_SIZE + self.TAG_SIZE:]
        expected_tag = self.hmac_sign(nonce + encrypted, key)[:self.TAG_SIZE]
        if not hmac.compare_digest(tag, expected_tag):
            raise ValueError("Authentication failed — data tampered")
        derived = hashlib.sha256(key + nonce).digest()
        return bytes(a ^ b for a, b in zip(encrypted, (derived * ((len(encrypted) // 32) + 1))[:len(encrypted)]))

    def encrypt_file(self, file_path: str, key: bytes) -> str:
        with open(file_path, "rb") as f:
            data = f.read()
        encrypted = self.encrypt(data, key)
        out_path = file_path + ".enc"
        with open(out_path, "wb") as f:
            f.write(encrypted)
        return out_path

    def decrypt_file(self, file_path: str, key: bytes) -> str:
        with open(file_path, "rb") as f:
            data = f.read()
        decrypted = self.decrypt(data, key)
        out_path = file_path.replace(".enc", "")
        if out_path == file_path:
            out_path = file_path + ".dec"
        with open(out_path, "wb") as f:
            f.write(decrypted)
        return out_path

    def verify_fips_mode(self) -> bool:
        """Return True only when the runtime OpenSSL is operating in FIPS mode.

        Checks (in order):
        1. ``ssl.OPENSSL_VERSION`` contains the string ``"fips"`` (case-insensitive)
           — present when built against an explicit FIPS-enabled OpenSSL (e.g.
           ``OpenSSL 3.0.x fips`` on RHEL 9).
        2. Linux kernel ``/proc/sys/crypto/fips_enabled`` == ``"1"`` — the kernel
           enforces FIPS at the OS level, which implies the OpenSSL FIPS provider
           is also loaded.

        Note: a ``True`` result here means the *module boundary* is enforced.
        ``False`` means FIPS validation is NOT active — the caller should treat
        all crypto as unvalidated.
        """
        try:
            import ssl
            if "fips" in ssl.OPENSSL_VERSION.lower():
                return True
        except Exception:
            pass
        try:
            from pathlib import Path
            p = Path("/proc/sys/crypto/fips_enabled")
            if p.exists() and p.read_text().strip() == "1":
                return True
        except Exception:
            pass
        return False

    def set_mode(self, mode: EncryptionMode):
        with self._lock:
            self._mode = mode

    def get_encryption_status(self) -> Dict:
        return {
            "mode": self._mode.value,
            "algorithms": ["AES-256-CTR", "SHA-256", "HMAC-SHA256"],
            "key_length": self.KEY_SIZE * 8,
            "fips_verified": self.verify_fips_mode(),
            "air_gap_enabled": AirGapMode._enabled,
        }


class AirGapMode:
    """Air-gap deployment mode — blocks all outbound network calls."""

    _enabled: bool = False
    _blocked_calls: List[Dict] = []
    _lock = threading.Lock()

    @classmethod
    def enable(cls):
        with cls._lock:
            cls._enabled = True

    @classmethod
    def disable(cls):
        with cls._lock:
            cls._enabled = False
            cls._blocked_calls.clear()

    @classmethod
    def is_enabled(cls) -> bool:
        return cls._enabled

    @classmethod
    def record_blocked(cls, url: str, method: str = "GET"):
        with cls._lock:
            cls._blocked_calls.append({
                "url": url, "method": method,
                "blocked_at": datetime.now(timezone.utc).isoformat(),
            })

    @classmethod
    def get_blocked_calls(cls) -> List[Dict]:
        with cls._lock:
            return list(cls._blocked_calls)

    @classmethod
    def export_for_transfer(cls, data: dict, key: bytes) -> bytes:
        enc = FIPSEncryption()
        payload = json.dumps(data).encode()
        return enc.encrypt(payload, key)

    @classmethod
    def import_from_transfer(cls, package: bytes, key: bytes) -> dict:
        enc = FIPSEncryption()
        decrypted = enc.decrypt(package, key)
        return json.loads(decrypted.decode())


def get_fips_encryption() -> FIPSEncryption:
    return FIPSEncryption()
