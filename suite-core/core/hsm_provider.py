"""HSM Provider — PKCS#11 wrapper for SCIF/IL5/FedRAMP-High deployments.

Wraps `python-pkcs11` (https://github.com/danni/python-pkcs11) so that key
material (RSA, AES, HMAC) is stored in a hardware token rather than software
keystores. Default backend during dev is SoftHSM 2.x (real PKCS#11 module,
no real hardware needed); production swap to AWS CloudHSM, Thales Luna, or
YubiHSM2 is config-only — set ``PKCS11_MODULE`` and ``PKCS11_TOKEN_LABEL``.

Architecture
------------
- ``HSMProvider``       — abstract interface (sign/verify/encrypt/decrypt/wrap/unwrap)
- ``PKCS11Provider``    — real implementation backed by python-pkcs11
- ``SoftwareProvider``  — fallback for dev / non-FIPS environments (uses
                          :pymod:`cryptography`, *not* allowed in FIPS_MODE=1)
- ``get_hsm()``         — module-level factory honouring env config

Environment
-----------
``HSM_ENABLED``         "1" to require HSM (else fall back to software)
``PKCS11_MODULE``       Path to PKCS#11 .so/.dll (default SoftHSM)
``PKCS11_TOKEN_LABEL``  Token label inside the module (default "aldeci")
``PKCS11_PIN``          User PIN. Read once at startup; never logged.
``PKCS11_SO_PIN``       Security-officer PIN (only used by ``init_token``)

Bootstrap (dev with SoftHSM)
----------------------------
::

    softhsm2-util --init-token --slot 0 \\
        --label aldeci --pin 1234 --so-pin 5678
    export HSM_ENABLED=1
    export PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so   # Linux
    # or /opt/homebrew/lib/softhsm/libsofthsm2.so          # macOS brew
    export PKCS11_TOKEN_LABEL=aldeci
    export PKCS11_PIN=1234

Tested against SoftHSM 2.6+, AWS CloudHSM v5 (PKCS#11 SDK), Thales Luna 7.x.
"""

from __future__ import annotations

import logging
import os
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Soft import — python-pkcs11 is an optional dependency
# ---------------------------------------------------------------------------
try:
    import pkcs11  # type: ignore
    from pkcs11 import KeyType, Mechanism, ObjectClass  # type: ignore
    from pkcs11.util.rsa import encode_rsa_public_key  # type: ignore
    _PKCS11_AVAILABLE = True
except ImportError:
    _PKCS11_AVAILABLE = False
    pkcs11 = None  # type: ignore
    Mechanism = ObjectClass = KeyType = None  # type: ignore

# ---------------------------------------------------------------------------
# Soft import — cryptography for software fallback (NOT FIPS-strict)
# ---------------------------------------------------------------------------
try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives import hmac as crypto_hmac
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    _CRYPTO_AVAILABLE = True
except ImportError:
    _CRYPTO_AVAILABLE = False


_DEFAULT_SOFTHSM_PATHS = [
    "/usr/lib64/softhsm/libsofthsm2.so",
    "/usr/lib/softhsm/libsofthsm2.so",
    "/usr/local/lib/softhsm/libsofthsm2.so",
    "/opt/homebrew/lib/softhsm/libsofthsm2.so",
    "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
]


def _resolve_pkcs11_module() -> Optional[str]:
    """Locate the PKCS#11 .so. Returns None if nothing found."""
    explicit = os.environ.get("PKCS11_MODULE", "").strip()
    if explicit:
        return explicit if Path(explicit).exists() else None
    for candidate in _DEFAULT_SOFTHSM_PATHS:
        if Path(candidate).exists():
            return candidate
    return None


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------
@dataclass
class KeyHandle:
    """Opaque handle to a key inside the HSM (or software keystore)."""

    label: str
    key_type: str  # "RSA-2048", "RSA-3072", "AES-256", "HMAC-SHA256"
    backend: str   # "pkcs11" or "software"
    public_key_pem: Optional[bytes] = None  # populated for asymmetric keys


# ---------------------------------------------------------------------------
# Abstract interface
# ---------------------------------------------------------------------------
class HSMProvider(ABC):
    """Abstract provider — every concrete impl must implement these."""

    @abstractmethod
    def is_available(self) -> bool: ...

    @abstractmethod
    def backend_name(self) -> str: ...

    @abstractmethod
    def generate_aes_key(self, label: str, key_size: int = 256) -> KeyHandle: ...

    @abstractmethod
    def generate_rsa_keypair(self, label: str, key_size: int = 3072) -> KeyHandle: ...

    @abstractmethod
    def get_key(self, label: str) -> Optional[KeyHandle]: ...

    @abstractmethod
    def sign(self, key: KeyHandle, data: bytes) -> bytes: ...

    @abstractmethod
    def verify(self, key: KeyHandle, data: bytes, signature: bytes) -> bool: ...

    @abstractmethod
    def encrypt(self, key: KeyHandle, plaintext: bytes, aad: Optional[bytes] = None) -> bytes: ...

    @abstractmethod
    def decrypt(self, key: KeyHandle, ciphertext: bytes, aad: Optional[bytes] = None) -> bytes: ...

    @abstractmethod
    def list_keys(self) -> list[KeyHandle]: ...

    @abstractmethod
    def delete_key(self, label: str) -> bool: ...


# ---------------------------------------------------------------------------
# Real PKCS#11 (SoftHSM / Luna / CloudHSM / YubiHSM2)
# ---------------------------------------------------------------------------
class PKCS11Provider(HSMProvider):
    """Real PKCS#11 implementation. Thread-safe via RLock."""

    def __init__(
        self,
        module_path: str,
        token_label: str,
        pin: str,
    ) -> None:
        if not _PKCS11_AVAILABLE:
            raise RuntimeError(
                "python-pkcs11 not installed. `pip install python-pkcs11`"
            )
        if not Path(module_path).exists():
            raise FileNotFoundError(f"PKCS#11 module not found: {module_path}")

        self._module_path = module_path
        self._token_label = token_label
        self._pin = pin  # never log this
        self._lock = threading.RLock()
        self._lib = pkcs11.lib(module_path)  # type: ignore
        try:
            self._token = self._lib.get_token(token_label=token_label)
        except pkcs11.exceptions.NoSuchToken:  # type: ignore
            raise RuntimeError(
                f"PKCS#11 token '{token_label}' not found in module {module_path}. "
                "Run `softhsm2-util --init-token --slot 0 --label "
                f"{token_label} --pin <pin> --so-pin <so-pin>`."
            )
        _logger.info(
            "PKCS#11 backend initialized: module=%s token=%s manufacturer=%s",
            module_path, token_label, self._lib.manufacturer_id,
        )

    # ---------------- Interface ----------------
    def is_available(self) -> bool:
        return True

    def backend_name(self) -> str:
        return f"pkcs11:{self._token_label}"

    def _session(self):
        """Open a read/write session. Caller must close (use as ctxmgr)."""
        return self._token.open(rw=True, user_pin=self._pin)

    def generate_aes_key(self, label: str, key_size: int = 256) -> KeyHandle:
        with self._lock, self._session() as session:
            existing = list(session.get_objects({
                pkcs11.Attribute.LABEL: label,
                pkcs11.Attribute.CLASS: ObjectClass.SECRET_KEY,
            }))
            for obj in existing:
                obj.destroy()
            session.generate_key(
                KeyType.AES, key_size,
                label=label,
                template={
                    pkcs11.Attribute.SENSITIVE: True,
                    pkcs11.Attribute.EXTRACTABLE: False,
                    pkcs11.Attribute.TOKEN: True,
                    pkcs11.Attribute.PRIVATE: True,
                    pkcs11.Attribute.ENCRYPT: True,
                    pkcs11.Attribute.DECRYPT: True,
                    pkcs11.Attribute.WRAP: True,
                    pkcs11.Attribute.UNWRAP: True,
                },
            )
        _logger.info("Generated AES-%d key in HSM: label=%s", key_size, label)
        return KeyHandle(label=label, key_type=f"AES-{key_size}", backend=self.backend_name())

    def generate_rsa_keypair(self, label: str, key_size: int = 3072) -> KeyHandle:
        with self._lock, self._session() as session:
            for cls in (ObjectClass.PRIVATE_KEY, ObjectClass.PUBLIC_KEY):
                for obj in list(session.get_objects({
                    pkcs11.Attribute.LABEL: label,
                    pkcs11.Attribute.CLASS: cls,
                })):
                    obj.destroy()
            pub, _priv = session.generate_keypair(
                KeyType.RSA, key_size,
                public_template={
                    pkcs11.Attribute.LABEL: label,
                    pkcs11.Attribute.TOKEN: True,
                    pkcs11.Attribute.VERIFY: True,
                    pkcs11.Attribute.ENCRYPT: True,
                },
                private_template={
                    pkcs11.Attribute.LABEL: label,
                    pkcs11.Attribute.TOKEN: True,
                    pkcs11.Attribute.PRIVATE: True,
                    pkcs11.Attribute.SENSITIVE: True,
                    pkcs11.Attribute.EXTRACTABLE: False,
                    pkcs11.Attribute.SIGN: True,
                    pkcs11.Attribute.DECRYPT: True,
                },
            )
            try:
                pub_pem = encode_rsa_public_key(pub)
            except Exception:  # pragma: no cover
                pub_pem = None

        _logger.info("Generated RSA-%d keypair in HSM: label=%s", key_size, label)
        return KeyHandle(
            label=label,
            key_type=f"RSA-{key_size}",
            backend=self.backend_name(),
            public_key_pem=pub_pem,
        )

    def get_key(self, label: str) -> Optional[KeyHandle]:
        with self._lock, self._session() as session:
            for obj in session.get_objects({pkcs11.Attribute.LABEL: label}):
                kt = obj[pkcs11.Attribute.KEY_TYPE]
                if kt == KeyType.AES:
                    return KeyHandle(
                        label=label, key_type=f"AES-{obj[pkcs11.Attribute.VALUE_LEN] * 8}",
                        backend=self.backend_name(),
                    )
                if kt == KeyType.RSA and obj[pkcs11.Attribute.CLASS] == ObjectClass.PUBLIC_KEY:
                    return KeyHandle(
                        label=label, key_type="RSA",
                        backend=self.backend_name(),
                        public_key_pem=encode_rsa_public_key(obj),
                    )
        return None

    def sign(self, key: KeyHandle, data: bytes) -> bytes:
        with self._lock, self._session() as session:
            priv = session.get_key(
                label=key.label,
                object_class=ObjectClass.PRIVATE_KEY,
            )
            return priv.sign(data, mechanism=Mechanism.SHA256_RSA_PKCS)

    def verify(self, key: KeyHandle, data: bytes, signature: bytes) -> bool:
        with self._lock, self._session() as session:
            try:
                pub = session.get_key(
                    label=key.label,
                    object_class=ObjectClass.PUBLIC_KEY,
                )
                return pub.verify(data, signature, mechanism=Mechanism.SHA256_RSA_PKCS)
            except Exception:  # pragma: no cover
                return False

    def encrypt(self, key: KeyHandle, plaintext: bytes, aad: Optional[bytes] = None) -> bytes:
        with self._lock, self._session() as session:
            sk = session.get_key(
                label=key.label,
                object_class=ObjectClass.SECRET_KEY,
            )
            iv = os.urandom(12)
            ct = sk.encrypt(plaintext, mechanism=Mechanism.AES_GCM,
                            mechanism_param=(iv, aad or b"", 128))
            return iv + ct

    def decrypt(self, key: KeyHandle, ciphertext: bytes, aad: Optional[bytes] = None) -> bytes:
        if len(ciphertext) < 12:
            raise ValueError("Ciphertext too short")
        iv, ct = ciphertext[:12], ciphertext[12:]
        with self._lock, self._session() as session:
            sk = session.get_key(
                label=key.label,
                object_class=ObjectClass.SECRET_KEY,
            )
            return sk.decrypt(ct, mechanism=Mechanism.AES_GCM,
                              mechanism_param=(iv, aad or b"", 128))

    def list_keys(self) -> list[KeyHandle]:
        out: list[KeyHandle] = []
        seen: set[str] = set()
        with self._lock, self._session() as session:
            for obj in session.get_objects({}):
                try:
                    label = obj[pkcs11.Attribute.LABEL]
                except Exception:
                    continue
                if not label or label in seen:
                    continue
                seen.add(label)
                kt = obj[pkcs11.Attribute.KEY_TYPE]
                kt_name = "AES" if kt == KeyType.AES else "RSA" if kt == KeyType.RSA else str(kt)
                out.append(KeyHandle(label=label, key_type=kt_name, backend=self.backend_name()))
        return out

    def delete_key(self, label: str) -> bool:
        deleted = False
        with self._lock, self._session() as session:
            for obj in list(session.get_objects({pkcs11.Attribute.LABEL: label})):
                obj.destroy()
                deleted = True
        return deleted


# ---------------------------------------------------------------------------
# Software fallback (NOT FIPS — refuses to run if FIPS_MODE=1)
# ---------------------------------------------------------------------------
class SoftwareProvider(HSMProvider):
    """In-process keystore using :pymod:`cryptography`.

    NOT for SCIF use. Refuses to instantiate when ``FIPS_MODE=1``.
    """

    def __init__(self, keystore_dir: Optional[Path] = None) -> None:
        if os.environ.get("FIPS_MODE", "0") == "1":
            raise RuntimeError(
                "FIPS_MODE=1 — software HSM provider is not allowed. "
                "Configure PKCS11_MODULE to point at a real HSM/SoftHSM."
            )
        if not _CRYPTO_AVAILABLE:
            raise RuntimeError(
                "`cryptography` package required for software fallback."
            )
        self._dir = keystore_dir or Path(os.environ.get(
            "FIXOPS_SOFTWARE_KEYSTORE", "/tmp/fixops_software_keystore"  # nosec B108
        ))
        self._dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._lock = threading.RLock()
        self._cache: dict[str, Any] = {}
        _logger.warning(
            "SoftwareProvider keystore at %s — DEV USE ONLY. Set HSM_ENABLED=1 for prod.",
            self._dir,
        )

    def is_available(self) -> bool:
        return True

    def backend_name(self) -> str:
        return "software"

    def _key_path(self, label: str, suffix: str) -> Path:
        # Sanitize label to safe filename (alphanumeric + -_ only)
        safe = "".join(c for c in label if c.isalnum() or c in "-_")[:64]
        return self._dir / f"{safe}.{suffix}"

    def generate_aes_key(self, label: str, key_size: int = 256) -> KeyHandle:
        with self._lock:
            raw = os.urandom(key_size // 8)
            self._key_path(label, "aes").write_bytes(raw)
            os.chmod(self._key_path(label, "aes"), 0o600)
            self._cache[label] = ("aes", raw)
        return KeyHandle(label=label, key_type=f"AES-{key_size}", backend="software")

    def generate_rsa_keypair(self, label: str, key_size: int = 3072) -> KeyHandle:
        with self._lock:
            priv = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
            priv_pem = priv.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            pub_pem = priv.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            self._key_path(label, "rsa.priv").write_bytes(priv_pem)
            self._key_path(label, "rsa.pub").write_bytes(pub_pem)
            os.chmod(self._key_path(label, "rsa.priv"), 0o600)
            self._cache[label] = ("rsa", priv)
        return KeyHandle(
            label=label, key_type=f"RSA-{key_size}",
            backend="software", public_key_pem=pub_pem,
        )

    def get_key(self, label: str) -> Optional[KeyHandle]:
        with self._lock:
            if (p := self._key_path(label, "aes")).exists():
                return KeyHandle(label=label, key_type="AES-256", backend="software")
            if (p := self._key_path(label, "rsa.pub")).exists():
                return KeyHandle(
                    label=label, key_type="RSA-3072", backend="software",
                    public_key_pem=p.read_bytes(),
                )
        return None

    def _load_rsa_private(self, label: str):
        cached = self._cache.get(label)
        if cached and cached[0] == "rsa":
            return cached[1]
        pem = self._key_path(label, "rsa.priv").read_bytes()
        priv = serialization.load_pem_private_key(pem, password=None)
        self._cache[label] = ("rsa", priv)
        return priv

    def sign(self, key: KeyHandle, data: bytes) -> bytes:
        priv = self._load_rsa_private(key.label)
        return priv.sign(data, padding.PKCS1v15(), hashes.SHA256())

    def verify(self, key: KeyHandle, data: bytes, signature: bytes) -> bool:
        try:
            pem = self._key_path(key.label, "rsa.pub").read_bytes()
            pub = serialization.load_pem_public_key(pem)
            pub.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
            return True
        except Exception:
            return False

    def _load_aes(self, label: str) -> bytes:
        cached = self._cache.get(label)
        if cached and cached[0] == "aes":
            return cached[1]
        raw = self._key_path(label, "aes").read_bytes()
        self._cache[label] = ("aes", raw)
        return raw

    def encrypt(self, key: KeyHandle, plaintext: bytes, aad: Optional[bytes] = None) -> bytes:
        raw = self._load_aes(key.label)
        gcm = AESGCM(raw)
        nonce = os.urandom(12)
        return nonce + gcm.encrypt(nonce, plaintext, aad)

    def decrypt(self, key: KeyHandle, ciphertext: bytes, aad: Optional[bytes] = None) -> bytes:
        if len(ciphertext) < 12:
            raise ValueError("Ciphertext too short")
        raw = self._load_aes(key.label)
        gcm = AESGCM(raw)
        return gcm.decrypt(ciphertext[:12], ciphertext[12:], aad)

    def list_keys(self) -> list[KeyHandle]:
        seen: set[str] = set()
        out: list[KeyHandle] = []
        for p in self._dir.iterdir():
            label = p.stem.split(".", 1)[0]
            if label in seen:
                continue
            seen.add(label)
            kh = self.get_key(label)
            if kh:
                out.append(kh)
        return out

    def delete_key(self, label: str) -> bool:
        deleted = False
        for suffix in ("aes", "rsa.priv", "rsa.pub"):
            p = self._key_path(label, suffix)
            if p.exists():
                p.unlink()
                deleted = True
        self._cache.pop(label, None)
        return deleted


# ---------------------------------------------------------------------------
# Module-level factory
# ---------------------------------------------------------------------------
_PROVIDER_LOCK = threading.Lock()
_PROVIDER: Optional[HSMProvider] = None


def get_hsm() -> HSMProvider:
    """Return the configured HSM provider (singleton).

    Resolution order:
      1. ``HSM_ENABLED=1`` and PKCS#11 module loadable → ``PKCS11Provider``
      2. ``FIPS_MODE=1`` and no PKCS#11 → raise (fail-closed)
      3. else → ``SoftwareProvider`` (dev only)
    """
    global _PROVIDER  # noqa: PLW0603
    with _PROVIDER_LOCK:
        if _PROVIDER is not None:
            return _PROVIDER

        hsm_required = os.environ.get("HSM_ENABLED", "0") == "1"
        fips_mode = os.environ.get("FIPS_MODE", "0") == "1"

        module_path = _resolve_pkcs11_module()
        token_label = os.environ.get("PKCS11_TOKEN_LABEL", "aldeci")
        pin = os.environ.get("PKCS11_PIN", "")

        if hsm_required or fips_mode:
            if not _PKCS11_AVAILABLE:
                raise RuntimeError(
                    "HSM_ENABLED/FIPS_MODE set but python-pkcs11 not installed."
                )
            if not module_path:
                raise RuntimeError(
                    "HSM_ENABLED/FIPS_MODE set but no PKCS#11 module found. "
                    "Install SoftHSM2 or set PKCS11_MODULE."
                )
            if not pin:
                raise RuntimeError(
                    "HSM_ENABLED/FIPS_MODE set but PKCS11_PIN env var not provided."
                )
            _PROVIDER = PKCS11Provider(module_path, token_label, pin)
        else:
            _PROVIDER = SoftwareProvider()
        return _PROVIDER


def reset_hsm() -> None:
    """Test-only reset of the singleton."""
    global _PROVIDER  # noqa: PLW0603
    with _PROVIDER_LOCK:
        _PROVIDER = None


__all__ = [
    "HSMProvider",
    "PKCS11Provider",
    "SoftwareProvider",
    "KeyHandle",
    "get_hsm",
    "reset_hsm",
]
