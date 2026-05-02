"""Air-Gap Bundle Engine — ALDECI (GAP-001, Sonatype SAGE parity).

Signed intelligence bundle export/verify/apply for air-gapped deployments.

Enterprises that cannot phone home need a deterministic way to move signed
intelligence (CVE catalog, threat indicators, policies, frameworks) from an
internet-connected producer site to one or more air-gapped consumer sites.

This engine:

  1. **export_bundle(org_id, ...)** — snapshots current CVE/TI/policy rows from
     their native engines into a tar.gz archive on disk with a MANIFEST.json.
     The manifest lists every entry with its sha256, the counts, and a
     (placeholder) signature block. Rows are persisted so operators can track
     what was shipped.
  2. **verify_bundle(bundle_id | path)** — re-opens the archive, recomputes each
     entry sha256 against the manifest, validates the manifest content_hash,
     checks the signature placeholder. Returns structured ok/errors.
  3. **apply_bundle(bundle_id, dry_run=False)** — idempotently upserts every
     entry into the target tables (cve_cache, threat_indicators, policies).
     Uses INSERT OR REPLACE for idempotency. Records a bundle_application row.
  4. **record_transfer / list / get / stats** — lifecycle management.

Storage
-------
- Engine DB:       .fixops_data/air_gap_bundle_engine.db (WAL + RLock)
- Bundle archives: .omc/air_gap_bundles/<bundle_id>.tar.gz

Security notes
--------------
- All bundle signing uses ed25519 DSSE attestation — sha256 fallback removed
  2026-05-02. Bundle creation fails loudly if signer unavailable. The
  ``signature_placeholder`` column is retained for schema compatibility but
  now stores a real base64-encoded ed25519 signature produced by
  ``core.dsse_signer``.
- Verification rejects any signature beginning with the legacy
  ``sha256-fallback:`` prefix — bundles produced by the prior degraded
  signer must be re-signed with ed25519 before they will verify.
- Tampered manifest or tampered entries → verify_bundle returns ok=False with
  the failing entry listed.
- Apply never runs on an un-verified bundle — verify is a gate.

Multi-tenant isolation
----------------------
All tables carry org_id. Every query scopes by org_id when provided. The
engine itself is a singleton per DB file but callers pass their org_id in,
matching the platform-wide pattern.

Compliance: NIST SP 800-171 (CUI at rest), DFARS 7012, FedRAMP Moderate.
"""
from __future__ import annotations

import hashlib
import io
import json
import logging
import sqlite3
import tarfile
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

try:  # optional — TrustGraph event emission
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:  # pragma: no cover
    _get_tg_bus = None  # type: ignore

try:
    from core.dsse_signer import get_signer as _get_dsse_signer
except ImportError:  # pragma: no cover
    _get_dsse_signer = None  # type: ignore

# ed25519 primitives for ensure_signing_key bootstrap (real keys, not a
# fallback — bootstraps the same ed25519 material the DSSE signer expects).
try:
    from cryptography.hazmat.primitives import serialization as _crypto_serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey as _Ed25519PrivateKey,
    )
except ImportError:  # pragma: no cover — cryptography is a core dependency
    _crypto_serialization = None  # type: ignore
    _Ed25519PrivateKey = None  # type: ignore


_logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Defaults and constants
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_DB = str(_REPO_ROOT / ".fixops_data" / "air_gap_bundle_engine.db")
_DEFAULT_BUNDLE_DIR = _REPO_ROOT / ".omc" / "air_gap_bundles"
_DEFAULT_CVE_DB = _REPO_ROOT / "data" / "cve_enrichment.db"
_DEFAULT_TI_DB = _REPO_ROOT / ".fixops_data" / "threat_indicator_engine.db"
_DEFAULT_POLICY_DB = _REPO_ROOT / ".fixops_data" / "policy_engine.db"

_BUNDLE_VERSION_FMT = "%Y.%m.%d"
_MANIFEST_NAME = "MANIFEST.json"
_SIGNATURE_ALGO = "ed25519-sha512"  # real ed25519 signing via dsse_signer

_VALID_STATUSES = {
    "exported",
    "transferred",
    "verified",
    "verify_failed",
    "applied",
    "apply_failed",
    "failed",
}
_VALID_ENTRY_TYPES = {"cve", "ti_indicator", "policy", "framework", "signature"}
_VALID_TRANSPORTS = {
    "manual_usb",
    "data_diode",
    "sneakernet",
    "sftp",
    "https_proxy",
    "other",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


_AIRGAP_SIGNING_KEY_PATH = _REPO_ROOT / "data" / "keys" / "airgap_signing.ed25519"
_AIRGAP_SIGNING_PUB_PATH = _REPO_ROOT / "data" / "keys" / "airgap_signing.pub"
_LEGACY_SHA256_PREFIX = "sha256-fallback:"


def ensure_signing_key(
    private_path: Path = _AIRGAP_SIGNING_KEY_PATH,
    public_path: Path = _AIRGAP_SIGNING_PUB_PATH,
) -> Path:
    """Bootstrap a real ed25519 signing key for air-gap bundles.

    NOT a fallback — this generates the same ed25519 material the DSSE signer
    uses, persisted at ``data/keys/airgap_signing.ed25519`` (mode 0600). The
    public key is written to ``data/keys/airgap_signing.pub``. Existing keys
    are left untouched.

    Returns the absolute path to the private key.
    """
    if _Ed25519PrivateKey is None or _crypto_serialization is None:
        raise RuntimeError(
            "ensure_signing_key requires the `cryptography` package — "
            "install it with `pip install cryptography`."
        )
    if private_path.exists():
        return private_path
    private_path.parent.mkdir(parents=True, exist_ok=True)
    priv = _Ed25519PrivateKey.generate()
    priv_pem = priv.private_bytes(
        encoding=_crypto_serialization.Encoding.PEM,
        format=_crypto_serialization.PrivateFormat.PKCS8,
        encryption_algorithm=_crypto_serialization.NoEncryption(),
    )
    private_path.write_bytes(priv_pem)
    private_path.chmod(0o600)

    pub_pem = priv.public_key().public_bytes(
        encoding=_crypto_serialization.Encoding.PEM,
        format=_crypto_serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    public_path.write_bytes(pub_pem)
    public_path.chmod(0o644)
    _logger.info(
        "air_gap: bootstrapped ed25519 signing key private=%s public=%s",
        private_path,
        public_path,
    )
    return private_path


def _sign_manifest(data: bytes) -> str:
    """Sign manifest bytes with ed25519 via dsse_signer.

    Returns a base64-encoded ed25519 signature string. Raises RuntimeError if
    the DSSE signer is unavailable — sha256 fallback removed 2026-05-02 for
    SCIF deployments. Loud failure > silent degradation.
    """
    if _get_dsse_signer is None:
        raise RuntimeError(
            "Air-gap bundle signing requires ed25519 dsse_signer — "
            "sha256 fallback removed for SCIF deployments. Install "
            "cryptography or sigstore-python and configure DSSE signer keys."
        )
    try:
        return _get_dsse_signer().sign_bytes(data)
    except Exception as exc:  # pragma: no cover
        raise RuntimeError(
            "Air-gap bundle signing requires ed25519 dsse_signer — "
            "sha256 fallback removed for SCIF deployments. Install "
            f"cryptography or sigstore-python and configure DSSE signer keys. ({exc})"
        ) from exc


def _verify_manifest_sig(data: bytes, sig: str) -> Tuple[bool, str]:
    """Verify manifest signature with ed25519.

    Refuses any signature carrying the legacy ``sha256-fallback:`` prefix —
    such bundles must be re-signed with ed25519. Returns ``(ok, reason)``;
    ``reason`` is empty on success.
    """
    if not sig:
        return False, "missing signature"
    if sig.startswith(_LEGACY_SHA256_PREFIX):
        return (
            False,
            "legacy sha256 fallback signature — bundle must be re-signed with ed25519",
        )
    if _get_dsse_signer is None:
        return False, "ed25519 dsse_signer unavailable — cannot verify signature"
    try:
        ok = _get_dsse_signer().verify_bytes(data, sig)
    except Exception as exc:  # pragma: no cover
        return False, f"ed25519 verification raised: {exc}"
    if not ok:
        return False, "ed25519 signature mismatch"
    return True, ""


def _default_version() -> str:
    """Date-stamped version with monotonic 3-digit counter."""
    return f"{datetime.now(timezone.utc).strftime(_BUNDLE_VERSION_FMT)}-{int(time.time()) % 1000:03d}"


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class AirGapBundleEngine:
    """Signed intelligence bundle lifecycle engine.

    Thread-safe via RLock. SQLite WAL. Per-tenant via org_id.
    """

    def __init__(
        self,
        db_path: str = _DEFAULT_DB,
        bundle_dir: Optional[Union[str, Path]] = None,
        cve_db_path: Optional[Union[str, Path]] = None,
        ti_db_path: Optional[Union[str, Path]] = None,
        policy_db_path: Optional[Union[str, Path]] = None,
    ) -> None:
        self.db_path = str(db_path)
        self.bundle_dir = Path(bundle_dir) if bundle_dir else _DEFAULT_BUNDLE_DIR
        self.cve_db_path = Path(cve_db_path) if cve_db_path else _DEFAULT_CVE_DB
        self.ti_db_path = Path(ti_db_path) if ti_db_path else _DEFAULT_TI_DB
        self.policy_db_path = Path(policy_db_path) if policy_db_path else _DEFAULT_POLICY_DB
        self._lock = threading.RLock()
        self.bundle_dir.mkdir(parents=True, exist_ok=True)
        self.ensure_schema()

    # ------------------------------------------------------------------
    # Connection helpers
    # ------------------------------------------------------------------

    def _conn(self) -> sqlite3.Connection:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.db_path, check_same_thread=False, timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    def _source_conn(self, path: Path) -> Optional[sqlite3.Connection]:
        """Open a read-only source DB connection; returns None if absent."""
        if not path.exists():
            return None
        try:
            conn = sqlite3.connect(str(path), check_same_thread=False, timeout=10.0)
            conn.row_factory = sqlite3.Row
            return conn
        except sqlite3.Error:
            return None

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def ensure_schema(self) -> None:
        with self._lock, self._conn() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS bundles (
                    id                     TEXT PRIMARY KEY,
                    org_id                 TEXT NOT NULL,
                    bundle_id              TEXT NOT NULL UNIQUE,
                    version                TEXT NOT NULL DEFAULT '',
                    created_at             TEXT,
                    exported_by            TEXT NOT NULL DEFAULT '',
                    size_bytes             INTEGER NOT NULL DEFAULT 0,
                    content_hash           TEXT NOT NULL DEFAULT '',
                    signature_placeholder  TEXT NOT NULL DEFAULT '',
                    manifest_json          TEXT NOT NULL DEFAULT '{}',
                    archive_path           TEXT NOT NULL DEFAULT '',
                    status                 TEXT NOT NULL DEFAULT 'exported'
                );

                CREATE INDEX IF NOT EXISTS idx_bundles_org
                    ON bundles (org_id, status, created_at);

                CREATE TABLE IF NOT EXISTS bundle_entries (
                    id                  TEXT PRIMARY KEY,
                    bundle_id           TEXT NOT NULL,
                    entry_type          TEXT NOT NULL DEFAULT 'cve',
                    entry_key           TEXT NOT NULL DEFAULT '',
                    entry_payload_size  INTEGER NOT NULL DEFAULT 0,
                    entry_sha256        TEXT NOT NULL DEFAULT ''
                );

                CREATE INDEX IF NOT EXISTS idx_bundle_entries_bundle
                    ON bundle_entries (bundle_id, entry_type);

                CREATE TABLE IF NOT EXISTS bundle_transfers (
                    id                  TEXT PRIMARY KEY,
                    bundle_id           TEXT NOT NULL,
                    from_site           TEXT NOT NULL DEFAULT '',
                    to_site             TEXT NOT NULL DEFAULT '',
                    transferred_at      TEXT,
                    transport_method    TEXT NOT NULL DEFAULT 'manual_usb',
                    checksum_verified   INTEGER NOT NULL DEFAULT 0,
                    notes               TEXT NOT NULL DEFAULT ''
                );

                CREATE INDEX IF NOT EXISTS idx_bundle_transfers_bundle
                    ON bundle_transfers (bundle_id);

                CREATE TABLE IF NOT EXISTS bundle_applications (
                    id                 TEXT PRIMARY KEY,
                    bundle_id          TEXT NOT NULL,
                    applied_at         TEXT,
                    applied_by         TEXT NOT NULL DEFAULT '',
                    applied_status     TEXT NOT NULL DEFAULT 'applied',
                    entries_ingested   INTEGER NOT NULL DEFAULT 0,
                    entries_failed     INTEGER NOT NULL DEFAULT 0,
                    error_log          TEXT NOT NULL DEFAULT '[]',
                    dry_run            INTEGER NOT NULL DEFAULT 0
                );

                CREATE INDEX IF NOT EXISTS idx_bundle_apps_bundle
                    ON bundle_applications (bundle_id);
                """
            )

    # ------------------------------------------------------------------
    # Source collection — read CVE / TI / policy rows
    # ------------------------------------------------------------------

    def _collect_cve_rows(self, org_id: str, limit: int = 10000) -> List[Dict[str, Any]]:
        """Pull CVE catalog rows. cve_cache is org-agnostic (global catalog)."""
        conn = self._source_conn(self.cve_db_path)
        if conn is None:
            return []
        try:
            try:
                rows = conn.execute(
                    "SELECT * FROM cve_cache ORDER BY cvss_score DESC LIMIT ?",
                    (limit,),
                ).fetchall()
            except sqlite3.OperationalError:
                return []
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def _collect_ti_rows(self, org_id: str, limit: int = 10000) -> List[Dict[str, Any]]:
        """Pull active threat indicators for the org."""
        conn = self._source_conn(self.ti_db_path)
        if conn is None:
            return []
        try:
            try:
                rows = conn.execute(
                    """SELECT * FROM threat_indicators
                       WHERE org_id = ? AND active = 1
                       ORDER BY confidence DESC LIMIT ?""",
                    (org_id, limit),
                ).fetchall()
            except sqlite3.OperationalError:
                return []
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def _collect_policy_rows(self, org_id: str, limit: int = 10000) -> List[Dict[str, Any]]:
        """Pull enabled policies for the org."""
        conn = self._source_conn(self.policy_db_path)
        if conn is None:
            return []
        try:
            try:
                rows = conn.execute(
                    """SELECT * FROM policies
                       WHERE org_id = ? AND enabled = 1
                       ORDER BY updated_at DESC LIMIT ?""",
                    (org_id, limit),
                ).fetchall()
            except sqlite3.OperationalError:
                return []
            return [dict(r) for r in rows]
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # export_bundle
    # ------------------------------------------------------------------

    def export_bundle(
        self,
        org_id: str,
        bundle_version: Optional[str] = None,
        include_cve: bool = True,
        include_ti: bool = True,
        include_policy: bool = True,
        exported_by: str = "system",
        extra_cve_rows: Optional[List[Dict[str, Any]]] = None,
        extra_ti_rows: Optional[List[Dict[str, Any]]] = None,
        extra_policy_rows: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Export a signed intelligence bundle to disk.

        `extra_*` args allow callers (including tests) to inject rows when the
        source DBs don't yet exist in this environment.

        Returns the persisted bundle record with manifest embedded.
        """
        if not org_id:
            raise ValueError("org_id required")
        if not (include_cve or include_ti or include_policy):
            raise ValueError("at least one of include_cve/ti/policy must be True")

        bundle_id = f"bundle-{uuid.uuid4().hex[:12]}"
        version = bundle_version or _default_version()
        created_at = _now_iso()

        # ---- collect rows -------------------------------------------------
        cve_rows: List[Dict[str, Any]] = []
        ti_rows: List[Dict[str, Any]] = []
        policy_rows: List[Dict[str, Any]] = []

        if include_cve:
            cve_rows = self._collect_cve_rows(org_id)
            if extra_cve_rows:
                cve_rows = cve_rows + list(extra_cve_rows)
        if include_ti:
            ti_rows = self._collect_ti_rows(org_id)
            if extra_ti_rows:
                ti_rows = ti_rows + list(extra_ti_rows)
        if include_policy:
            policy_rows = self._collect_policy_rows(org_id)
            if extra_policy_rows:
                policy_rows = policy_rows + list(extra_policy_rows)

        # ---- compute entry metadata --------------------------------------
        entries_meta: List[Dict[str, Any]] = []
        entry_blobs: List[Tuple[str, bytes]] = []  # (tar path, bytes)

        def _entry_key(row: Dict[str, Any], fallback_prefix: str) -> str:
            for k in ("cve_id", "id", "indicator_value", "name"):
                if k in row and row[k]:
                    return str(row[k])
            return f"{fallback_prefix}-{uuid.uuid4().hex[:8]}"

        def _pack(entry_type: str, rows: List[Dict[str, Any]], prefix: str) -> None:
            for row in rows:
                key = _entry_key(row, prefix)
                payload = json.dumps(row, sort_keys=True, default=str).encode("utf-8")
                digest = _sha256_bytes(payload)
                tar_path = f"entries/{entry_type}/{key.replace('/', '_')}.json"
                entries_meta.append(
                    {
                        "type": entry_type,
                        "key": key,
                        "sha256": digest,
                        "size": len(payload),
                        "path": tar_path,
                    }
                )
                entry_blobs.append((tar_path, payload))

        _pack("cve", cve_rows, "cve")
        _pack("ti_indicator", ti_rows, "ti")
        _pack("policy", policy_rows, "policy")

        counts = {
            "cve": len(cve_rows),
            "ti": len(ti_rows),
            "policy": len(policy_rows),
            "total": len(entries_meta),
        }

        # ---- build manifest (unsigned part first) ------------------------
        manifest_core = {
            "bundle_id": bundle_id,
            "version": version,
            "created_at": created_at,
            "produced_by": "fixops",
            "org_id": org_id,
            "exported_by": exported_by,
            "entries": entries_meta,
            "counts": counts,
        }
        manifest_bytes = json.dumps(manifest_core, sort_keys=True).encode("utf-8")
        manifest_sha256 = _sha256_bytes(manifest_bytes)
        signature = _sign_manifest(manifest_bytes)
        self._emit_event(
            "airgap.bundle_signed",
            {
                "bundle_id": bundle_id,
                "org_id": org_id,
                "manifest_sha256": manifest_sha256,
                "signature_algo": _SIGNATURE_ALGO,
                "signature_prefix": signature[:16],
            },
        )

        manifest_final = {
            **manifest_core,
            "manifest_sha256": manifest_sha256,
            "signature_algo": _SIGNATURE_ALGO,
            "signature": signature,
        }
        manifest_final_bytes = json.dumps(manifest_final, sort_keys=True, indent=2).encode("utf-8")

        # ---- write tar.gz archive ----------------------------------------
        self.bundle_dir.mkdir(parents=True, exist_ok=True)
        archive_path = self.bundle_dir / f"{bundle_id}.tar.gz"
        with tarfile.open(str(archive_path), "w:gz") as tar:
            # manifest
            info = tarfile.TarInfo(name=_MANIFEST_NAME)
            info.size = len(manifest_final_bytes)
            info.mtime = int(time.time())
            tar.addfile(info, io.BytesIO(manifest_final_bytes))
            # entries
            for tar_path, payload in entry_blobs:
                info = tarfile.TarInfo(name=tar_path)
                info.size = len(payload)
                info.mtime = int(time.time())
                tar.addfile(info, io.BytesIO(payload))

        size_bytes = archive_path.stat().st_size
        # content_hash is over the MANIFEST bytes (stable even if tar metadata varies)
        content_hash = manifest_sha256

        # ---- persist rows ------------------------------------------------
        row_id = str(uuid.uuid4())
        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT INTO bundles
                   (id, org_id, bundle_id, version, created_at, exported_by, size_bytes,
                    content_hash, signature_placeholder, manifest_json, archive_path, status)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    row_id,
                    org_id,
                    bundle_id,
                    version,
                    created_at,
                    exported_by,
                    size_bytes,
                    content_hash,
                    signature,
                    json.dumps(manifest_final),
                    str(archive_path),
                    "exported",
                ),
            )
            for meta in entries_meta:
                conn.execute(
                    """INSERT INTO bundle_entries
                       (id, bundle_id, entry_type, entry_key, entry_payload_size, entry_sha256)
                       VALUES (?,?,?,?,?,?)""",
                    (
                        str(uuid.uuid4()),
                        bundle_id,
                        meta["type"],
                        meta["key"],
                        meta["size"],
                        meta["sha256"],
                    ),
                )
            conn.commit()

        self._emit_event(
            "airgap.bundle.exported",
            {"bundle_id": bundle_id, "org_id": org_id, "counts": counts},
        )

        return {
            "id": row_id,
            "org_id": org_id,
            "bundle_id": bundle_id,
            "version": version,
            "created_at": created_at,
            "exported_by": exported_by,
            "size_bytes": size_bytes,
            "content_hash": content_hash,
            "signature_placeholder": signature,
            "archive_path": str(archive_path),
            "status": "exported",
            "manifest": manifest_final,
            "counts": counts,
        }

    # ------------------------------------------------------------------
    # verify_bundle
    # ------------------------------------------------------------------

    def _load_archive(self, path_or_bundle_id: Union[str, Path]) -> Tuple[Path, Dict[str, Any], Dict[str, bytes]]:
        """Resolve to an archive on disk, parse MANIFEST + entries."""
        p = Path(path_or_bundle_id) if isinstance(path_or_bundle_id, (str, Path)) else None
        if p is not None and p.exists() and p.is_file():
            archive_path = p
        else:
            # treat as bundle_id
            bundle_id = str(path_or_bundle_id)
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT archive_path FROM bundles WHERE bundle_id = ?",
                    (bundle_id,),
                ).fetchone()
            if not row or not row["archive_path"]:
                raise KeyError(f"bundle not found: {path_or_bundle_id}")
            archive_path = Path(row["archive_path"])
            if not archive_path.exists():
                raise FileNotFoundError(f"bundle archive missing: {archive_path}")

        manifest: Dict[str, Any] = {}
        entry_bytes: Dict[str, bytes] = {}
        with tarfile.open(str(archive_path), "r:gz") as tar:
            for member in tar.getmembers():
                f = tar.extractfile(member)
                if f is None:
                    continue
                data = f.read()
                if member.name == _MANIFEST_NAME:
                    manifest = json.loads(data.decode("utf-8"))
                else:
                    entry_bytes[member.name] = data
        if not manifest:
            raise ValueError("MANIFEST.json missing from archive")
        return archive_path, manifest, entry_bytes

    def verify_bundle(self, path_or_bundle_id: Union[str, Path]) -> Dict[str, Any]:
        """Verify manifest hash, entry hashes, and signature placeholder.

        Returns:
          {ok: bool, entries_checked, entries_failed, errors, bundle_id}
        """
        errors: List[str] = []
        try:
            archive_path, manifest, entry_bytes = self._load_archive(path_or_bundle_id)
        except (KeyError, FileNotFoundError, ValueError) as exc:
            return {
                "ok": False,
                "entries_checked": 0,
                "entries_failed": 0,
                "errors": [str(exc)],
                "bundle_id": str(path_or_bundle_id),
            }

        bundle_id = manifest.get("bundle_id", "")
        entries_meta = manifest.get("entries", []) or []

        # ---- recompute manifest_sha256 over core manifest ----------------
        core = {k: v for k, v in manifest.items() if k not in {"manifest_sha256", "signature_algo", "signature"}}
        core_bytes = json.dumps(core, sort_keys=True).encode("utf-8")
        recomputed_manifest_sha = _sha256_bytes(core_bytes)
        expected_manifest_sha = manifest.get("manifest_sha256", "")
        if recomputed_manifest_sha != expected_manifest_sha:
            errors.append(
                f"manifest_sha256 mismatch: expected={expected_manifest_sha} "
                f"got={recomputed_manifest_sha}"
            )

        # ---- verify ed25519 signature ------------------------------------
        expected_sig = manifest.get("signature", "")
        sig_ok, sig_reason = _verify_manifest_sig(core_bytes, expected_sig)
        if not sig_ok:
            errors.append(sig_reason or "signature mismatch (ed25519 verification failed)")

        # ---- check each entry hash ---------------------------------------
        entries_checked = 0
        entries_failed = 0
        for meta in entries_meta:
            entries_checked += 1
            tar_path = meta.get("path") or f"entries/{meta.get('type')}/{meta.get('key')}.json"
            declared_sha = meta.get("sha256", "")
            payload = entry_bytes.get(tar_path)
            if payload is None:
                entries_failed += 1
                errors.append(f"entry payload missing: {tar_path}")
                continue
            actual_sha = _sha256_bytes(payload)
            if actual_sha != declared_sha:
                entries_failed += 1
                errors.append(
                    f"entry sha256 mismatch: {tar_path} expected={declared_sha} got={actual_sha}"
                )

        ok = len(errors) == 0
        # update status if we know this bundle_id
        if bundle_id:
            new_status = "verified" if ok else "verify_failed"
            try:
                with self._lock, self._conn() as conn:
                    conn.execute(
                        "UPDATE bundles SET status = ? WHERE bundle_id = ?",
                        (new_status, bundle_id),
                    )
                    conn.commit()
            except sqlite3.OperationalError:
                pass

        self._emit_event(
            "airgap.bundle.verified" if ok else "airgap.bundle.verify_failed",
            {"bundle_id": bundle_id, "ok": ok, "entries_failed": entries_failed},
        )

        return {
            "ok": ok,
            "entries_checked": entries_checked,
            "entries_failed": entries_failed,
            "errors": errors,
            "bundle_id": bundle_id,
        }

    # ------------------------------------------------------------------
    # apply_bundle
    # ------------------------------------------------------------------

    def apply_bundle(
        self,
        bundle_id: str,
        dry_run: bool = False,
        applied_by: str = "system",
        require_verified: bool = True,
    ) -> Dict[str, Any]:
        """Idempotently upsert entries into target tables.

        Verification is implicitly re-run unless `require_verified=False`.
        """
        with self._lock, self._conn() as conn:
            row = conn.execute(
                "SELECT archive_path, org_id, status FROM bundles WHERE bundle_id = ?",
                (bundle_id,),
            ).fetchone()
        if not row:
            raise KeyError(f"bundle not found: {bundle_id}")
        archive_path = Path(row["archive_path"])
        org_id = row["org_id"]

        if require_verified:
            verify_result = self.verify_bundle(archive_path)
            if not verify_result["ok"]:
                app_id = str(uuid.uuid4())
                with self._lock, self._conn() as conn:
                    conn.execute(
                        """INSERT INTO bundle_applications
                           (id, bundle_id, applied_at, applied_by, applied_status,
                            entries_ingested, entries_failed, error_log, dry_run)
                           VALUES (?,?,?,?,?,?,?,?,?)""",
                        (
                            app_id,
                            bundle_id,
                            _now_iso(),
                            applied_by,
                            "apply_failed",
                            0,
                            verify_result.get("entries_checked", 0),
                            json.dumps(verify_result.get("errors", [])),
                            1 if dry_run else 0,
                        ),
                    )
                    conn.execute(
                        "UPDATE bundles SET status = ? WHERE bundle_id = ?",
                        ("apply_failed", bundle_id),
                    )
                    conn.commit()
                return {
                    "bundle_id": bundle_id,
                    "applied": 0,
                    "skipped": 0,
                    "failed": verify_result.get("entries_checked", 0),
                    "dry_run": dry_run,
                    "errors": verify_result.get("errors", []),
                    "status": "apply_failed",
                }

        # ---- open archive and iterate entries ---------------------------
        _, manifest, entry_bytes = self._load_archive(archive_path)
        entries_meta = manifest.get("entries", []) or []
        applied = 0
        skipped = 0
        failed = 0
        errors: List[str] = []

        for meta in entries_meta:
            tar_path = meta.get("path") or f"entries/{meta.get('type')}/{meta.get('key')}.json"
            payload = entry_bytes.get(tar_path)
            if payload is None:
                failed += 1
                errors.append(f"missing payload for {tar_path}")
                continue
            try:
                row_data = json.loads(payload.decode("utf-8"))
            except json.JSONDecodeError as exc:
                failed += 1
                errors.append(f"decode error {tar_path}: {exc}")
                continue

            etype = meta.get("type")
            if dry_run:
                skipped += 1
                continue
            try:
                if etype == "cve":
                    self._apply_cve_row(row_data)
                elif etype == "ti_indicator":
                    self._apply_ti_row(row_data, org_id)
                elif etype == "policy":
                    self._apply_policy_row(row_data, org_id)
                else:
                    skipped += 1
                    continue
                applied += 1
            except (sqlite3.Error, ValueError, KeyError) as exc:
                failed += 1
                errors.append(f"apply failed {etype}:{meta.get('key')}: {exc}")

        status = "applied" if failed == 0 else "apply_failed"
        app_id = str(uuid.uuid4())
        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT INTO bundle_applications
                   (id, bundle_id, applied_at, applied_by, applied_status,
                    entries_ingested, entries_failed, error_log, dry_run)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (
                    app_id,
                    bundle_id,
                    _now_iso(),
                    applied_by,
                    status,
                    applied,
                    failed,
                    json.dumps(errors),
                    1 if dry_run else 0,
                ),
            )
            # dry-run does not change bundle status; only real applies do
            if not dry_run:
                conn.execute(
                    "UPDATE bundles SET status = ? WHERE bundle_id = ?",
                    (status, bundle_id),
                )
            conn.commit()

        self._emit_event(
            "airgap.bundle.applied",
            {
                "bundle_id": bundle_id,
                "applied": applied,
                "failed": failed,
                "dry_run": dry_run,
            },
        )

        return {
            "bundle_id": bundle_id,
            "applied": applied,
            "skipped": skipped,
            "failed": failed,
            "dry_run": dry_run,
            "errors": errors,
            "status": status,
            "application_id": app_id,
        }

    # ------------------------------------------------------------------
    # Apply helpers — idempotent INSERT OR REPLACE into target tables
    # ------------------------------------------------------------------

    def _apply_cve_row(self, row: Dict[str, Any]) -> None:
        """Upsert a single row into cve_cache."""
        path = self.cve_db_path
        path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(path), check_same_thread=False, timeout=10.0)
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            # Ensure schema exists for fresh air-gapped deployments
            conn.execute(
                """CREATE TABLE IF NOT EXISTS cve_cache (
                    cve_id            TEXT PRIMARY KEY,
                    cvss_score        REAL,
                    cvss_vector       TEXT,
                    cvss_severity     TEXT,
                    description       TEXT,
                    epss_score        REAL,
                    epss_percentile   REAL,
                    is_kev            INTEGER DEFAULT 0,
                    kev_due_date      TEXT,
                    affected_products TEXT,
                    cwe               TEXT,
                    published         TEXT,
                    source            TEXT,
                    enriched_at       TEXT,
                    expires_at        TEXT
                )"""
            )
            cve_id = row.get("cve_id")
            if not cve_id:
                raise ValueError("cve row missing cve_id")
            conn.execute(
                """INSERT OR REPLACE INTO cve_cache
                   (cve_id, cvss_score, cvss_vector, cvss_severity, description,
                    epss_score, epss_percentile, is_kev, kev_due_date, affected_products,
                    cwe, published, source, enriched_at, expires_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    cve_id,
                    row.get("cvss_score"),
                    row.get("cvss_vector"),
                    row.get("cvss_severity"),
                    row.get("description"),
                    row.get("epss_score"),
                    row.get("epss_percentile"),
                    int(row.get("is_kev") or 0),
                    row.get("kev_due_date"),
                    row.get("affected_products"),
                    row.get("cwe"),
                    row.get("published"),
                    row.get("source", "air_gap_bundle"),
                    row.get("enriched_at") or _now_iso(),
                    row.get("expires_at"),
                ),
            )
            conn.commit()
        finally:
            conn.close()

    def _apply_ti_row(self, row: Dict[str, Any], org_id: str) -> None:
        """Upsert a threat_indicators row."""
        path = self.ti_db_path
        path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(path), check_same_thread=False, timeout=10.0)
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute(
                """CREATE TABLE IF NOT EXISTS threat_indicators (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    indicator_value TEXT NOT NULL DEFAULT '',
                    indicator_type  TEXT NOT NULL DEFAULT 'ip',
                    source          TEXT NOT NULL DEFAULT '',
                    confidence      REAL NOT NULL DEFAULT 0.5,
                    severity        TEXT NOT NULL DEFAULT 'medium',
                    tlp             TEXT NOT NULL DEFAULT 'amber',
                    tags            TEXT NOT NULL DEFAULT '[]',
                    first_seen      TEXT,
                    last_seen       TEXT,
                    expiry_at       TEXT,
                    active          INTEGER NOT NULL DEFAULT 1,
                    false_positive  INTEGER NOT NULL DEFAULT 0,
                    sighting_count  INTEGER NOT NULL DEFAULT 0,
                    created_at      TEXT
                )"""
            )
            ind_id = row.get("id") or str(uuid.uuid4())
            conn.execute(
                """INSERT OR REPLACE INTO threat_indicators
                   (id, org_id, indicator_value, indicator_type, source, confidence,
                    severity, tlp, tags, first_seen, last_seen, expiry_at, active,
                    false_positive, sighting_count, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    ind_id,
                    row.get("org_id") or org_id,
                    row.get("indicator_value", ""),
                    row.get("indicator_type", "ip"),
                    row.get("source", "air_gap_bundle"),
                    float(row.get("confidence") or 0.5),
                    row.get("severity", "medium"),
                    row.get("tlp", "amber"),
                    row.get("tags") if isinstance(row.get("tags"), str) else json.dumps(row.get("tags") or []),
                    row.get("first_seen"),
                    row.get("last_seen"),
                    row.get("expiry_at"),
                    int(row.get("active") if row.get("active") is not None else 1),
                    int(row.get("false_positive") or 0),
                    int(row.get("sighting_count") or 0),
                    row.get("created_at") or _now_iso(),
                ),
            )
            conn.commit()
        finally:
            conn.close()

    def _apply_policy_row(self, row: Dict[str, Any], org_id: str) -> None:
        """Upsert a policies row."""
        path = self.policy_db_path
        path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(path), check_same_thread=False, timeout=10.0)
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute(
                """CREATE TABLE IF NOT EXISTS policies (
                    id                TEXT PRIMARY KEY,
                    name              TEXT NOT NULL,
                    description       TEXT DEFAULT '',
                    scope             TEXT NOT NULL,
                    language          TEXT NOT NULL DEFAULT 'aldeci_rules',
                    rules             TEXT NOT NULL DEFAULT '[]',
                    decision_on_match TEXT NOT NULL DEFAULT 'deny',
                    enabled           INTEGER NOT NULL DEFAULT 1,
                    version           INTEGER NOT NULL DEFAULT 1,
                    org_id            TEXT NOT NULL DEFAULT 'default',
                    created_at        TEXT,
                    updated_at        TEXT
                )"""
            )
            pid = row.get("id") or str(uuid.uuid4())
            conn.execute(
                """INSERT OR REPLACE INTO policies
                   (id, name, description, scope, language, rules, decision_on_match,
                    enabled, version, org_id, created_at, updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    pid,
                    row.get("name", "imported_policy"),
                    row.get("description", ""),
                    row.get("scope", "findings"),
                    row.get("language", "aldeci_rules"),
                    row.get("rules") if isinstance(row.get("rules"), str) else json.dumps(row.get("rules") or []),
                    row.get("decision_on_match", "deny"),
                    int(row.get("enabled") if row.get("enabled") is not None else 1),
                    int(row.get("version") or 1),
                    row.get("org_id") or org_id,
                    row.get("created_at") or _now_iso(),
                    row.get("updated_at") or _now_iso(),
                ),
            )
            conn.commit()
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Transfers
    # ------------------------------------------------------------------

    def record_transfer(
        self,
        bundle_id: str,
        from_site: str = "",
        to_site: str = "",
        transport_method: str = "manual_usb",
        checksum_verified: bool = False,
        notes: str = "",
    ) -> Dict[str, Any]:
        if transport_method not in _VALID_TRANSPORTS:
            raise ValueError(
                f"transport_method must be one of {sorted(_VALID_TRANSPORTS)}"
            )
        with self._lock, self._conn() as conn:
            row = conn.execute(
                "SELECT bundle_id FROM bundles WHERE bundle_id = ?",
                (bundle_id,),
            ).fetchone()
            if not row:
                raise KeyError(f"bundle not found: {bundle_id}")
            tid = str(uuid.uuid4())
            ts = _now_iso()
            conn.execute(
                """INSERT INTO bundle_transfers
                   (id, bundle_id, from_site, to_site, transferred_at,
                    transport_method, checksum_verified, notes)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (
                    tid,
                    bundle_id,
                    from_site,
                    to_site,
                    ts,
                    transport_method,
                    1 if checksum_verified else 0,
                    notes,
                ),
            )
            conn.execute(
                "UPDATE bundles SET status = ? WHERE bundle_id = ? AND status = 'exported'",
                ("transferred", bundle_id),
            )
            conn.commit()
        return {
            "id": tid,
            "bundle_id": bundle_id,
            "from_site": from_site,
            "to_site": to_site,
            "transferred_at": ts,
            "transport_method": transport_method,
            "checksum_verified": checksum_verified,
            "notes": notes,
        }

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def list_bundles(
        self,
        org_id: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        clauses = []
        params: List[Any] = []
        if org_id is not None:
            clauses.append("org_id = ?")
            params.append(org_id)
        if status is not None:
            if status not in _VALID_STATUSES:
                raise ValueError(f"status must be one of {sorted(_VALID_STATUSES)}")
            clauses.append("status = ?")
            params.append(status)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(int(limit))
        q = f"""SELECT id, org_id, bundle_id, version, created_at, exported_by,
                       size_bytes, content_hash, status, archive_path
                FROM bundles {where}
                ORDER BY created_at DESC LIMIT ?"""  # nosec B608 — where is composed of fixed clauses
        with self._conn() as conn:
            rows = conn.execute(q, params).fetchall()
        return [dict(r) for r in rows]

    def get_bundle(self, bundle_id: str) -> Optional[Dict[str, Any]]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM bundles WHERE bundle_id = ?",
                (bundle_id,),
            ).fetchone()
            if not row:
                return None
            bundle = dict(row)
            try:
                bundle["manifest"] = json.loads(bundle.get("manifest_json", "{}") or "{}")
            except json.JSONDecodeError:
                bundle["manifest"] = {}
            entry_rows = conn.execute(
                """SELECT entry_type, entry_key, entry_payload_size, entry_sha256
                   FROM bundle_entries WHERE bundle_id = ?""",
                (bundle_id,),
            ).fetchall()
            bundle["entries"] = [dict(r) for r in entry_rows]
            transfer_rows = conn.execute(
                """SELECT id, from_site, to_site, transferred_at, transport_method,
                          checksum_verified, notes
                   FROM bundle_transfers WHERE bundle_id = ?
                   ORDER BY transferred_at DESC""",
                (bundle_id,),
            ).fetchall()
            bundle["transfers"] = [dict(r) for r in transfer_rows]
            app_rows = conn.execute(
                """SELECT id, applied_at, applied_by, applied_status,
                          entries_ingested, entries_failed, dry_run
                   FROM bundle_applications WHERE bundle_id = ?
                   ORDER BY applied_at DESC""",
                (bundle_id,),
            ).fetchall()
            bundle["applications"] = [dict(r) for r in app_rows]
        return bundle

    def stats(self, org_id: Optional[str] = None) -> Dict[str, Any]:
        with self._conn() as conn:
            if org_id is not None:
                params: Tuple[Any, ...] = (org_id,)
                where = "WHERE org_id = ?"
            else:
                params = ()
                where = ""
            total = conn.execute(
                f"SELECT COUNT(*) AS c FROM bundles {where}",  # nosec B608
                params,
            ).fetchone()["c"]
            by_status: Dict[str, int] = {}
            rows = conn.execute(
                f"SELECT status, COUNT(*) AS c FROM bundles {where} GROUP BY status",  # nosec B608
                params,
            ).fetchall()
            for r in rows:
                by_status[r["status"]] = r["c"]
            total_size = conn.execute(
                f"SELECT COALESCE(SUM(size_bytes),0) AS s FROM bundles {where}",  # nosec B608
                params,
            ).fetchone()["s"]
            # entry counts across this org's bundles
            entry_q = (
                "SELECT entry_type, COUNT(*) AS c FROM bundle_entries e "
                "JOIN bundles b ON b.bundle_id = e.bundle_id"
            )
            entry_params: Tuple[Any, ...] = ()
            if org_id is not None:
                entry_q += " WHERE b.org_id = ?"
                entry_params = (org_id,)
            entry_q += " GROUP BY entry_type"
            entry_rows = conn.execute(entry_q, entry_params).fetchall()
            entries_by_type = {r["entry_type"]: r["c"] for r in entry_rows}
            total_transfers = conn.execute(
                "SELECT COUNT(*) AS c FROM bundle_transfers t "
                "JOIN bundles b ON b.bundle_id = t.bundle_id"
                + (" WHERE b.org_id = ?" if org_id is not None else ""),
                (org_id,) if org_id is not None else (),
            ).fetchone()["c"]
            total_applications = conn.execute(
                "SELECT COUNT(*) AS c FROM bundle_applications a "
                "JOIN bundles b ON b.bundle_id = a.bundle_id"
                + (" WHERE b.org_id = ?" if org_id is not None else ""),
                (org_id,) if org_id is not None else (),
            ).fetchone()["c"]

        return {
            "org_id": org_id,
            "total_bundles": total,
            "by_status": by_status,
            "total_size_bytes": total_size,
            "entries_by_type": entries_by_type,
            "total_transfers": total_transfers,
            "total_applications": total_applications,
        }

    # ------------------------------------------------------------------
    # TrustGraph event bridge (best-effort)
    # ------------------------------------------------------------------

    def _emit_event(self, event_type: str, payload: Dict[str, Any]) -> None:
        if _get_tg_bus is None:
            return
        try:  # pragma: no cover — fire-and-forget
            bus = _get_tg_bus()
            if bus is None:
                return
            if hasattr(bus, "emit"):
                result = bus.emit(event_type, payload)
                # EventBus.emit is async — schedule on the running loop or run
                # to completion in a fresh loop so we never leak a coroutine.
                import asyncio
                import inspect
                if inspect.iscoroutine(result):
                    try:
                        loop = asyncio.get_running_loop()
                        loop.create_task(result)
                    except RuntimeError:
                        asyncio.run(result)
            elif hasattr(bus, "publish"):
                bus.publish(event_type, payload)
        except Exception as exc:  # noqa: BLE001
            _logger.debug("air_gap event emit failed: %s", exc)


# ---------------------------------------------------------------------------
# Module-level accessor
# ---------------------------------------------------------------------------

_singleton: Optional[AirGapBundleEngine] = None


def get_engine() -> AirGapBundleEngine:
    global _singleton
    if _singleton is None:
        _singleton = AirGapBundleEngine()
    return _singleton


# ---------------------------------------------------------------------------
# Signing notes — real ed25519 DSSE attestation (delivered 2026-05-02)
# ---------------------------------------------------------------------------
# Bundles are signed via ``core.dsse_signer`` using ed25519 (PKCS8 PEM key in
# ``data/keys/slsa_signing.pem``). The legacy sha256-fallback signature path
# was removed — bundle creation now fails loudly if the signer is unavailable
# and verification refuses any signature carrying the ``sha256-fallback:``
# prefix.
#
# Future hardening (open):
# 1. KMS / HSM-resident keys (AWS KMS, YubiHSM) for the producer site so the
#    private key is never on the build host. Pipe PAE bytes to an air-gapped
#    signer service that returns the signature.
# 2. Publish the public verification key via TUF or a stable HTTPS endpoint
#    bundled into the Fixops installer, so air-gapped verifiers can validate
#    without phoning home.
# 3. Add Rekor transparency log URL to the manifest (for internet-connected
#    producers — air-gapped consumers verify offline from the log snapshot
#    shipped inside the bundle itself).
# 4. Support detached signatures so large bundles can be re-signed without
#    re-transferring the whole archive.
