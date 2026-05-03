"""SLSA Provenance Engine — ALDECI GAP-018.

SLSA v1.0 attestation generation in the in-toto format with DSSE envelope
wrapping. Distinct from generic ``evidence_vault_engine`` — this engine is
SLSA-specific and produces spec-compliant in-toto Statement v0.1 /
provenance v0.2 predicates that downstream verifiers (Kyverno, policy
engines, Sigstore) can ingest.

What this engine does
---------------------
- Generates an in-toto Statement v0.1 JSON document with a SLSA provenance
  v0.2 predicate.
- Wraps the payload in a DSSE envelope (base64-encoded payload + placeholder
  signature block). Real cryptographic signing via cosign/sigstore is
  out-of-scope for v0 — we emit a documented placeholder signature so the
  envelope remains shape-compliant with the DSSE spec.
- Stores the full envelope, raw predicate, and metadata in SQLite.
- Provides a v0 verifier that checks structural compliance (shape, required
  fields, SLSA level enum, builder/materials present). Real cryptographic
  verification is a TODO.
- Emits stats and list/get queries with full org_id isolation.

Specs
-----
- in-toto Statement: https://github.com/in-toto/attestation/blob/main/spec/v0.1/README.md
- SLSA provenance v0.2: https://slsa.dev/provenance/v0.2
- DSSE: https://github.com/secure-systems-lab/dsse/blob/master/envelope.md

Design notes
------------
- SQLite WAL + RLock (same pattern as every other ALDECI engine).
- No new third-party deps. No sigstore/cosign imports.
- Multi-tenant isolation via ``org_id`` on ``slsa_attestations``; verifications
  join via ``attestation_id`` so isolation is preserved transitively.
"""

from __future__ import annotations

import base64
import json
import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:  # pragma: no cover - optional wiring
    _get_tg_bus = None

try:
    from core.dsse_signer import get_signer as _get_dsse_signer
except ImportError:  # pragma: no cover - fallback if cryptography not installed
    _get_dsse_signer = None  # type: ignore


_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "slsa_provenance.db"
)

# in-toto Statement v0.1 constants
_IN_TOTO_STATEMENT_TYPE = "https://in-toto.io/Statement/v0.1"
_SLSA_PROVENANCE_V02_TYPE = "https://slsa.dev/provenance/v0.2"
_DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json"

# Valid SLSA levels per SLSA v1.0 spec (1..4)
_VALID_SLSA_LEVELS = frozenset({1, 2, 3, 4})
_VALID_VERIFIER_VERDICTS = frozenset({"pass", "fail"})

# Exported for test introspection — identifies unsigned fallback keyid
_PLACEHOLDER_SIG = "unsigned-fallback-signature-not-for-production-use"

# Real DSSE signing via ed25519 (cryptography package).
# Key is generated/loaded from data/keys/slsa_signing.pem (0600, gitignored).
# PAE: "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body
# Signature: ed25519 over PAE bytes → base64-encoded in envelope.signatures[].sig
# keyid: SHA-256 hex fingerprint of DER-encoded public key.
# Fallback: if dsse_signer unavailable, we fall back to a clearly-labelled
# placeholder so the envelope shape stays spec-compliant.


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64_decode(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


class SLSAProvenanceEngine:
    """SQLite WAL-backed SLSA Provenance engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    """

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self.db_path = db_path
        self._lock = threading.RLock()
        self.ensure_schema()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def ensure_schema(self) -> None:
        """Create tables if they do not exist. Idempotent."""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            with self._conn() as conn:
                conn.execute("PRAGMA journal_mode=WAL")
                conn.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS slsa_attestations (
                        id                     TEXT PRIMARY KEY,
                        org_id                 TEXT NOT NULL,
                        subject_name           TEXT NOT NULL,
                        subject_sha256         TEXT NOT NULL,
                        builder_id             TEXT NOT NULL,
                        build_type             TEXT NOT NULL,
                        invocation_json        TEXT NOT NULL DEFAULT '{}',
                        materials_json         TEXT NOT NULL DEFAULT '[]',
                        metadata_json          TEXT NOT NULL DEFAULT '{}',
                        signature_placeholder  TEXT NOT NULL DEFAULT '',
                        dsse_envelope_json     TEXT NOT NULL,
                        slsa_level             INTEGER NOT NULL DEFAULT 3,
                        created_at             TEXT NOT NULL
                    );

                    CREATE INDEX IF NOT EXISTS idx_slsa_org
                        ON slsa_attestations (org_id, subject_name, builder_id);

                    CREATE TABLE IF NOT EXISTS slsa_verifications (
                        id              TEXT PRIMARY KEY,
                        attestation_id  TEXT NOT NULL,
                        verifier        TEXT NOT NULL DEFAULT 'internal',
                        verified_at     TEXT NOT NULL,
                        verdict         TEXT NOT NULL DEFAULT 'fail',
                        verdict_detail  TEXT NOT NULL DEFAULT '',
                        created_at      TEXT NOT NULL
                    );

                    CREATE INDEX IF NOT EXISTS idx_slsa_ver_att
                        ON slsa_verifications (attestation_id, verified_at);
                    """
                )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _coerce_level(level: Any) -> int:
        """Coerce an arbitrary level input to an integer ∈ {1,2,3,4} or ValueError."""
        try:
            lvl = int(level)
        except (TypeError, ValueError):
            raise ValueError(
                f"slsa_level must be an integer in {sorted(_VALID_SLSA_LEVELS)}"
            )
        if lvl not in _VALID_SLSA_LEVELS:
            raise ValueError(
                f"slsa_level must be one of {sorted(_VALID_SLSA_LEVELS)}, got {lvl}"
            )
        return lvl

    @staticmethod
    def _build_in_toto_statement(
        subject_name: str,
        subject_sha256: str,
        builder_id: str,
        build_type: str,
        invocation: Dict[str, Any],
        materials: List[Dict[str, Any]],
        metadata: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Build an in-toto Statement v0.1 with a SLSA provenance v0.2 predicate.

        Shape (per spec):
            {
              "_type": "https://in-toto.io/Statement/v0.1",
              "predicateType": "https://slsa.dev/provenance/v0.2",
              "subject": [{"name": ..., "digest": {"sha256": ...}}],
              "predicate": {
                "builder": {"id": ...},
                "buildType": ...,
                "invocation": {...},
                "materials": [...],
                "metadata": {...}
              }
            }
        """
        return {
            "_type": _IN_TOTO_STATEMENT_TYPE,
            "predicateType": _SLSA_PROVENANCE_V02_TYPE,
            "subject": [
                {
                    "name": subject_name,
                    "digest": {"sha256": subject_sha256},
                }
            ],
            "predicate": {
                "builder": {"id": builder_id},
                "buildType": build_type,
                "invocation": dict(invocation or {}),
                "materials": list(materials or []),
                "metadata": dict(metadata or {}),
            },
        }

    @staticmethod
    def _wrap_dsse(payload_obj: Dict[str, Any]) -> Dict[str, Any]:
        """Wrap a payload object in a real DSSE envelope signed with ed25519.

        Shape (per DSSE spec):
            {
              "payloadType": "application/vnd.in-toto+json",
              "payload": "<base64(canonical_json)>",
              "signatures": [{"keyid": <sha256-fingerprint>, "sig": <base64-ed25519>}]
            }

        Falls back to a labelled placeholder if the signing module is
        unavailable (e.g. cryptography not installed), so the envelope shape
        stays spec-compliant even in degraded environments.
        """
        if _get_dsse_signer is not None:
            try:
                signer = _get_dsse_signer()
                return signer.sign_dsse(_DSSE_PAYLOAD_TYPE, payload_obj)
            except Exception as exc:  # pragma: no cover - signer init failure
                _logger.warning(
                    "dsse_signer unavailable, falling back to placeholder: %s", exc
                )

        # Graceful fallback — shape-compliant, clearly labelled as unsigned.
        payload_bytes = json.dumps(
            payload_obj, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        return {
            "payloadType": _DSSE_PAYLOAD_TYPE,
            "payload": _b64(payload_bytes),
            "signatures": [
                {
                    "keyid": "unsigned-fallback-keyid",
                    "sig": "unsigned-fallback-signature-not-for-production-use",
                }
            ],
        }

    def _row_to_dict(self, row: Optional[sqlite3.Row]) -> Optional[Dict[str, Any]]:
        if row is None:
            return None
        d = dict(row)
        # Deserialise JSON columns for convenience.
        for field in ("invocation_json", "materials_json", "metadata_json", "dsse_envelope_json"):
            raw = d.get(field, "")
            if not raw:
                continue
            try:
                d[field.removesuffix("_json")] = json.loads(raw)
            except (json.JSONDecodeError, ValueError):
                d[field.removesuffix("_json")] = None
        return d

    def _emit_event(self, event_type: str, org_id: str, extra: Optional[Dict[str, Any]] = None) -> None:
        if not _get_tg_bus:
            return
        try:
            bus = _get_tg_bus()
            if bus and getattr(bus, "enabled", False):
                payload = {
                    "entity_type": "slsa_attestation",
                    "org_id": org_id,
                    "source_engine": "slsa_provenance_engine",
                }
                if extra:
                    payload.update(extra)
                bus.emit(event_type, payload)
        except Exception:  # pragma: no cover - bus must never break engine
            _logger.debug("TrustGraph bus emit failed", exc_info=True)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate_attestation(
        self,
        org_id: str,
        subject_name: str,
        subject_sha256: str,
        builder_id: str,
        build_type: str,
        invocation: Optional[Dict[str, Any]] = None,
        materials: Optional[List[Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        slsa_level: int = 3,
    ) -> Dict[str, Any]:
        """Generate, persist and return a SLSA v0.2 in-toto attestation.

        Returns the stored attestation row with an added ``envelope`` and
        ``statement`` (raw predicate) field for caller convenience.
        """
        if not org_id or not isinstance(org_id, str):
            raise ValueError("org_id is required and must be a non-empty string")
        if not subject_name or not isinstance(subject_name, str):
            raise ValueError("subject_name is required")
        if not subject_sha256 or not isinstance(subject_sha256, str):
            raise ValueError("subject_sha256 is required")
        if not builder_id or not isinstance(builder_id, str):
            raise ValueError("builder_id is required")
        if not build_type or not isinstance(build_type, str):
            raise ValueError("build_type is required")

        lvl = self._coerce_level(slsa_level)

        invocation = invocation or {}
        materials = materials or []
        metadata = metadata or {}

        if not isinstance(invocation, dict):
            raise ValueError("invocation must be a dict")
        if not isinstance(materials, list):
            raise ValueError("materials must be a list of dicts")
        for m in materials:
            if not isinstance(m, dict):
                raise ValueError("each material must be a dict")
        if not isinstance(metadata, dict):
            raise ValueError("metadata must be a dict")

        statement = self._build_in_toto_statement(
            subject_name=subject_name,
            subject_sha256=subject_sha256,
            builder_id=builder_id,
            build_type=build_type,
            invocation=invocation,
            materials=materials,
            metadata=metadata,
        )
        envelope = self._wrap_dsse(statement)

        attestation_id = str(uuid.uuid4())
        now = _now_iso()

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO slsa_attestations
                       (id, org_id, subject_name, subject_sha256, builder_id,
                        build_type, invocation_json, materials_json, metadata_json,
                        signature_placeholder, dsse_envelope_json, slsa_level,
                        created_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        attestation_id,
                        org_id,
                        subject_name,
                        subject_sha256,
                        builder_id,
                        build_type,
                        json.dumps(invocation, sort_keys=True),
                        json.dumps(materials, sort_keys=True),
                        json.dumps(metadata, sort_keys=True),
                        json.dumps(envelope.get("signatures", []), sort_keys=True),
                        json.dumps(envelope, sort_keys=True),
                        lvl,
                        now,
                    ),
                )

        self._emit_event(
            "ATTESTATION_GENERATED",
            org_id,
            {"attestation_id": attestation_id, "slsa_level": lvl},
        )

        return {
            "id": attestation_id,
            "org_id": org_id,
            "subject_name": subject_name,
            "subject_sha256": subject_sha256,
            "builder_id": builder_id,
            "build_type": build_type,
            "invocation": invocation,
            "materials": materials,
            "metadata": metadata,
            "slsa_level": lvl,
            "statement": statement,
            "envelope": envelope,
            "created_at": now,
        }

    def verify_attestation(
        self,
        attestation_id: str,
        verifier: str = "internal",
    ) -> Dict[str, Any]:
        """V0 structural verifier.

        Checks:
          1. Attestation exists.
          2. DSSE envelope shape: payloadType, payload, signatures present.
          3. Payload base64-decodes and parses as JSON.
          4. In-toto Statement v0.1 shape: _type, predicateType, subject, predicate.
          5. predicateType == SLSA provenance v0.2.
          6. predicate.builder.id non-empty.
          7. predicate.materials is a non-empty list.
          8. slsa_level ∈ {1,2,3,4}.

        Does NOT perform cryptographic signature verification — TODO when
        sigstore/cosign integration lands.
        """
        if not attestation_id:
            raise ValueError("attestation_id is required")

        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM slsa_attestations WHERE id=?",
                    (attestation_id,),
                ).fetchone()

        if row is None:
            return {
                "attestation_id": attestation_id,
                "verdict": "fail",
                "verdict_detail": "attestation not found",
                "verifier": verifier,
                "verified_at": _now_iso(),
                "checks": {},
            }

        checks: Dict[str, bool] = {}
        details: List[str] = []

        # 1. DSSE envelope shape
        try:
            envelope = json.loads(row["dsse_envelope_json"])
        except (json.JSONDecodeError, TypeError):
            envelope = None
        checks["envelope_parsable"] = envelope is not None
        if not checks["envelope_parsable"]:
            details.append("DSSE envelope is not valid JSON")

        payload_type_ok = (
            checks["envelope_parsable"]
            and isinstance(envelope, dict)
            and envelope.get("payloadType") == _DSSE_PAYLOAD_TYPE
        )
        checks["envelope_payload_type"] = bool(payload_type_ok)
        if not payload_type_ok:
            details.append(
                f"DSSE payloadType missing or != {_DSSE_PAYLOAD_TYPE}"
            )

        sig_ok = (
            checks["envelope_parsable"]
            and isinstance(envelope, dict)
            and isinstance(envelope.get("signatures"), list)
            and len(envelope["signatures"]) >= 1
        )
        checks["envelope_has_signature_block"] = bool(sig_ok)
        if not sig_ok:
            details.append("DSSE signatures block missing or empty")

        # 2. Payload parses
        statement = None
        if checks["envelope_parsable"] and isinstance(envelope, dict):
            try:
                payload_b64 = envelope.get("payload", "")
                raw = _b64_decode(payload_b64) if payload_b64 else b""
                statement = json.loads(raw)
            except (ValueError, json.JSONDecodeError):
                statement = None
        checks["payload_parsable"] = statement is not None
        if not checks["payload_parsable"]:
            details.append("DSSE payload is not base64-decodable JSON")

        # 3. In-toto statement shape
        if checks["payload_parsable"] and isinstance(statement, dict):
            checks["statement_type_ok"] = (
                statement.get("_type") == _IN_TOTO_STATEMENT_TYPE
            )
            checks["predicate_type_ok"] = (
                statement.get("predicateType") == _SLSA_PROVENANCE_V02_TYPE
            )
            checks["has_subject"] = (
                isinstance(statement.get("subject"), list)
                and len(statement["subject"]) >= 1
            )
            checks["has_predicate"] = isinstance(statement.get("predicate"), dict)
        else:
            checks["statement_type_ok"] = False
            checks["predicate_type_ok"] = False
            checks["has_subject"] = False
            checks["has_predicate"] = False

        for k in (
            "statement_type_ok",
            "predicate_type_ok",
            "has_subject",
            "has_predicate",
        ):
            if not checks[k]:
                details.append(f"in-toto check failed: {k}")

        # 4. SLSA predicate checks
        predicate = (
            statement.get("predicate", {}) if isinstance(statement, dict) else {}
        )
        builder = predicate.get("builder", {}) if isinstance(predicate, dict) else {}
        checks["builder_id_present"] = bool(
            isinstance(builder, dict) and builder.get("id")
        )
        if not checks["builder_id_present"]:
            details.append("predicate.builder.id is missing or empty")

        mats = predicate.get("materials") if isinstance(predicate, dict) else None
        checks["materials_non_empty"] = bool(isinstance(mats, list) and len(mats) > 0)
        if not checks["materials_non_empty"]:
            details.append("predicate.materials is empty or missing")

        # 5. SLSA level valid
        try:
            lvl = int(row["slsa_level"])
            checks["slsa_level_valid"] = lvl in _VALID_SLSA_LEVELS
        except (TypeError, ValueError):
            checks["slsa_level_valid"] = False
        if not checks["slsa_level_valid"]:
            details.append("slsa_level is not in {1,2,3,4}")

        # 6. Real cryptographic signature verification (ed25519 DSSE).
        if _get_dsse_signer is not None and checks.get("envelope_parsable") and isinstance(envelope, dict):
            try:
                signer = _get_dsse_signer()
                sig_valid = signer.verify_dsse(envelope)
            except Exception as exc:  # pragma: no cover - signer failure is non-fatal
                _logger.warning("dsse verify failed: %s", exc)
                sig_valid = False
        else:
            # Fallback: if signer unavailable, pass through without crypto check
            sig_valid = None  # type: ignore

        if sig_valid is not None:
            checks["signature_crypto_valid"] = sig_valid
            if not sig_valid:
                details.append("ed25519 DSSE signature verification failed")

        # Verdict: pass iff every structural check passes AND (if crypto checked) sig valid.
        all_pass = all(
            checks[k]
            for k in checks
            if k != "signature_crypto_valid" or sig_valid is not None
        )
        verdict = "pass" if all_pass else "fail"
        verdict_detail = "; ".join(details) if details else "all structural checks passed"

        # Persist verification record.
        ver_id = str(uuid.uuid4())
        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO slsa_verifications
                       (id, attestation_id, verifier, verified_at, verdict,
                        verdict_detail, created_at)
                       VALUES (?,?,?,?,?,?,?)""",
                    (ver_id, attestation_id, verifier, now, verdict, verdict_detail, now),
                )

        self._emit_event(
            "ATTESTATION_VERIFIED",
            row["org_id"],
            {
                "attestation_id": attestation_id,
                "verdict": verdict,
                "verifier": verifier,
            },
        )

        return {
            "id": ver_id,
            "attestation_id": attestation_id,
            "verifier": verifier,
            "verified_at": now,
            "verdict": verdict,
            "verdict_detail": verdict_detail,
            "checks": checks,
        }

    def list_attestations(
        self,
        org_id: str,
        subject_name: Optional[str] = None,
        builder_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List attestations for an org with optional filters."""
        if not org_id:
            raise ValueError("org_id is required")

        sql = "SELECT * FROM slsa_attestations WHERE org_id=?"
        params: List[Any] = [org_id]
        if subject_name:
            sql += " AND subject_name=?"
            params.append(subject_name)
        if builder_id:
            sql += " AND builder_id=?"
            params.append(builder_id)
        sql += " ORDER BY created_at DESC"

        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(sql, params).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def get_attestation(self, attestation_id: str) -> Optional[Dict[str, Any]]:
        """Return a single attestation by id. Callers must enforce org scoping
        downstream if needed (returns None if not found)."""
        if not attestation_id:
            return None
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM slsa_attestations WHERE id=?",
                    (attestation_id,),
                ).fetchone()
        return self._row_to_dict(row)

    def stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregate stats for an org.

        Includes counts by slsa_level and verification pass/fail rate.
        """
        if not org_id:
            raise ValueError("org_id is required")

        with self._lock:
            with self._conn() as conn:
                total_row = conn.execute(
                    "SELECT COUNT(*) AS c FROM slsa_attestations WHERE org_id=?",
                    (org_id,),
                ).fetchone()
                total = int(total_row["c"]) if total_row else 0

                level_rows = conn.execute(
                    """SELECT slsa_level, COUNT(*) AS c
                       FROM slsa_attestations
                       WHERE org_id=?
                       GROUP BY slsa_level""",
                    (org_id,),
                ).fetchall()
                by_level = {int(r["slsa_level"]): int(r["c"]) for r in level_rows}

                verdict_rows = conn.execute(
                    """SELECT v.verdict AS verdict, COUNT(*) AS c
                       FROM slsa_verifications v
                       JOIN slsa_attestations a ON v.attestation_id = a.id
                       WHERE a.org_id=?
                       GROUP BY v.verdict""",
                    (org_id,),
                ).fetchall()
                verdict_counts = {r["verdict"]: int(r["c"]) for r in verdict_rows}

        pass_count = int(verdict_counts.get("pass", 0))
        fail_count = int(verdict_counts.get("fail", 0))
        ver_total = pass_count + fail_count
        pass_rate = (pass_count / ver_total) if ver_total > 0 else 0.0

        # Ensure every SLSA level key is present with a default of 0 so
        # downstream dashboards don't have to handle missing keys.
        by_level_full = {lvl: int(by_level.get(lvl, 0)) for lvl in sorted(_VALID_SLSA_LEVELS)}

        return {
            "org_id": org_id,
            "total_attestations": total,
            "by_slsa_level": by_level_full,
            "verifications": {
                "total": ver_total,
                "pass": pass_count,
                "fail": fail_count,
                "pass_rate": round(pass_rate, 4),
            },
        }
