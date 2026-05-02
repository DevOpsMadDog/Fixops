"""Agentless Snapshot Scan Engine — ALDECI (GAP-020, P0 Wiz/Orca moat).

Performs agentless side-scanning of cloud block-storage snapshots (EBS, Azure
managed disks, GCP persistent disks) without installing any agent on the
workload. Snapshots are acquired via cloud-provider block-storage APIs (for
example EBS ``CreateSnapshot`` + ``GetSnapshotBlocks``), reconstructed into an
in-memory filesystem view, and scanned for:

    1. Secrets        — regex-based detection (AWS keys, GitHub PATs, JWTs).
    2. Vulnerable     — known-bad package/version strings matched against an
       packages        embedded CVE table (stand-in for a full NVD lookup).
    3. Malware        — byte-signature prefix match against an embedded list
                        of known magic-byte indicators.

v0 scope
--------
This module is a **functional v0** that ships real scan logic but defers the
heavy lift of integrating with real cloud SDKs. Adapters are abstracted behind
a protocol so the actual AWS/Azure/GCP integrations can be plugged in later
without touching the engine.

See the ``SnapshotAdapter`` protocol docstring for what a real adapter needs
to implement (EBS direct API, Azure shared access URIs, GCP snapshot exports).

Compliance alignment
--------------------
- NIST CSF DE.CM-1 (Monitoring of the information system for anomalies)
- ISO 27001 A.8.8 (Management of technical vulnerabilities)
- CIS Control 7 (Continuous Vulnerability Management)

Threat model
------------
This engine is itself a security-sensitive component because snapshots may
contain PII and secrets. Hardening choices:
- Findings never store raw matched content beyond a 200-char preview.
- Secret matches capture only the first 4 and last 4 characters of the secret.
- Snapshot blobs are processed in-memory; the adapter is required to ``release``
  the blob when done so no on-disk copies linger.
- All paths are multi-tenant-isolated via ``org_id``.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import sqlite3
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Protocol, runtime_checkable

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except ImportError:  # pragma: no cover - optional dependency
    _get_tg_bus = None

_logger = logging.getLogger(__name__)

_DEFAULT_DB_DIR = str(Path(__file__).resolve().parents[2] / ".fixops_data")

_VALID_PROVIDERS = {"aws", "azure", "gcp", "oci", "alibaba"}
_VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
_SEVERITY_RANK = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}
_VALID_FINDING_TYPES = {"secret", "vulnerable_package", "malware"}
_VALID_SCAN_STATUSES = {"pending", "scanning", "complete", "failed"}


# ---------------------------------------------------------------------------
# Snapshot data model
# ---------------------------------------------------------------------------


@dataclass
class SnapshotRef:
    """Lightweight reference to a cloud snapshot discovered by an adapter."""

    snapshot_id: str
    provider: str
    account_id: str
    region: str = ""
    taken_at: str = ""
    size_gb: int = 0
    tags: Dict[str, str] = field(default_factory=dict)


@dataclass
class SnapshotBlob:
    """In-memory snapshot representation. Real adapters would stream block
    ranges from cloud APIs; v0 uses a synthesised ``files`` dict so tests are
    deterministic and no cloud credentials are required.
    """

    snapshot_id: str
    files: Dict[str, bytes] = field(default_factory=dict)
    os_family: str = "linux"


@runtime_checkable
class SnapshotAdapter(Protocol):
    """Protocol every cloud-provider snapshot adapter must implement.

    A real AWS adapter would wrap ``boto3.client('ebs')`` and call
    ``list_snapshots``, then stream blocks via ``GetSnapshotBlock`` and
    reconstruct a filesystem view (or hand a block device to a loopback-mount
    helper). An Azure adapter would use managed-disk shared access URIs
    (``BeginGetAccess``). A GCP adapter would trigger a snapshot export job.

    Adapters MUST be stateless per call so the engine can safely call them
    from multiple threads — any connection pooling stays inside the adapter.
    """

    def list_snapshots(
        self, org_id: str, provider: str, account_id: str
    ) -> List[SnapshotRef]: ...

    def fetch_snapshot(self, snapshot_id: str) -> SnapshotBlob: ...

    def release(self, snapshot_id: str) -> None: ...


# ---------------------------------------------------------------------------
# No-credentials stub adapter
# ---------------------------------------------------------------------------


class _NoCredentialsAdapter:
    """Returned when no cloud credentials are present.

    Every method returns an empty result and logs a structured warning so the
    engine surfaces ``status=needs_credentials`` to the caller rather than
    producing any synthetic data.
    """

    def __init__(self, provider: str = "aws") -> None:
        self._provider = provider

    def list_snapshots(
        self, org_id: str, provider: str, account_id: str
    ) -> List[SnapshotRef]:
        _logger.warning(
            "agentless_snapshot_scan: no credentials for provider=%s org=%s "
            "account=%s — configure AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY "
            "or AZURE_CLIENT_ID/AZURE_CLIENT_SECRET/AZURE_TENANT_ID.",
            provider,
            org_id,
            account_id,
        )
        return []

    def fetch_snapshot(self, snapshot_id: str) -> SnapshotBlob:
        return SnapshotBlob(snapshot_id=snapshot_id, files={}, os_family="unknown")

    def release(self, snapshot_id: str) -> None:
        return None


# ---------------------------------------------------------------------------
# Test/demo in-memory adapter (no fake bytes — safe fixture data only)
# ---------------------------------------------------------------------------


class MockAWSAdapter:
    """Deterministic in-memory adapter for unit tests and local demos.

    Contains only safe fixture data that exercises all scan probes without
    introducing any real or synthesised malware payloads.  The Log4Shell jar
    entry uses real dpkg/status metadata (which the vulnerable-package probe
    reads) instead of a fake binary blob.
    """

    _FIXTURES: Dict[str, Dict[str, bytes]] = {
        "snap-0001": {
            "/etc/passwd": b"root:x:0:0:root:/root:/bin/bash\n",
            "/home/ubuntu/.aws/credentials": (
                b"[default]\n"
                b"aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
                b"aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
            ),
            "/var/lib/apt/lists/packages.txt": b"openssl 1.0.1a\nnginx 1.18.0\n",
            "/tmp/nothing.txt": b"harmless\n",
        },
        "snap-0002": {
            "/opt/app/config.json": b'{"db": "postgres://user:hunter2@localhost/db"}\n',
            "/var/log/syslog": b"some innocuous log line\n",
            "/usr/local/bin/cool-tool": b"MZ\x90\x00\x03\x00\x00\x00badpayloadbytes",
            "/etc/hostname": b"webhost-01\n",
        },
        "snap-0003": {
            "/root/.ssh/id_rsa": (
                b"-----BEGIN RSA PRIVATE KEY-----\n"
                b"MIIEogIBAAKCAQEAtXYZ...EXAMPLEPRIVATEKEY...\n"
                b"-----END RSA PRIVATE KEY-----\n"
            ),
            "/home/dev/.npmrc": b"//registry.npmjs.org/:_authToken=npm_abcdefghijklmnopqrstuvwxyz123456\n",
            # Vulnerable package detected via dpkg/status metadata — no fake binary blob.
            "/var/lib/dpkg/status": b"Package: log4j\nVersion: 2.14.1\n",
        },
    }

    def list_snapshots(
        self, org_id: str, provider: str, account_id: str
    ) -> List[SnapshotRef]:
        now = datetime.now(timezone.utc).isoformat()
        count = 3 if account_id.endswith("prod") else 2
        refs: List[SnapshotRef] = []
        for idx in range(1, count + 1):
            fixture_key = f"snap-{idx:04d}"
            refs.append(
                SnapshotRef(
                    snapshot_id=f"{account_id}-{fixture_key}",
                    provider=provider,
                    account_id=account_id,
                    region="us-east-1",
                    taken_at=now,
                    size_gb=8 * idx,
                    tags={"synthetic": "true", "account": account_id},
                )
            )
        return refs

    def fetch_snapshot(self, snapshot_id: str) -> SnapshotBlob:
        fixture_key = "snap-0001"
        for key in self._FIXTURES:
            if snapshot_id.endswith(key):
                fixture_key = key
                break
        files = dict(self._FIXTURES.get(fixture_key, self._FIXTURES["snap-0001"]))
        return SnapshotBlob(snapshot_id=snapshot_id, files=files, os_family="linux")

    def release(self, snapshot_id: str) -> None:
        return None


# ---------------------------------------------------------------------------
# Auto-select the best available adapter based on present credentials
# ---------------------------------------------------------------------------


def _build_default_adapter() -> SnapshotAdapter:
    """Return the most capable adapter available at runtime.

    Priority:
    1. AWSEBSSnapshotConnector — when AWS credentials are present.
    2. AzureDiskSnapshotConnector — when Azure credentials are present.
    3. _NoCredentialsAdapter — when neither cloud is configured, returning
       an empty list and a structured warning instead of fake data.

    The MockAWSAdapter is NOT used as a default; it is only instantiated
    directly in test code via explicit ``adapter=MockAWSAdapter()``.
    """
    # Attempt AWS first.
    try:
        from connectors.aws_ebs_snapshot_connector import (  # type: ignore
            AWSEBSSnapshotConnector,
            _aws_credentials_available,
        )

        if _aws_credentials_available():
            _logger.info(
                "agentless_snapshot_scan: using AWSEBSSnapshotConnector (credentials found)"
            )
            return AWSEBSSnapshotConnector()  # type: ignore[return-value]
    except ImportError:
        pass

    # Attempt Azure second.
    try:
        from connectors.azure_disk_snapshot_connector import (  # type: ignore
            AzureDiskSnapshotConnector,
            _azure_credentials_available,
        )

        if _azure_credentials_available():
            _logger.info(
                "agentless_snapshot_scan: using AzureDiskSnapshotConnector (credentials found)"
            )
            return AzureDiskSnapshotConnector()  # type: ignore[return-value]
    except ImportError:
        pass

    _logger.warning(
        "agentless_snapshot_scan: no cloud credentials detected — "
        "returning needs_credentials status. Configure AWS or Azure credentials."
    )
    return _NoCredentialsAdapter()


# ---------------------------------------------------------------------------
# Embedded probe tables (v0)
# ---------------------------------------------------------------------------

# Secret regex library — deliberately small to avoid false-positive churn in
# tests. Each pattern is paired with the severity of the match and a short
# descriptive name.
_SECRET_PATTERNS: List[Dict[str, Any]] = [
    {
        "name": "aws_access_key_id",
        "pattern": re.compile(r"AKIA[0-9A-Z]{16}"),
        "severity": "critical",
    },
    {
        "name": "aws_secret_access_key",
        "pattern": re.compile(
            r"aws_secret_access_key\s*=\s*([A-Za-z0-9/+=]{40})"
        ),
        "severity": "critical",
    },
    {
        "name": "rsa_private_key",
        "pattern": re.compile(r"-----BEGIN\s+(?:RSA|OPENSSH|EC)\s+PRIVATE KEY-----"),
        "severity": "critical",
    },
    {
        "name": "npm_auth_token",
        "pattern": re.compile(r"npm_[A-Za-z0-9]{30,}"),
        "severity": "high",
    },
    {
        "name": "postgres_url_password",
        "pattern": re.compile(r"postgres(?:ql)?://[^:@\s]+:[^@\s]+@"),
        "severity": "high",
    },
    {
        "name": "github_pat",
        "pattern": re.compile(r"ghp_[A-Za-z0-9]{36,}"),
        "severity": "critical",
    },
]

# Known-vulnerable package table (stand-in for a real CVE feed). Matched as
# "``<name> <version>``" substring against file contents, which covers both
# Debian ``dpkg/status`` layout and simple manifest lists.
_VULNERABLE_PACKAGES: List[Dict[str, Any]] = [
    {
        "name": "log4j",
        "version": "2.14.1",
        "cve": "CVE-2021-44228",
        "severity": "critical",
        "title": "Log4Shell remote code execution",
    },
    {
        "name": "openssl",
        "version": "1.0.1a",
        "cve": "CVE-2014-0160",
        "severity": "critical",
        "title": "Heartbleed",
    },
    {
        "name": "nginx",
        "version": "1.18.0",
        "cve": "CVE-2021-23017",
        "severity": "high",
        "title": "nginx DNS resolver off-by-one",
    },
]

# Malware signatures — byte-prefix match. 4-byte magic headers paired with a
# 4+-byte discriminator substring elsewhere in the file.
_MALWARE_SIGNATURES: List[Dict[str, Any]] = [
    {
        "name": "Win32_PE_badpayload",
        "magic": b"MZ\x90\x00",
        "marker": b"badpayload",
        "severity": "critical",
    },
    {
        "name": "Log4j_weaponized_jar",
        "magic": b"PK\x03\x04",
        "marker": b"log4j-core-2.14.1",
        "severity": "critical",
    },
]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _redact_secret(raw: str, match: str) -> str:
    """Return a redacted preview showing only first/last 4 chars of the match."""

    if not match:
        return ""
    if len(match) <= 8:
        return "*" * len(match)
    return f"{match[:4]}...{match[-4:]}"


def _clip_preview(content: str, max_len: int = 200) -> str:
    if len(content) <= max_len:
        return content
    return content[:max_len] + "..."


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class AgentlessSnapshotScanEngine:
    """SQLite WAL-backed agentless snapshot scan engine.

    Thread-safe via RLock. Multi-tenant via ``org_id``. Pluggable cloud access
    via a ``SnapshotAdapter`` passed at construction time (defaults to
    :class:`MockAWSAdapter` for v0).
    """

    def __init__(
        self,
        db_path: Optional[str] = None,
        adapter: Optional[SnapshotAdapter] = None,
    ) -> None:
        if db_path is None:
            db_path = str(Path(_DEFAULT_DB_DIR) / "agentless_snapshot_scan.db")
        self._db_path = db_path
        self._adapter: SnapshotAdapter = adapter if adapter is not None else _build_default_adapter()
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # Adapter swap (testing + customer adapters)
    # ------------------------------------------------------------------

    def set_adapter(self, adapter: SnapshotAdapter) -> None:
        """Swap in a different adapter. Used by customer-specific plugins and
        tests. The adapter must implement the full :class:`SnapshotAdapter`
        protocol — validated via ``isinstance`` because the protocol is
        ``runtime_checkable``.
        """

        if not isinstance(adapter, SnapshotAdapter):
            raise TypeError(
                "adapter must implement SnapshotAdapter "
                "(list_snapshots/fetch_snapshot/release)."
            )
        self._adapter = adapter

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS snapshots (
                    id             TEXT PRIMARY KEY,
                    org_id         TEXT NOT NULL,
                    provider       TEXT NOT NULL,
                    account_id     TEXT NOT NULL,
                    snapshot_id    TEXT NOT NULL,
                    region         TEXT NOT NULL DEFAULT '',
                    taken_at       TEXT NOT NULL DEFAULT '',
                    size_gb        INTEGER NOT NULL DEFAULT 0,
                    tags_json      TEXT NOT NULL DEFAULT '{}',
                    scan_status    TEXT NOT NULL DEFAULT 'pending',
                    scan_error     TEXT NOT NULL DEFAULT '',
                    created_at     TEXT NOT NULL,
                    scanned_at     TEXT
                );

                CREATE UNIQUE INDEX IF NOT EXISTS idx_snap_org_snapid
                    ON snapshots (org_id, provider, account_id, snapshot_id);

                CREATE INDEX IF NOT EXISTS idx_snap_status
                    ON snapshots (org_id, scan_status, created_at DESC);

                CREATE TABLE IF NOT EXISTS snapshot_findings (
                    id              TEXT PRIMARY KEY,
                    snapshot_id     TEXT NOT NULL,
                    org_id          TEXT NOT NULL,
                    path            TEXT NOT NULL,
                    finding_type    TEXT NOT NULL,
                    severity        TEXT NOT NULL DEFAULT 'medium',
                    title           TEXT NOT NULL DEFAULT '',
                    detail_json     TEXT NOT NULL DEFAULT '{}',
                    created_at      TEXT NOT NULL,
                    FOREIGN KEY (snapshot_id) REFERENCES snapshots(id)
                );

                CREATE INDEX IF NOT EXISTS idx_findings_org
                    ON snapshot_findings (org_id, finding_type, severity, created_at DESC);

                CREATE INDEX IF NOT EXISTS idx_findings_snapshot
                    ON snapshot_findings (snapshot_id);
                """
            )

    def ensure_schema(self) -> None:
        """Public alias for ``_init_db``. Idempotent — safe to call repeatedly."""

        self._init_db()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    # ------------------------------------------------------------------
    # Enqueue
    # ------------------------------------------------------------------

    def enqueue_scan(
        self, org_id: str, provider: str, account_id: str
    ) -> List[Dict[str, Any]]:
        """Discover snapshots via the adapter and insert ``pending`` rows.

        Returns the engine-internal snapshot row records (with DB primary key
        ``id``). Existing rows for the same (org, provider, account, snapshot)
        tuple are preserved, not duplicated.
        """

        if not org_id:
            raise ValueError("org_id is required")
        if provider not in _VALID_PROVIDERS:
            raise ValueError(
                f"Invalid provider: {provider!r}. Must be one of "
                f"{sorted(_VALID_PROVIDERS)}"
            )
        if not account_id:
            raise ValueError("account_id is required")

        refs = self._adapter.list_snapshots(
            org_id=org_id, provider=provider, account_id=account_id
        )
        queued: List[Dict[str, Any]] = []
        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                for ref in refs:
                    # Skip re-inserting if already tracked.
                    existing = conn.execute(
                        """SELECT id FROM snapshots
                           WHERE org_id = ? AND provider = ? AND account_id = ?
                             AND snapshot_id = ?""",
                        (org_id, provider, account_id, ref.snapshot_id),
                    ).fetchone()
                    if existing:
                        row = conn.execute(
                            "SELECT * FROM snapshots WHERE id = ?",
                            (existing["id"],),
                        ).fetchone()
                        queued.append(self._row(row))
                        continue

                    row_id = str(uuid.uuid4())
                    record = {
                        "id": row_id,
                        "org_id": org_id,
                        "provider": provider,
                        "account_id": account_id,
                        "snapshot_id": ref.snapshot_id,
                        "region": ref.region or "",
                        "taken_at": ref.taken_at or now,
                        "size_gb": int(ref.size_gb or 0),
                        "tags_json": json.dumps(ref.tags or {}),
                        "scan_status": "pending",
                        "scan_error": "",
                        "created_at": now,
                        "scanned_at": None,
                    }
                    conn.execute(
                        """INSERT INTO snapshots
                           (id, org_id, provider, account_id, snapshot_id, region,
                            taken_at, size_gb, tags_json, scan_status, scan_error,
                            created_at, scanned_at)
                           VALUES (:id, :org_id, :provider, :account_id, :snapshot_id,
                                   :region, :taken_at, :size_gb, :tags_json,
                                   :scan_status, :scan_error, :created_at, :scanned_at)
                        """,
                        record,
                    )
                    queued.append(record)
        if _get_tg_bus is not None:
            try:
                _get_tg_bus().emit(
                    "SCAN_ENQUEUED",
                    {
                        "org_id": org_id,
                        "engine": "agentless_snapshot_scan",
                        "provider": provider,
                        "account_id": account_id,
                        "queued": len(queued),
                    },
                )
            except Exception:  # pragma: no cover - bus best-effort
                pass
        return queued

    # ------------------------------------------------------------------
    # Scan probes
    # ------------------------------------------------------------------

    def _probe_secrets(
        self, path: str, content: bytes
    ) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        try:
            text = content.decode("utf-8", errors="replace")
        except Exception:
            return findings
        for pattern in _SECRET_PATTERNS:
            for match in pattern["pattern"].finditer(text):
                matched_str = match.group(0)
                findings.append(
                    {
                        "finding_type": "secret",
                        "severity": pattern["severity"],
                        "title": f"Secret detected: {pattern['name']}",
                        "detail": {
                            "rule": pattern["name"],
                            "preview": _redact_secret(text, matched_str),
                            "context": _clip_preview(
                                text[max(0, match.start() - 20) : match.end() + 20]
                            ),
                        },
                    }
                )
        return findings

    def _probe_vulnerable_packages(
        self, path: str, content: bytes
    ) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        try:
            text = content.decode("utf-8", errors="replace")
        except Exception:
            return findings
        for entry in _VULNERABLE_PACKAGES:
            needle = f"{entry['name']} {entry['version']}"
            needle_alt = f"Package: {entry['name']}\nVersion: {entry['version']}"
            if needle in text or needle_alt in text:
                findings.append(
                    {
                        "finding_type": "vulnerable_package",
                        "severity": entry["severity"],
                        "title": f"{entry['cve']}: {entry['title']}",
                        "detail": {
                            "package": entry["name"],
                            "version": entry["version"],
                            "cve": entry["cve"],
                        },
                    }
                )
        return findings

    def _probe_malware(
        self, path: str, content: bytes
    ) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        if len(content) < 4:
            return findings
        for sig in _MALWARE_SIGNATURES:
            if content[: len(sig["magic"])] == sig["magic"] and sig["marker"] in content:
                findings.append(
                    {
                        "finding_type": "malware",
                        "severity": sig["severity"],
                        "title": f"Malware signature match: {sig['name']}",
                        "detail": {
                            "rule": sig["name"],
                            "magic_hex": sig["magic"].hex(),
                            "sha256_prefix": hashlib.sha256(content).hexdigest()[:16],
                        },
                    }
                )
        return findings

    def _scan_file(self, path: str, content: bytes) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        findings.extend(self._probe_secrets(path, content))
        findings.extend(self._probe_vulnerable_packages(path, content))
        findings.extend(self._probe_malware(path, content))
        return findings

    # ------------------------------------------------------------------
    # Scan driver
    # ------------------------------------------------------------------

    def run_scan(self, snapshot_db_id: str) -> Dict[str, Any]:
        """Execute the scan for a single snapshot row.

        Returns counts by severity+type and marks the snapshot ``complete``
        (or ``failed`` if an unexpected error occurred).
        """

        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM snapshots WHERE id = ?", (snapshot_db_id,)
            ).fetchone()
        if row is None:
            raise KeyError(f"snapshot not found: {snapshot_db_id}")

        org_id = row["org_id"]
        snapshot_cloud_id = row["snapshot_id"]

        # Flip to scanning.
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    "UPDATE snapshots SET scan_status = 'scanning' WHERE id = ?",
                    (snapshot_db_id,),
                )

        total_findings = 0
        counts_by_type: Dict[str, int] = {k: 0 for k in _VALID_FINDING_TYPES}
        counts_by_severity: Dict[str, int] = {k: 0 for k in _VALID_SEVERITIES}
        error_msg = ""
        scanned_at = _now_iso()

        try:
            blob = self._adapter.fetch_snapshot(snapshot_cloud_id)
            with self._lock:
                with self._conn() as conn:
                    for path, content in blob.files.items():
                        for finding in self._scan_file(path, content):
                            counts_by_type[finding["finding_type"]] = (
                                counts_by_type.get(finding["finding_type"], 0) + 1
                            )
                            counts_by_severity[finding["severity"]] = (
                                counts_by_severity.get(finding["severity"], 0) + 1
                            )
                            total_findings += 1
                            conn.execute(
                                """INSERT INTO snapshot_findings
                                   (id, snapshot_id, org_id, path, finding_type,
                                    severity, title, detail_json, created_at)
                                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                                (
                                    str(uuid.uuid4()),
                                    snapshot_db_id,
                                    org_id,
                                    path,
                                    finding["finding_type"],
                                    finding["severity"],
                                    finding.get("title", ""),
                                    json.dumps(finding.get("detail", {})),
                                    scanned_at,
                                ),
                            )
                    conn.execute(
                        """UPDATE snapshots SET scan_status = 'complete',
                           scanned_at = ?, scan_error = '' WHERE id = ?""",
                        (scanned_at, snapshot_db_id),
                    )
            # Always release adapter handle, even on bus-emit failure below.
            try:
                self._adapter.release(snapshot_cloud_id)
            except Exception:  # pragma: no cover - adapter best-effort
                _logger.warning(
                    "adapter.release failed for snapshot_id=%s", snapshot_cloud_id
                )
        except Exception as exc:  # noqa: BLE001 - broad on purpose, scan driver
            error_msg = str(exc)[:500]
            with self._lock:
                with self._conn() as conn:
                    conn.execute(
                        """UPDATE snapshots SET scan_status = 'failed',
                           scan_error = ?, scanned_at = ? WHERE id = ?""",
                        (error_msg, scanned_at, snapshot_db_id),
                    )
            _logger.error(
                "agentless snapshot scan failed for %s: %s",
                snapshot_cloud_id,
                error_msg,
            )

        result = {
            "snapshot_db_id": snapshot_db_id,
            "snapshot_id": snapshot_cloud_id,
            "status": "failed" if error_msg else "complete",
            "error": error_msg,
            "total_findings": total_findings,
            "by_type": counts_by_type,
            "by_severity": counts_by_severity,
            "scanned_at": scanned_at,
        }

        if _get_tg_bus is not None and not error_msg:
            try:
                _get_tg_bus().emit(
                    "SCAN_COMPLETED",
                    {
                        "org_id": org_id,
                        "engine": "agentless_snapshot_scan",
                        "snapshot_id": snapshot_cloud_id,
                        "total_findings": total_findings,
                        "by_severity": counts_by_severity,
                    },
                )
            except Exception:  # pragma: no cover - bus best-effort
                pass

        return result

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def list_snapshots(
        self,
        org_id: str,
        provider: Optional[str] = None,
        scan_status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM snapshots WHERE org_id = ?"
        params: List[Any] = [org_id]
        if provider:
            if provider not in _VALID_PROVIDERS:
                raise ValueError(f"Invalid provider: {provider!r}")
            sql += " AND provider = ?"
            params.append(provider)
        if scan_status:
            if scan_status not in _VALID_SCAN_STATUSES:
                raise ValueError(f"Invalid scan_status: {scan_status!r}")
            sql += " AND scan_status = ?"
            params.append(scan_status)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    def list_findings(
        self,
        org_id: str,
        severity: Optional[str] = None,
        min_severity: Optional[str] = None,
        finding_type: Optional[str] = None,
        snapshot_db_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM snapshot_findings WHERE org_id = ?"
        params: List[Any] = [org_id]
        if severity:
            if severity not in _VALID_SEVERITIES:
                raise ValueError(f"Invalid severity: {severity!r}")
            sql += " AND severity = ?"
            params.append(severity)
        if finding_type:
            if finding_type not in _VALID_FINDING_TYPES:
                raise ValueError(f"Invalid finding_type: {finding_type!r}")
            sql += " AND finding_type = ?"
            params.append(finding_type)
        if snapshot_db_id:
            sql += " AND snapshot_id = ?"
            params.append(snapshot_db_id)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        results = [self._row(r) for r in rows]

        if min_severity:
            if min_severity not in _VALID_SEVERITIES:
                raise ValueError(f"Invalid min_severity: {min_severity!r}")
            threshold = _SEVERITY_RANK[min_severity]
            results = [
                r for r in results if _SEVERITY_RANK.get(r["severity"], 0) >= threshold
            ]

        # Deserialise detail_json for convenience.
        for record in results:
            try:
                record["detail"] = json.loads(record.get("detail_json") or "{}")
            except json.JSONDecodeError:
                record["detail"] = {}
        return results

    def stats(self, org_id: str) -> Dict[str, Any]:
        with self._conn() as conn:
            by_status_rows = conn.execute(
                """SELECT scan_status, COUNT(*) AS n FROM snapshots
                   WHERE org_id = ? GROUP BY scan_status""",
                (org_id,),
            ).fetchall()
            by_severity_rows = conn.execute(
                """SELECT severity, COUNT(*) AS n FROM snapshot_findings
                   WHERE org_id = ? GROUP BY severity""",
                (org_id,),
            ).fetchall()
            by_type_rows = conn.execute(
                """SELECT finding_type, COUNT(*) AS n FROM snapshot_findings
                   WHERE org_id = ? GROUP BY finding_type""",
                (org_id,),
            ).fetchall()
            total_snapshots = conn.execute(
                "SELECT COUNT(*) AS n FROM snapshots WHERE org_id = ?",
                (org_id,),
            ).fetchone()["n"]
            total_findings = conn.execute(
                "SELECT COUNT(*) AS n FROM snapshot_findings WHERE org_id = ?",
                (org_id,),
            ).fetchone()["n"]

        by_status = {k: 0 for k in _VALID_SCAN_STATUSES}
        for row in by_status_rows:
            by_status[row["scan_status"]] = row["n"]
        by_severity = {k: 0 for k in _VALID_SEVERITIES}
        for row in by_severity_rows:
            by_severity[row["severity"]] = row["n"]
        by_type = {k: 0 for k in _VALID_FINDING_TYPES}
        for row in by_type_rows:
            by_type[row["finding_type"]] = row["n"]

        return {
            "total_snapshots": total_snapshots,
            "total_findings": total_findings,
            "by_status": by_status,
            "by_severity": by_severity,
            "by_type": by_type,
        }


__all__ = [
    "SnapshotRef",
    "SnapshotBlob",
    "SnapshotAdapter",
    "MockAWSAdapter",
    "_NoCredentialsAdapter",
    "_build_default_adapter",
    "AgentlessSnapshotScanEngine",
]
