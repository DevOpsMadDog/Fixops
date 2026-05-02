"""
Backup and restore engine for all SQLite databases.

Supports full, incremental, and config-only backups with scheduling,
encryption, checksum verification, and retention management.
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import logging
import os
import sqlite3
import uuid
import zipfile
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from pydantic import BaseModel

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Encryption helpers
# ---------------------------------------------------------------------------
_FERNET_HEADER = b"ALDECI_ENC_V2:"
_LEGACY_XOR_HEADER = b"ALDECI_ENC_V1:"
_PBKDF2_SALT = b"aldeci-backup-pbkdf2-salt-2026"  # static salt; key material comes from env
_PBKDF2_ITERATIONS = 480_000


def _derive_fernet_key(raw_key: bytes) -> Fernet:
    """Derive a Fernet key from raw key material using PBKDF2-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_PBKDF2_SALT,
        iterations=_PBKDF2_ITERATIONS,
    )
    key_bytes = kdf.derive(raw_key)
    return Fernet(base64.urlsafe_b64encode(key_bytes))


def _get_fernet() -> Fernet:
    """Return a Fernet instance keyed from FIXOPS_BACKUP_KEY env var."""
    raw = os.environ.get("FIXOPS_BACKUP_KEY", "").strip()
    if not raw:
        raise RuntimeError(
            "FIXOPS_BACKUP_KEY environment variable is not set. "
            "Set it to a strong secret before using backup encryption."
        )
    return _derive_fernet_key(raw.encode())


class BackupStatus(str, Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    VERIFIED = "verified"


class BackupType(str, Enum):
    FULL = "full"
    INCREMENTAL = "incremental"
    CONFIG_ONLY = "config_only"


class BackupRecord(BaseModel):
    id: str
    type: BackupType
    status: BackupStatus
    databases: List[str]
    file_path: str
    file_size_bytes: int
    checksum: str  # sha256
    encrypted: bool
    created_at: datetime
    completed_at: Optional[datetime] = None
    retention_days: int
    org_id: str


class RestoreRecord(BaseModel):
    id: str
    backup_id: str
    status: BackupStatus
    restored_databases: List[str]
    started_at: datetime
    completed_at: Optional[datetime] = None
    error: Optional[str] = None


class BackupEngine:
    """SQLite-backed backup and restore engine."""

    def __init__(self, db_path: str = "data/backup.db", backup_dir: str = "data/backups"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.backup_dir = Path(backup_dir)
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        self._init_tables()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_tables(self) -> None:
        conn = self._get_connection()
        try:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS backup_records (
                    id TEXT PRIMARY KEY,
                    type TEXT NOT NULL,
                    status TEXT NOT NULL,
                    databases TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    file_size_bytes INTEGER NOT NULL DEFAULT 0,
                    checksum TEXT NOT NULL DEFAULT '',
                    encrypted INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    completed_at TEXT,
                    retention_days INTEGER NOT NULL DEFAULT 30,
                    org_id TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS restore_records (
                    id TEXT PRIMARY KEY,
                    backup_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    restored_databases TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    error TEXT,
                    FOREIGN KEY (backup_id) REFERENCES backup_records(id)
                );

                CREATE TABLE IF NOT EXISTS backup_schedules (
                    id TEXT PRIMARY KEY,
                    org_id TEXT NOT NULL,
                    backup_type TEXT NOT NULL,
                    frequency TEXT NOT NULL,
                    retention_days INTEGER NOT NULL DEFAULT 30,
                    created_at TEXT NOT NULL,
                    last_run TEXT,
                    next_run TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_backup_org ON backup_records(org_id);
                CREATE INDEX IF NOT EXISTS idx_backup_status ON backup_records(status);
                CREATE INDEX IF NOT EXISTS idx_restore_backup ON restore_records(backup_id);
                CREATE INDEX IF NOT EXISTS idx_schedule_org ON backup_schedules(org_id);
                """
            )
            conn.commit()
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Core operations
    # ------------------------------------------------------------------

    def create_backup(
        self,
        org_id: str,
        backup_type: BackupType = BackupType.FULL,
        databases: Optional[List[str]] = None,
        encrypt: bool = False,
        retention_days: int = 30,
    ) -> BackupRecord:
        """Snapshot databases to a zip archive and return a BackupRecord."""
        record_id = str(uuid.uuid4())
        created_at = datetime.now(timezone.utc)

        if databases is None:
            databases = []

        file_path = str(self.backup_dir / f"backup_{record_id}.zip")

        # Insert PENDING record
        record = BackupRecord(
            id=record_id,
            type=backup_type,
            status=BackupStatus.PENDING,
            databases=databases,
            file_path=file_path,
            file_size_bytes=0,
            checksum="",
            encrypted=encrypt,
            created_at=created_at,
            completed_at=None,
            retention_days=retention_days,
            org_id=org_id,
        )
        self._upsert_backup(record)

        # Update to IN_PROGRESS
        record.status = BackupStatus.IN_PROGRESS
        self._upsert_backup(record)

        try:
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
                for db_path in databases:
                    path = Path(db_path)
                    if path.exists():
                        snapshot = self._snapshot_database(db_path)
                    else:
                        snapshot = b""
                    arcname = path.name if path.name else db_path
                    zf.writestr(arcname, snapshot)

                # Write manifest
                manifest = {
                    "backup_id": record_id,
                    "org_id": org_id,
                    "type": backup_type.value,
                    "databases": databases,
                    "created_at": created_at.isoformat(),
                    "encrypted": encrypt,
                }
                zf.writestr("manifest.json", json.dumps(manifest, indent=2))

            data = buf.getvalue()
            if encrypt:
                data = self._encrypt_data(data)

            Path(file_path).write_bytes(data)

            checksum = self._calculate_checksum(file_path)
            file_size = Path(file_path).stat().st_size
            completed_at = datetime.now(timezone.utc)

            record.status = BackupStatus.COMPLETED
            record.file_size_bytes = file_size
            record.checksum = checksum
            record.completed_at = completed_at
            self._upsert_backup(record)
            return record

        except Exception as exc:
            record.status = BackupStatus.FAILED
            record.completed_at = datetime.now(timezone.utc)
            self._upsert_backup(record)
            raise RuntimeError(f"Backup failed: {exc}") from exc

    def restore_backup(
        self,
        backup_id: str,
        target_databases: Optional[List[str]] = None,
    ) -> RestoreRecord:
        """Restore databases from a backup archive."""
        restore_id = str(uuid.uuid4())
        started_at = datetime.now(timezone.utc)

        backup = self.get_backup(backup_id)
        if backup is None:
            raise ValueError(f"Backup {backup_id} not found")

        restore = RestoreRecord(
            id=restore_id,
            backup_id=backup_id,
            status=BackupStatus.IN_PROGRESS,
            restored_databases=[],
            started_at=started_at,
            completed_at=None,
            error=None,
        )
        self._upsert_restore(restore)

        try:
            data = Path(backup.file_path).read_bytes()
            if backup.encrypted:
                data = self._decrypt_data(data)

            buf = io.BytesIO(data)
            restored: List[str] = []
            with zipfile.ZipFile(buf, "r") as zf:
                names = [n for n in zf.namelist() if n != "manifest.json"]
                for arcname in names:
                    db_bytes = zf.read(arcname)
                    # Find matching target path
                    target_path: Optional[str] = None
                    if target_databases:
                        for td in target_databases:
                            if Path(td).name == arcname:
                                target_path = td
                                break
                    else:
                        # Restore to original paths from backup record
                        for orig in backup.databases:
                            if Path(orig).name == arcname:
                                target_path = orig
                                break

                    if target_path is None:
                        target_path = str(self.backup_dir / f"restored_{arcname}")

                    Path(target_path).parent.mkdir(parents=True, exist_ok=True)
                    Path(target_path).write_bytes(db_bytes)
                    restored.append(target_path)

            restore.status = BackupStatus.COMPLETED
            restore.restored_databases = restored
            restore.completed_at = datetime.now(timezone.utc)
            self._upsert_restore(restore)
            return restore

        except Exception as exc:
            restore.status = BackupStatus.FAILED
            restore.error = str(exc)
            restore.completed_at = datetime.now(timezone.utc)
            self._upsert_restore(restore)
            raise RuntimeError(f"Restore failed: {exc}") from exc

    def verify_backup(self, backup_id: str) -> bool:
        """Verify backup file integrity via SHA-256 checksum."""
        backup = self.get_backup(backup_id)
        if backup is None:
            return False
        if not Path(backup.file_path).exists():
            return False
        actual = self._calculate_checksum(backup.file_path)
        valid = actual == backup.checksum
        if valid and backup.status != BackupStatus.VERIFIED:
            backup.status = BackupStatus.VERIFIED
            self._upsert_backup(backup)
        return valid

    def list_backups(
        self,
        org_id: str,
        type_filter: Optional[BackupType] = None,
    ) -> List[BackupRecord]:
        conn = self._get_connection()
        try:
            if type_filter:
                rows = conn.execute(
                    "SELECT * FROM backup_records WHERE org_id=? AND type=? ORDER BY created_at DESC",
                    (org_id, type_filter.value),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM backup_records WHERE org_id=? ORDER BY created_at DESC",
                    (org_id,),
                ).fetchall()
            return [self._row_to_backup(r) for r in rows]
        finally:
            conn.close()

    def get_backup(self, backup_id: str, org_id: Optional[str] = None) -> Optional[BackupRecord]:
        conn = self._get_connection()
        try:
            if org_id is not None:
                row = conn.execute(
                    "SELECT * FROM backup_records WHERE id=? AND org_id=?",
                    (backup_id, org_id),
                ).fetchone()
            else:
                row = conn.execute(
                    "SELECT * FROM backup_records WHERE id=?", (backup_id,)
                ).fetchone()
            return self._row_to_backup(row) if row else None
        finally:
            conn.close()

    def delete_backup(self, backup_id: str, org_id: Optional[str] = None) -> None:
        """Remove backup file and database record."""
        backup = self.get_backup(backup_id, org_id=org_id)
        if backup is None:
            raise ValueError(f"Backup {backup_id} not found")
        fp = Path(backup.file_path)
        if fp.exists():
            fp.unlink()
        conn = self._get_connection()
        try:
            if org_id is not None:
                conn.execute(
                    "DELETE FROM backup_records WHERE id=? AND org_id=?",
                    (backup_id, org_id),
                )
            else:
                conn.execute("DELETE FROM backup_records WHERE id=?", (backup_id,))
            conn.commit()
        finally:
            conn.close()

    def schedule_backup(
        self,
        org_id: str,
        backup_type: BackupType,
        frequency: str,
        retention_days: int = 30,
    ) -> Dict[str, Any]:
        """Create a backup schedule entry."""
        schedule_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        next_run = self._compute_next_run(now, frequency)
        conn = self._get_connection()
        try:
            conn.execute(
                """INSERT INTO backup_schedules
                   (id, org_id, backup_type, frequency, retention_days, created_at, next_run)
                   VALUES (?,?,?,?,?,?,?)""",
                (
                    schedule_id,
                    org_id,
                    backup_type.value,
                    frequency,
                    retention_days,
                    now.isoformat(),
                    next_run.isoformat(),
                ),
            )
            conn.commit()
            return {
                "id": schedule_id,
                "org_id": org_id,
                "backup_type": backup_type.value,
                "frequency": frequency,
                "retention_days": retention_days,
                "created_at": now.isoformat(),
                "next_run": next_run.isoformat(),
            }
        finally:
            conn.close()

    def get_schedules(self, org_id: str) -> List[Dict[str, Any]]:
        conn = self._get_connection()
        try:
            rows = conn.execute(
                "SELECT * FROM backup_schedules WHERE org_id=? ORDER BY created_at DESC",
                (org_id,),
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def cleanup_expired(self, org_id: str) -> int:
        """Remove backups whose retention period has elapsed. Returns count removed."""
        backups = self.list_backups(org_id)
        now = datetime.now(timezone.utc)
        removed = 0
        for b in backups:
            created = b.created_at
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            cutoff = created + timedelta(days=b.retention_days)
            if now >= cutoff:
                fp = Path(b.file_path)
                if fp.exists():
                    fp.unlink()
                conn = self._get_connection()
                try:
                    conn.execute("DELETE FROM backup_records WHERE id=?", (b.id,))
                    conn.commit()
                finally:
                    conn.close()
                removed += 1
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "backup", "org_id": org_id, "source_engine": "backup"})
            except Exception:
                pass

        return removed

    def get_backup_stats(self, org_id: str) -> Dict[str, Any]:
        backups = self.list_backups(org_id)
        total_size = sum(b.file_size_bytes for b in backups)
        by_type: Dict[str, int] = {}
        for b in backups:
            by_type[b.type.value] = by_type.get(b.type.value, 0) + 1
        last_backup = backups[0].created_at.isoformat() if backups else None
        return {
            "org_id": org_id,
            "total_backups": len(backups),
            "total_size_bytes": total_size,
            "by_type": by_type,
            "last_backup": last_backup,
        }

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _snapshot_database(self, db_path: str) -> bytes:
        """Use SQLite online backup API to create an in-memory snapshot."""
        src_path = Path(db_path)
        if not src_path.exists():
            return b""
        io.BytesIO()
        # Write to a temp in-memory db then dump bytes
        mem_conn = sqlite3.connect(":memory:")
        try:
            src_conn = sqlite3.connect(str(src_path))
            try:
                src_conn.backup(mem_conn)
            finally:
                src_conn.close()
            # Serialize mem db to bytes by writing to temp file path approach
            tmp_path = src_path.parent / f"_snap_{uuid.uuid4().hex}.db"
            disk_conn = sqlite3.connect(str(tmp_path))
            try:
                mem_conn.backup(disk_conn)
            finally:
                disk_conn.close()
            data = tmp_path.read_bytes()
            tmp_path.unlink()
            return data
        finally:
            mem_conn.close()

    def _encrypt_data(self, data: bytes) -> bytes:
        """Fernet (AES-128-CBC + HMAC-SHA256) encryption using FIXOPS_BACKUP_KEY."""
        fernet = _get_fernet()
        return _FERNET_HEADER + fernet.encrypt(data)

    def _decrypt_data(self, data: bytes) -> bytes:
        """Fernet decryption with legacy XOR fallback for V1 backups."""
        if data.startswith(_FERNET_HEADER):
            fernet = _get_fernet()
            return fernet.decrypt(data[len(_FERNET_HEADER):])
        if data.startswith(_LEGACY_XOR_HEADER):
            # LEGACY: XOR-only fallback for backups created before V2 encryption.
            # SECURITY: XOR is not secure — migrate existing backups to V2.
            logger.warning(
                "backup_engine: Decrypting legacy XOR-encrypted backup (V1). "
                "Re-encrypt this backup using the current Fernet-based method."
            )
            legacy_key = b"aldeci-backup-key-2026"
            payload = data[len(_LEGACY_XOR_HEADER):]
            key_len = len(legacy_key)
            return bytes(b ^ legacy_key[i % key_len] for i, b in enumerate(payload))
        # No header — treat as unencrypted (should not happen, but be defensive)
        return data

    def _calculate_checksum(self, file_path: str) -> str:
        """SHA-256 checksum of a file."""
        h = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()

    def _compute_next_run(self, from_dt: datetime, frequency: str) -> datetime:
        freq = frequency.lower()
        if freq == "hourly":
            return from_dt + timedelta(hours=1)
        if freq == "daily":
            return from_dt + timedelta(days=1)
        if freq == "weekly":
            return from_dt + timedelta(weeks=1)
        if freq == "monthly":
            return from_dt + timedelta(days=30)
        return from_dt + timedelta(days=1)

    def _upsert_backup(self, record: BackupRecord) -> None:
        conn = self._get_connection()
        try:
            conn.execute(
                """INSERT OR REPLACE INTO backup_records
                   (id, type, status, databases, file_path, file_size_bytes, checksum,
                    encrypted, created_at, completed_at, retention_days, org_id)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    record.id,
                    record.type.value,
                    record.status.value,
                    json.dumps(record.databases),
                    record.file_path,
                    record.file_size_bytes,
                    record.checksum,
                    1 if record.encrypted else 0,
                    record.created_at.isoformat(),
                    record.completed_at.isoformat() if record.completed_at else None,
                    record.retention_days,
                    record.org_id,
                ),
            )
            conn.commit()
        finally:
            conn.close()

    def _upsert_restore(self, record: RestoreRecord) -> None:
        conn = self._get_connection()
        try:
            conn.execute(
                """INSERT OR REPLACE INTO restore_records
                   (id, backup_id, status, restored_databases, started_at, completed_at, error)
                   VALUES (?,?,?,?,?,?,?)""",
                (
                    record.id,
                    record.backup_id,
                    record.status.value,
                    json.dumps(record.restored_databases),
                    record.started_at.isoformat(),
                    record.completed_at.isoformat() if record.completed_at else None,
                    record.error,
                ),
            )
            conn.commit()
        finally:
            conn.close()

    def _row_to_backup(self, row: sqlite3.Row) -> BackupRecord:
        d = dict(row)
        d["databases"] = json.loads(d["databases"])
        d["encrypted"] = bool(d["encrypted"])
        d["created_at"] = datetime.fromisoformat(d["created_at"])
        if d["completed_at"]:
            d["completed_at"] = datetime.fromisoformat(d["completed_at"])
        return BackupRecord(**d)
