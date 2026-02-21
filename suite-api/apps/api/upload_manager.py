"""Chunked upload manager used by the ingestion API."""

from __future__ import annotations

import json
import os
import re
import threading
import time
from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path
from typing import Any, Dict, Optional


@dataclass
class UploadSession:
    """State persisted for each in-flight upload session."""

    session_id: str
    stage: str
    filename: str
    total_bytes: Optional[int]
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    received_bytes: int = 0
    checksum: Optional[str] = None
    content_type: Optional[str] = None
    path: Path | None = None
    completed: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "stage": self.stage,
            "filename": self.filename,
            "total_bytes": self.total_bytes,
            "received_bytes": self.received_bytes,
            "progress": self.progress,
            "completed": self.completed,
            "checksum": self.checksum,
            "content_type": self.content_type,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @property
    def progress(self) -> float:
        if not self.total_bytes or self.total_bytes <= 0:
            return 0.0
        return round(min(1.0, self.received_bytes / self.total_bytes), 4)


def _sanitize_filename(filename: str) -> str:
    """
    Sanitize filename to prevent path traversal attacks.

    Args:
        filename: The original filename from user input

    Returns:
        A sanitized filename safe for filesystem operations
    """
    filename = os.path.basename(filename)

    filename = filename.replace("\x00", "")

    filename = re.sub(r'[<>:"|?*]', "_", filename)

    filename = filename.strip(". ")

    if not filename or filename in (".", ".."):
        filename = "upload.bin"

    if len(filename) > 255:
        name, ext = os.path.splitext(filename)
        max_name_len = 255 - len(ext)
        filename = name[:max_name_len] + ext

    return filename


class ChunkUploadManager:
    """Persist upload chunks to disk so clients can resume transfers."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        self._sessions: Dict[str, UploadSession] = {}
        self._lock = threading.RLock()
        self._load_existing_sessions()

    # ------------------------------------------------------------------
    # Session lifecycle helpers
    # ------------------------------------------------------------------
    def create_session(
        self,
        stage: str,
        *,
        filename: str,
        total_bytes: Optional[int] = None,
        content_type: Optional[str] = None,
        checksum: Optional[str] = None,
    ) -> UploadSession:
        import secrets

        sanitized_filename = _sanitize_filename(filename)
        session_id = secrets.token_hex(
            16
        )  # 32 hex characters, cryptographically secure
        with self._lock:
            session_dir = self._session_dir(session_id)
            session_dir.mkdir(parents=True, exist_ok=True)
            session = UploadSession(
                session_id=session_id,
                stage=stage,
                filename=sanitized_filename,
                total_bytes=total_bytes,
                checksum=checksum,
                content_type=content_type,
                path=session_dir / "payload.bin",
            )
            self._sessions[session_id] = session
            self._persist_metadata(session)
        return session

    def append_chunk(
        self,
        session_id: str,
        chunk: bytes,
        *,
        offset: Optional[int] = None,
    ) -> UploadSession:
        if not chunk:
            raise ValueError("Chunk payload must not be empty")
        with self._lock:
            session = self._require_session(session_id)
            if session.completed:
                raise ValueError("Upload session already finalised")
            path = session.path
            if path is None:
                raise ValueError("Upload session missing payload path")
            mode = "r+b" if path.exists() else "wb"
            with path.open(mode) as handle:
                if offset is not None:
                    handle.seek(offset)
                else:
                    handle.seek(0, os.SEEK_END)
                handle.write(chunk)
            session.received_bytes = max(session.received_bytes, path.stat().st_size)
            session.updated_at = time.time()
            self._persist_metadata(session)
            return session

    def finalise(self, session_id: str) -> UploadSession:
        with self._lock:
            session = self._require_session(session_id)
            if session.completed:
                return session
            path = session.path
            if path is None or not path.exists():
                raise ValueError("Upload payload missing for completion")
            if (
                session.total_bytes is not None
                and path.stat().st_size != session.total_bytes
            ):
                raise ValueError(
                    "Uploaded size does not match declared total bytes",
                )
            if session.checksum:
                digest = sha256(path.read_bytes()).hexdigest()
                if digest != session.checksum:
                    raise ValueError("Uploaded payload checksum mismatch")
            session.received_bytes = path.stat().st_size
            session.completed = True
            session.updated_at = time.time()
            self._persist_metadata(session)
            return session

    def status(self, session_id: str) -> UploadSession:
        with self._lock:
            return self._require_session(session_id)

    def abandon(self, session_id: str) -> None:
        with self._lock:
            session = self._sessions.pop(session_id, None)
            if session is None:
                return
            session_dir = self._session_dir(session_id)
            if session_dir.exists():
                for child in session_dir.iterdir():
                    child.unlink(missing_ok=True)  # type: ignore[arg-type]
                session_dir.rmdir()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _load_existing_sessions(self) -> None:
        for directory in self.root.iterdir():
            if not directory.is_dir():
                continue
            metadata_file = directory / "metadata.json"
            payload_path = directory / "payload.bin"
            if not metadata_file.exists():
                continue
            try:
                payload = json.loads(metadata_file.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                continue
            session = UploadSession(
                session_id=payload.get("session_id", directory.name),
                stage=payload.get("stage", "unknown"),
                filename=payload.get("filename", "payload.bin"),
                total_bytes=payload.get("total_bytes"),
                created_at=payload.get("created_at", time.time()),
                updated_at=payload.get("updated_at", time.time()),
                received_bytes=payload.get("received_bytes", 0),
                checksum=payload.get("checksum"),
                content_type=payload.get("content_type"),
                completed=payload.get("completed", False),
                path=payload_path if payload_path.exists() else None,
            )
            self._sessions[session.session_id] = session

    def _persist_metadata(self, session: UploadSession) -> None:
        directory = self._session_dir(session.session_id)
        directory.mkdir(parents=True, exist_ok=True)
        payload = dict(session.to_dict())
        if session.path is not None:
            payload["path"] = str(session.path)
        metadata_path = directory / "metadata.json"
        metadata_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def _require_session(self, session_id: str) -> UploadSession:
        session = self._sessions.get(session_id)
        if session is None:
            raise KeyError(f"Upload session '{session_id}' not found")
        return session

    def _session_dir(self, session_id: str) -> Path:
        return self.root / session_id


__all__ = ["ChunkUploadManager", "UploadSession"]
