from pathlib import Path

import pytest

from apps.api.upload_manager import ChunkUploadManager


def test_chunk_upload_manager_supports_resumable_uploads(tmp_path: Path) -> None:
    manager = ChunkUploadManager(tmp_path)
    session = manager.create_session("sarif", filename="scan.json", total_bytes=11)

    manager.append_chunk(session.session_id, b"hello ")
    manager.append_chunk(session.session_id, b"world")

    finalised = manager.finalise(session.session_id)
    assert finalised.completed is True
    assert finalised.received_bytes == 11
    assert pytest.approx(finalised.progress) == 1.0

    rehydrated = ChunkUploadManager(tmp_path)
    restored = rehydrated.status(session.session_id)
    assert restored.completed is True
    assert restored.filename == "scan.json"

    orphan = manager.create_session("sbom", filename="sbom.json", total_bytes=5)
    manager.append_chunk(orphan.session_id, b"12345")
    manager.abandon(orphan.session_id)

    with pytest.raises(KeyError):
        manager.status(orphan.session_id)
