import os
from pathlib import Path

import pytest
from core.storage import ArtefactArchive


@pytest.fixture
def allowlisted_root(tmp_path: Path) -> Path:
    root = tmp_path / "allowlisted"
    root.mkdir()
    return root


def test_archive_rejects_directory_outside_allowlist(
    tmp_path: Path, allowlisted_root: Path
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    with pytest.raises(PermissionError):
        ArtefactArchive(outside, allowlist=(allowlisted_root,))


def test_archive_rejects_world_writable_root(allowlisted_root: Path) -> None:
    os.chmod(allowlisted_root, 0o777)
    with pytest.raises(PermissionError):
        ArtefactArchive(allowlisted_root / "archive", allowlist=(allowlisted_root,))
