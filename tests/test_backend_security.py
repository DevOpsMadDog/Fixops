import os
from pathlib import Path

import pytest

from apps.api import app as backend_app
from core.configuration import OverlayConfig


def _make_overlay(root: Path) -> OverlayConfig:
    overlay = OverlayConfig()
    overlay.allowed_data_roots = (root,)
    overlay.data = {}
    overlay.toggles = {}
    overlay.metadata = {}
    return overlay


def test_create_app_rejects_insecure_allowlisted_root(
    monkeypatch, tmp_path: Path
) -> None:
    insecure_root = tmp_path / "insecure"
    insecure_root.mkdir()
    os.chmod(insecure_root, 0o777)

    overlay = _make_overlay(insecure_root)

    monkeypatch.setattr(backend_app, "load_overlay", lambda: overlay)

    with pytest.raises(PermissionError):
        backend_app.create_app()
