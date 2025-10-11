from pathlib import Path

import yaml

from core.overlay_runtime import prepare_overlay


def test_prepare_overlay_disables_encryption_without_fernet(monkeypatch):
    monkeypatch.setenv("FIXOPS_API_TOKEN", "demo-token")
    monkeypatch.setenv("FIXOPS_EVIDENCE_KEY", "Zz6A0n4P3skS8F6edSxE2xe50Tzw9uQWGWp9JYG1ChE=")
    monkeypatch.setattr("core.overlay_runtime.Fernet", None)
    overlay = prepare_overlay(path=Path("config/fixops.overlay.yml"), ensure_directories=False)
    evidence_limits = overlay.limits.get("evidence", {})
    assert evidence_limits.get("encrypt") is False


def test_prepare_overlay_disables_encryption_when_key_missing(monkeypatch):
    monkeypatch.setenv("FIXOPS_API_TOKEN", "demo-token")
    monkeypatch.delenv("FIXOPS_EVIDENCE_KEY", raising=False)
    monkeypatch.setattr("core.overlay_runtime.Fernet", object())
    overlay = prepare_overlay(path=Path("config/fixops.overlay.yml"), ensure_directories=False)
    evidence_limits = overlay.limits.get("evidence", {})
    assert evidence_limits.get("encrypt") is False


def test_prepare_overlay_creates_directories_when_requested(tmp_path, monkeypatch):
    monkeypatch.setenv("FIXOPS_API_TOKEN", "demo-token")
    monkeypatch.setenv("FIXOPS_EVIDENCE_KEY", "Zz6A0n4P3skS8F6edSxE2xe50Tzw9uQWGWp9JYG1ChE=")
    monkeypatch.setenv("FIXOPS_DATA_ROOT_ALLOWLIST", str(tmp_path))
    overlay_path = tmp_path / "overlay.yml"
    evidence_dir = tmp_path / "evidence" / "enterprise"
    overlay_payload = {
        "mode": "enterprise",
        "data": {"evidence_dir": str(evidence_dir)},
        "limits": {"evidence": {"encrypt": False}},
    }
    overlay_path.write_text(yaml.safe_dump(overlay_payload), encoding="utf-8")

    overlay = prepare_overlay(path=overlay_path, ensure_directories=True)

    assert overlay.mode == "enterprise"
    assert evidence_dir.exists(), "evidence directory should be created"
