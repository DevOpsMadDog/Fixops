"""An air-gapped site must be able to refresh its feeds, and prove what it got.

The bundle ships with the feed databases it was built with and nothing updates
them. Measured: 327,252 EPSS scores and 1,568 KEV entries, last refreshed **135
days** before the build, whose newest entry is ``CVE-2026-6328`` while a current
scan returns ``CVE-2026-49855`` and later. Every recent finding therefore falls
back to an *estimated* EPSS — honest, and not what a customer paying for exploit
intelligence is buying.

``scripts/feed_bundle.py`` is the carry-in path. What these tests protect is not
that it copies a file — it is that the file cannot be swapped on the way in. A
feed database that crossed an air gap on removable media is precisely the
artifact whose provenance matters, and a tampered one would silently change
every exploitability verdict the site produces.
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import sqlite3
import subprocess
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "feed_bundle.py"


def _load():
    spec = importlib.util.spec_from_file_location("feed_bundle", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def feeds(tmp_path) -> pathlib.Path:
    """A minimal but real feeds.db — same tables the product reads."""
    db = tmp_path / "src" / "feeds" / "feeds.db"
    db.parent.mkdir(parents=True)
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE epss_scores (cve_id TEXT, epss REAL, percentile REAL, date TEXT, updated_at TEXT)")
    conn.execute("CREATE TABLE kev_entries (cve_id TEXT, vendor_project TEXT, updated_at TEXT)")
    conn.execute("CREATE TABLE feed_metadata (feed_name TEXT, last_refresh TEXT, records_count INT, status TEXT, category TEXT, error_message TEXT)")
    conn.executemany("INSERT INTO epss_scores VALUES (?,?,?,?,?)",
                     [(f"CVE-2026-{i}", 0.1, 0.5, "2026-08-31", "2026-08-31") for i in range(25)])
    conn.execute("INSERT INTO kev_entries VALUES ('CVE-2026-1','acme','2026-08-31')")
    conn.execute("INSERT INTO feed_metadata VALUES ('epss','2026-08-31T00:00:00+00:00',25,'success',NULL,NULL)")
    conn.commit()
    return db


def _run(*args, env_extra=None) -> subprocess.CompletedProcess:
    import os

    env = dict(os.environ)
    env["PYTHONPATH"] = "suite-core:."
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True, text=True, cwd=REPO, env=env, timeout=600,
    )


def test_export_produces_a_bundle_and_a_signature_sidecar(feeds, tmp_path) -> None:
    out = tmp_path / "dist"
    result = _run("--db", str(feeds), "export", "--out", str(out))
    assert result.returncode == 0, result.stderr[-500:]

    bundles = list(out.glob("fixops-feeds-*.tar.gz"))
    assert len(bundles) == 1
    sidecar = pathlib.Path(str(bundles[0]) + ".sig.json")
    assert sidecar.is_file(), (
        "the sidecar name must be APPENDED; with_suffix on 'x.tar.gz' strips "
        "'.gz' and produces 'x.tar.tar.gz.sig.json'"
    )
    data = json.loads(sidecar.read_text())
    assert data["source_state"]["epss_scores"] == 25
    assert data["source_state"]["kev_entries"] == 1


def test_a_tampered_bundle_fails_verification(feeds, tmp_path) -> None:
    """The whole point. A file that crossed an air gap must be checkable."""
    out = tmp_path / "dist"
    _run("--db", str(feeds), "export", "--out", str(out))
    bundle = next(out.glob("fixops-feeds-*.tar.gz"))

    assert _run("verify", str(bundle)).returncode == 0

    with bundle.open("ab") as handle:
        handle.write(b"x")
    tampered = _run("verify", str(bundle))
    assert tampered.returncode == 1
    assert "MISMATCH" in tampered.stdout


def test_import_refuses_an_unverified_bundle(feeds, tmp_path) -> None:
    out = tmp_path / "dist"
    _run("--db", str(feeds), "export", "--out", str(out))
    bundle = next(out.glob("fixops-feeds-*.tar.gz"))
    with bundle.open("ab") as handle:
        handle.write(b"x")

    site = tmp_path / "site"
    result = _run("import", str(bundle), "--apply", env_extra={"FIXOPS_DATA_DIR": str(site)})
    assert result.returncode == 1
    assert "REFUSING" in result.stdout
    assert not (site / "feeds" / "feeds.db").exists(), (
        "a rejected bundle must not leave a partially installed feed database — "
        "a half-written one is worse than a stale one, because the verdicts it "
        "produces look current"
    )


def test_a_genuine_bundle_installs_and_reports_what_changed(feeds, tmp_path) -> None:
    out = tmp_path / "dist"
    _run("--db", str(feeds), "export", "--out", str(out))
    bundle = next(out.glob("fixops-feeds-*.tar.gz"))

    site = tmp_path / "site"
    result = _run("import", str(bundle), "--apply", env_extra={"FIXOPS_DATA_DIR": str(site)})
    assert result.returncode == 0, result.stdout + result.stderr[-400:]

    installed = site / "feeds" / "feeds.db"
    assert installed.is_file()
    conn = sqlite3.connect(installed)
    assert conn.execute("SELECT COUNT(*) FROM epss_scores").fetchone()[0] == 25
    assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    # The operator sees the transition, not just a success message.
    assert "EPSS" in result.stdout and "->" in result.stdout


def test_a_dry_run_changes_nothing(feeds, tmp_path) -> None:
    out = tmp_path / "dist"
    _run("--db", str(feeds), "export", "--out", str(out))
    bundle = next(out.glob("fixops-feeds-*.tar.gz"))

    site = tmp_path / "site"
    result = _run("import", str(bundle), env_extra={"FIXOPS_DATA_DIR": str(site)})
    assert result.returncode == 0
    assert "dry run" in result.stdout
    assert not (site / "feeds" / "feeds.db").exists()
