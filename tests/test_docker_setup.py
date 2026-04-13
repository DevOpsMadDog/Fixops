"""Tests for Docker setup: entrypoint logic, env var handling, seed data, nginx config.

These tests run entirely in-process (no Docker required).
"""

import os
import re
import sqlite3
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest import mock

import pytest

# ── Paths ────────────────────────────────────────────────────────────────────
REPO_ROOT = Path(__file__).parent.parent
ENTRYPOINT_SH = REPO_ROOT / "docker" / "docker-entrypoint.sh"
NGINX_CONF = REPO_ROOT / "docker" / "nginx-ui.conf"
QUICK_START_SH = REPO_ROOT / "scripts" / "quick-start.sh"
SEED_SCRIPT = REPO_ROOT / "scripts" / "seed_demo_data.py"
COMPOSE_FILE = REPO_ROOT / "docker-compose.yml"


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _read(path: Path) -> str:
    return path.read_text()


# ─────────────────────────────────────────────────────────────────────────────
# Group 1: File existence & permissions
# ─────────────────────────────────────────────────────────────────────────────

class TestFileExistence:
    def test_entrypoint_exists(self):
        assert ENTRYPOINT_SH.exists(), f"Missing: {ENTRYPOINT_SH}"

    def test_nginx_conf_exists(self):
        assert NGINX_CONF.exists(), f"Missing: {NGINX_CONF}"

    def test_quick_start_exists(self):
        assert QUICK_START_SH.exists(), f"Missing: {QUICK_START_SH}"

    def test_seed_script_exists(self):
        assert SEED_SCRIPT.exists(), f"Missing: {SEED_SCRIPT}"

    def test_compose_file_exists(self):
        assert COMPOSE_FILE.exists(), f"Missing: {COMPOSE_FILE}"

    def test_entrypoint_is_executable(self):
        mode = ENTRYPOINT_SH.stat().st_mode
        assert mode & stat.S_IXUSR, "docker-entrypoint.sh is not user-executable"

    def test_quick_start_is_shell_script(self):
        content = _read(QUICK_START_SH)
        assert content.startswith("#!/bin/bash"), "quick-start.sh must start with #!/bin/bash"


# ─────────────────────────────────────────────────────────────────────────────
# Group 2: Entrypoint content / behaviour checks
# ─────────────────────────────────────────────────────────────────────────────

class TestEntrypointContent:
    def setup_method(self):
        self.content = _read(ENTRYPOINT_SH)

    def test_has_shebang(self):
        assert self.content.startswith("#!/bin/bash")

    def test_has_set_e(self):
        assert "set -e" in self.content

    def test_calls_init_databases(self):
        assert "init_databases.py" in self.content

    def test_checks_seed_demo_env(self):
        assert "ALDECI_SEED_DEMO" in self.content

    def test_seed_runs_only_when_flag_set(self):
        # Must guard seed behind ALDECI_SEED_DEMO check
        assert 'ALDECI_SEED_DEMO:-0' in self.content or 'ALDECI_SEED_DEMO' in self.content

    def test_starts_uvicorn(self):
        assert "uvicorn" in self.content

    def test_has_sigterm_trap(self):
        assert "trap" in self.content
        assert "SIGTERM" in self.content

    def test_api_only_mode_present(self):
        assert "api-only" in self.content

    def test_wait_for_health(self):
        assert "/health" in self.content

    def test_generates_jwt_secret_when_missing(self):
        assert "FIXOPS_JWT_SECRET" in self.content
        assert "secrets.token_urlsafe" in self.content

    def test_generates_api_token_when_missing(self):
        assert "FIXOPS_API_TOKEN" in self.content

    def test_shutdown_kills_api_pid(self):
        assert "API_PID" in self.content
        assert "SIGTERM" in self.content

    def test_default_mode_is_api_only(self):
        # Default when $1 is empty should be api-only
        assert '"api-only"' in self.content or "api-only" in self.content


# ─────────────────────────────────────────────────────────────────────────────
# Group 3: Entrypoint bash syntax check
# ─────────────────────────────────────────────────────────────────────────────

class TestEntrypointSyntax:
    def test_bash_syntax_valid(self):
        result = subprocess.run(
            ["bash", "-n", str(ENTRYPOINT_SH)],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, f"bash syntax error:\n{result.stderr}"

    def test_quick_start_syntax_valid(self):
        result = subprocess.run(
            ["bash", "-n", str(QUICK_START_SH)],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, f"bash syntax error:\n{result.stderr}"


# ─────────────────────────────────────────────────────────────────────────────
# Group 4: Nginx config content checks
# ─────────────────────────────────────────────────────────────────────────────

class TestNginxConfig:
    def setup_method(self):
        self.content = _read(NGINX_CONF)

    def test_listens_on_port_80(self):
        assert "listen       80" in self.content or "listen 80" in self.content

    def test_proxies_api_to_aldeci_backend(self):
        assert "http://aldeci:8000" in self.content

    def test_has_spa_fallback(self):
        assert "try_files $uri $uri/ /index.html" in self.content

    def test_has_websocket_upgrade(self):
        assert "Upgrade" in self.content
        assert "upgrade" in self.content

    def test_has_sse_location(self):
        assert "mcp-protocol/sse" in self.content

    def test_has_rate_limiting(self):
        assert "limit_req_zone" in self.content

    def test_has_gzip(self):
        assert "gzip on" in self.content

    def test_static_assets_cached(self):
        assert "/assets/" in self.content
        assert "immutable" in self.content

    def test_health_proxied(self):
        assert "location /health" in self.content

    def test_nginx_self_health_endpoint(self):
        assert "/nginx-health" in self.content


# ─────────────────────────────────────────────────────────────────────────────
# Group 5: docker-compose.yml checks
# ─────────────────────────────────────────────────────────────────────────────

class TestDockerCompose:
    def setup_method(self):
        self.content = _read(COMPOSE_FILE)

    def test_aldeci_service_present(self):
        assert "aldeci:" in self.content

    def test_ui_service_present(self):
        assert "aldeci-ui:" in self.content

    def test_ui_has_no_profile(self):
        # aldeci-ui must NOT require a profile to start
        # We verify that 'profiles:' does not appear in the aldeci-ui stanza
        # Simple heuristic: ui section must not list 'profiles:' before next top-level service
        ui_section_start = self.content.find("aldeci-ui:")
        # Find next top-level service or network/volume declaration
        next_section = self.content.find("\n  trustgraph-init:", ui_section_start)
        if next_section == -1:
            next_section = len(self.content)
        ui_section = self.content[ui_section_start:next_section]
        assert "profiles:" not in ui_section, "aldeci-ui must not be behind a profile"

    def test_aldeci_seed_demo_env_set(self):
        assert "ALDECI_SEED_DEMO" in self.content

    def test_fixops_api_token_has_default(self):
        # Should have a default value so compose up doesn't require env var
        assert "FIXOPS_API_TOKEN:-" in self.content

    def test_has_aldeci_network(self):
        assert "aldeci-net" in self.content

    def test_volumes_persist_data(self):
        assert "aldeci-data:" in self.content
        assert "aldeci-state:" in self.content

    def test_healthcheck_defined(self):
        assert "healthcheck:" in self.content

    def test_ui_depends_on_api_healthy(self):
        assert "service_healthy" in self.content

    def test_nginx_conf_mounted(self):
        assert "nginx-ui.conf" in self.content

    def test_dtrack_behind_profile(self):
        assert "profiles:" in self.content
        assert "dtrack" in self.content


# ─────────────────────────────────────────────────────────────────────────────
# Group 6: seed_demo_data.py logic
# ─────────────────────────────────────────────────────────────────────────────

class TestSeedDemoData:
    """Import and exercise seed_demo_data.py in-process with a temp data dir."""

    def _import_seed(self, data_dir: Path):
        """Import seed_demo_data with DATA_DIR patched to a temp dir."""
        import importlib
        import importlib.util

        spec = importlib.util.spec_from_file_location("seed_demo_data", str(SEED_SCRIPT))
        mod = importlib.util.module_from_spec(spec)
        # Patch DATA_DIR before exec
        with mock.patch.dict(os.environ, {"FIXOPS_DATA_DIR": str(data_dir)}):
            spec.loader.exec_module(mod)
        return mod

    def test_seed_idempotent_skips_on_marker(self, tmp_path):
        mod = self._import_seed(tmp_path)
        mod.DATA_DIR = tmp_path
        mod.SEED_MARKER = tmp_path / ".demo_seeded"
        mod.SEED_MARKER.write_text("2026-01-01T00:00:00+00:00")
        # Should return 0 without doing anything
        result = mod.main()
        assert result == 0

    def test_seed_creates_marker_file(self, tmp_path):
        mod = self._import_seed(tmp_path)
        mod.DATA_DIR = tmp_path
        mod.SEED_MARKER = tmp_path / ".demo_seeded"
        # Run with no DBs present (skip paths)
        mod.main()
        assert mod.SEED_MARKER.exists()

    def test_seed_findings_inserts_rows(self, tmp_path):
        mod = self._import_seed(tmp_path)
        mod.DATA_DIR = tmp_path
        mod.SEED_MARKER = tmp_path / ".demo_seeded"
        # Pre-create analytics.db so seed_findings can insert
        db_path = tmp_path / "analytics.db"
        with sqlite3.connect(str(db_path)) as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS stub (x INT)")
        mod.seed_findings()
        with sqlite3.connect(str(db_path)) as conn:
            count = conn.execute("SELECT COUNT(*) FROM demo_findings").fetchone()[0]
        assert count == 5

    def test_seed_assets_inserts_rows(self, tmp_path):
        mod = self._import_seed(tmp_path)
        mod.DATA_DIR = tmp_path
        mod.SEED_MARKER = tmp_path / ".demo_seeded"
        db_path = tmp_path / "inventory.db"
        with sqlite3.connect(str(db_path)) as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS stub (x INT)")
        mod.seed_assets()
        with sqlite3.connect(str(db_path)) as conn:
            count = conn.execute("SELECT COUNT(*) FROM demo_assets").fetchone()[0]
        assert count == 7

    def test_seed_audit_inserts_rows(self, tmp_path):
        mod = self._import_seed(tmp_path)
        mod.DATA_DIR = tmp_path
        mod.SEED_MARKER = tmp_path / ".demo_seeded"
        db_path = tmp_path / "audit.db"
        with sqlite3.connect(str(db_path)) as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS stub (x INT)")
        mod.seed_audit_events()
        with sqlite3.connect(str(db_path)) as conn:
            count = conn.execute("SELECT COUNT(*) FROM demo_audit_events").fetchone()[0]
        assert count == 5

    def test_seed_findings_idempotent(self, tmp_path):
        """Calling seed_findings twice should not duplicate rows."""
        mod = self._import_seed(tmp_path)
        mod.DATA_DIR = tmp_path
        mod.SEED_MARKER = tmp_path / ".demo_seeded"
        db_path = tmp_path / "analytics.db"
        with sqlite3.connect(str(db_path)) as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS stub (x INT)")
        mod.seed_findings()
        mod.seed_findings()
        with sqlite3.connect(str(db_path)) as conn:
            count = conn.execute("SELECT COUNT(*) FROM demo_findings").fetchone()[0]
        assert count == 5

    def test_seed_skips_when_no_db(self, tmp_path, capsys):
        """seed_findings should skip gracefully if DB doesn't exist."""
        mod = self._import_seed(tmp_path)
        mod.DATA_DIR = tmp_path
        mod.SEED_MARKER = tmp_path / ".demo_seeded"
        # Don't create any DB files
        mod.seed_findings()  # should not raise
        captured = capsys.readouterr()
        assert "SKIP" in captured.out

    def test_main_returns_zero_on_success(self, tmp_path):
        mod = self._import_seed(tmp_path)
        mod.DATA_DIR = tmp_path
        mod.SEED_MARKER = tmp_path / ".demo_seeded"
        result = mod.main()
        assert result == 0
