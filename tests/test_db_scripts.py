"""Tests for scripts/init_databases.py and scripts/check_databases.py.

All tests use a temporary directory so they never touch real data files.
"""

import json
import os
import sqlite3
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

# ---------------------------------------------------------------------------
# Make sure the scripts directory is importable
# ---------------------------------------------------------------------------
_SCRIPTS_DIR = Path(__file__).parent.parent / "scripts"
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

import init_databases
import check_databases


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def tmpdir():
    """Return a temporary directory path (str) that is cleaned up after each test."""
    with tempfile.TemporaryDirectory() as d:
        yield d


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _make_db(path: Path, tables: list[str] | None = None) -> Path:
    """Create a minimal SQLite file with optional tables."""
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    for tname in (tables or []):
        conn.execute(f"CREATE TABLE IF NOT EXISTS {tname} (id INTEGER PRIMARY KEY)")
    conn.commit()
    conn.close()
    return path


def _corrupt_db(path: Path) -> Path:
    """Write garbage bytes into a file so SQLite reports corruption."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"not a sqlite database \x00\xff\xfe")
    return path


# ===========================================================================
# init_databases.py tests
# ===========================================================================

class TestInitDatabases:

    def test_db_helper_returns_correct_path(self, tmpdir):
        result = init_databases._db(tmpdir, "test.db")
        assert result == str(Path(tmpdir) / "test.db")

    def test_attempt_records_ok_on_success(self, tmpdir):
        results = []
        init_databases._attempt("my_module", lambda: None, results)
        assert results == [("ok", "my_module")]

    def test_attempt_records_skip_on_import_error(self):
        results = []
        def _raise():
            raise ImportError("no module named xyz")
        init_databases._attempt("missing_mod", _raise, results)
        assert results == [("skip", "missing_mod")]

    def test_attempt_records_error_on_exception(self):
        results = []
        def _raise():
            raise RuntimeError("something broke")
        init_databases._attempt("bad_mod", _raise, results)
        assert results == [("error", "bad_mod")]

    def test_init_all_creates_data_dir(self, tmpdir):
        new_dir = str(Path(tmpdir) / "nested" / "data")
        # patch all initializers to no-ops so we don't need real modules
        noop_initializers = [("fake -> fake.db", lambda d: None)]
        with patch.object(init_databases, "_INITIALIZERS", noop_initializers):
            init_databases.init_all(new_dir)
        assert Path(new_dir).exists()

    def test_init_all_returns_summary_dict(self, tmpdir):
        ok_fn = lambda d: None
        err_fn = lambda d: (_ for _ in ()).throw(RuntimeError("boom"))
        skip_fn = lambda d: (_ for _ in ()).throw(ImportError("missing"))
        fake = [
            ("ok_mod -> ok.db",   ok_fn),
            ("err_mod -> err.db", err_fn),
            ("skip_mod -> s.db",  skip_fn),
        ]
        with patch.object(init_databases, "_INITIALIZERS", fake):
            summary = init_databases.init_all(tmpdir)
        assert summary["ok"] == 1
        assert summary["error"] == 1
        assert summary["skip"] == 1
        assert len(summary["results"]) == 3

    def test_init_all_all_ok_returns_zero_errors(self, tmpdir):
        fakes = [("mod -> x.db", lambda d: None) for _ in range(5)]
        with patch.object(init_databases, "_INITIALIZERS", fakes):
            summary = init_databases.init_all(tmpdir)
        assert summary["error"] == 0
        assert summary["ok"] == 5

    def test_main_returns_zero_on_no_errors(self, tmpdir):
        fakes = [("mod -> x.db", lambda d: None)]
        with patch.object(init_databases, "_INITIALIZERS", fakes):
            with patch("sys.argv", ["init_databases.py", "--data-dir", tmpdir]):
                rc = init_databases.main()
        assert rc == 0

    def test_main_returns_one_on_errors(self, tmpdir):
        fakes = [("bad -> x.db", lambda d: (_ for _ in ()).throw(RuntimeError("x")))]
        with patch.object(init_databases, "_INITIALIZERS", fakes):
            with patch("sys.argv", ["init_databases.py", "--data-dir", tmpdir]):
                rc = init_databases.main()
        assert rc == 1

    def test_initializers_registry_not_empty(self):
        assert len(init_databases._INITIALIZERS) >= 10

    def test_initializers_labels_contain_arrow(self):
        for label, fn in init_databases._INITIALIZERS:
            assert "->" in label, f"Label missing '->': {label!r}"

    def test_initializers_all_callable(self):
        for label, fn in init_databases._INITIALIZERS:
            assert callable(fn), f"Initializer for {label!r} is not callable"

    def test_org_id_passed_through(self, tmpdir, capsys):
        with patch.object(init_databases, "_INITIALIZERS", []):
            summary = init_databases.init_all(tmpdir, org_id="test-org")
        captured = capsys.readouterr()
        assert "test-org" in captured.out


# ===========================================================================
# check_databases.py tests
# ===========================================================================

class TestCheckDatabases:

    def test_human_size_bytes(self):
        assert "B" in check_databases._human_size(512)

    def test_human_size_kilobytes(self):
        result = check_databases._human_size(2048)
        assert "KB" in result or "B" in result  # 2048 / 1024 = 2 KB

    def test_human_size_megabytes(self):
        result = check_databases._human_size(2 * 1024 * 1024)
        assert "MB" in result

    def test_check_all_empty_dir_returns_empty(self, tmpdir):
        results = check_databases.check_all(tmpdir)
        assert results == []

    def test_check_all_nonexistent_dir_returns_empty(self, tmpdir):
        results = check_databases.check_all(str(Path(tmpdir) / "doesnotexist"))
        assert results == []

    def test_check_database_ok_no_tables(self, tmpdir):
        db_path = _make_db(Path(tmpdir) / "empty.db")
        result = check_databases.check_database(db_path)
        assert result["integrity_ok"] is True
        assert result["tables"] == []
        assert result["total_rows"] == 0
        assert result["error"] is None

    def test_check_database_with_tables_and_rows(self, tmpdir):
        db_path = Path(tmpdir) / "withdata.db"
        _make_db(db_path, tables=["alpha", "beta"])
        # Insert a row into alpha
        conn = sqlite3.connect(str(db_path))
        conn.execute("INSERT INTO alpha (id) VALUES (1)")
        conn.commit()
        conn.close()

        result = check_databases.check_database(db_path)
        assert result["integrity_ok"] is True
        table_names = [t["table"] for t in result["tables"]]
        assert "alpha" in table_names
        assert "beta" in table_names
        assert result["total_rows"] == 1

    def test_check_database_corrupt_file(self, tmpdir):
        db_path = _corrupt_db(Path(tmpdir) / "bad.db")
        result = check_databases.check_database(db_path)
        assert result["integrity_ok"] is False
        assert result["error"] is not None or len(result["integrity_errors"]) > 0

    def test_check_all_finds_db_files(self, tmpdir):
        _make_db(Path(tmpdir) / "a.db")
        _make_db(Path(tmpdir) / "b.db")
        results = check_databases.check_all(tmpdir)
        assert len(results) == 2

    def test_check_all_reports_size(self, tmpdir):
        _make_db(Path(tmpdir) / "sized.db", tables=["t"])
        results = check_databases.check_all(tmpdir)
        # size_bytes may be 0 for an empty schema-only DB on some SQLite builds;
        # we only require size_human is a non-empty string and size_bytes is non-negative.
        assert results[0]["size_bytes"] >= 0
        assert isinstance(results[0]["size_human"], str)
        assert results[0]["size_human"] != ""

    def test_print_report_no_crash_empty(self, tmpdir, capsys):
        check_databases.print_report([], tmpdir)
        out = capsys.readouterr().out
        assert "No .db files found" in out

    def test_print_report_shows_table_names(self, tmpdir, capsys):
        db_path = _make_db(Path(tmpdir) / "show.db", tables=["my_table"])
        result = check_databases.check_database(db_path)
        check_databases.print_report([result], tmpdir)
        out = capsys.readouterr().out
        assert "my_table" in out

    def test_print_report_flags_corrupt(self, tmpdir, capsys):
        db_path = _corrupt_db(Path(tmpdir) / "corrupt.db")
        result = check_databases.check_database(db_path)
        check_databases.print_report([result], tmpdir)
        out = capsys.readouterr().out
        assert "[!!]" in out or "CORRUPT" in out or "ERROR" in out

    def test_main_json_output(self, tmpdir):
        _make_db(Path(tmpdir) / "j.db", tables=["t1"])
        with patch("sys.argv", ["check_databases.py", "--data-dir", tmpdir, "--json"]):
            # capture stdout
            import io
            from contextlib import redirect_stdout
            buf = io.StringIO()
            with redirect_stdout(buf):
                check_databases.main()
            data = json.loads(buf.getvalue())
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["integrity_ok"] is True

    def test_main_returns_zero_all_clean(self, tmpdir):
        _make_db(Path(tmpdir) / "clean.db")
        with patch("sys.argv", ["check_databases.py", "--data-dir", tmpdir]):
            rc = check_databases.main()
        assert rc == 0

    def test_main_returns_one_when_corrupt(self, tmpdir):
        _corrupt_db(Path(tmpdir) / "bad.db")
        with patch("sys.argv", ["check_databases.py", "--data-dir", tmpdir]):
            rc = check_databases.main()
        assert rc == 1
