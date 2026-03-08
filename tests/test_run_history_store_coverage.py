"""Tests for RunHistoryStore — SQLite run tracking and finding persistence."""

from core.services.history import RunHistoryStore


class TestRunHistoryStore:
    def test_init(self, tmp_path):
        db_path = tmp_path / "history.db"
        RunHistoryStore(db_path)
        assert db_path.exists()

    def test_init_creates_parent_dirs(self, tmp_path):
        db_path = tmp_path / "deep" / "nested" / "history.db"
        RunHistoryStore(db_path)
        assert db_path.exists()

    def test_record_run(self, tmp_path):
        store = RunHistoryStore(tmp_path / "history.db")
        store.record_run(
            run_id="run-001",
            org_id="org-1",
            app_id="APP-001",
            findings=[
                {"severity": "CRITICAL", "correlation_key": "ck1"},
                {"severity": "HIGH", "correlation_key": "ck2"},
                {"severity": "MEDIUM", "correlation_key": "ck3"},
            ],
        )
        # Should not raise

    def test_get_history(self, tmp_path):
        store = RunHistoryStore(tmp_path / "history.db")
        store.record_run(
            run_id="run-001",
            org_id="org-1",
            app_id="APP-001",
            findings=[],
        )
        history = store.get_runs(org_id="org-1", app_id="APP-001")
        assert isinstance(history, list)

    def test_empty_history(self, tmp_path):
        store = RunHistoryStore(tmp_path / "history.db")
        history = store.get_runs(org_id="nonexistent", app_id="none")
        assert isinstance(history, list)
        assert len(history) == 0

    def test_multiple_runs(self, tmp_path):
        store = RunHistoryStore(tmp_path / "history.db")
        for i in range(5):
            store.record_run(
                run_id=f"run-{i:03d}",
                org_id="org-1",
                app_id="APP-001",
                findings=[{"severity": "LOW"}],
            )
        history = store.get_runs(org_id="org-1", app_id="APP-001")
        assert isinstance(history, list)
