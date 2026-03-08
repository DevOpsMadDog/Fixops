"""Tests for enterprise ID allocator — APP-ID and run-ID allocation."""

from core.services.enterprise.id_allocator import (
    ensure_ids,
    allocate_run_id,
    allocate_app_id,
    _stable_hash,
    _next_app_id,
)


class TestStableHash:
    def test_deterministic(self):
        h1 = _stable_hash("my-app")
        h2 = _stable_hash("my-app")
        assert h1 == h2

    def test_different_names_different_hashes(self):
        h1 = _stable_hash("app-a")
        h2 = _stable_hash("app-b")
        assert h1 != h2

    def test_returns_int(self):
        result = _stable_hash("test")
        assert isinstance(result, int)

    def test_empty_string(self):
        result = _stable_hash("")
        assert isinstance(result, int)


class TestNextAppId:
    def test_format(self):
        app_id = _next_app_id()
        assert app_id.startswith("APP-")

    def test_increments(self):
        id1 = _next_app_id()
        id2 = _next_app_id()
        # Numeric parts should differ
        n1 = int(id1.split("-")[1])
        n2 = int(id2.split("-")[1])
        assert n2 > n1


class TestEnsureIds:
    def test_empty_payload_gets_ids(self):
        result = ensure_ids({})
        assert "app_id" in result
        assert "run_id" in result
        assert result["app_id"].startswith("APP-")
        assert len(result["run_id"]) == 12

    def test_existing_app_id_preserved(self):
        result = ensure_ids({"app_id": "APP-12345"})
        assert result["app_id"] == "APP-12345"

    def test_existing_run_id_preserved(self):
        result = ensure_ids({"run_id": "abc123"})
        assert result["run_id"] == "abc123"

    def test_app_name_deterministic(self):
        r1 = ensure_ids({"app_name": "billing-service"})
        r2 = ensure_ids({"app_name": "billing-service"})
        assert r1["app_id"] == r2["app_id"]

    def test_different_app_names_different_ids(self):
        r1 = ensure_ids({"app_name": "service-a"})
        r2 = ensure_ids({"app_name": "service-b"})
        assert r1["app_id"] != r2["app_id"]

    def test_does_not_mutate_input(self):
        payload = {"data": "value"}
        ensure_ids(payload)
        assert "app_id" not in payload  # Original not mutated

    def test_preserves_other_fields(self):
        result = ensure_ids({"custom": "field", "other": 42})
        assert result["custom"] == "field"
        assert result["other"] == 42


class TestAllocateRunId:
    def test_format(self):
        run_id = allocate_run_id()
        assert len(run_id) == 12
        assert run_id.isalnum()

    def test_unique(self):
        ids = {allocate_run_id() for _ in range(100)}
        assert len(ids) == 100  # All unique


class TestAllocateAppId:
    def test_with_name(self):
        app_id = allocate_app_id("my-app")
        assert app_id.startswith("APP-")

    def test_without_name(self):
        app_id = allocate_app_id()
        assert app_id.startswith("APP-")

    def test_deterministic_with_name(self):
        id1 = allocate_app_id("same-name")
        id2 = allocate_app_id("same-name")
        assert id1 == id2

    def test_none_name(self):
        app_id = allocate_app_id(None)
        assert app_id.startswith("APP-")
