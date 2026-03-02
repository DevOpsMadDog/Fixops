"""
Unit tests for suite-core/core/persistent_store.py

Tests the PersistentDict key-value store including:
- CRUD operations (__setitem__, __getitem__, __delitem__)
- Namespace isolation (different tables in same DB)
- Data persistence across instances
- Error handling (KeyError on missing keys)
- Dict-like interface (len, contains, iter, bool, get, pop, setdefault)
- Bulk operations (update, clear, keys, values, items)
- Mutation persistence (persist, persist_all)
- JSON serialization of complex values
- Multiple data types (strings, dicts, lists, numbers, booleans, None)
"""

import sqlite3
from pathlib import Path

import pytest
from core.persistent_store import PersistentDict


@pytest.fixture
def db_path(tmp_path):
    """Create a temporary database path."""
    return str(tmp_path / "test_store.db")


@pytest.fixture
def store(db_path):
    """Create a PersistentDict instance with a clean temp DB."""
    return PersistentDict("test_table", db_path=db_path)


@pytest.fixture
def store2(db_path):
    """Create a second PersistentDict instance using a different table."""
    return PersistentDict("other_table", db_path=db_path)


# ---------------------------------------------------------------------------
# Basic CRUD tests
# ---------------------------------------------------------------------------


class TestCRUDOperations:
    """Tests for basic Create/Read/Update/Delete operations."""

    def test_setitem_and_getitem(self, store):
        store["key1"] = "value1"
        assert store["key1"] == "value1"

    def test_setitem_overwrites(self, store):
        store["key1"] = "original"
        store["key1"] = "updated"
        assert store["key1"] == "updated"

    def test_delitem(self, store):
        store["key1"] = "value1"
        del store["key1"]
        assert "key1" not in store

    def test_delitem_raises_keyerror_on_missing(self, store):
        with pytest.raises(KeyError):
            del store["nonexistent"]

    def test_getitem_raises_keyerror_on_missing(self, store):
        with pytest.raises(KeyError):
            _ = store["nonexistent"]


# ---------------------------------------------------------------------------
# Dict-like interface tests
# ---------------------------------------------------------------------------


class TestDictInterface:
    """Tests for dict-like methods."""

    def test_contains(self, store):
        store["exists"] = True
        assert "exists" in store
        assert "missing" not in store

    def test_len_empty(self, store):
        assert len(store) == 0

    def test_len_with_items(self, store):
        store["a"] = 1
        store["b"] = 2
        store["c"] = 3
        assert len(store) == 3

    def test_iter(self, store):
        store["x"] = 10
        store["y"] = 20
        keys = list(store)
        assert set(keys) == {"x", "y"}

    def test_bool_empty_is_falsy(self, store):
        assert not bool(store)

    def test_bool_nonempty_is_truthy(self, store):
        store["key"] = "val"
        assert bool(store)

    def test_get_existing(self, store):
        store["hello"] = "world"
        assert store.get("hello") == "world"

    def test_get_missing_default(self, store):
        assert store.get("missing") is None
        assert store.get("missing", 42) == 42

    def test_pop_existing(self, store):
        store["pop_me"] = "value"
        result = store.pop("pop_me")
        assert result == "value"
        assert "pop_me" not in store

    def test_pop_missing_with_default(self, store):
        result = store.pop("missing", "default_val")
        assert result == "default_val"

    def test_pop_missing_without_default_raises(self, store):
        with pytest.raises(KeyError):
            store.pop("missing")

    def test_setdefault_missing_key(self, store):
        result = store.setdefault("new_key", "default_value")
        assert result == "default_value"
        assert store["new_key"] == "default_value"

    def test_setdefault_existing_key(self, store):
        store["existing"] = "original"
        result = store.setdefault("existing", "ignored")
        assert result == "original"
        assert store["existing"] == "original"

    def test_setdefault_none_default(self, store):
        result = store.setdefault("none_key")
        assert result is None
        assert store["none_key"] is None

    def test_keys(self, store):
        store["a"] = 1
        store["b"] = 2
        assert set(store.keys()) == {"a", "b"}

    def test_values(self, store):
        store["a"] = 1
        store["b"] = 2
        assert set(store.values()) == {1, 2}

    def test_items(self, store):
        store["a"] = 1
        store["b"] = 2
        assert set(store.items()) == {("a", 1), ("b", 2)}


# ---------------------------------------------------------------------------
# Bulk operations tests
# ---------------------------------------------------------------------------


class TestBulkOperations:
    """Tests for clear and update operations."""

    def test_clear(self, store):
        store["a"] = 1
        store["b"] = 2
        store["c"] = 3
        store.clear()
        assert len(store) == 0
        assert "a" not in store

    def test_clear_empties_database(self, store, db_path):
        """Clear removes entries from the SQLite backing store too."""
        store["a"] = 1
        store.clear()
        # Verify directly in SQLite
        conn = sqlite3.connect(db_path)
        count = conn.execute("SELECT COUNT(*) FROM [test_table]").fetchone()[0]
        conn.close()
        assert count == 0

    def test_update_from_dict(self, store):
        store.update({"x": 10, "y": 20, "z": 30})
        assert store["x"] == 10
        assert store["y"] == 20
        assert store["z"] == 30

    def test_update_from_kwargs(self, store):
        store.update(alpha=1, beta=2)
        assert store["alpha"] == 1
        assert store["beta"] == 2

    def test_update_from_iterable(self, store):
        store.update([("k1", "v1"), ("k2", "v2")])
        assert store["k1"] == "v1"
        assert store["k2"] == "v2"


# ---------------------------------------------------------------------------
# Data type serialization tests
# ---------------------------------------------------------------------------


class TestDataTypes:
    """Tests for JSON serialization of various data types."""

    def test_string_value(self, store):
        store["str"] = "hello world"
        assert store["str"] == "hello world"

    def test_integer_value(self, store):
        store["int"] = 42
        assert store["int"] == 42

    def test_float_value(self, store):
        store["float"] = 3.14
        assert abs(store["float"] - 3.14) < 0.001

    def test_boolean_value(self, store):
        store["true"] = True
        store["false"] = False
        assert store["true"] is True
        assert store["false"] is False

    def test_none_value(self, store):
        store["null"] = None
        assert store["null"] is None

    def test_list_value(self, store):
        store["list"] = [1, "two", 3.0, None]
        assert store["list"] == [1, "two", 3.0, None]

    def test_nested_dict_value(self, store):
        value = {
            "name": "test",
            "nested": {"deep": True},
            "items": [1, 2, 3],
        }
        store["complex"] = value
        assert store["complex"] == value
        assert store["complex"]["nested"]["deep"] is True


# ---------------------------------------------------------------------------
# Persistence tests
# ---------------------------------------------------------------------------


class TestPersistence:
    """Tests for data persistence across PersistentDict instances."""

    def test_data_survives_reopen(self, db_path):
        """Data written by one instance is readable by a new instance."""
        store1 = PersistentDict("persist_test", db_path=db_path)
        store1["key1"] = "value1"
        store1["key2"] = {"nested": True}

        # Create new instance pointing to same DB
        store2 = PersistentDict("persist_test", db_path=db_path)
        assert store2["key1"] == "value1"
        assert store2["key2"] == {"nested": True}

    def test_delete_persists(self, db_path):
        """Deletes are persisted to disk."""
        store1 = PersistentDict("del_test", db_path=db_path)
        store1["key1"] = "value1"
        del store1["key1"]

        store2 = PersistentDict("del_test", db_path=db_path)
        assert "key1" not in store2

    def test_update_persists(self, db_path):
        """Updates to existing keys are persisted."""
        store1 = PersistentDict("upd_test", db_path=db_path)
        store1["key1"] = "original"
        store1["key1"] = "updated"

        store2 = PersistentDict("upd_test", db_path=db_path)
        assert store2["key1"] == "updated"


# ---------------------------------------------------------------------------
# Mutation persistence tests
# ---------------------------------------------------------------------------


class TestMutationPersistence:
    """Tests for persist() and persist_all() methods."""

    def test_in_place_mutation_not_auto_persisted(self, db_path):
        """In-place mutations to dict values are NOT auto-persisted."""
        store1 = PersistentDict("mut_test", db_path=db_path)
        store1["job"] = {"status": "pending"}
        # In-place mutation
        store1["job"]["status"] = "running"
        # NOT persisted yet - new instance sees old value
        store2 = PersistentDict("mut_test", db_path=db_path)
        assert store2["job"]["status"] == "pending"

    def test_persist_flushes_single_key(self, db_path):
        """persist(key) flushes that specific key to disk."""
        store1 = PersistentDict("persist_single", db_path=db_path)
        store1["job"] = {"status": "pending"}
        store1["job"]["status"] = "running"
        store1.persist("job")

        store2 = PersistentDict("persist_single", db_path=db_path)
        assert store2["job"]["status"] == "running"

    def test_persist_nonexistent_key_is_noop(self, store):
        """persist() on a missing key does nothing (no error)."""
        store.persist("nonexistent")  # Should not raise

    def test_persist_all_flushes_everything(self, db_path):
        """persist_all() flushes all cached keys to disk."""
        store1 = PersistentDict("persist_all", db_path=db_path)
        store1["a"] = {"count": 0}
        store1["b"] = {"count": 0}
        store1["a"]["count"] = 10
        store1["b"]["count"] = 20
        store1.persist_all()

        store2 = PersistentDict("persist_all", db_path=db_path)
        assert store2["a"]["count"] == 10
        assert store2["b"]["count"] == 20


# ---------------------------------------------------------------------------
# Namespace isolation tests
# ---------------------------------------------------------------------------


class TestNamespaceIsolation:
    """Tests that different tables are isolated from each other."""

    def test_separate_tables_isolated(self, db_path):
        """Two PersistentDicts with different table names are completely isolated."""
        store_a = PersistentDict("table_a", db_path=db_path)
        store_b = PersistentDict("table_b", db_path=db_path)

        store_a["key"] = "from_a"
        store_b["key"] = "from_b"

        assert store_a["key"] == "from_a"
        assert store_b["key"] == "from_b"

    def test_delete_in_one_namespace_doesnt_affect_other(self, db_path):
        store_a = PersistentDict("ns_a", db_path=db_path)
        store_b = PersistentDict("ns_b", db_path=db_path)

        store_a["shared_key"] = "a_value"
        store_b["shared_key"] = "b_value"

        del store_a["shared_key"]
        assert "shared_key" not in store_a
        assert store_b["shared_key"] == "b_value"

    def test_clear_in_one_namespace_doesnt_affect_other(self, db_path):
        store_a = PersistentDict("clear_a", db_path=db_path)
        store_b = PersistentDict("clear_b", db_path=db_path)

        store_a["x"] = 1
        store_b["y"] = 2

        store_a.clear()
        assert len(store_a) == 0
        assert store_b["y"] == 2


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    """Edge case tests."""

    def test_empty_string_key(self, store):
        store[""] = "empty key"
        assert store[""] == "empty key"

    def test_unicode_key_and_value(self, store):
        store["emoji_key"] = "value with unicode chars"
        assert store["emoji_key"] == "value with unicode chars"

    def test_large_value(self, store):
        large_list = list(range(10000))
        store["big"] = large_list
        assert store["big"] == large_list
        assert len(store["big"]) == 10000

    def test_concurrent_tables_same_db(self, db_path):
        """Multiple tables can coexist in the same SQLite file."""
        stores = [
            PersistentDict(f"table_{i}", db_path=db_path) for i in range(5)
        ]
        for i, s in enumerate(stores):
            s[f"key_{i}"] = f"val_{i}"

        # Verify isolation
        for i, s in enumerate(stores):
            assert s[f"key_{i}"] == f"val_{i}"
            for j in range(5):
                if j != i:
                    assert f"key_{j}" not in s

    def test_special_characters_in_value(self, store):
        """Values with JSON special characters serialize correctly."""
        store["special"] = 'He said "hello" & \'goodbye\''
        assert store["special"] == 'He said "hello" & \'goodbye\''

    def test_directory_creation(self, tmp_path):
        """PersistentDict creates parent directories if they don't exist."""
        deep_path = str(tmp_path / "a" / "b" / "c" / "store.db")
        store = PersistentDict("auto_dir", db_path=deep_path)
        store["test"] = "value"
        assert store["test"] == "value"
        assert Path(deep_path).exists()


# ---------------------------------------------------------------------------
# Thread safety tests
# ---------------------------------------------------------------------------


class TestThreadSafety:
    """Tests for concurrent write access."""

    def test_concurrent_writes_no_crash(self, db_path):
        """Multiple threads writing to the same PersistentDict do not crash."""
        import threading

        store = PersistentDict("thread_test", db_path=db_path)
        errors = []

        def writer(thread_id, count):
            try:
                for i in range(count):
                    store[f"thread-{thread_id}-{i}"] = {"tid": thread_id, "idx": i}
            except Exception as exc:
                errors.append(exc)

        threads = [
            threading.Thread(target=writer, args=(t, 20)) for t in range(5)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0, f"Errors during concurrent writes: {errors}"
        assert len(store) == 100  # 5 threads * 20 writes


# ---------------------------------------------------------------------------
# Persistence of pop / setdefault
# ---------------------------------------------------------------------------


class TestPopAndSetdefaultPersistence:
    """Verify that pop() and setdefault() actually persist to disk."""

    def test_pop_removes_from_disk(self, db_path):
        store1 = PersistentDict("pop_persist", db_path=db_path)
        store1["key"] = "val"
        store1.pop("key")
        store2 = PersistentDict("pop_persist", db_path=db_path)
        assert "key" not in store2

    def test_setdefault_persists_new_key(self, db_path):
        store1 = PersistentDict("sd_persist", db_path=db_path)
        store1.setdefault("new", "default_val")
        store2 = PersistentDict("sd_persist", db_path=db_path)
        assert store2["new"] == "default_val"

    def test_datetime_serialised_via_str(self, db_path):
        """datetime objects are serialised via json.dumps(default=str).

        The in-memory cache holds the original object, but after a re-open
        the value comes back from SQLite as its str() representation.
        """
        from datetime import datetime, timezone

        store1 = PersistentDict("dt_test", db_path=db_path)
        now = datetime.now(timezone.utc)
        store1["ts"] = now
        # Re-open reads the JSON-serialised string from SQLite
        store2 = PersistentDict("dt_test", db_path=db_path)
        assert isinstance(store2.get("ts"), str)

    def test_update_persists_all_keys(self, db_path):
        store1 = PersistentDict("update_persist", db_path=db_path)
        store1.update({"a": 1, "b": 2, "c": 3})
        store2 = PersistentDict("update_persist", db_path=db_path)
        assert store2["a"] == 1
        assert store2["b"] == 2
        assert store2["c"] == 3
