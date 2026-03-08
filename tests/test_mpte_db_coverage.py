"""Tests for core.mpte_db — MPTE database manager."""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "suite-core"))

import sqlite3

import pytest
from core.mpte_db import MPTEDB


class TestMPTEDB:
    @pytest.fixture
    def db(self, tmp_path):
        db_path = str(tmp_path / "mpte_test.db")
        return MPTEDB(db_path=db_path)

    def test_init_creates_db(self, db, tmp_path):
        assert os.path.exists(db.db_path)

    def test_init_creates_tables(self, db):
        conn = sqlite3.connect(db.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        )
        tables = [row[0] for row in cursor.fetchall()]
        conn.close()
        assert "pen_test_requests" in tables
        assert "pen_test_results" in tables
        assert "pen_test_configs" in tables

    def test_connection_has_row_factory(self, db):
        conn = db._get_connection()
        assert conn.row_factory == sqlite3.Row
        conn.close()

    def test_idempotent_init(self, tmp_path):
        db_path = str(tmp_path / "mpte_init.db")
        MPTEDB(db_path=db_path)
        db2 = MPTEDB(db_path=db_path)
        # Should not raise on second init
        conn = db2._get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]
        conn.close()
        assert len(tables) >= 3

    def test_creates_parent_dirs(self, tmp_path):
        db_path = str(tmp_path / "deep" / "nested" / "mpte.db")
        MPTEDB(db_path=db_path)
        assert os.path.exists(db_path)
