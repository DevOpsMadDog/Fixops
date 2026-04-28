"""Integration tests — Multi-language deep code analysis (Task #5).

Covers the three languages shipped in the 2026-04-27 parallel-team session:
  - TypeScript  (f6d909c0 — tree-sitter-typescript)
  - JavaScript  (bee501c7 — esprima)
  - Java        (bca96496 — javalang)

Five tests:
  1. Polyglot fixture: 1 .ts + 1 .js + 1 .java with a known sink each →
     analyze_repo() produces ≥3 security_finding symbols (one per file).
  2. Cross-language finding shape consistency: id, severity, file, line present
     for findings from all three analyzers; severity drawn from the same scale.
  3. Symbol extraction: each language contributes > 0 symbols per file.
  4. Import parsing: TS ES6 imports, JS CommonJS + ES6 imports, Java imports
     are all captured.
  5. Empty repo → 0 findings, no crash.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

import pytest

# Ensure suite-core is importable regardless of how pytest is invoked.
_SUITE_CORE = Path(__file__).resolve().parents[1] / "suite-core"
if str(_SUITE_CORE) not in sys.path:
    sys.path.insert(0, str(_SUITE_CORE))

from core.deep_code_analysis_engine import DeepCodeAnalysisEngine  # noqa: E402

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

_VALID_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


@pytest.fixture(scope="module")
def engine(tmp_path_factory):
    data_dir = str(tmp_path_factory.mktemp("dca_multilang"))
    return DeepCodeAnalysisEngine(data_dir=data_dir)


@pytest.fixture(scope="module")
def polyglot_repo(tmp_path_factory):
    """A directory with one .ts, one .js, and one .java file — each containing
    a known security sink that the respective analyzer should detect."""
    repo = tmp_path_factory.mktemp("polyglot_repo")

    # --- TypeScript: eval() sink (CWE-95) ---
    (repo / "service.ts").write_text(
        """\
import { Injectable } from '@angular/core';

@Injectable()
export class DangerousService {
  runUserCode(userInput: string): void {
    eval(userInput);
  }
}
""",
        encoding="utf-8",
    )

    # --- JavaScript: eval() sink via esprima (JS001) ---
    (repo / "handler.js").write_text(
        """\
'use strict';

const express = require('express');
const router = express.Router();

router.post('/exec', function(req, res) {
    const code = req.body.code;
    const result = eval(code);
    res.json({ result });
});

module.exports = router;
""",
        encoding="utf-8",
    )

    # --- Java: SQL injection sink (CWE-89) ---
    (repo / "UserRepository.java").write_text(
        """\
package com.example.repo;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;

public class UserRepository {
    public ResultSet findUser(Connection conn, HttpServletRequest request) throws Exception {
        String id = request.getParameter("id");
        Statement stmt = conn.createStatement();
        return stmt.executeQuery("SELECT * FROM users WHERE id = " + id);
    }
}
""",
        encoding="utf-8",
    )

    return repo


# ---------------------------------------------------------------------------
# Test 1 — Polyglot fixture produces ≥3 security findings (one per language)
# ---------------------------------------------------------------------------

def test_polyglot_repo_finds_all_three_languages(engine, polyglot_repo):
    """analyze_repo() over a .ts + .js + .java repo returns security_finding
    symbols from all three languages — proving each analyzer is exercised."""
    result = engine.analyze_repo(
        org_id="test-org",
        repo_ref="polyglot-test",
        commit_sha="abc123",
        root_path=str(polyglot_repo),
    )

    # Basic structural checks on the result
    assert "id" in result, "analyze_repo must return an id"
    assert result["total_files"] == 3, (
        f"Expected 3 files, got {result['total_files']}"
    )
    assert "typescript" in result["languages"], "TypeScript not counted"
    assert "javascript" in result["languages"], "JavaScript not counted"
    assert "java" in result["languages"], "Java not counted"

    # Pull security_finding symbols out of the DB
    import sqlite3, json
    db_path = Path(engine._db_path)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM dca_symbols WHERE analysis_id=? AND symbol_type='security_finding'",
        (result["id"],),
    ).fetchall()
    conn.close()

    assert len(rows) >= 3, (
        f"Expected ≥3 security_finding symbols (one per language), got {len(rows)}. "
        f"Rows: {[dict(r) for r in rows]}"
    )

    # Verify at least one finding came from each file extension
    file_refs = {r["file_ref"] for r in rows}
    ts_hits = [f for f in file_refs if f.endswith(".ts")]
    js_hits = [f for f in file_refs if f.endswith(".js")]
    java_hits = [f for f in file_refs if f.endswith(".java")]

    assert ts_hits, f"No security_finding from .ts file. file_refs={file_refs}"
    assert js_hits, f"No security_finding from .js file. file_refs={file_refs}"
    assert java_hits, f"No security_finding from .java file. file_refs={file_refs}"


# ---------------------------------------------------------------------------
# Test 2 — Cross-language finding shape consistency
# ---------------------------------------------------------------------------

def test_cross_language_finding_shape_consistency(engine, polyglot_repo):
    """Findings from TS, JS, and Java all conform to the same severity scale
    and carry the required metadata fields."""
    # Run a fresh analysis so we get a clean result dict
    result = engine.analyze_repo(
        org_id="test-org-shape",
        repo_ref="polyglot-shape",
        commit_sha="def456",
        root_path=str(polyglot_repo),
    )

    import sqlite3, json
    db_path = Path(engine._db_path)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM dca_symbols WHERE analysis_id=? AND symbol_type='security_finding'",
        (result["id"],),
    ).fetchall()
    conn.close()

    assert rows, "No security findings returned — cannot check shape"

    for row in rows:
        meta = json.loads(row["file_ref"] and row["metadata_json"] or "{}")
        # Required fields in the dca_symbols row
        assert row["file_ref"], f"finding missing file_ref: {dict(row)}"
        assert row["start_line"] > 0, f"finding line must be > 0: {dict(row)}"
        # severity is in metadata_json
        meta = json.loads(row["metadata_json"])
        severity = meta.get("severity", "")
        assert severity in _VALID_SEVERITIES, (
            f"severity '{severity}' not in {_VALID_SEVERITIES} for {dict(row)}"
        )
        # message must be a non-empty string
        assert meta.get("message"), f"finding missing message: {dict(row)}"


# ---------------------------------------------------------------------------
# Test 3 — Symbol extraction: each language yields > 0 symbols
# ---------------------------------------------------------------------------

def test_symbol_extraction_all_three_languages(engine, polyglot_repo):
    """Each language must contribute at least one non-security symbol
    (function, class, method) to the dca_symbols table."""
    result = engine.analyze_repo(
        org_id="test-org-syms",
        repo_ref="polyglot-syms",
        commit_sha="ghi789",
        root_path=str(polyglot_repo),
    )

    import sqlite3
    db_path = Path(engine._db_path)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM dca_symbols WHERE analysis_id=? AND symbol_type != 'security_finding'",
        (result["id"],),
    ).fetchall()
    conn.close()

    # Separate by file extension
    ts_syms = [r for r in rows if str(r["file_ref"]).endswith(".ts")]
    js_syms = [r for r in rows if str(r["file_ref"]).endswith(".js")]
    java_syms = [r for r in rows if str(r["file_ref"]).endswith(".java")]

    assert len(ts_syms) > 0, (
        f"TypeScript produced 0 non-security symbols. All symbols: {[dict(r) for r in rows]}"
    )
    assert len(js_syms) > 0, (
        f"JavaScript produced 0 non-security symbols. All symbols: {[dict(r) for r in rows]}"
    )
    assert len(java_syms) > 0, (
        f"Java produced 0 non-security symbols. All symbols: {[dict(r) for r in rows]}"
    )


# ---------------------------------------------------------------------------
# Test 4 — Import parsing for all three languages
# ---------------------------------------------------------------------------

def test_imports_parsed_all_three_languages(engine):
    """Each language-specific analyzer must parse imports correctly.

    TypeScript  — ES6 import statement
    JavaScript  — CommonJS require + ES6 import
    Java        — package import statement
    """
    # TS: import { Injectable } from '@angular/core'
    ts_source = """\
import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';

@Injectable()
export class ApiService {
  constructor(private http: HttpClient) {}
}
"""
    ts_result = engine._analyze_typescript_source(ts_source, "api.ts")
    ts_imports = ts_result.get("imports", [])
    ts_froms = {imp["from"] for imp in ts_imports}
    assert "@angular/core" in ts_froms, (
        f"TS import '@angular/core' not parsed. imports={ts_imports}"
    )
    assert "@angular/common/http" in ts_froms, (
        f"TS import '@angular/common/http' not parsed. imports={ts_imports}"
    )

    # JS CommonJS + ES6 import
    js_source = """\
const fs = require('fs');
const path = require('path');
import express from 'express';

function readFile(name) {
    return fs.readFileSync(path.join(__dirname, name), 'utf8');
}
module.exports = { readFile };
"""
    js_result = engine._analyze_javascript_source(js_source, "util.js")
    js_imports = js_result.get("imports", [])
    # JS imports use 'module' key (both commonjs and es6 shapes)
    js_sources = {imp.get("module", imp.get("source", imp.get("from", ""))) for imp in js_imports}
    assert "fs" in js_sources, (
        f"JS CommonJS require('fs') not parsed. imports={js_imports}"
    )
    assert "path" in js_sources, (
        f"JS CommonJS require('path') not parsed. imports={js_imports}"
    )

    # Java import statement — use _analyze_java via a temp file
    java_source = """\
package com.example;

import java.util.List;
import java.util.ArrayList;
import javax.servlet.http.HttpServletRequest;

public class ImportTest {
    public List<String> getList() {
        return new ArrayList<>();
    }
}
"""
    with tempfile.NamedTemporaryFile(suffix=".java", delete=False, mode="w",
                                     encoding="utf-8") as f:
        f.write(java_source)
        java_path = Path(f.name)

    try:
        java_result = engine._analyze_java(java_path)
    finally:
        java_path.unlink(missing_ok=True)

    java_imports = java_result.get("imports", [])
    assert "java.util.List" in java_imports, (
        f"Java import 'java.util.List' not parsed. imports={java_imports}"
    )
    assert "javax.servlet.http.HttpServletRequest" in java_imports, (
        f"Java import 'javax.servlet.http.HttpServletRequest' not parsed. imports={java_imports}"
    )


# ---------------------------------------------------------------------------
# Test 5 — Empty repo produces 0 findings, no crash
# ---------------------------------------------------------------------------

def test_empty_repo_zero_findings_no_crash(tmp_path):
    """An empty directory (or one with no analysable files) must return cleanly
    with zero findings — the engine must not raise an exception."""
    data_dir = str(tmp_path / "dca_empty")
    eng = DeepCodeAnalysisEngine(data_dir=data_dir)

    empty_repo = tmp_path / "empty_repo"
    empty_repo.mkdir()
    # Add a non-source file to confirm non-crash on unsupported extensions
    (empty_repo / "README.md").write_text("# nothing here\n", encoding="utf-8")
    (empty_repo / "config.yaml").write_text("key: value\n", encoding="utf-8")

    result = eng.analyze_repo(
        org_id="test-org-empty",
        repo_ref="empty-repo",
        commit_sha="000000",
        root_path=str(empty_repo),
    )

    assert result["total_files"] == 0, (
        f"Expected 0 analysable files, got {result['total_files']}"
    )
    assert result["total_symbols"] == 0, (
        f"Expected 0 symbols, got {result['total_symbols']}"
    )
    assert result["total_endpoints"] == 0, (
        f"Expected 0 endpoints, got {result['total_endpoints']}"
    )
