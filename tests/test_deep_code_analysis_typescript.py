"""Tests for the TypeScript AST analyzer in DeepCodeAnalysisEngine.

Five tests:
  1. Clean .ts file → 0 security findings
  2. eval() in .ts → 1 finding with severity HIGH
  3. Express req.body → eval() chain → taint flow finding
  4. Imports + exports parsed correctly
  5. Multiple files in one analyze_repo call (batch mode)
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from core.deep_code_analysis_engine import DeepCodeAnalysisEngine


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _engine(tmp_path: Path) -> DeepCodeAnalysisEngine:
    return DeepCodeAnalysisEngine(data_dir=str(tmp_path / "dca_data"))


def _analyze(source: str, filename: str = "test.ts", tmp_path: Path | None = None):
    """Run _analyze_typescript_source and return the result dict."""
    import tempfile as _tmp
    _dir = tmp_path or Path(_tmp.mkdtemp())
    eng = _engine(_dir)
    is_tsx = filename.endswith(".tsx")
    return eng._analyze_typescript_source(source, filename, is_tsx=is_tsx)


# ---------------------------------------------------------------------------
# Test 1 — clean file, zero findings
# ---------------------------------------------------------------------------

def test_clean_ts_file_zero_findings(tmp_path):
    """A TypeScript file with no dangerous sinks produces zero security findings."""
    source = """
import { Injectable } from '@angular/core';

interface User {
  id: number;
  name: string;
  email: string;
}

@Injectable()
export class UserService {
  private users: User[] = [];

  getUser(id: number): User | undefined {
    return this.users.find(u => u.id === id);
  }

  addUser(user: User): void {
    this.users.push(user);
  }
}
"""
    result = _analyze(source, "user.service.ts", tmp_path)
    findings = result["findings"]
    assert findings == [], (
        f"Expected 0 findings for clean file, got {len(findings)}: {findings}"
    )


# ---------------------------------------------------------------------------
# Test 2 — eval() → severity HIGH
# ---------------------------------------------------------------------------

def test_eval_call_produces_high_severity_finding(tmp_path):
    """eval() in a TypeScript file must produce exactly one HIGH-severity finding."""
    source = """
function runDynamic(code: string): void {
    eval(code);
}
"""
    result = _analyze(source, "dynamic.ts", tmp_path)
    findings = result["findings"]

    # Filter to eval-rule findings only (taint-flow variant also acceptable)
    eval_findings = [
        f for f in findings if "eval" in f["rule_id"]
    ]
    assert len(eval_findings) >= 1, (
        f"Expected at least 1 eval finding, got {findings}"
    )
    # All eval findings must be HIGH or CRITICAL
    for f in eval_findings:
        assert f["severity"] in ("HIGH", "CRITICAL"), (
            f"Expected HIGH severity for eval finding, got {f['severity']}"
        )
    # Must include CWE-95
    cwe_values = {f.get("cwe", "") for f in eval_findings}
    assert any("CWE-95" in c for c in cwe_values), (
        f"Expected CWE-95 in findings, got {cwe_values}"
    )


# ---------------------------------------------------------------------------
# Test 3 — req.body → eval() taint flow
# ---------------------------------------------------------------------------

def test_express_req_body_to_eval_taint_flow(tmp_path):
    """req.body flowing into eval() must produce a taint_flow finding."""
    source = """
import express from 'express';
const app = express();

app.post('/run', (req, res) => {
    const userCode = req.body.code;
    eval(req.body.code);
    res.send('done');
});
"""
    result = _analyze(source, "server.ts", tmp_path)
    findings = result["findings"]

    taint_findings = [f for f in findings if f.get("type") == "taint_flow"]
    assert len(taint_findings) >= 1, (
        f"Expected taint_flow finding for req.body → eval, got all findings: {findings}"
    )
    tf = taint_findings[0]
    assert "req.body" in tf["message"], (
        f"Taint source req.body not mentioned in message: {tf['message']}"
    )
    assert "eval" in tf["message"].lower(), (
        f"Sink eval not mentioned in message: {tf['message']}"
    )
    assert tf["taint_flow"] is not None
    assert tf["taint_flow"]["source"] == "req.body"


# ---------------------------------------------------------------------------
# Test 4 — imports and exports parsed correctly
# ---------------------------------------------------------------------------

def test_imports_and_exports_extracted(tmp_path):
    """Named imports and exports must appear in the result metadata."""
    source = """
import { Component, OnInit } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import defaultExport from './utils';

export interface Config {
  apiUrl: string;
  timeout: number;
}

export class AppComponent implements OnInit {
  title = 'my-app';

  constructor(private http: HttpClient) {}

  ngOnInit(): void {}
}

export default AppComponent;
"""
    result = _analyze(source, "app.component.ts", tmp_path)

    # Imports
    imports = result["imports"]
    assert len(imports) >= 2, f"Expected at least 2 imports, got {imports}"

    angular_import = next(
        (i for i in imports if "@angular/core" in i["from"]), None
    )
    assert angular_import is not None, "Expected @angular/core import"
    assert "Component" in angular_import["named"], (
        f"Expected 'Component' in named imports: {angular_import['named']}"
    )
    assert "OnInit" in angular_import["named"], (
        f"Expected 'OnInit' in named imports: {angular_import['named']}"
    )

    # Exports
    exports = result["exports"]
    assert len(exports) >= 1, f"Expected at least 1 export, got {exports}"

    # Symbols — class must appear
    symbols = result["symbols"]
    class_syms = [s for s in symbols if s["symbol_type"] == "class"]
    assert any(s["symbol_name"] == "AppComponent" for s in class_syms), (
        f"Expected AppComponent class symbol, got {[s['symbol_name'] for s in class_syms]}"
    )


# ---------------------------------------------------------------------------
# Test 5 — batch mode via analyze_repo
# ---------------------------------------------------------------------------

def test_batch_multiple_ts_files(tmp_path):
    """analyze_repo must process multiple .ts files and aggregate symbols."""
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()

    # File 1: clean utility
    (repo_dir / "utils.ts").write_text(
        """
export function add(a: number, b: number): number {
    return a + b;
}

export function greet(name: string): string {
    return `Hello, ${name}`;
}
""",
        encoding="utf-8",
    )

    # File 2: dangerous code
    (repo_dir / "danger.ts").write_text(
        """
import { exec } from 'child_process';

export function runCmd(cmd: string): void {
    exec(cmd);
}

export function dangerousEval(code: string): any {
    return eval(code);
}
""",
        encoding="utf-8",
    )

    # File 3: plain Python (must still be analysed)
    (repo_dir / "helper.py").write_text(
        """
def greet(name: str) -> str:
    return f"Hello {name}"
""",
        encoding="utf-8",
    )

    eng = _engine(tmp_path)
    result = eng.analyze_repo(
        org_id="test-org",
        repo_ref="batch-test-repo",
        commit_sha="abc123",
        root_path=str(repo_dir),
    )

    assert result["total_files"] == 3, (
        f"Expected 3 total files, got {result['total_files']}"
    )
    assert result["languages"].get("typescript", 0) == 2, (
        f"Expected 2 TypeScript files, got {result['languages']}"
    )
    assert result["languages"].get("python", 0) == 1, (
        f"Expected 1 Python file, got {result['languages']}"
    )
    # Symbols should include functions from both TS files
    assert result["total_symbols"] >= 4, (
        f"Expected at least 4 symbols (2 TS funcs + 2 TS funcs + Python), "
        f"got {result['total_symbols']}"
    )
    # Security findings from danger.ts must be stored as security_finding symbols
    # Query the DB directly to confirm
    import sqlite3, json as _json
    db_path = tmp_path / "dca_data" / "dca.db"
    with sqlite3.connect(str(db_path)) as conn:
        rows = conn.execute(
            "SELECT symbol_type, symbol_name, metadata_json "
            "FROM dca_symbols WHERE symbol_type = 'security_finding'"
        ).fetchall()
    assert len(rows) >= 1, (
        f"Expected security_finding rows in dca_symbols, got {rows}"
    )
    severities = {_json.loads(r[2]).get("severity") for r in rows}
    assert severities & {"HIGH", "CRITICAL"}, (
        f"Expected HIGH or CRITICAL finding from danger.ts, got {severities}"
    )
