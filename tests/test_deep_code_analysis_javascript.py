"""Tests for the JavaScript AST analyzer in DeepCodeAnalysisEngine (task #3).

Five required tests:
  1. Parse a clean .js file  → 0 findings
  2. eval() in .js           → HIGH finding (JS001)
  3. CommonJS require parsed
  4. ES6 import parsed
  5. Prototype pollution pattern detected (__proto__ assignment)
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

import pytest

# Ensure suite-core is on the path regardless of cwd.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "suite-core"))

from core.deep_code_analysis_engine import DeepCodeAnalysisEngine  # noqa: E402


@pytest.fixture(scope="module")
def engine(tmp_path_factory):
    data_dir = str(tmp_path_factory.mktemp("dca_js_test"))
    return DeepCodeAnalysisEngine(data_dir=data_dir)


# ---------------------------------------------------------------------------
# Test 1 — clean file produces zero findings
# ---------------------------------------------------------------------------
def test_js_clean_file_no_findings(engine):
    source = """\
'use strict';

function add(a, b) {
    return a + b;
}

const multiply = (x, y) => x * y;

class Calculator {
    constructor(base) {
        this.base = base;
    }
    compute(n) {
        return this.base + n;
    }
}

module.exports = { add, multiply, Calculator };
"""
    result = engine._analyze_javascript_source(source, "calc.js")
    assert result["findings"] == [], (
        f"Expected 0 findings for clean file, got: {result['findings']}"
    )
    # Bonus: symbols should include the function and class
    symbol_names = {s["symbol_name"] for s in result["symbols"]}
    assert "add" in symbol_names or "Calculator" in symbol_names


# ---------------------------------------------------------------------------
# Test 2 — eval() in .js produces HIGH finding (JS001)
# ---------------------------------------------------------------------------
def test_js_eval_detected_as_high(engine):
    source = """\
function runUserCode(input) {
    return eval(input);
}
"""
    result = engine._analyze_javascript_source(source, "dangerous.js")
    assert len(result["findings"]) >= 1, "Expected at least 1 finding for eval()"
    eval_findings = [f for f in result["findings"] if f["rule_id"] == "JS001"]
    assert eval_findings, f"Expected JS001 finding, got: {result['findings']}"
    assert eval_findings[0]["severity"] == "HIGH"
    assert eval_findings[0]["line"] == 2


# ---------------------------------------------------------------------------
# Test 3 — CommonJS require() is parsed
# ---------------------------------------------------------------------------
def test_js_commonjs_require_parsed(engine):
    source = """\
const fs = require('fs');
const path = require('path');
const express = require('express');
"""
    result = engine._analyze_javascript_source(source, "server.js")
    cjs_imports = [i for i in result["imports"] if i["import_type"] == "commonjs"]
    assert len(cjs_imports) == 3, f"Expected 3 CJS imports, got {cjs_imports}"
    modules = {i["module"] for i in cjs_imports}
    assert modules == {"fs", "path", "express"}
    bindings = {i["binding"] for i in cjs_imports}
    assert "fs" in bindings
    assert "express" in bindings


# ---------------------------------------------------------------------------
# Test 4 — ES6 import is parsed
# ---------------------------------------------------------------------------
def test_js_es6_import_parsed(engine):
    source = """\
import React from 'react';
import { useState, useEffect } from 'react';
import * as _ from 'lodash';
"""
    result = engine._analyze_javascript_source(source, "component.js")
    es6_imports = [i for i in result["imports"] if i["import_type"] == "es6"]
    assert len(es6_imports) == 3, f"Expected 3 ES6 imports, got {es6_imports}"
    modules = {i["module"] for i in es6_imports}
    assert "react" in modules
    assert "lodash" in modules
    # default import
    default_imports = [
        sp
        for i in es6_imports
        for sp in i.get("specifiers", [])
        if sp["type"] == "default"
    ]
    assert default_imports, "Expected at least one default import specifier"
    # named imports
    named_imports = [
        sp
        for i in es6_imports
        for sp in i.get("specifiers", [])
        if sp["type"] == "named"
    ]
    assert named_imports, "Expected at least one named import specifier"
    named_names = {sp["imported"] for sp in named_imports}
    assert "useState" in named_names
    assert "useEffect" in named_names


# ---------------------------------------------------------------------------
# Test 5 — prototype pollution via __proto__ assignment
# ---------------------------------------------------------------------------
def test_js_prototype_pollution_detected(engine):
    source = """\
function merge(target, source) {
    // Dangerous: allows __proto__ pollution
    target.__proto__ = source;
    return target;
}
"""
    result = engine._analyze_javascript_source(source, "merge.js")
    proto_findings = [f for f in result["findings"] if f["rule_id"] == "JS007"]
    assert proto_findings, (
        f"Expected JS007 (prototype pollution) finding, got: {result['findings']}"
    )
    assert proto_findings[0]["severity"] == "HIGH"
    assert "__proto__" in proto_findings[0]["evidence"]


# ---------------------------------------------------------------------------
# Bonus: disk-based _analyze_javascript uses same logic (integration test)
# ---------------------------------------------------------------------------
def test_js_analyze_javascript_disk(engine, tmp_path):
    js_file = tmp_path / "attack.js"
    js_file.write_text(
        "const result = eval(document.location.hash.substring(1));\n",
        encoding="utf-8",
    )
    result = engine._analyze_javascript(js_file)
    assert any(f["rule_id"] == "JS001" for f in result["findings"]), (
        "disk-based _analyze_javascript did not detect eval()"
    )
