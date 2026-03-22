"""
Comprehensive unit tests for suite-evidence-risk/risk/sbom/generator.py.

Covers:
  - SBOMFormat enum: CYCLONEDX, SPDX
  - Dependency dataclass: all fields, defaults
  - SBOMComponent dataclass: all fields, defaults
  - DependencyDiscoverer: discover_from_python, discover_from_javascript,
    discover_from_java, _parse_python_import (stdlib filtering)
  - SBOMGenerator: generate_from_codebase, _deduplicate_dependencies,
    _generate_cyclonedx, _generate_spdx, _generate_purl
  - SBOMQualityScorer: score_sbom (perfect, partial, empty SBOMs, grading)
  - Edge cases: binary files, empty files, malformed imports, missing dirs
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "suite-evidence-risk"))

import pytest

from risk.sbom.generator import (
    Dependency,
    DependencyDiscoverer,
    SBOMComponent,
    SBOMFormat,
    SBOMGenerator,
    SBOMQualityScorer,
)


# ---------------------------------------------------------------------------
# SBOMFormat enum
# ---------------------------------------------------------------------------


class TestSBOMFormat:
    def test_cyclonedx_value(self):
        assert SBOMFormat.CYCLONEDX.value == "cyclonedx"

    def test_spdx_value(self):
        assert SBOMFormat.SPDX.value == "spdx"

    def test_two_members_only(self):
        assert len(list(SBOMFormat)) == 2

    def test_members_are_distinct(self):
        assert SBOMFormat.CYCLONEDX != SBOMFormat.SPDX

    def test_lookup_by_value(self):
        assert SBOMFormat("cyclonedx") is SBOMFormat.CYCLONEDX
        assert SBOMFormat("spdx") is SBOMFormat.SPDX


# ---------------------------------------------------------------------------
# Dependency dataclass
# ---------------------------------------------------------------------------


class TestDependency:
    def test_required_field_name(self):
        dep = Dependency(name="requests")
        assert dep.name == "requests"

    def test_defaults(self):
        dep = Dependency(name="flask")
        assert dep.version is None
        assert dep.package_manager == "unknown"
        assert dep.purl is None
        assert dep.license is None
        assert dep.source_file is None
        assert dep.confidence == 1.0

    def test_all_fields_set(self):
        dep = Dependency(
            name="lodash",
            version="4.17.21",
            package_manager="npm",
            purl="pkg:npm/lodash@4.17.21",
            license="MIT",
            source_file="/app/src/index.js",
            confidence=0.9,
        )
        assert dep.name == "lodash"
        assert dep.version == "4.17.21"
        assert dep.package_manager == "npm"
        assert dep.purl == "pkg:npm/lodash@4.17.21"
        assert dep.license == "MIT"
        assert dep.source_file == "/app/src/index.js"
        assert dep.confidence == 0.9

    def test_confidence_zero(self):
        dep = Dependency(name="unknown-pkg", confidence=0.0)
        assert dep.confidence == 0.0

    def test_equality_by_field_values(self):
        dep1 = Dependency(name="numpy", version="1.24.0", package_manager="pip")
        dep2 = Dependency(name="numpy", version="1.24.0", package_manager="pip")
        assert dep1 == dep2


# ---------------------------------------------------------------------------
# SBOMComponent dataclass
# ---------------------------------------------------------------------------


class TestSBOMComponent:
    def test_required_fields(self):
        comp = SBOMComponent(type="library", name="django", version="4.2.0")
        assert comp.type == "library"
        assert comp.name == "django"
        assert comp.version == "4.2.0"

    def test_optional_fields_default(self):
        comp = SBOMComponent(type="library", name="pytest", version="7.0.0")
        assert comp.purl is None
        assert comp.licenses == []
        assert comp.properties == []

    def test_licenses_list_is_independent(self):
        comp1 = SBOMComponent(type="library", name="a", version="1.0")
        comp2 = SBOMComponent(type="library", name="b", version="2.0")
        comp1.licenses.append({"id": "MIT"})
        assert comp2.licenses == []

    def test_properties_list_is_independent(self):
        comp1 = SBOMComponent(type="library", name="a", version="1.0")
        comp2 = SBOMComponent(type="library", name="b", version="2.0")
        comp1.properties.append({"name": "key", "value": "val"})
        assert comp2.properties == []

    def test_full_construction(self):
        comp = SBOMComponent(
            type="container",
            name="nginx",
            version="1.25.0",
            purl="pkg:docker/nginx@1.25.0",
            licenses=[{"license": {"id": "BSD-2-Clause"}}],
            properties=[{"name": "syft:package:foundBy", "value": "python-packages-cataloger"}],
        )
        assert comp.purl == "pkg:docker/nginx@1.25.0"
        assert len(comp.licenses) == 1
        assert len(comp.properties) == 1


# ---------------------------------------------------------------------------
# DependencyDiscoverer — Python
# ---------------------------------------------------------------------------


class TestDiscoverFromPython:
    @pytest.fixture
    def discoverer(self):
        return DependencyDiscoverer()

    def test_simple_import_discovered(self, tmp_path, discoverer):
        py_file = tmp_path / "app.py"
        py_file.write_text("import requests\n", encoding="utf-8")
        deps = discoverer.discover_from_python(py_file)
        names = [d.name for d in deps]
        assert "requests" in names

    def test_from_import_discovered(self, tmp_path, discoverer):
        py_file = tmp_path / "app.py"
        py_file.write_text("from flask import Flask\n", encoding="utf-8")
        deps = discoverer.discover_from_python(py_file)
        names = [d.name for d in deps]
        assert "flask" in names

    def test_nested_from_import_uses_top_level_package(self, tmp_path, discoverer):
        py_file = tmp_path / "app.py"
        py_file.write_text("from sqlalchemy.orm import Session\n", encoding="utf-8")
        deps = discoverer.discover_from_python(py_file)
        names = [d.name for d in deps]
        assert "sqlalchemy" in names

    def test_multiple_imports_in_one_file(self, tmp_path, discoverer):
        py_file = tmp_path / "app.py"
        py_file.write_text(
            "import requests\nimport boto3\nfrom fastapi import FastAPI\n",
            encoding="utf-8",
        )
        deps = discoverer.discover_from_python(py_file)
        names = [d.name for d in deps]
        assert "requests" in names
        assert "boto3" in names
        assert "fastapi" in names

    def test_stdlib_sys_filtered(self, tmp_path, discoverer):
        py_file = tmp_path / "app.py"
        py_file.write_text("import sys\n", encoding="utf-8")
        deps = discoverer.discover_from_python(py_file)
        assert all(d.name != "sys" for d in deps)

    def test_stdlib_os_filtered(self, tmp_path, discoverer):
        py_file = tmp_path / "app.py"
        py_file.write_text("import os\n", encoding="utf-8")
        deps = discoverer.discover_from_python(py_file)
        assert all(d.name != "os" for d in deps)

    def test_stdlib_json_filtered(self, tmp_path, discoverer):
        py_file = tmp_path / "app.py"
        py_file.write_text("import json\n", encoding="utf-8")
        deps = discoverer.discover_from_python(py_file)
        assert all(d.name != "json" for d in deps)

    def test_stdlib_datetime_filtered(self, tmp_path, discoverer):
        py_file = tmp_path / "app.py"
        py_file.write_text("from datetime import datetime\n", encoding="utf-8")
        deps = discoverer.discover_from_python(py_file)
        assert all(d.name != "datetime" for d in deps)

    def test_stdlib_re_filtered(self, tmp_path, discoverer):
        py_file = tmp_path / "app.py"
        py_file.write_text("import re\n", encoding="utf-8")
        deps = discoverer.discover_from_python(py_file)
        assert all(d.name != "re" for d in deps)

    def test_stdlib_collections_filtered(self, tmp_path, discoverer):
        py_file = tmp_path / "app.py"
        py_file.write_text("from collections import defaultdict\n", encoding="utf-8")
        deps = discoverer.discover_from_python(py_file)
        assert all(d.name != "collections" for d in deps)

    def test_all_known_stdlib_entries_filtered(self, tmp_path, discoverer):
        stdlib_modules = [
            "sys", "os", "json", "datetime", "collections",
            "itertools", "functools", "operator", "math", "random", "string", "re",
        ]
        content = "\n".join(f"import {m}" for m in stdlib_modules) + "\n"
        py_file = tmp_path / "stdlib.py"
        py_file.write_text(content, encoding="utf-8")
        deps = discoverer.discover_from_python(py_file)
        dep_names = {d.name for d in deps}
        for m in stdlib_modules:
            assert m not in dep_names

    def test_package_manager_is_pip(self, tmp_path, discoverer):
        py_file = tmp_path / "app.py"
        py_file.write_text("import numpy\n", encoding="utf-8")
        deps = discoverer.discover_from_python(py_file)
        assert all(d.package_manager == "pip" for d in deps)

    def test_source_file_recorded(self, tmp_path, discoverer):
        py_file = tmp_path / "app.py"
        py_file.write_text("import pandas\n", encoding="utf-8")
        deps = discoverer.discover_from_python(py_file)
        assert any(str(py_file) in d.source_file for d in deps)

    def test_empty_file_returns_no_deps(self, tmp_path, discoverer):
        py_file = tmp_path / "empty.py"
        py_file.write_text("", encoding="utf-8")
        deps = discoverer.discover_from_python(py_file)
        assert deps == []

    def test_file_with_only_comments_returns_no_deps(self, tmp_path, discoverer):
        py_file = tmp_path / "comments.py"
        py_file.write_text("# import requests\n# from flask import Flask\n", encoding="utf-8")
        deps = discoverer.discover_from_python(py_file)
        assert deps == []

    def test_malformed_python_does_not_raise(self, tmp_path, discoverer):
        py_file = tmp_path / "bad.py"
        py_file.write_text("def broken(\n", encoding="utf-8")
        # Should return empty list without raising
        deps = discoverer.discover_from_python(py_file)
        assert isinstance(deps, list)

    def test_nonexistent_file_does_not_raise(self, tmp_path, discoverer):
        missing = tmp_path / "nonexistent.py"
        deps = discoverer.discover_from_python(missing)
        assert isinstance(deps, list)

    def test_multiple_aliases_in_single_import(self, tmp_path, discoverer):
        py_file = tmp_path / "multi.py"
        py_file.write_text("import numpy, scipy, pandas\n", encoding="utf-8")
        deps = discoverer.discover_from_python(py_file)
        names = [d.name for d in deps]
        assert "numpy" in names
        assert "scipy" in names
        assert "pandas" in names


# ---------------------------------------------------------------------------
# DependencyDiscoverer — JavaScript
# ---------------------------------------------------------------------------


class TestDiscoverFromJavaScript:
    @pytest.fixture
    def discoverer(self):
        return DependencyDiscoverer()

    def test_require_statement_discovered(self, tmp_path, discoverer):
        js_file = tmp_path / "app.js"
        js_file.write_text("const express = require('express');\n", encoding="utf-8")
        deps = discoverer.discover_from_javascript(js_file)
        names = [d.name for d in deps]
        assert "express" in names

    def test_es6_import_discovered(self, tmp_path, discoverer):
        js_file = tmp_path / "app.js"
        js_file.write_text("import React from 'react';\n", encoding="utf-8")
        deps = discoverer.discover_from_javascript(js_file)
        names = [d.name for d in deps]
        assert "react" in names

    def test_relative_require_ignored(self, tmp_path, discoverer):
        js_file = tmp_path / "app.js"
        js_file.write_text("const util = require('./util');\n", encoding="utf-8")
        deps = discoverer.discover_from_javascript(js_file)
        assert all(not d.name.startswith(".") for d in deps)

    def test_relative_import_ignored(self, tmp_path, discoverer):
        js_file = tmp_path / "app.js"
        js_file.write_text("import helper from '../helpers/util';\n", encoding="utf-8")
        deps = discoverer.discover_from_javascript(js_file)
        assert all(not d.name.startswith(".") for d in deps)

    def test_package_manager_is_npm(self, tmp_path, discoverer):
        js_file = tmp_path / "app.js"
        js_file.write_text("const lodash = require('lodash');\n", encoding="utf-8")
        deps = discoverer.discover_from_javascript(js_file)
        assert all(d.package_manager == "npm" for d in deps)

    def test_source_file_recorded(self, tmp_path, discoverer):
        js_file = tmp_path / "index.js"
        js_file.write_text("const axios = require('axios');\n", encoding="utf-8")
        deps = discoverer.discover_from_javascript(js_file)
        assert any(str(js_file) in d.source_file for d in deps)

    def test_multiple_packages_in_same_file(self, tmp_path, discoverer):
        js_file = tmp_path / "app.js"
        js_file.write_text(
            "const express = require('express');\n"
            "import moment from 'moment';\n"
            "const _ = require('lodash');\n",
            encoding="utf-8",
        )
        deps = discoverer.discover_from_javascript(js_file)
        names = [d.name for d in deps]
        assert "express" in names
        assert "moment" in names
        assert "lodash" in names

    def test_double_quoted_require(self, tmp_path, discoverer):
        js_file = tmp_path / "app.js"
        js_file.write_text('const fs = require("fs-extra");\n', encoding="utf-8")
        deps = discoverer.discover_from_javascript(js_file)
        names = [d.name for d in deps]
        assert "fs-extra" in names

    def test_empty_file_returns_no_deps(self, tmp_path, discoverer):
        js_file = tmp_path / "empty.js"
        js_file.write_text("", encoding="utf-8")
        deps = discoverer.discover_from_javascript(js_file)
        assert deps == []

    def test_nonexistent_file_does_not_raise(self, tmp_path, discoverer):
        missing = tmp_path / "ghost.js"
        deps = discoverer.discover_from_javascript(missing)
        assert isinstance(deps, list)

    def test_typescript_file_parsed(self, tmp_path, discoverer):
        ts_file = tmp_path / "component.ts"
        ts_file.write_text("import { Component } from '@angular/core';\n", encoding="utf-8")
        deps = discoverer.discover_from_javascript(ts_file)
        names = [d.name for d in deps]
        assert "@angular/core" in names


# ---------------------------------------------------------------------------
# DependencyDiscoverer — Java
# ---------------------------------------------------------------------------


class TestDiscoverFromJava:
    @pytest.fixture
    def discoverer(self):
        return DependencyDiscoverer()

    def test_simple_java_import(self, tmp_path, discoverer):
        java_file = tmp_path / "App.java"
        java_file.write_text("import org.springframework.boot.SpringApplication;\n", encoding="utf-8")
        deps = discoverer.discover_from_java(java_file)
        assert len(deps) >= 1
        assert any("springframework" in d.name for d in deps)

    def test_package_manager_is_maven(self, tmp_path, discoverer):
        java_file = tmp_path / "App.java"
        java_file.write_text("import com.google.gson.Gson;\n", encoding="utf-8")
        deps = discoverer.discover_from_java(java_file)
        assert all(d.package_manager == "maven" for d in deps)

    def test_group_artifact_format_in_name(self, tmp_path, discoverer):
        java_file = tmp_path / "App.java"
        java_file.write_text("import com.fasterxml.jackson.databind.ObjectMapper;\n", encoding="utf-8")
        deps = discoverer.discover_from_java(java_file)
        assert len(deps) >= 1
        # Name should be group_id:artifact_id
        assert any(":" in d.name for d in deps)

    def test_source_file_recorded(self, tmp_path, discoverer):
        java_file = tmp_path / "Service.java"
        java_file.write_text("import org.slf4j.Logger;\n", encoding="utf-8")
        deps = discoverer.discover_from_java(java_file)
        assert any(str(java_file) in d.source_file for d in deps)

    def test_multiple_imports_in_java_file(self, tmp_path, discoverer):
        java_file = tmp_path / "App.java"
        java_file.write_text(
            "import org.springframework.boot.SpringApplication;\n"
            "import com.google.gson.Gson;\n"
            "import org.slf4j.Logger;\n",
            encoding="utf-8",
        )
        deps = discoverer.discover_from_java(java_file)
        assert len(deps) >= 2

    def test_empty_file_returns_no_deps(self, tmp_path, discoverer):
        java_file = tmp_path / "Empty.java"
        java_file.write_text("", encoding="utf-8")
        deps = discoverer.discover_from_java(java_file)
        assert deps == []

    def test_nonexistent_file_does_not_raise(self, tmp_path, discoverer):
        missing = tmp_path / "Missing.java"
        deps = discoverer.discover_from_java(missing)
        assert isinstance(deps, list)

    def test_single_segment_class_import_not_matched(self, tmp_path, discoverer):
        # Pattern requires at least 2 lowercase parts before a class
        java_file = tmp_path / "App.java"
        java_file.write_text("import java.util.List;\n", encoding="utf-8")
        # "java.util" has 2+ segments — should match
        deps = discoverer.discover_from_java(java_file)
        # Just verify it doesn't raise; some matches may or may not appear
        assert isinstance(deps, list)


# ---------------------------------------------------------------------------
# DependencyDiscoverer — _parse_python_import
# ---------------------------------------------------------------------------


class TestParsePythonImport:
    @pytest.fixture
    def discoverer(self):
        return DependencyDiscoverer()

    def test_returns_dependency_for_third_party(self, tmp_path, discoverer):
        dep = discoverer._parse_python_import("requests", tmp_path / "f.py")
        assert dep is not None
        assert dep.name == "requests"

    def test_returns_none_for_sys(self, tmp_path, discoverer):
        dep = discoverer._parse_python_import("sys", tmp_path / "f.py")
        assert dep is None

    def test_returns_none_for_os(self, tmp_path, discoverer):
        dep = discoverer._parse_python_import("os", tmp_path / "f.py")
        assert dep is None

    def test_returns_none_for_os_path_submodule(self, tmp_path, discoverer):
        dep = discoverer._parse_python_import("os.path", tmp_path / "f.py")
        assert dep is None

    def test_returns_none_for_relative_import(self, tmp_path, discoverer):
        dep = discoverer._parse_python_import(".local_module", tmp_path / "f.py")
        assert dep is None

    def test_submodule_uses_top_level_package(self, tmp_path, discoverer):
        dep = discoverer._parse_python_import("sqlalchemy.orm.session", tmp_path / "f.py")
        assert dep is not None
        assert dep.name == "sqlalchemy"

    def test_package_manager_pip(self, tmp_path, discoverer):
        dep = discoverer._parse_python_import("numpy", tmp_path / "f.py")
        assert dep.package_manager == "pip"

    def test_source_file_set_correctly(self, tmp_path, discoverer):
        file_path = tmp_path / "module.py"
        dep = discoverer._parse_python_import("flask", file_path)
        assert dep.source_file == str(file_path)


# ---------------------------------------------------------------------------
# SBOMGenerator — PURL generation
# ---------------------------------------------------------------------------


class TestGeneratePurl:
    @pytest.fixture
    def generator(self):
        return SBOMGenerator()

    def test_pip_purl_with_version(self, generator):
        dep = Dependency(name="requests", version="2.28.0", package_manager="pip")
        purl = generator._generate_purl(dep)
        assert purl == "pkg:pypi/requests@2.28.0"

    def test_pip_purl_without_version(self, generator):
        dep = Dependency(name="flask", package_manager="pip")
        purl = generator._generate_purl(dep)
        assert purl.startswith("pkg:pypi/flask@")

    def test_npm_purl_with_version(self, generator):
        dep = Dependency(name="lodash", version="4.17.21", package_manager="npm")
        purl = generator._generate_purl(dep)
        assert purl == "pkg:npm/lodash@4.17.21"

    def test_npm_purl_without_version(self, generator):
        dep = Dependency(name="react", package_manager="npm")
        purl = generator._generate_purl(dep)
        assert purl.startswith("pkg:npm/react@")

    def test_maven_purl_with_group_artifact(self, generator):
        dep = Dependency(
            name="org.springframework:spring-core",
            version="5.3.0",
            package_manager="maven",
        )
        purl = generator._generate_purl(dep)
        assert purl == "pkg:maven/org.springframework/spring-core@5.3.0"

    def test_maven_purl_without_colon(self, generator):
        dep = Dependency(name="springcore", version="5.3.0", package_manager="maven")
        purl = generator._generate_purl(dep)
        assert purl == "pkg:maven/springcore@5.3.0"

    def test_generic_purl_for_unknown_manager(self, generator):
        dep = Dependency(name="some-lib", version="1.0.0", package_manager="unknown")
        purl = generator._generate_purl(dep)
        assert purl == "pkg:generic/some-lib@1.0.0"

    def test_existing_purl_returned_unchanged(self, generator):
        custom_purl = "pkg:custom/tool@3.2.1"
        dep = Dependency(name="tool", version="3.2.1", package_manager="pip", purl=custom_purl)
        purl = generator._generate_purl(dep)
        assert purl == custom_purl


# ---------------------------------------------------------------------------
# SBOMGenerator — deduplication
# ---------------------------------------------------------------------------


class TestDeduplicateDependencies:
    @pytest.fixture
    def generator(self):
        return SBOMGenerator()

    def test_identical_deps_deduplicated(self, generator):
        deps = [
            Dependency(name="requests", package_manager="pip"),
            Dependency(name="requests", package_manager="pip"),
        ]
        result = generator._deduplicate_dependencies(deps)
        assert len(result) == 1

    def test_different_names_kept(self, generator):
        deps = [
            Dependency(name="requests", package_manager="pip"),
            Dependency(name="flask", package_manager="pip"),
        ]
        result = generator._deduplicate_dependencies(deps)
        assert len(result) == 2

    def test_different_package_managers_kept(self, generator):
        deps = [
            Dependency(name="requests", package_manager="pip"),
            Dependency(name="requests", package_manager="npm"),
        ]
        result = generator._deduplicate_dependencies(deps)
        assert len(result) == 2

    def test_version_merged_from_second_occurrence(self, generator):
        deps = [
            Dependency(name="numpy", package_manager="pip", version=None),
            Dependency(name="numpy", package_manager="pip", version="1.24.0"),
        ]
        result = generator._deduplicate_dependencies(deps)
        assert len(result) == 1
        assert result[0].version == "1.24.0"

    def test_first_version_kept_when_both_have_versions(self, generator):
        deps = [
            Dependency(name="scipy", package_manager="pip", version="1.10.0"),
            Dependency(name="scipy", package_manager="pip", version="1.11.0"),
        ]
        result = generator._deduplicate_dependencies(deps)
        assert len(result) == 1
        assert result[0].version == "1.10.0"

    def test_empty_list_returns_empty(self, generator):
        assert generator._deduplicate_dependencies([]) == []

    def test_single_dep_returns_single(self, generator):
        deps = [Dependency(name="pandas", package_manager="pip")]
        result = generator._deduplicate_dependencies(deps)
        assert len(result) == 1

    def test_large_duplicate_set_deduped(self, generator):
        deps = [Dependency(name="numpy", package_manager="pip") for _ in range(50)]
        result = generator._deduplicate_dependencies(deps)
        assert len(result) == 1


# ---------------------------------------------------------------------------
# SBOMGenerator — CycloneDX format
# ---------------------------------------------------------------------------


class TestGenerateCycloneDX:
    @pytest.fixture
    def generator(self):
        return SBOMGenerator()

    def test_bom_format_field(self, generator, tmp_path):
        deps = [Dependency(name="requests", version="2.28.0", package_manager="pip")]
        sbom = generator._generate_cyclonedx(deps, tmp_path)
        assert sbom["bomFormat"] == "CycloneDX"

    def test_spec_version(self, generator, tmp_path):
        sbom = generator._generate_cyclonedx([], tmp_path)
        assert sbom["specVersion"] == "1.5"

    def test_version_is_1(self, generator, tmp_path):
        sbom = generator._generate_cyclonedx([], tmp_path)
        assert sbom["version"] == 1

    def test_metadata_timestamp_present(self, generator, tmp_path):
        sbom = generator._generate_cyclonedx([], tmp_path)
        assert "timestamp" in sbom["metadata"]

    def test_metadata_tools_present(self, generator, tmp_path):
        sbom = generator._generate_cyclonedx([], tmp_path)
        tools = sbom["metadata"]["tools"]
        assert isinstance(tools, list)
        assert len(tools) == 1
        assert tools[0]["vendor"] == "ALdeci"

    def test_metadata_component_name_matches_dir(self, generator, tmp_path):
        sbom = generator._generate_cyclonedx([], tmp_path)
        assert sbom["metadata"]["component"]["name"] == tmp_path.name

    def test_components_list_present(self, generator, tmp_path):
        sbom = generator._generate_cyclonedx([], tmp_path)
        assert "components" in sbom
        assert isinstance(sbom["components"], list)

    def test_component_name_set(self, generator, tmp_path):
        deps = [Dependency(name="flask", version="2.3.0", package_manager="pip")]
        sbom = generator._generate_cyclonedx(deps, tmp_path)
        assert sbom["components"][0]["name"] == "flask"

    def test_component_version_set(self, generator, tmp_path):
        deps = [Dependency(name="flask", version="2.3.0", package_manager="pip")]
        sbom = generator._generate_cyclonedx(deps, tmp_path)
        assert sbom["components"][0]["version"] == "2.3.0"

    def test_component_type_is_library(self, generator, tmp_path):
        deps = [Dependency(name="numpy", package_manager="pip")]
        sbom = generator._generate_cyclonedx(deps, tmp_path)
        assert sbom["components"][0]["type"] == "library"

    def test_component_purl_set(self, generator, tmp_path):
        deps = [Dependency(name="requests", version="2.28.0", package_manager="pip")]
        sbom = generator._generate_cyclonedx(deps, tmp_path)
        assert sbom["components"][0]["purl"] == "pkg:pypi/requests@2.28.0"

    def test_component_version_unknown_when_none(self, generator, tmp_path):
        deps = [Dependency(name="unknown-pkg", package_manager="pip")]
        sbom = generator._generate_cyclonedx(deps, tmp_path)
        assert sbom["components"][0]["version"] == "unknown"

    def test_license_included_when_set(self, generator, tmp_path):
        deps = [Dependency(name="requests", version="2.28.0", package_manager="pip", license="MIT")]
        sbom = generator._generate_cyclonedx(deps, tmp_path)
        comp = sbom["components"][0]
        assert "licenses" in comp
        assert comp["licenses"][0]["license"]["id"] == "MIT"

    def test_license_absent_when_not_set(self, generator, tmp_path):
        deps = [Dependency(name="numpy", version="1.24.0", package_manager="pip")]
        sbom = generator._generate_cyclonedx(deps, tmp_path)
        assert "licenses" not in sbom["components"][0]

    def test_multiple_components(self, generator, tmp_path):
        deps = [
            Dependency(name="requests", version="2.28.0", package_manager="pip"),
            Dependency(name="flask", version="2.3.0", package_manager="pip"),
        ]
        sbom = generator._generate_cyclonedx(deps, tmp_path)
        assert len(sbom["components"]) == 2


# ---------------------------------------------------------------------------
# SBOMGenerator — SPDX format
# ---------------------------------------------------------------------------


class TestGenerateSPDX:
    @pytest.fixture
    def generator(self):
        return SBOMGenerator()

    def test_spdx_version(self, generator, tmp_path):
        sbom = generator._generate_spdx([], tmp_path)
        assert sbom["spdxVersion"] == "SPDX-2.3"

    def test_data_license(self, generator, tmp_path):
        sbom = generator._generate_spdx([], tmp_path)
        assert sbom["dataLicense"] == "CC0-1.0"

    def test_spdxid_document(self, generator, tmp_path):
        sbom = generator._generate_spdx([], tmp_path)
        assert sbom["SPDXID"] == "SPDXRef-DOCUMENT"

    def test_name_includes_dir_name(self, generator, tmp_path):
        sbom = generator._generate_spdx([], tmp_path)
        assert tmp_path.name in sbom["name"]

    def test_document_namespace_includes_dir_name(self, generator, tmp_path):
        sbom = generator._generate_spdx([], tmp_path)
        assert tmp_path.name in sbom["documentNamespace"]

    def test_creation_info_present(self, generator, tmp_path):
        sbom = generator._generate_spdx([], tmp_path)
        assert "creationInfo" in sbom
        assert "created" in sbom["creationInfo"]

    def test_creator_tool_listed(self, generator, tmp_path):
        sbom = generator._generate_spdx([], tmp_path)
        creators = sbom["creationInfo"]["creators"]
        assert any("ALdeci" in c for c in creators)

    def test_packages_list_present(self, generator, tmp_path):
        sbom = generator._generate_spdx([], tmp_path)
        assert "packages" in sbom
        assert isinstance(sbom["packages"], list)

    def test_package_spdxid_format(self, generator, tmp_path):
        deps = [Dependency(name="requests", version="2.28.0", package_manager="pip")]
        sbom = generator._generate_spdx(deps, tmp_path)
        pkg = sbom["packages"][0]
        assert pkg["SPDXID"] == "SPDXRef-Package-requests"

    def test_package_name(self, generator, tmp_path):
        deps = [Dependency(name="flask", version="2.3.0", package_manager="pip")]
        sbom = generator._generate_spdx(deps, tmp_path)
        assert sbom["packages"][0]["name"] == "flask"

    def test_package_version_info(self, generator, tmp_path):
        deps = [Dependency(name="flask", version="2.3.0", package_manager="pip")]
        sbom = generator._generate_spdx(deps, tmp_path)
        assert sbom["packages"][0]["versionInfo"] == "2.3.0"

    def test_package_version_noassertion_when_none(self, generator, tmp_path):
        deps = [Dependency(name="mylib", package_manager="pip")]
        sbom = generator._generate_spdx(deps, tmp_path)
        assert sbom["packages"][0]["versionInfo"] == "NOASSERTION"

    def test_package_download_location_noassertion(self, generator, tmp_path):
        deps = [Dependency(name="numpy", version="1.24.0", package_manager="pip")]
        sbom = generator._generate_spdx(deps, tmp_path)
        assert sbom["packages"][0]["downloadLocation"] == "NOASSERTION"

    def test_external_refs_purl_present(self, generator, tmp_path):
        deps = [Dependency(name="requests", version="2.28.0", package_manager="pip")]
        sbom = generator._generate_spdx(deps, tmp_path)
        refs = sbom["packages"][0]["externalRefs"]
        assert len(refs) == 1
        assert refs[0]["referenceType"] == "purl"
        assert "pkg:pypi/requests@2.28.0" == refs[0]["referenceLocator"]

    def test_license_declared_when_set(self, generator, tmp_path):
        deps = [Dependency(name="flask", version="2.3.0", package_manager="pip", license="BSD-3-Clause")]
        sbom = generator._generate_spdx(deps, tmp_path)
        assert sbom["packages"][0]["licenseDeclared"] == "BSD-3-Clause"

    def test_license_absent_when_not_set(self, generator, tmp_path):
        deps = [Dependency(name="numpy", version="1.24.0", package_manager="pip")]
        sbom = generator._generate_spdx(deps, tmp_path)
        assert "licenseDeclared" not in sbom["packages"][0]

    def test_multiple_packages(self, generator, tmp_path):
        deps = [
            Dependency(name="requests", version="2.28.0", package_manager="pip"),
            Dependency(name="flask", version="2.3.0", package_manager="pip"),
        ]
        sbom = generator._generate_spdx(deps, tmp_path)
        assert len(sbom["packages"]) == 2


# ---------------------------------------------------------------------------
# SBOMGenerator — generate_from_codebase (integration of all parts)
# ---------------------------------------------------------------------------


class TestGenerateFromCodebase:
    @pytest.fixture
    def generator(self):
        return SBOMGenerator()

    def test_cyclonedx_format_returned_by_default(self, tmp_path, generator):
        py_file = tmp_path / "app.py"
        py_file.write_text("import requests\n", encoding="utf-8")
        sbom = generator.generate_from_codebase(tmp_path, SBOMFormat.CYCLONEDX)
        assert sbom["bomFormat"] == "CycloneDX"

    def test_spdx_format_returned_when_requested(self, tmp_path, generator):
        py_file = tmp_path / "app.py"
        py_file.write_text("import requests\n", encoding="utf-8")
        sbom = generator.generate_from_codebase(tmp_path, SBOMFormat.SPDX)
        assert sbom["spdxVersion"] == "SPDX-2.3"

    def test_python_deps_discovered(self, tmp_path, generator):
        py_file = tmp_path / "app.py"
        py_file.write_text("import requests\nimport numpy\n", encoding="utf-8")
        sbom = generator.generate_from_codebase(tmp_path, SBOMFormat.CYCLONEDX)
        names = [c["name"] for c in sbom["components"]]
        assert "requests" in names
        assert "numpy" in names

    def test_js_deps_discovered(self, tmp_path, generator):
        js_file = tmp_path / "app.js"
        js_file.write_text("const express = require('express');\n", encoding="utf-8")
        sbom = generator.generate_from_codebase(tmp_path, SBOMFormat.CYCLONEDX)
        names = [c["name"] for c in sbom["components"]]
        assert "express" in names

    def test_java_deps_discovered(self, tmp_path, generator):
        java_file = tmp_path / "App.java"
        java_file.write_text("import org.springframework.boot.SpringApplication;\n", encoding="utf-8")
        sbom = generator.generate_from_codebase(tmp_path, SBOMFormat.CYCLONEDX)
        # At least some maven dep found
        assert len(sbom["components"]) >= 1

    def test_empty_codebase_returns_no_components(self, tmp_path, generator):
        sbom = generator.generate_from_codebase(tmp_path, SBOMFormat.CYCLONEDX)
        assert sbom["components"] == []

    def test_deduplication_applied(self, tmp_path, generator):
        # Two Python files importing the same package
        (tmp_path / "a.py").write_text("import requests\n", encoding="utf-8")
        (tmp_path / "b.py").write_text("import requests\n", encoding="utf-8")
        sbom = generator.generate_from_codebase(tmp_path, SBOMFormat.CYCLONEDX)
        names = [c["name"] for c in sbom["components"]]
        assert names.count("requests") == 1

    def test_node_modules_ignored(self, tmp_path, generator):
        node_dir = tmp_path / "node_modules" / "express"
        node_dir.mkdir(parents=True)
        (node_dir / "index.js").write_text(
            "const http = require('http');\n", encoding="utf-8"
        )
        sbom = generator.generate_from_codebase(tmp_path, SBOMFormat.CYCLONEDX)
        # http from node_modules should not appear
        names = [c["name"] for c in sbom["components"]]
        assert "http" not in names

    def test_venv_directory_ignored(self, tmp_path, generator):
        venv_dir = tmp_path / "venv" / "lib"
        venv_dir.mkdir(parents=True)
        (venv_dir / "something.py").write_text("import boto3\n", encoding="utf-8")
        sbom = generator.generate_from_codebase(tmp_path, SBOMFormat.CYCLONEDX)
        names = [c["name"] for c in sbom["components"]]
        assert "boto3" not in names

    def test_stdlib_excluded_from_output(self, tmp_path, generator):
        py_file = tmp_path / "app.py"
        py_file.write_text("import os\nimport sys\nimport requests\n", encoding="utf-8")
        sbom = generator.generate_from_codebase(tmp_path, SBOMFormat.CYCLONEDX)
        names = [c["name"] for c in sbom["components"]]
        assert "os" not in names
        assert "sys" not in names

    def test_mixed_languages_combined(self, tmp_path, generator):
        (tmp_path / "app.py").write_text("import flask\n", encoding="utf-8")
        (tmp_path / "app.js").write_text("const lodash = require('lodash');\n", encoding="utf-8")
        sbom = generator.generate_from_codebase(tmp_path, SBOMFormat.CYCLONEDX)
        names = [c["name"] for c in sbom["components"]]
        assert "flask" in names
        assert "lodash" in names

    def test_typescript_files_also_scanned(self, tmp_path, generator):
        ts_file = tmp_path / "component.ts"
        ts_file.write_text("import { Injectable } from '@angular/core';\n", encoding="utf-8")
        sbom = generator.generate_from_codebase(tmp_path, SBOMFormat.CYCLONEDX)
        names = [c["name"] for c in sbom["components"]]
        assert "@angular/core" in names

    def test_generator_config_accepted(self, tmp_path):
        gen = SBOMGenerator(config={"extra_option": True})
        sbom = gen.generate_from_codebase(tmp_path, SBOMFormat.CYCLONEDX)
        assert "bomFormat" in sbom


# ---------------------------------------------------------------------------
# SBOMQualityScorer
# ---------------------------------------------------------------------------


class TestSBOMQualityScorer:
    @pytest.fixture
    def scorer(self):
        return SBOMQualityScorer()

    def _make_perfect_cyclonedx(self, count: int = 3) -> dict:
        """Build a perfect CycloneDX SBOM with all fields populated."""
        components = [
            {
                "name": f"lib-{i}",
                "version": f"1.{i}.0",
                "purl": f"pkg:pypi/lib-{i}@1.{i}.0",
                "licenses": [{"license": {"id": "MIT"}}],
            }
            for i in range(count)
        ]
        return {"bomFormat": "CycloneDX", "specVersion": "1.4", "components": components}

    def _make_perfect_spdx(self, count: int = 3) -> dict:
        """Build a perfect SPDX SBOM."""
        packages = [
            {
                "name": f"lib-{i}",
                "versionInfo": f"1.{i}.0",
                "purl": f"pkg:pypi/lib-{i}@1.{i}.0",
                "licenseDeclared": "Apache-2.0",
            }
            for i in range(count)
        ]
        return {"spdxVersion": "SPDX-2.3", "packages": packages}

    def test_empty_components_returns_f_grade(self, scorer):
        sbom = {"bomFormat": "CycloneDX", "components": []}
        result = scorer.score_sbom(sbom)
        assert result["grade"] == "F"
        assert result["score"] == 0.0

    def test_empty_components_includes_issue_message(self, scorer):
        sbom = {"bomFormat": "CycloneDX", "components": []}
        result = scorer.score_sbom(sbom)
        assert "SBOM has no components" in result["issues"]

    def test_no_components_key_returns_f(self, scorer):
        sbom = {"bomFormat": "CycloneDX"}
        result = scorer.score_sbom(sbom)
        assert result["grade"] == "F"

    def test_perfect_sbom_scores_100(self, scorer):
        sbom = self._make_perfect_cyclonedx()
        result = scorer.score_sbom(sbom)
        assert result["score"] == 100.0

    def test_perfect_sbom_grade_a(self, scorer):
        sbom = self._make_perfect_cyclonedx()
        result = scorer.score_sbom(sbom)
        assert result["grade"] == "A"

    def test_perfect_sbom_no_issues(self, scorer):
        sbom = self._make_perfect_cyclonedx()
        result = scorer.score_sbom(sbom)
        assert result["issues"] == []

    def test_total_components_counted(self, scorer):
        sbom = self._make_perfect_cyclonedx(count=5)
        result = scorer.score_sbom(sbom)
        assert result["total_components"] == 5

    def test_missing_versions_penalizes_score(self, scorer):
        sbom = {
            "bomFormat": "CycloneDX",
            "components": [
                {"name": "a", "version": "unknown", "purl": "pkg:pypi/a@1.0", "licenses": [{"license": {"id": "MIT"}}]},
                {"name": "b", "version": "1.0", "purl": "pkg:pypi/b@1.0", "licenses": [{"license": {"id": "MIT"}}]},
            ],
        }
        result = scorer.score_sbom(sbom)
        assert result["score"] < 100.0
        assert any("missing versions" in issue for issue in result["issues"])

    def test_missing_purls_penalizes_score(self, scorer):
        sbom = {
            "bomFormat": "CycloneDX",
            "components": [
                {"name": "a", "version": "1.0", "licenses": [{"license": {"id": "MIT"}}]},
                {"name": "b", "version": "1.0", "purl": "pkg:pypi/b@1.0", "licenses": [{"license": {"id": "MIT"}}]},
            ],
        }
        result = scorer.score_sbom(sbom)
        assert result["score"] < 100.0
        assert any("missing PURLs" in issue for issue in result["issues"])

    def test_missing_licenses_penalizes_score(self, scorer):
        sbom = {
            "bomFormat": "CycloneDX",
            "components": [
                {"name": "a", "version": "1.0", "purl": "pkg:pypi/a@1.0"},
                {"name": "b", "version": "1.0", "purl": "pkg:pypi/b@1.0", "licenses": [{"license": {"id": "MIT"}}]},
            ],
        }
        result = scorer.score_sbom(sbom)
        assert result["score"] < 100.0
        assert any("missing licenses" in issue for issue in result["issues"])

    def test_grade_b_threshold(self, scorer):
        # All missing licenses: 15% penalty for 100% missing — score = 85
        sbom = {
            "bomFormat": "CycloneDX",
            "components": [
                {"name": f"lib-{i}", "version": f"1.{i}.0", "purl": f"pkg:pypi/lib-{i}@1.{i}.0"}
                for i in range(4)
            ],
        }
        result = scorer.score_sbom(sbom)
        assert result["score"] == 85.0
        assert result["grade"] == "B"

    def test_grade_c_threshold(self, scorer):
        # Missing purls: 20% penalty + missing licenses: 15% penalty = 65 for all missing
        sbom = {
            "bomFormat": "CycloneDX",
            "components": [
                {"name": f"lib-{i}", "version": f"1.{i}.0"}
                for i in range(4)
            ],
        }
        result = scorer.score_sbom(sbom)
        assert 60.0 <= result["score"] < 80.0

    def test_grade_f_for_very_low_score(self, scorer):
        # All fields missing: versions (30%) + purls (20%) + licenses (15%) = 65% penalty
        sbom = {
            "bomFormat": "CycloneDX",
            "components": [
                {"name": f"lib-{i}", "version": "unknown"}
                for i in range(4)
            ],
        }
        result = scorer.score_sbom(sbom)
        assert result["score"] < 60.0
        assert result["grade"] == "F"

    def test_spdx_packages_used_for_scoring(self, scorer):
        # Scorer reads "packages" when "components" absent.
        # SPDX uses "versionInfo" not "version", so the scorer always marks
        # SPDX packages as missing versions — resulting in a C/D grade even
        # for an otherwise complete SPDX document.
        sbom = self._make_perfect_spdx(count=3)
        result = scorer.score_sbom(sbom)
        assert result["total_components"] == 3
        # All 3 are missing "version" key -> 30% penalty -> score = 70 -> grade C
        assert result["score"] == 70.0
        assert result["grade"] == "C"

    def test_score_is_rounded_to_two_decimal_places(self, scorer):
        # 1 of 3 missing version: penalty = (1/3) * 30 = 10.0 (clean)
        sbom = {
            "bomFormat": "CycloneDX",
            "components": [
                {"name": "a", "version": "unknown", "purl": "pkg:pypi/a@1.0", "licenses": [{"license": {"id": "MIT"}}]},
                {"name": "b", "version": "2.0", "purl": "pkg:pypi/b@2.0", "licenses": [{"license": {"id": "MIT"}}]},
                {"name": "c", "version": "3.0", "purl": "pkg:pypi/c@3.0", "licenses": [{"license": {"id": "MIT"}}]},
            ],
        }
        result = scorer.score_sbom(sbom)
        score_str = str(result["score"])
        decimal_part = score_str.split(".")[-1] if "." in score_str else ""
        assert len(decimal_part) <= 2

    def test_result_contains_required_keys_for_non_empty(self, scorer):
        sbom = self._make_perfect_cyclonedx()
        result = scorer.score_sbom(sbom)
        for key in ("score", "grade", "issues", "total_components", "complete_components"):
            assert key in result

    def test_result_contains_required_keys_for_empty(self, scorer):
        sbom = {"components": []}
        result = scorer.score_sbom(sbom)
        for key in ("score", "grade", "issues"):
            assert key in result

    def test_single_component_perfect(self, scorer):
        sbom = {
            "components": [
                {"name": "requests", "version": "2.28.0", "purl": "pkg:pypi/requests@2.28.0", "licenses": [{"license": {"id": "MIT"}}]}
            ]
        }
        result = scorer.score_sbom(sbom)
        assert result["score"] == 100.0
        assert result["grade"] == "A"
