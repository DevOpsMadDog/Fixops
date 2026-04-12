"""
Tests for core.pr_generator — dependency vulnerability PR auto-generation.

Covers:
- analyze_finding: Snyk, Trivy, Grype, Dependabot, minimal, unfixable shapes
- Manifest parsing: requirements.txt, package.json
- Manifest updating: requirements.txt, package.json
- Branch naming
- PR template generation: title, body, labels
- create_pr: draft (no token) and mocked GitHub API
- batch_generate
- list_generated_prs / get_pr
- API router endpoints (generate, batch, list, get)

Run with:
    python -m pytest tests/test_pr_generator_new.py -x --tb=short --timeout=10 -q
"""

from __future__ import annotations

import json
import sys
import uuid
from pathlib import Path
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest

# Ensure suite-core is on the path
sys.path.insert(0, str(Path(__file__).parent.parent / "suite-core"))
sys.path.insert(0, str(Path(__file__).parent.parent / "suite-api"))

from core.pr_generator import (
    DependencyFix,
    GeneratedPR,
    PRGenerator,
    PRTemplate,
    _default_manifest,
    _normalize_ecosystem,
)


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def generator(tmp_path):
    """PRGenerator backed by a temp SQLite file, no GitHub token."""
    db = str(tmp_path / "prs.db")
    return PRGenerator(db_path=db)


@pytest.fixture
def generator_with_token(tmp_path):
    """PRGenerator with a fake token to trigger GitHub API path."""
    db = str(tmp_path / "prs_token.db")
    return PRGenerator(db_path=db, github_token="ghp_fake_token")


@pytest.fixture
def snyk_finding() -> Dict[str, Any]:
    return {
        "package_name": "lodash",
        "current_version": "4.17.15",
        "fix": {"versions": ["4.17.21"]},
        "ecosystem": "npm",
        "cve_ids": ["CVE-2021-23337"],
        "severity": "high",
        "manifest_file": "package.json",
    }


@pytest.fixture
def trivy_finding() -> Dict[str, Any]:
    return {
        "artifact": {"name": "requests", "version": "2.25.0", "type": "python"},
        "fixedVersion": "2.31.0",
        "cve": "CVE-2023-32681",
        "severity": "medium",
    }


@pytest.fixture
def grype_finding() -> Dict[str, Any]:
    return {
        "artifact": {"name": "pyyaml", "version": "5.3.1", "type": "python"},
        "vulnerability": {
            "id": "CVE-2020-14343",
            "fixedIn": "5.4",
            "severity": "critical",
        },
    }


@pytest.fixture
def dependabot_finding() -> Dict[str, Any]:
    return {
        "package": "django",
        "currentVersion": "3.2.0",
        "fixVersion": "3.2.19",
        "language": "Python",
        "identifiers": {"CVE": ["CVE-2023-41164"]},
        "severity": "high",
    }


@pytest.fixture
def simple_fix() -> DependencyFix:
    return DependencyFix(
        package_name="requests",
        current_version="2.25.0",
        fix_version="2.31.0",
        ecosystem="pip",
        cve_ids=["CVE-2023-32681"],
        severity="medium",
        manifest_file="requirements.txt",
    )


# ============================================================================
# 1. analyze_finding — various scanner shapes
# ============================================================================


class TestAnalyzeFinding:
    def test_snyk_shape(self, generator, snyk_finding):
        fix = generator.analyze_finding(snyk_finding)
        assert fix is not None
        assert fix.package_name == "lodash"
        assert fix.current_version == "4.17.15"
        assert fix.fix_version == "4.17.21"
        assert fix.ecosystem == "npm"
        assert "CVE-2021-23337" in fix.cve_ids
        assert fix.severity == "high"

    def test_trivy_shape(self, generator, trivy_finding):
        fix = generator.analyze_finding(trivy_finding)
        assert fix is not None
        assert fix.package_name == "requests"
        assert fix.current_version == "2.25.0"
        assert fix.fix_version == "2.31.0"
        assert fix.ecosystem == "pip"
        assert "CVE-2023-32681" in fix.cve_ids

    def test_grype_shape(self, generator, grype_finding):
        fix = generator.analyze_finding(grype_finding)
        assert fix is not None
        assert fix.package_name == "pyyaml"
        assert fix.current_version == "5.3.1"
        assert fix.fix_version == "5.4"
        assert fix.severity == "critical"

    def test_dependabot_shape(self, generator, dependabot_finding):
        fix = generator.analyze_finding(dependabot_finding)
        assert fix is not None
        assert fix.package_name == "django"
        assert fix.current_version == "3.2.0"
        assert fix.fix_version == "3.2.19"
        assert "CVE-2023-41164" in fix.cve_ids

    def test_minimal_valid_finding(self, generator):
        finding = {
            "package_name": "urllib3",
            "current_version": "1.26.0",
            "fix_version": "1.26.18",
            "ecosystem": "pip",
        }
        fix = generator.analyze_finding(finding)
        assert fix is not None
        assert fix.package_name == "urllib3"
        assert fix.cve_ids == []

    def test_no_fix_version_returns_none(self, generator):
        finding = {
            "package_name": "flask",
            "current_version": "1.0.0",
            "ecosystem": "pip",
        }
        assert generator.analyze_finding(finding) is None

    def test_no_package_name_returns_none(self, generator):
        finding = {
            "current_version": "1.0.0",
            "fix_version": "2.0.0",
        }
        assert generator.analyze_finding(finding) is None

    def test_non_dict_returns_none(self, generator):
        assert generator.analyze_finding("not a dict") is None  # type: ignore[arg-type]
        assert generator.analyze_finding(None) is None  # type: ignore[arg-type]

    def test_default_severity_medium(self, generator):
        finding = {
            "package_name": "foo",
            "current_version": "1.0",
            "fix_version": "2.0",
        }
        fix = generator.analyze_finding(finding)
        assert fix is not None
        assert fix.severity == "medium"

    def test_default_manifest_pip(self, generator):
        finding = {
            "package_name": "foo",
            "current_version": "1.0",
            "fix_version": "2.0",
            "ecosystem": "pip",
        }
        fix = generator.analyze_finding(finding)
        assert fix is not None
        assert fix.manifest_file == "requirements.txt"


# ============================================================================
# 2. Manifest parsing
# ============================================================================


class TestManifestParsing:
    def test_parse_requirements_txt_pinned(self, generator):
        content = "requests==2.25.0\nflask>=1.0.0\nDjango==3.2.0\n"
        result = generator._parse_requirements_txt(content)
        assert result["requests"] == "==2.25.0"
        assert "flask" in result
        assert "django" in result

    def test_parse_requirements_txt_comments(self, generator):
        content = "# This is a comment\nrequests==2.25.0\n"
        result = generator._parse_requirements_txt(content)
        assert "requests" in result
        assert len([k for k in result if k.startswith("#")]) == 0

    def test_parse_requirements_txt_no_version(self, generator):
        content = "boto3\n"
        result = generator._parse_requirements_txt(content)
        assert "boto3" in result

    def test_parse_requirements_txt_empty(self, generator):
        assert generator._parse_requirements_txt("") == {}

    def test_parse_package_json_deps(self, generator):
        content = json.dumps({
            "name": "myapp",
            "dependencies": {"lodash": "4.17.15", "axios": "^0.21.0"},
            "devDependencies": {"jest": "27.0.0"},
        })
        result = generator._parse_package_json(content)
        assert result["lodash"] == "4.17.15"
        assert result["axios"] == "^0.21.0"
        assert result["jest"] == "27.0.0"

    def test_parse_package_json_invalid(self, generator):
        assert generator._parse_package_json("not json") == {}

    def test_parse_package_json_empty_deps(self, generator):
        content = json.dumps({"name": "empty"})
        result = generator._parse_package_json(content)
        assert result == {}


# ============================================================================
# 3. Manifest updating
# ============================================================================


class TestManifestUpdating:
    def test_update_requirements_txt_exact_pin(self, generator):
        content = "requests==2.25.0\nflask==1.0.0\n"
        updated = generator._update_requirements_txt(content, "requests", "2.31.0")
        assert "requests==2.31.0" in updated
        assert "flask==1.0.0" in updated

    def test_update_requirements_txt_case_insensitive(self, generator):
        content = "Requests==2.25.0\n"
        updated = generator._update_requirements_txt(content, "requests", "2.31.0")
        assert "2.31.0" in updated

    def test_update_requirements_txt_not_found_appends(self, generator):
        content = "flask==1.0.0\n"
        updated = generator._update_requirements_txt(content, "newpkg", "1.0.0")
        assert "newpkg==1.0.0" in updated
        assert "flask==1.0.0" in updated

    def test_update_requirements_txt_preserves_comments(self, generator):
        content = "# security deps\nrequests==2.25.0\n"
        updated = generator._update_requirements_txt(content, "requests", "2.31.0")
        assert "# security deps" in updated

    def test_update_package_json_existing_dep(self, generator):
        content = json.dumps({
            "name": "app",
            "dependencies": {"lodash": "4.17.15"},
        })
        updated = generator._update_package_json(content, "lodash", "4.17.21")
        data = json.loads(updated)
        assert data["dependencies"]["lodash"] == "4.17.21"

    def test_update_package_json_new_dep_added(self, generator):
        content = json.dumps({"name": "app", "dependencies": {}})
        updated = generator._update_package_json(content, "newpkg", "2.0.0")
        data = json.loads(updated)
        assert "newpkg" in data["dependencies"]

    def test_update_package_json_invalid_json_returns_original(self, generator):
        content = "not json"
        result = generator._update_package_json(content, "lodash", "4.17.21")
        assert result == content


# ============================================================================
# 4. Branch naming
# ============================================================================


class TestBranchNaming:
    def test_branch_name_with_cve(self, generator, simple_fix):
        name = generator._generate_branch_name(simple_fix)
        assert name.startswith("aldeci/fix-CVE-")
        assert "requests" in name

    def test_branch_name_without_cve(self, generator):
        fix = DependencyFix(
            package_name="lodash",
            current_version="4.0.0",
            fix_version="4.17.21",
            ecosystem="npm",
            cve_ids=[],
            manifest_file="package.json",
        )
        name = generator._generate_branch_name(fix)
        assert name.startswith("aldeci/fix-lodash")

    def test_branch_name_sanitizes_special_chars(self, generator):
        fix = DependencyFix(
            package_name="@scope/pkg",
            current_version="1.0.0",
            fix_version="2.0.0",
            ecosystem="npm",
            cve_ids=[],
            manifest_file="package.json",
        )
        name = generator._generate_branch_name(fix)
        # After the "aldeci/fix-" prefix the rest should have no @ or raw slashes
        suffix = name[len("aldeci/fix-"):]
        assert "@" not in suffix
        assert "/" not in suffix


# ============================================================================
# 5. PR template generation
# ============================================================================


class TestBuildPRTemplate:
    def test_template_title_includes_package_and_versions(self, generator, simple_fix):
        tpl = generator.build_pr_template(simple_fix)
        assert "requests" in tpl.title
        assert "2.25.0" in tpl.title
        assert "2.31.0" in tpl.title

    def test_template_title_includes_severity(self, generator, simple_fix):
        tpl = generator.build_pr_template(simple_fix)
        assert "MEDIUM" in tpl.title

    def test_template_body_contains_cve(self, generator, simple_fix):
        tpl = generator.build_pr_template(simple_fix)
        assert "CVE-2023-32681" in tpl.body

    def test_template_body_contains_aldeci_badge(self, generator, simple_fix):
        tpl = generator.build_pr_template(simple_fix)
        assert "ALDECI" in tpl.body

    def test_template_body_contains_nvd_link(self, generator, simple_fix):
        tpl = generator.build_pr_template(simple_fix)
        assert "nvd.nist.gov" in tpl.body

    def test_template_labels_include_severity(self, generator, simple_fix):
        tpl = generator.build_pr_template(simple_fix)
        assert "medium" in tpl.labels
        assert "security" in tpl.labels
        assert "dependencies" in tpl.labels

    def test_template_branch_name_set(self, generator, simple_fix):
        tpl = generator.build_pr_template(simple_fix)
        assert tpl.branch_name.startswith("aldeci/fix-")

    def test_template_no_cve_body_graceful(self, generator):
        fix = DependencyFix(
            package_name="boto3",
            current_version="1.20.0",
            fix_version="1.34.0",
            ecosystem="pip",
            cve_ids=[],
            manifest_file="requirements.txt",
        )
        tpl = generator.build_pr_template(fix)
        assert "boto3" in tpl.title
        assert tpl.body  # non-empty body even without CVEs


# ============================================================================
# 6. create_pr — draft (no token)
# ============================================================================


class TestCreatePRDraft:
    def test_create_pr_draft_no_token(self, generator, simple_fix):
        pr = generator.create_pr(simple_fix, repo="Fixops", owner="DevOpsMadDog")
        assert pr.status == "draft"
        assert pr.pr_number is None
        assert pr.repo == "DevOpsMadDog/Fixops"

    def test_create_pr_persisted(self, generator, simple_fix):
        pr = generator.create_pr(simple_fix, repo="Fixops", owner="DevOpsMadDog")
        fetched = generator.get_pr(pr.id)
        assert fetched is not None
        assert fetched.id == pr.id

    def test_create_pr_org_id_stored(self, generator, simple_fix):
        pr = generator.create_pr(
            simple_fix, repo="Fixops", owner="DevOpsMadDog", org_id="acme"
        )
        fetched = generator.get_pr(pr.id)
        assert fetched is not None
        assert fetched.org_id == "acme"


# ============================================================================
# 7. create_pr — mocked GitHub API
# ============================================================================


class TestCreatePRWithToken:
    def test_create_pr_success(self, generator_with_token, simple_fix):
        mock_responses = [
            {"default_branch": "main"},
            {"object": {"sha": "abc123"}},
            {"ref": "refs/heads/aldeci/fix-CVE-2023-32681-requests"},
            {"number": 42, "html_url": "https://github.com/owner/repo/pull/42"},
        ]
        call_count = {"n": 0}

        def fake_call(method, url, payload=None):
            idx = call_count["n"]
            call_count["n"] += 1
            return mock_responses[idx]

        generator_with_token._call_github_api = fake_call

        pr = generator_with_token.create_pr(
            simple_fix, repo="Fixops", owner="DevOpsMadDog"
        )
        assert pr.status == "created"
        assert pr.pr_number == 42

    def test_create_pr_api_failure_marks_failed(self, generator_with_token, simple_fix):
        def fake_call(method, url, payload=None):
            raise RuntimeError("GitHub API timeout")

        generator_with_token._call_github_api = fake_call
        pr = generator_with_token.create_pr(
            simple_fix, repo="Fixops", owner="DevOpsMadDog"
        )
        assert pr.status == "failed"


# ============================================================================
# 8. batch_generate
# ============================================================================


class TestBatchGenerate:
    def test_batch_generates_fixable_findings(self, generator, snyk_finding, trivy_finding):
        prs = generator.batch_generate(
            findings=[snyk_finding, trivy_finding],
            repo="Fixops",
            owner="DevOpsMadDog",
        )
        assert len(prs) == 2

    def test_batch_skips_unfixable_findings(self, generator, snyk_finding):
        unfixable = {"package_name": "foo"}  # no fix_version
        prs = generator.batch_generate(
            findings=[snyk_finding, unfixable],
            repo="Fixops",
            owner="DevOpsMadDog",
        )
        assert len(prs) == 1

    def test_batch_empty_findings(self, generator):
        prs = generator.batch_generate(findings=[], repo="Fixops", owner="DevOpsMadDog")
        assert prs == []

    def test_batch_all_prs_persisted(self, generator, snyk_finding, trivy_finding):
        prs = generator.batch_generate(
            findings=[snyk_finding, trivy_finding],
            repo="Fixops",
            owner="DevOpsMadDog",
            org_id="batch-test",
        )
        stored = generator.list_generated_prs(org_id="batch-test")
        assert len(stored) == len(prs)


# ============================================================================
# 9. list_generated_prs / get_pr
# ============================================================================


class TestStorage:
    def test_list_prs_empty(self, generator):
        assert generator.list_generated_prs() == []

    def test_list_prs_all(self, generator, simple_fix):
        generator.create_pr(simple_fix, repo="Fixops", owner="Owner1", org_id="o1")
        generator.create_pr(simple_fix, repo="Fixops", owner="Owner2", org_id="o2")
        all_prs = generator.list_generated_prs()
        assert len(all_prs) == 2

    def test_list_prs_filter_org_id(self, generator, simple_fix):
        generator.create_pr(simple_fix, repo="Fixops", owner="O", org_id="acme")
        generator.create_pr(simple_fix, repo="Fixops", owner="O", org_id="other")
        acme_prs = generator.list_generated_prs(org_id="acme")
        assert all(pr.org_id == "acme" for pr in acme_prs)
        assert len(acme_prs) == 1

    def test_list_prs_filter_status(self, generator, simple_fix):
        pr = generator.create_pr(simple_fix, repo="Fixops", owner="O")
        assert pr.status == "draft"
        draft_prs = generator.list_generated_prs(status="draft")
        assert len(draft_prs) >= 1
        created_prs = generator.list_generated_prs(status="created")
        assert len(created_prs) == 0

    def test_get_pr_found(self, generator, simple_fix):
        pr = generator.create_pr(simple_fix, repo="Fixops", owner="O")
        fetched = generator.get_pr(pr.id)
        assert fetched is not None
        assert fetched.id == pr.id
        assert fetched.dependency_fix.package_name == simple_fix.package_name

    def test_get_pr_not_found(self, generator):
        assert generator.get_pr("nonexistent-id") is None


# ============================================================================
# 10. Helper functions
# ============================================================================


class TestHelpers:
    def test_normalize_ecosystem_python(self):
        assert _normalize_ecosystem("python") == "pip"
        assert _normalize_ecosystem("Python") == "pip"
        assert _normalize_ecosystem("pip") == "pip"

    def test_normalize_ecosystem_node(self):
        assert _normalize_ecosystem("javascript") == "npm"
        assert _normalize_ecosystem("node") == "npm"
        assert _normalize_ecosystem("npm") == "npm"

    def test_normalize_ecosystem_java(self):
        assert _normalize_ecosystem("java") == "maven"
        assert _normalize_ecosystem("gradle") == "maven"

    def test_normalize_ecosystem_go(self):
        assert _normalize_ecosystem("go") == "go"
        assert _normalize_ecosystem("golang") == "go"

    def test_normalize_ecosystem_unknown(self):
        result = _normalize_ecosystem("rust")
        assert result == "rust"

    def test_default_manifest_pip(self):
        assert _default_manifest("pip") == "requirements.txt"

    def test_default_manifest_npm(self):
        assert _default_manifest("npm") == "package.json"

    def test_default_manifest_maven(self):
        assert _default_manifest("maven") == "pom.xml"

    def test_default_manifest_go(self):
        assert _default_manifest("go") == "go.mod"


# ============================================================================
# 11. generate_manifest_diff
# ============================================================================


class TestGenerateManifestDiff:
    def test_diff_pip_no_file(self, generator, simple_fix, tmp_path):
        diff = generator.generate_manifest_diff(simple_fix, str(tmp_path))
        assert "---" in diff
        assert "+++" in diff
        assert "2.31.0" in diff

    def test_diff_npm_no_file(self, generator, tmp_path):
        fix = DependencyFix(
            package_name="lodash",
            current_version="4.17.15",
            fix_version="4.17.21",
            ecosystem="npm",
            cve_ids=["CVE-2021-23337"],
            severity="high",
            manifest_file="package.json",
        )
        diff = generator.generate_manifest_diff(fix, str(tmp_path))
        assert "4.17.21" in diff

    def test_diff_with_real_file(self, generator, simple_fix, tmp_path):
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("requests==2.25.0\nflask==2.0.0\n")
        diff = generator.generate_manifest_diff(simple_fix, str(tmp_path))
        assert "2.31.0" in diff
        assert "requirements.txt" in diff


# ============================================================================
# 12. API router (direct function calls — no HTTP server needed)
# ============================================================================


class TestAPIRouter:
    @pytest.fixture(autouse=True)
    def reset_generator(self, tmp_path, monkeypatch):
        """Inject a fresh temp-db generator into the router module."""
        import apps.api.pr_generator_router as router_mod
        from core.pr_generator import PRGenerator

        fresh_gen = PRGenerator(db_path=str(tmp_path / "api_test.db"))
        monkeypatch.setattr(router_mod, "_generator", fresh_gen)

    def test_generate_valid_finding(self, snyk_finding):
        import apps.api.pr_generator_router as router_mod
        from apps.api.pr_generator_router import GeneratePRRequest

        req = GeneratePRRequest(
            finding=snyk_finding, repo="Fixops", owner="DevOpsMadDog"
        )
        result = router_mod.generate_pr(req)
        assert result["status"] == "draft"
        assert result["repo"] == "DevOpsMadDog/Fixops"

    def test_generate_unfixable_raises_422(self):
        import apps.api.pr_generator_router as router_mod
        from apps.api.pr_generator_router import GeneratePRRequest
        from fastapi import HTTPException

        req = GeneratePRRequest(
            finding={"package_name": "foo"}, repo="Fixops", owner="O"
        )
        with pytest.raises(HTTPException) as exc_info:
            router_mod.generate_pr(req)
        assert exc_info.value.status_code == 422

    def test_batch_generate(self, snyk_finding, trivy_finding):
        import apps.api.pr_generator_router as router_mod
        from apps.api.pr_generator_router import BatchGeneratePRRequest

        req = BatchGeneratePRRequest(
            findings=[snyk_finding, trivy_finding, {"bad": "finding"}],
            repo="Fixops",
            owner="DevOpsMadDog",
        )
        result = router_mod.batch_generate_prs(req)
        assert result["generated"] == 2
        assert result["skipped"] == 1
        assert len(result["prs"]) == 2

    def test_list_prs_empty(self):
        import apps.api.pr_generator_router as router_mod

        result = router_mod.list_prs()
        assert result["count"] == 0
        assert result["prs"] == []

    def test_list_prs_after_generate(self, snyk_finding):
        import apps.api.pr_generator_router as router_mod
        from apps.api.pr_generator_router import GeneratePRRequest

        req = GeneratePRRequest(
            finding=snyk_finding, repo="Fixops", owner="DevOpsMadDog"
        )
        router_mod.generate_pr(req)
        result = router_mod.list_prs()
        assert result["count"] == 1

    def test_get_pr_found(self, snyk_finding):
        import apps.api.pr_generator_router as router_mod
        from apps.api.pr_generator_router import GeneratePRRequest

        req = GeneratePRRequest(
            finding=snyk_finding, repo="Fixops", owner="DevOpsMadDog"
        )
        created = router_mod.generate_pr(req)
        fetched = router_mod.get_pr(created["id"])
        assert fetched["id"] == created["id"]

    def test_get_pr_not_found_raises_404(self):
        import apps.api.pr_generator_router as router_mod
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc_info:
            router_mod.get_pr("does-not-exist")
        assert exc_info.value.status_code == 404
