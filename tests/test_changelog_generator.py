"""
Comprehensive tests for the ALDECI Changelog Auto-Generator.

Tests cover:
- Conventional commit parsing (feat, fix, docs, refactor, test, perf, security)
- Beast Mode commit parsing (beast-mode(type): description)
- Breaking change detection (! suffix, BREAKING CHANGE body)
- Grouping by ChangeType
- Semver suggestion (major / minor / patch)
- All 3 output formats (Markdown, JSON, HTML)
- Release notes generation
- Edge cases: unknown types, empty input, mixed formats
- API router request/response models (unit-level)

30+ tests, all must pass with --timeout=10.
"""

from __future__ import annotations

import json
import sys
from typing import List

import pytest

sys.path.insert(0, "suite-core")
sys.path.insert(0, "suite-api")

from core.changelog_generator import (
    ChangeEntry,
    ChangelogGenerator,
    ChangelogVersion,
    ChangeType,
    OutputFormat,
)


# ============================================================================
# FIXTURES
# ============================================================================


@pytest.fixture
def gen() -> ChangelogGenerator:
    return ChangelogGenerator()


CONVENTIONAL_SAMPLES = """\
feat(auth): add OAuth2 login support
fix(api): handle null response from scanner
docs: update README with new setup steps
refactor(core): extract helper into utility module
test(connectors): add integration tests for GitHub connector
perf(db): add index on findings table for faster queries
security(auth): patch JWT secret exposure in logs
feat!: remove legacy v1 API endpoints
"""

BEAST_MODE_SAMPLES = """\
beast-mode(feature): Add TrustGraph knowledge cores with 162 entities
beast-mode(fix): Correct CTEM pipeline stage transitions
beast-mode(docs): Update ALDECI rearchitecture spec
beast-mode(docker): Full-stack docker compose with UI + TrustGraph init
beast-mode(tests): Add 81 tests for TrustGraph indexer
beast-mode(dashboard): CISO executive dashboard with risk posture
beast-mode(trustgraph): Populate 5 Knowledge Cores
beast-mode(security): Patch API key exposure in error responses
beast-mode(perf): Reduce LLM council latency by 40%
beast-mode(wip): Incremental progress checkpoint
"""

TABULAR_SAMPLES = """\
abc1234\tAlice Dev\t2026-04-12T10:00:00Z\tfeat(api): add changelog endpoints
def5678\tBob Ops\t2026-04-12T11:00:00Z\tfix(scanner): handle empty CVE list
ghi9012\tCarol CTO\t2026-04-12T12:00:00Z\tbeast-mode(dashboard): new CISO view
"""

MIXED_SAMPLES = CONVENTIONAL_SAMPLES + BEAST_MODE_SAMPLES


# ============================================================================
# CONVENTIONAL COMMIT PARSING
# ============================================================================


class TestConventionalParsing:
    def test_feat_parses_to_feature(self, gen: ChangelogGenerator) -> None:
        entry = gen._parse_conventional_commit("feat(auth): add OAuth2 login")
        assert entry is not None
        assert entry.type == ChangeType.FEATURE
        assert entry.scope == "auth"
        assert "OAuth2" in entry.description

    def test_fix_parses_to_fix(self, gen: ChangelogGenerator) -> None:
        entry = gen._parse_conventional_commit("fix(api): handle null response")
        assert entry is not None
        assert entry.type == ChangeType.FIX

    def test_docs_parses_to_docs(self, gen: ChangelogGenerator) -> None:
        entry = gen._parse_conventional_commit("docs: update README")
        assert entry is not None
        assert entry.type == ChangeType.DOCS
        assert entry.scope is None

    def test_refactor_parses_correctly(self, gen: ChangelogGenerator) -> None:
        entry = gen._parse_conventional_commit("refactor(core): extract helper")
        assert entry is not None
        assert entry.type == ChangeType.REFACTOR
        assert entry.scope == "core"

    def test_test_parses_correctly(self, gen: ChangelogGenerator) -> None:
        entry = gen._parse_conventional_commit("test(connectors): add integration tests")
        assert entry is not None
        assert entry.type == ChangeType.TEST

    def test_perf_parses_to_performance(self, gen: ChangelogGenerator) -> None:
        entry = gen._parse_conventional_commit("perf(db): add index on findings table")
        assert entry is not None
        assert entry.type == ChangeType.PERFORMANCE

    def test_security_parses_to_security(self, gen: ChangelogGenerator) -> None:
        entry = gen._parse_conventional_commit("security(auth): patch JWT secret exposure")
        assert entry is not None
        assert entry.type == ChangeType.SECURITY

    def test_breaking_bang_sets_breaking_flag(self, gen: ChangelogGenerator) -> None:
        entry = gen._parse_conventional_commit("feat!: remove legacy v1 API endpoints")
        assert entry is not None
        assert entry.breaking is True
        assert entry.type == ChangeType.BREAKING

    def test_breaking_change_body_sets_breaking_flag(self, gen: ChangelogGenerator) -> None:
        msg = "feat(api): new endpoint\n\nBREAKING CHANGE: removes old auth header"
        entry = gen._parse_conventional_commit(msg)
        assert entry is not None
        assert entry.breaking is True

    def test_unknown_type_returns_none(self, gen: ChangelogGenerator) -> None:
        entry = gen._parse_conventional_commit("randomtype: something happened")
        assert entry is None

    def test_empty_message_returns_none(self, gen: ChangelogGenerator) -> None:
        entry = gen._parse_conventional_commit("")
        assert entry is None

    def test_non_commit_message_returns_none(self, gen: ChangelogGenerator) -> None:
        entry = gen._parse_conventional_commit("Just a random commit message with no prefix")
        assert entry is None


# ============================================================================
# BEAST MODE COMMIT PARSING
# ============================================================================


class TestBeastModeParsing:
    def test_beast_mode_feature_parses(self, gen: ChangelogGenerator) -> None:
        entry = gen._parse_beast_mode_commit(
            "beast-mode(feature): Add TrustGraph knowledge cores"
        )
        assert entry is not None
        assert entry.type == ChangeType.FEATURE
        assert entry.scope == "feature"

    def test_beast_mode_fix_parses(self, gen: ChangelogGenerator) -> None:
        entry = gen._parse_beast_mode_commit("beast-mode(fix): Correct pipeline transitions")
        assert entry is not None
        assert entry.type == ChangeType.FIX

    def test_beast_mode_docker_parses_as_feature(self, gen: ChangelogGenerator) -> None:
        entry = gen._parse_beast_mode_commit(
            "beast-mode(docker): Full-stack docker compose"
        )
        assert entry is not None
        assert entry.type == ChangeType.FEATURE

    def test_beast_mode_security_parses(self, gen: ChangelogGenerator) -> None:
        entry = gen._parse_beast_mode_commit(
            "beast-mode(security): Patch API key exposure"
        )
        assert entry is not None
        assert entry.type == ChangeType.SECURITY

    def test_beast_mode_wip_parses_as_other(self, gen: ChangelogGenerator) -> None:
        entry = gen._parse_beast_mode_commit("beast-mode(wip): Incremental checkpoint")
        assert entry is not None
        assert entry.type == ChangeType.OTHER

    def test_non_beast_mode_returns_none(self, gen: ChangelogGenerator) -> None:
        entry = gen._parse_beast_mode_commit("feat(api): not a beast mode commit")
        assert entry is None

    def test_beast_mode_case_insensitive(self, gen: ChangelogGenerator) -> None:
        entry = gen._parse_beast_mode_commit("Beast-Mode(Feature): Something")
        assert entry is not None
        assert entry.type == ChangeType.FEATURE


# ============================================================================
# PARSE COMMITS (BULK)
# ============================================================================


class TestParseCommits:
    def test_parse_conventional_block(self, gen: ChangelogGenerator) -> None:
        entries = gen.parse_commits(CONVENTIONAL_SAMPLES)
        assert len(entries) >= 7

    def test_parse_beast_mode_block(self, gen: ChangelogGenerator) -> None:
        entries = gen.parse_commits(BEAST_MODE_SAMPLES)
        assert len(entries) >= 8

    def test_parse_mixed_block(self, gen: ChangelogGenerator) -> None:
        entries = gen.parse_commits(MIXED_SAMPLES)
        assert len(entries) >= 15

    def test_parse_tabular_format(self, gen: ChangelogGenerator) -> None:
        entries = gen.parse_commits(TABULAR_SAMPLES)
        assert len(entries) == 3
        assert entries[0].commit_sha == "abc1234"
        assert entries[0].author == "Alice Dev"
        assert entries[1].type == ChangeType.FIX
        assert entries[2].type == ChangeType.FEATURE  # dashboard mapped to FEATURE

    def test_parse_empty_returns_empty(self, gen: ChangelogGenerator) -> None:
        entries = gen.parse_commits("")
        assert entries == []

    def test_parse_blank_lines_skipped(self, gen: ChangelogGenerator) -> None:
        text = "\n\n  \nfeat: add something\n\n\n"
        entries = gen.parse_commits(text)
        assert len(entries) == 1


# ============================================================================
# GROUP BY TYPE
# ============================================================================


class TestGroupByType:
    def test_groups_are_correct_types(self, gen: ChangelogGenerator) -> None:
        entries = gen.parse_commits(CONVENTIONAL_SAMPLES)
        groups = gen.group_by_type(entries)
        # Should have FEATURE, FIX, DOCS, etc.
        assert ChangeType.FEATURE in groups or ChangeType.BREAKING in groups
        assert ChangeType.FIX in groups

    def test_empty_groups_excluded(self, gen: ChangelogGenerator) -> None:
        entries = gen.parse_commits("feat: add login\nfix: correct typo\n")
        groups = gen.group_by_type(entries)
        # DOCS, TEST, etc. should not be present
        assert ChangeType.DOCS not in groups
        assert ChangeType.TEST not in groups

    def test_all_entries_preserved(self, gen: ChangelogGenerator) -> None:
        entries = gen.parse_commits(MIXED_SAMPLES)
        groups = gen.group_by_type(entries)
        total = sum(len(v) for v in groups.values())
        assert total == len(entries)


# ============================================================================
# VERSION SUGGESTION
# ============================================================================


class TestSuggestVersion:
    def test_feature_bumps_minor(self, gen: ChangelogGenerator) -> None:
        entries = gen.parse_commits("feat: add new feature\n")
        version = gen.suggest_version(entries, "1.2.3")
        assert version == "1.3.0"

    def test_fix_bumps_patch(self, gen: ChangelogGenerator) -> None:
        entries = gen.parse_commits("fix: correct null pointer\n")
        version = gen.suggest_version(entries, "1.2.3")
        assert version == "1.2.4"

    def test_breaking_bumps_major(self, gen: ChangelogGenerator) -> None:
        entries = gen.parse_commits("feat!: remove old API\n")
        version = gen.suggest_version(entries, "1.2.3")
        assert version == "2.0.0"

    def test_default_version_fallback(self, gen: ChangelogGenerator) -> None:
        entries = gen.parse_commits("fix: something small\n")
        version = gen.suggest_version(entries)
        assert version == "0.0.1"

    def test_empty_entries_patch_bump(self, gen: ChangelogGenerator) -> None:
        version = gen.suggest_version([], "2.0.0")
        assert version == "2.0.1"

    def test_breaking_beats_feature(self, gen: ChangelogGenerator) -> None:
        entries = gen.parse_commits("feat: add thing\nfeat!: remove thing\n")
        version = gen.suggest_version(entries, "3.4.5")
        assert version == "4.0.0"


# ============================================================================
# MARKDOWN OUTPUT
# ============================================================================


class TestMarkdownOutput:
    def test_markdown_contains_version(self, gen: ChangelogGenerator) -> None:
        entries = gen.parse_commits("feat: add login\n")
        md = gen.generate_markdown(entries, "1.0.0")
        assert "1.0.0" in md

    def test_markdown_contains_section_heading(self, gen: ChangelogGenerator) -> None:
        entries = gen.parse_commits("feat: add login\n")
        md = gen.generate_markdown(entries, "1.0.0")
        assert "New Features" in md

    def test_markdown_fix_section(self, gen: ChangelogGenerator) -> None:
        entries = gen.parse_commits("fix: correct bug\n")
        md = gen.generate_markdown(entries, "1.0.0")
        assert "Bug Fixes" in md

    def test_markdown_breaking_section_first(self, gen: ChangelogGenerator) -> None:
        entries = gen.parse_commits("feat!: remove old API\nfeat: add login\n")
        md = gen.generate_markdown(entries, "2.0.0")
        assert md.index("Breaking Changes") < md.index("New Features")

    def test_generate_changelog_markdown(self, gen: ChangelogGenerator) -> None:
        entries = gen.parse_commits("feat: something\n")
        out = gen.generate_changelog(entries, "1.0.0", OutputFormat.MARKDOWN)
        assert out.startswith("##")


# ============================================================================
# JSON OUTPUT
# ============================================================================


class TestJsonOutput:
    def test_json_is_valid(self, gen: ChangelogGenerator) -> None:
        entries = gen.parse_commits("feat: add login\nfix: correct bug\n")
        raw = gen.generate_json(entries, "1.0.0")
        data = json.loads(raw)
        assert data["version"] == "1.0.0"

    def test_json_has_sections(self, gen: ChangelogGenerator) -> None:
        entries = gen.parse_commits("feat: add login\n")
        data = json.loads(gen.generate_json(entries, "1.0.0"))
        assert "New Features" in data["sections"]

    def test_json_total_entries(self, gen: ChangelogGenerator) -> None:
        entries = gen.parse_commits("feat: a\nfix: b\ndocs: c\n")
        data = json.loads(gen.generate_json(entries, "1.0.0"))
        assert data["total_entries"] == 3

    def test_generate_changelog_json(self, gen: ChangelogGenerator) -> None:
        entries = gen.parse_commits("feat: something\n")
        raw = gen.generate_changelog(entries, "1.0.0", OutputFormat.JSON)
        data = json.loads(raw)
        assert "version" in data


# ============================================================================
# HTML OUTPUT
# ============================================================================


class TestHtmlOutput:
    def test_html_is_valid_structure(self, gen: ChangelogGenerator) -> None:
        entries = gen.parse_commits("feat: add login\n")
        html = gen.generate_html(entries, "1.0.0")
        assert "<html" in html
        assert "</html>" in html

    def test_html_contains_version(self, gen: ChangelogGenerator) -> None:
        entries = gen.parse_commits("feat: add login\n")
        html = gen.generate_html(entries, "1.0.0")
        assert "1.0.0" in html

    def test_html_contains_list_items(self, gen: ChangelogGenerator) -> None:
        entries = gen.parse_commits("feat: add login\nfix: correct bug\n")
        html = gen.generate_html(entries, "1.0.0")
        assert "<li>" in html

    def test_generate_changelog_html(self, gen: ChangelogGenerator) -> None:
        entries = gen.parse_commits("feat: something\n")
        out = gen.generate_changelog(entries, "1.0.0", OutputFormat.HTML)
        assert "<!DOCTYPE html>" in out

    def test_html_breaking_marked(self, gen: ChangelogGenerator) -> None:
        entries = gen.parse_commits("feat!: remove v1 API\n")
        html = gen.generate_html(entries, "2.0.0")
        assert "(breaking)" in html


# ============================================================================
# RELEASE NOTES
# ============================================================================


class TestReleaseNotes:
    def test_release_notes_contains_version(self, gen: ChangelogGenerator) -> None:
        entries = gen.parse_commits("feat: add login\n")
        notes = gen.generate_release_notes("1.0.0", entries)
        assert "1.0.0" in notes

    def test_release_notes_highlights_breaking(self, gen: ChangelogGenerator) -> None:
        entries = gen.parse_commits("feat!: remove old API\nfeat: add new\n")
        notes = gen.generate_release_notes("2.0.0", entries)
        assert "BREAKING" in notes

    def test_release_notes_shows_highlights(self, gen: ChangelogGenerator) -> None:
        entries = gen.parse_commits(
            "feat: add auth\nfeat: add dashboard\nfix: correct bug\n"
        )
        notes = gen.generate_release_notes("1.1.0", entries)
        assert "Highlights" in notes

    def test_release_notes_summary_counts(self, gen: ChangelogGenerator) -> None:
        entries = gen.parse_commits("feat: a\nfeat: b\nfix: c\n")
        notes = gen.generate_release_notes("1.1.0", entries)
        assert "feature" in notes.lower() or "fix" in notes.lower()


# ============================================================================
# PYDANTIC MODELS
# ============================================================================


class TestModels:
    def test_change_entry_defaults(self) -> None:
        entry = ChangeEntry(type=ChangeType.FEATURE, description="test")
        assert entry.breaking is False
        assert entry.scope is None
        assert entry.commit_sha == ""

    def test_changelog_version_model(self) -> None:
        version = ChangelogVersion(version="1.0.0", summary="initial release")
        assert version.version == "1.0.0"
        assert isinstance(version.entries, list)
        assert version.date != ""

    def test_change_type_values(self) -> None:
        assert ChangeType.FEATURE.value == "feature"
        assert ChangeType.BREAKING.value == "breaking"
        assert ChangeType.SECURITY.value == "security"

    def test_output_format_values(self) -> None:
        assert OutputFormat.MARKDOWN.value == "markdown"
        assert OutputFormat.JSON.value == "json"
        assert OutputFormat.HTML.value == "html"
