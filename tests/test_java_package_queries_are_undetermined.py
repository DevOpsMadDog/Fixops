"""A package-level query about Java answers nothing, and must say so.

Measured 2026-08-31 on spring-petclinic (50 files, 835 nodes, 1,507 edges — the
first time ``parse_java_repo`` had ever been run): the number of graph nodes
whose name begins with ``org.postgresql.``, ``org.springframework.``,
``java.sql.`` or ``org.h2.`` is **zero**.

That is not a parser bug so much as how Java is written. A call site is
``Assert.notNull(...)``; the package lives in an ``import`` at the top of the
file, and a walk over ``method_invocation`` nodes never sees it. Python is the
opposite — ``requests.get`` carries its package in the expression, and the
FixOps graph holds 114 nodes under ``requests.%``.

So the pipeline's package fallback, ``f"{package}.%"``, cannot match a Java
graph whether or not the library is used — and "no callers" was being read as
"unreachable", with a priority downgrade attached. On 21 real Maven advisories
for this repo, 14 had no extractable symbol and would have been confidently
eliminated on a question that could not have returned anything.

These tests pin the asymmetry: Python keeps its elimination (it is real and it
is what makes the feature worth having), Java gets "undetermined".
"""

from __future__ import annotations

from core.brain_pipeline import (
    _PACKAGE_QUALIFIED_LANGUAGES,
    _package_query_is_answerable,
)


def test_java_cannot_answer_a_package_level_question() -> None:
    assert not _package_query_is_answerable(
        {"package_name": "postgresql", "language": "java"}
    )


def test_java_is_recognised_through_its_scanner_too() -> None:
    """Findings arrive from a tool, not always with a language field."""
    assert not _package_query_is_answerable(
        {"package_name": "postgresql", "source_tool": "owasp-dependency-check"}
    )
    assert not _package_query_is_answerable(
        {"package_name": "h2", "source_tool": "maven"}
    )


def test_python_and_javascript_keep_their_elimination() -> None:
    """The fix must not disarm the ecosystems where the query does work.

    84% of Python findings and 91% of TypeScript ones are eliminated by exactly
    this path; turning it off everywhere would be a bigger regression than the
    bug.
    """
    for language in ("python", "javascript", "typescript"):
        assert _package_query_is_answerable(
            {"package_name": "requests", "language": language}
        ), language


def test_an_unknown_language_stays_answerable() -> None:
    """Matches _graph_covers: with nothing to go on, a non-empty graph is the
    best we can say. Widening "undetermined" to every unrecognised ecosystem
    would quietly delete the feature."""
    assert _package_query_is_answerable({"package_name": "requests"})


def test_go_and_rust_are_not_silently_claimed() -> None:
    """Neither has been measured. Until someone runs the parser and counts the
    nodes, they are not in the set — the same standard Java was just held to."""
    assert "go" not in _PACKAGE_QUALIFIED_LANGUAGES
    assert "rust" not in _PACKAGE_QUALIFIED_LANGUAGES
