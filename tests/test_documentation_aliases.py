from __future__ import annotations

from pathlib import Path


def _has_non_empty_file(repo_root: Path, candidates: tuple[str, ...]) -> bool:
    for name in candidates:
        path = repo_root / name
        if path.is_file() and path.stat().st_size > 0:
            return True
    return False


def test_root_readme_alias_present() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    assert _has_non_empty_file(
        repo_root,
        ("README.md", "readme.md"),
    ), "Expected README.md or readme.md to exist and contain documentation."


def test_deep_reference_readme_alias_present() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    assert _has_non_empty_file(
        repo_root,
        ("readme_updated.md", "updated_readme.md"),
    ), "Expected readme_updated.md or updated_readme.md to exist and contain documentation."
