"""Smoke tests for suite-evidence-risk hardening fixes.

Covers the 5 OWASP issues fixed:
1. packager.py: subprocess.run timeout added (cosign sign-blob)
2. container.py: wrong except ImportError -> correct exception types
3. container.py: inline `import json` removed, module-level import used
4. git_integration.py: auth token redacted from error messages
5. git_integration.py: git metadata subprocess calls have 30s timeout
"""

import ast
import subprocess
import textwrap
from pathlib import Path

BASE = Path(__file__).parent.parent / "suite-evidence-risk"


# ---------------------------------------------------------------------------
# Issue 1: packager.py cosign subprocess has timeout
# ---------------------------------------------------------------------------
def test_packager_cosign_has_timeout():
    src = (BASE / "evidence" / "packager.py").read_text()
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not (
            isinstance(func, ast.Attribute)
            and func.attr == "run"
            and isinstance(func.value, ast.Name)
            and func.value.id == "subprocess"
        ):
            continue
        kw_names = {kw.arg for kw in node.keywords}
        # Every subprocess.run call must have a timeout
        assert "timeout" in kw_names, (
            f"subprocess.run at line {node.lineno} missing timeout= keyword"
        )


# ---------------------------------------------------------------------------
# Issue 2 & 3: container.py exception types and json import
# ---------------------------------------------------------------------------
def test_container_no_bare_import_error():
    src = (BASE / "risk" / "runtime" / "container.py").read_text()
    # Must NOT have bare `except ImportError` — that was the wrong exception type
    assert "except ImportError" not in src, (
        "container.py still catches ImportError — should catch SubprocessError/JSONDecodeError"
    )


def test_container_catches_json_decode_error():
    src = (BASE / "risk" / "runtime" / "container.py").read_text()
    assert "json.JSONDecodeError" in src, (
        "container.py must catch json.JSONDecodeError for json.loads failures"
    )


def test_container_json_module_level_import():
    src = (BASE / "risk" / "runtime" / "container.py").read_text()
    lines = src.splitlines()
    # json must be imported at module level (before first class/def)
    first_class_or_def = next(
        i for i, l in enumerate(lines) if l.startswith("class ") or l.startswith("def ")
    )
    module_imports = "\n".join(lines[:first_class_or_def])
    assert "import json" in module_imports, (
        "container.py must import json at module level (not inline inside try block)"
    )


def test_container_no_inline_import_json():
    src = (BASE / "risk" / "runtime" / "container.py").read_text()
    # Inline `import json` inside functions should be gone
    inline_count = src.count("                import json")
    assert inline_count == 0, (
        f"container.py has {inline_count} inline 'import json' inside try blocks — should be 0"
    )


# ---------------------------------------------------------------------------
# Issue 4: git_integration.py redacts auth token from error messages
# ---------------------------------------------------------------------------
def test_git_integration_redacts_token_in_error():
    src = (BASE / "risk" / "reachability" / "git_integration.py").read_text()
    assert "url-redacted" in src, (
        "git_integration.py must redact the clone URL in error messages to avoid leaking auth tokens"
    )
    # The raw clone_cmd must not be joined into the error message directly
    assert "' '.join(clone_cmd)" not in src, (
        "git_integration.py must not log raw clone_cmd (contains embedded auth token)"
    )


# ---------------------------------------------------------------------------
# Issue 5: git_integration.py metadata subprocess calls have timeout
# ---------------------------------------------------------------------------
def test_git_metadata_subprocesses_have_timeout():
    src = (BASE / "risk" / "reachability" / "git_integration.py").read_text()
    tree = ast.parse(src)

    # Collect all subprocess.run calls inside get_repository_metadata
    metadata_func = None
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "get_repository_metadata":
            metadata_func = node
            break

    assert metadata_func is not None, "get_repository_metadata function not found"

    subprocess_calls = [
        n for n in ast.walk(metadata_func)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and n.func.attr == "run"
        and isinstance(n.func.value, ast.Name)
        and n.func.value.id == "subprocess"
    ]

    assert len(subprocess_calls) >= 5, (
        f"Expected at least 5 subprocess.run calls in get_repository_metadata, found {len(subprocess_calls)}"
    )

    for call in subprocess_calls:
        kw_names = {kw.arg for kw in call.keywords}
        assert "timeout" in kw_names, (
            f"subprocess.run at line {call.lineno} in get_repository_metadata missing timeout="
        )


# ---------------------------------------------------------------------------
# Import smoke test — modules must be importable without errors
# ---------------------------------------------------------------------------
def test_container_module_imports():
    # sitecustomize.py adds suite-evidence-risk to sys.path, so standard import works
    from risk.runtime.container import ContainerRuntimeAnalyzer  # noqa: F401


def test_git_integration_module_imports():
    from risk.reachability.git_integration import GitRepository, GitRepositoryAnalyzer  # noqa: F401
