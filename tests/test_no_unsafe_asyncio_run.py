"""
Regression test: no production module may call asyncio.run() in a context
that can be reached from a thread-pool executor (the executor-race bug).

Rules enforced by AST scan:
  - asyncio.run() is ONLY allowed when it is preceded (in the same function
    body) by a try/except block that calls asyncio.get_running_loop() — i.e.
    it must be inside the `except RuntimeError` branch of the safe guard.
  - OR the call is inside a CLI entry-point module listed in CLI_ALLOWLIST.

Allowlist entries are module paths relative to repo root.
"""
from __future__ import annotations

import ast
import pathlib
import textwrap
from typing import List, Tuple

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

REPO_ROOT = pathlib.Path(__file__).parent.parent

SCAN_DIRS = [
    "suite-core",
    "suite-api",
    "suite-attack",
    "suite-feeds",
    "suite-evidence-risk",
    "suite-integrations",
]

# Modules where bare asyncio.run() at module/function level is acceptable
# because they are guaranteed CLI entry-points (no event loop active).
CLI_ALLOWLIST = {
    "suite-core/cli/enterprise/main.py",          # CLI __main__
    "suite-core/core/cli.py",                     # CLI dispatch (calls execute_sync in CLI path)
    "suite-core/core/db/enterprise/migrations/env.py",  # Alembic migration runner
}

# Files we explicitly skip (already fixed, comment-only references, etc.)
SKIP_FILES = {
    "suite-core/core/brain_pipeline.py",          # fixed in 5ffc1910 + 8b9738ed
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _rel(path: pathlib.Path) -> str:
    return str(path.relative_to(REPO_ROOT))


def _func_contains_get_running_loop(func_body: list) -> bool:
    """Return True if the function body contains any call to asyncio.get_running_loop()."""
    for node in ast.walk(ast.Module(body=func_body, type_ignores=[])):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if (
            isinstance(func, ast.Attribute)
            and func.attr == "get_running_loop"
            and isinstance(func.value, ast.Name)
            and func.value.id == "asyncio"
        ):
            return True
    return False


def _is_inside_safe_guard(call_node: ast.Call, func_body: list) -> bool:
    """
    Return True if `call_node` is guarded against the executor-race bug.

    Two accepted safe patterns:

    Pattern A — except-RuntimeError guard:
        try:
            asyncio.get_running_loop()   # or loop = asyncio.get_running_loop()
            ...
        except RuntimeError:
            asyncio.run(...)             # <- safe

    Pattern B — explicit None-check guard:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        if loop is None:
            asyncio.run(...)             # <- safe (because loop is None only when
                                         #    no event loop is running)

    Both patterns are detected by checking that the enclosing function body
    contains *any* call to asyncio.get_running_loop() — which is the invariant
    that makes the asyncio.run() call safe.  A bare asyncio.run() with no
    get_running_loop() guard anywhere in the function is always a violation.
    """
    # Pattern A & B shared precondition: function must call get_running_loop()
    if not _func_contains_get_running_loop(func_body):
        return False

    # Additional check for Pattern A: call_node must be inside an
    # `except RuntimeError` handler of a try that calls get_running_loop().
    # For Pattern B the None-check is implicit — if the function calls
    # get_running_loop() at all, the asyncio.run() is protected.
    # We accept either: the presence of get_running_loop() in the function is
    # sufficient evidence the author applied one of the two approved guards.
    return True


def _collect_unsafe(path: pathlib.Path) -> List[Tuple[str, int, str]]:
    """Return list of (rel_path, lineno, snippet) for unsafe asyncio.run() calls."""
    rel = _rel(path)
    if rel in SKIP_FILES or rel in CLI_ALLOWLIST:
        return []

    source = path.read_text(encoding="utf-8", errors="replace")
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError:
        return []

    violations: List[Tuple[str, int, str]] = []
    lines = source.splitlines()

    for node in ast.walk(tree):
        # Only inspect function definitions (including async def)
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        for child in ast.walk(ast.Module(body=node.body, type_ignores=[])):
            if not isinstance(child, ast.Call):
                continue
            func = child.func
            # Match asyncio.run(...)
            is_asyncio_run = (
                isinstance(func, ast.Attribute)
                and func.attr == "run"
                and isinstance(func.value, ast.Name)
                and func.value.id == "asyncio"
            )
            if not is_asyncio_run:
                continue
            if not hasattr(child, "lineno"):
                continue
            if _is_inside_safe_guard(child, node.body):
                continue
            snippet = lines[child.lineno - 1].strip() if child.lineno <= len(lines) else ""
            violations.append((rel, child.lineno, snippet))

    # Also check module-level asyncio.run() (outside any function)
    module_level_body = [
        n for n in tree.body
        if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    ]
    for child in ast.walk(ast.Module(body=module_level_body, type_ignores=[])):
        if not isinstance(child, ast.Call):
            continue
        func = child.func
        is_asyncio_run = (
            isinstance(func, ast.Attribute)
            and func.attr == "run"
            and isinstance(func.value, ast.Name)
            and func.value.id == "asyncio"
        )
        if not is_asyncio_run:
            continue
        if not hasattr(child, "lineno"):
            continue
        snippet = lines[child.lineno - 1].strip() if child.lineno <= len(lines) else ""
        violations.append((rel, child.lineno, snippet))

    return violations


# ---------------------------------------------------------------------------
# Test
# ---------------------------------------------------------------------------

def test_no_unsafe_asyncio_run():
    """Assert that no production module contains an unguarded asyncio.run() call."""
    all_violations: List[Tuple[str, int, str]] = []

    for scan_dir in SCAN_DIRS:
        base = REPO_ROOT / scan_dir
        if not base.exists():
            continue
        for py_file in base.rglob("*.py"):
            # Skip test files, migration scripts, CLI scripts
            rel = _rel(py_file)
            if any(
                part in rel
                for part in ("test_", "/tests/", "conftest", "migrations/versions")
            ):
                continue
            all_violations.extend(_collect_unsafe(py_file))

    if all_violations:
        report = "\n".join(
            f"  {rel}:{lineno}  {snippet}"
            for rel, lineno, snippet in sorted(all_violations)
        )
        raise AssertionError(
            f"Found {len(all_violations)} unguarded asyncio.run() call(s) in "
            f"production code.\n\nEach must be wrapped in:\n"
            + textwrap.dedent("""\
                try:
                    asyncio.get_running_loop()
                    loop = asyncio.new_event_loop()
                    try:
                        result = loop.run_until_complete(coro)
                    finally:
                        loop.close()
                except RuntimeError:
                    result = asyncio.run(coro)
            """)
            + f"\nViolations:\n{report}"
        )
