"""An ``except`` clause must name an exception that exists.

``suite-core/core/enterprise/security.py`` caught ``jwt.JWTError`` for eight
months. PyJWT has no such attribute — ``JWTError`` is python-jose's name, and
the two libraries are near-interchangeable everywhere *except* here. So the
clause written to turn a bad token into a clean 401 instead raised

    AttributeError: module 'jwt' has no attribute 'JWTError'

and three endpoints returned 500. The failure is invisible until the exception
it was meant to handle actually fires, which is exactly when you least want a
new one: a customer presenting an expired or malformed token got
"Internal server error" instead of "Invalid token", and the logs blamed the
handler rather than the credential.

Import-time checks cannot catch this — the module imports fine, the attribute
is only looked up when the ``except`` is evaluated. Nor could the existing
``test_no_calls_to_nonexistent_methods`` gate, which walks *calls* on
module-level singletons; this is an attribute reference on an imported module.

Scope: modules that resolve outside this repository (stdlib and site-packages).
Those are the ones where a name can be confidently checked with ``hasattr`` and
where cross-library confusion actually happens. First-party modules are skipped
rather than imported, because importing them has side effects.
"""

from __future__ import annotations

import ast
import importlib
import pathlib
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
SUITES = ["suite-api", "suite-core", "suite-attack", "suite-feeds",
          "suite-evidence-risk", "suite-integrations"]


def _module_aliases(tree: ast.AST) -> dict[str, str]:
    """Local name -> dotted module, for plain ``import x`` / ``import x as y``."""
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                aliases[alias.asname or alias.name.split(".")[0]] = alias.name
    return aliases


def _is_external(module_name: str) -> bool:
    """True when the module lives outside this repo (stdlib or site-packages)."""
    if module_name in sys.builtin_module_names:
        return True
    try:
        module = importlib.import_module(module_name)
    except Exception:  # noqa: BLE001 - unimportable here is simply not checkable
        return False
    origin = getattr(module, "__file__", None)
    if origin is None:
        return True
    try:
        pathlib.Path(origin).resolve().relative_to(REPO)
    except ValueError:
        return True
    return False


def _handler_attributes(tree: ast.AST):
    """Yield (lineno, module_local_name, attribute) for every caught X.Y."""
    for node in ast.walk(tree):
        if not isinstance(node, ast.ExceptHandler) or node.type is None:
            continue
        caught = node.type.elts if isinstance(node.type, ast.Tuple) else [node.type]
        for item in caught:
            if isinstance(item, ast.Attribute) and isinstance(item.value, ast.Name):
                yield node.lineno, item.value.id, item.attr


def _offenders(paths) -> list[str]:
    problems: list[str] = []
    for path in paths:
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:
            continue
        aliases = _module_aliases(tree)
        for lineno, local, attr in _handler_attributes(tree):
            dotted = aliases.get(local)
            if dotted is None or not _is_external(dotted):
                continue
            module = importlib.import_module(dotted)
            if not hasattr(module, attr):
                try:
                    rel = path.relative_to(REPO)
                except ValueError:
                    rel = path  # a planted file in tmp_path, from the self-test
                problems.append(f"{rel}:{lineno} catches {local}.{attr}, "
                                f"but module {dotted!r} has no attribute {attr!r}")
    return problems


def _suite_files():
    for suite in SUITES:
        root = REPO / suite
        if root.is_dir():
            yield from root.rglob("*.py")


def test_every_caught_exception_exists() -> None:
    problems = _offenders(_suite_files())
    assert not problems, (
        "An except clause names an exception that does not exist. When the "
        "error it guards is raised, the lookup raises AttributeError instead "
        "and the request becomes a 500:\n  " + "\n  ".join(problems)
    )


def test_this_gate_catches_the_bug_it_was_written_for(tmp_path) -> None:
    """Plant the original defect and confirm the scanner reports it.

    Without this, a scanner that silently matched nothing would report a clean
    run forever — the failure mode that made the real bug survive so long.
    """
    planted = tmp_path / "planted.py"
    planted.write_text(
        "import jwt\n"
        "def verify(token):\n"
        "    try:\n"
        "        return jwt.decode(token, 'k', algorithms=['HS256'])\n"
        "    except jwt.JWTError:\n"        # python-jose's name, not PyJWT's
        "        return None\n"
    )
    problems = _offenders([planted])
    assert len(problems) == 1, f"the gate missed the known defect: {problems}"
    assert "no attribute 'JWTError'" in problems[0]


def test_the_real_exception_name_passes(tmp_path) -> None:
    """The corrected form must not be flagged — otherwise the gate is noise."""
    ok = tmp_path / "ok.py"
    ok.write_text(
        "import jwt\n"
        "def verify(token):\n"
        "    try:\n"
        "        return jwt.decode(token, 'k', algorithms=['HS256'])\n"
        "    except (jwt.PyJWTError, jwt.ExpiredSignatureError):\n"
        "        return None\n"
    )
    assert _offenders([ok]) == []


@pytest.mark.parametrize("name", ["PyJWTError", "ExpiredSignatureError"])
def test_pyjwt_really_exposes_the_names_we_now_catch(name: str) -> None:
    """Pin the assumption itself, so a PyJWT upgrade that renames these fails
    here rather than as a 500 in production."""
    import jwt

    assert hasattr(jwt, name)
    assert not hasattr(jwt, "JWTError"), (
        "PyJWT gained a JWTError attribute; re-check the enterprise verify_token "
        "clause, which was corrected on the assumption it has none"
    )
