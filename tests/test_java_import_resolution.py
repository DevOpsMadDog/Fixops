"""Java call sites must carry their package, or the graph cannot be queried.

A Java call site is written ``Assert.notNull(...)``. The package lives in an
``import`` at the top of the file, so recording the receiver verbatim produced,
on spring-petclinic, 835 nodes of which ZERO began with any dependency package.
A dependency advisory can only ask ``org.springframework.%`` — the one shape the
graph could not contain — so the answer was always "nothing", whether or not the
library was used.

After resolving imports, on the same 50 files:

    org.springframework.%   0 -> 18
    org.junit.%             0 ->  7
    org.assertj.%           0 ->  3
    org.postgresql.%        0 ->  0   (correct: loaded reflectively as a JDBC
                                       driver, never called from app code)

That last row is the point. It is the first Java answer that means something.
"""

from __future__ import annotations

import pytest

from core.function_reachability_engine import FunctionReachabilityEngine

pytest.importorskip("tree_sitter_java")
pytest.importorskip("tree_sitter")


def _tree(source: str):
    import tree_sitter_java as tsj
    from tree_sitter import Language, Parser

    return Parser(Language(tsj.language())).parse(source.encode())


ENGINE = FunctionReachabilityEngine.__new__(FunctionReachabilityEngine)


def test_a_plain_import_maps_its_simple_name() -> None:
    tree = _tree("import org.springframework.util.Assert;\nclass A {}")
    assert ENGINE._java_imports(tree.root_node) == {
        "Assert": "org.springframework.util.Assert"
    }


def test_a_static_import_maps_the_method_name() -> None:
    """``assertTrue(...)`` is what appears at the call site, not ``Assert``."""
    tree = _tree("import static org.junit.Assert.assertTrue;\nclass A {}")
    assert ENGINE._java_imports(tree.root_node) == {
        "assertTrue": "org.junit.Assert.assertTrue"
    }


def test_a_wildcard_import_is_skipped() -> None:
    """``import java.util.*`` names a PACKAGE, not a class.

    Guessing which class a bare receiver came from would manufacture a
    fully-qualified name that is wrong in exactly the confident way this
    subsystem exists to avoid — and a wrong FQN produces a wrong elimination,
    which is worse than no answer.
    """
    tree = _tree("import java.util.*;\nclass A {}")
    assert ENGINE._java_imports(tree.root_node) == {}


def test_the_receiver_is_rewritten_to_the_imported_package() -> None:
    imports = {"Assert": "org.springframework.util.Assert"}
    assert ENGINE._qualify_java_receiver("Assert.notNull", imports) == (
        "org.springframework.util.Assert.notNull"
    )


def test_an_unimported_receiver_is_left_alone() -> None:
    """A local variable or same-package class cannot be qualified, and
    inventing a package for it would be worse than leaving it bare."""
    imports = {"Assert": "org.springframework.util.Assert"}
    assert ENGINE._qualify_java_receiver("owner.getPet", imports) == "owner.getPet"
    assert ENGINE._qualify_java_receiver("helper", imports) == "helper"


def test_qualification_is_a_no_op_without_imports() -> None:
    """Graphs parsed before this existed must keep their old names rather than
    acquiring half-qualified ones."""
    assert ENGINE._qualify_java_receiver("Assert.notNull", {}) == "Assert.notNull"


def test_calls_are_qualified_end_to_end() -> None:
    source = """
    import org.springframework.util.Assert;
    class Owner {
        void save(String name) {
            Assert.notNull(name, "required");
            helper(name);
        }
        void helper(String n) {}
    }
    """
    tree = _tree(source)
    imports = ENGINE._java_imports(tree.root_node)
    method = next(
        fn for _cls, fn in ENGINE._walk_java_methods(tree.root_node)
        if (fn.child_by_field_name("name").text.decode() == "save")
    )
    calls = ENGINE._find_java_calls(method, imports)
    assert "org.springframework.util.Assert.notNull" in calls
    assert "helper" in calls, "an unqualifiable local call must survive"
