"""GAP_MAP #4 / SPEC-011 — function-reachability /parse must work for TS/JS/Java.

Regression guard: the router used to call parse_typescript_repo()/parse_java_repo()
then `raise RuntimeError("unreachable")`, discarding the result and ALWAYS returning
500 for TypeScript/JavaScript/Java (leftover "Python only in v0" dead code). The
engine methods are real (-> int, with honest NotImplementedError->501 fallback when
tree-sitter is absent). This test pins that /parse never 500s for a supported language.
"""

from __future__ import annotations

import os
import tempfile

import pytest

os.environ.setdefault("FIXOPS_API_TOKEN", "ci-test-token")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

_TOKEN = os.environ.get("FIXOPS_API_TOKEN", "ci-test-token")


@pytest.fixture(scope="module")
def client():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    import apps.api.function_reachability_router as m

    app = FastAPI()
    app.include_router(m.router)
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture(scope="module")
def repo_dir():
    d = tempfile.mkdtemp()
    with open(os.path.join(d, "a.ts"), "w") as fh:
        fh.write("function foo(){ bar(); }\nfunction bar(){}\n")
    with open(os.path.join(d, "A.java"), "w") as fh:
        fh.write("class A { void foo(){ bar(); } void bar(){} }\n")
    return d


@pytest.mark.parametrize("lang", ["typescript", "javascript", "java", "python"])
def test_parse_never_500s_for_supported_language(client, repo_dir, lang):
    headers = {"X-API-Key": _TOKEN, "X-Org-ID": "reach-test-org"}
    resp = client.post(
        "/api/v1/reachability/parse",
        headers=headers,
        json={"org_id": "reach-test-org", "repo_ref": "r1", "root_path": repo_dir, "language": lang},
    )
    # 200 (parsed) or 501 (tree-sitter not installed — honest) — never 500.
    assert resp.status_code in (200, 501), f"{lang} -> {resp.status_code}: {resp.text[:200]}"
    if resp.status_code == 200:
        body = resp.json()
        assert "nodes_added" in body and isinstance(body["nodes_added"], int)
        assert body["language"] == lang


def test_unsupported_language_is_422_not_500(client, repo_dir):
    headers = {"X-API-Key": _TOKEN, "X-Org-ID": "reach-test-org"}
    resp = client.post(
        "/api/v1/reachability/parse",
        headers=headers,
        json={"org_id": "reach-test-org", "repo_ref": "r1", "root_path": repo_dir, "language": "cobol"},
    )
    assert resp.status_code == 422, f"expected 422 for unsupported lang, got {resp.status_code}"
