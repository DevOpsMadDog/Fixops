"""The call graph must live where the deployment keeps its data.

Both reachability databases were pinned to a path derived from the ENGINE
FILE's own location, ignoring FIXOPS_DATA_DIR — the only stores in the product
that did. Measured: with FIXOPS_DATA_DIR set to a scratch directory, a tenant
parsed a repo through POST /api/v1/reachability/parse and its 1,183-node call
graph was written to <repo>/.fixops_data/function_reachability.db instead.

In a container the code lives at /app, so the graph lands on the image layer
rather than the mounted volume: a customer parses their repository, the
container restarts, and the graph is gone. Reachability is the moat, and it was
the one store that could not survive a deploy. The cache was worse — inside the
source tree at suite-core/data/.

Local development is deliberately unchanged, because sitecustomize already sets
FIXOPS_DATA_DIR to <repo>/.fixops_data, which is exactly where these files were.
"""

from __future__ import annotations

import importlib
import pathlib


def test_both_databases_follow_a_configured_data_dir(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("FIXOPS_DATA_DIR", str(tmp_path))
    import core.function_reachability_engine as engine

    module = importlib.reload(engine)
    assert pathlib.Path(module._DEFAULT_DB).parent == tmp_path
    assert pathlib.Path(module._DEFAULT_CACHE_DB).parent == tmp_path


def test_the_cache_is_not_written_into_the_source_tree(monkeypatch, tmp_path) -> None:
    """It was at suite-core/data/reachability_cache.db — inside the code."""
    monkeypatch.setenv("FIXOPS_DATA_DIR", str(tmp_path))
    import core.function_reachability_engine as engine

    module = importlib.reload(engine)
    cache = pathlib.Path(module._DEFAULT_CACHE_DB).resolve()
    assert "suite-core" not in cache.parts, f"cache lives in the source tree: {cache}"


def test_an_unset_data_dir_keeps_the_historical_location(monkeypatch) -> None:
    """No silent migration for anyone who never configured a data dir: the
    fallback must stay <repo>/.fixops_data so existing graphs remain findable."""
    monkeypatch.delenv("FIXOPS_DATA_DIR", raising=False)
    import core.function_reachability_engine as engine

    module = importlib.reload(engine)
    assert pathlib.Path(module._DEFAULT_DB).parent.name == ".fixops_data"


def test_a_parsed_graph_actually_lands_in_the_configured_dir(monkeypatch, tmp_path) -> None:
    """The property, not just the constant — the constant was right-looking
    before too, it simply pointed somewhere else."""
    import sqlite3

    repo = tmp_path / "src"
    repo.mkdir()
    (repo / "app.py").write_text("import json\n\ndef handler():\n    return json.dumps({})\n")

    monkeypatch.setenv("FIXOPS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("FIXOPS_REACHABILITY_ALLOWED_ROOTS", str(tmp_path))
    import core.function_reachability_engine as engine

    module = importlib.reload(engine)
    eng = module.FunctionReachabilityEngine()
    eng.parse_python_repo("t1", "app@main", str(repo))

    db = tmp_path / "function_reachability.db"
    assert db.is_file(), "graph did not land in the configured data dir"
    count = sqlite3.connect(db).execute(
        "SELECT COUNT(*) FROM callgraph_nodes WHERE org_id = 't1'"
    ).fetchone()[0]
    assert count > 0
