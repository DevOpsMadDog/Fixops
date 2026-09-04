"""If any of the graph was fabricated, every read must say so.

``POST /knowledge-graph/seed-demo`` writes 73 nodes — 5 applications, 20
vulnerabilities and their CVE/CWE nodes — including a Log4Shell with CVSS 10.0
and KEV=true. Each is tagged ``is_demo=True`` / ``source="demo-seed"``.

That tag was written and never read. No analytics, export or attack-path
response mentioned it, so a seeded graph was indistinguishable from an
ingested one: the fabricated Log4Shell scored, ranked and appeared in blast
radius exactly like a real finding.

The seeding gate itself is sound — it requires FIXOPS_MODE != "enterprise"
AND FIXOPS_ALLOW_DEMO_SEED=1, and the shipped .env pins FIXOPS_MODE=enterprise,
so the default really is closed (verified: a probe with only
FIXOPS_ALLOW_DEMO_SEED=1 set still gets 403). But the gate governs the write,
while its docstring promises something about the read — that fabricated nodes
will not "surface in attack-path or blast-radius results as if they were real
findings". Once an operator opts in, which is the whole point of the endpoint,
that promise needed the read side to keep it.
"""

from __future__ import annotations

import pytest

from core.falkordb_client import GraphNode, KnowledgeGraphEngine, NodeType


@pytest.fixture()
def engine() -> KnowledgeGraphEngine:
    return KnowledgeGraphEngine()


def test_a_clean_graph_reports_zero_not_silence(engine) -> None:
    """0 means counted and clean. The field must always be present, so a
    consumer can tell "no demo data" from "this build never checked"."""
    analytics = engine.get_graph_analytics()
    assert analytics["demo_seeded_nodes"] == 0
    assert analytics["contains_demo_data"] is False


def test_it_counts_demo_nodes_and_not_real_ones(engine) -> None:
    """The discriminating case.

    A counter that returned node_count would also have passed a seeded-graph
    check, because every node in a freshly seeded graph is fabricated (73 of
    73). Mixing one real node with one demo node is what proves it reads the
    tag rather than counting rows.
    """
    engine._backend.add_node(GraphNode(
        id="finding:REAL-1", type=NodeType.FINDING,
        properties={"title": "ingested from a real scan"},
    ))
    engine._backend.add_node(GraphNode(
        id="finding:DEMO-1", type=NodeType.FINDING,
        properties={"title": "seeded", "is_demo": True, "source": "demo-seed"},
    ))

    analytics = engine.get_graph_analytics()
    assert analytics["node_count"] == 2
    assert analytics["demo_seeded_nodes"] == 1, (
        "must count the tagged node only — not every node, and not none"
    )
    assert analytics["contains_demo_data"] is True


def test_the_seeder_still_tags_what_it_writes() -> None:
    """The disclosure is only as good as the tag it reads.

    If seed-demo ever stops writing is_demo, the counters above silently
    return 0 for a fully fabricated graph — the original bug, restored and
    now wearing a green test. Pin the producer to the consumer.
    """
    source = (
        __import__("pathlib").Path(__file__).resolve().parents[1]
        / "suite-core" / "api" / "knowledge_graph_router.py"
    ).read_text(encoding="utf-8")

    seeder = source.split('@router.post("/seed-demo"')[1]
    assert seeder.count('"is_demo": True') >= 6, (
        "seed-demo must tag every category it writes (apps, components, "
        "endpoints, findings, cwe, cve, controls)"
    )
    assert '"source": "demo-seed"' in seeder


def test_the_default_posture_still_refuses_to_seed() -> None:
    """The shipped .env pins enterprise mode; seeding must stay closed there."""
    env = (
        __import__("pathlib").Path(__file__).resolve().parents[1] / ".env"
    )
    if not env.is_file():
        pytest.skip(".env not present in this checkout")
    assert "FIXOPS_MODE=enterprise" in env.read_text(encoding="utf-8"), (
        "the default mode no longer blocks demo seeding; re-check "
        "_require_non_enterprise before relying on it"
    )
