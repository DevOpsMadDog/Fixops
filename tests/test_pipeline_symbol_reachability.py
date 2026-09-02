"""The pipeline must ask reachability at symbol granularity, and must not
mistake an unanswerable question for a safe answer.

Two defects, both live before this:

1. **It never used the symbol.** ``_apply_reachability_verdicts`` built its
   query from ``dependency_fqn_pattern`` or ``package_name`` and ignored the
   ``vulnerable_symbols`` that ingest had already recovered from the advisory.
   A package-level query asks "do you use this library" — which the dependency
   file already answered — so every finding came back reachable and the noise
   reduction was zero. Measured on 119 real findings in
   ``docs/REACHABILITY_MEASURED_2026-08-29.md``.

2. **"No callers" was treated as proof of safety.** The verdict was a straight
   binary: no callers meant ``unreachable``, which DOWNGRADED the finding's
   ``consensus_priority``. But "no callers" only means something when the
   question was specific enough to answer. Asking ``requests.%`` and getting
   nothing means the library is unused; asking it while we *do* use the library
   and simply do not know where the flaw lives means nothing at all — and that
   case was quietly pushing real findings down the queue.

The fix gives the middle case a name. ``undetermined`` does not downgrade
anything, and the exploitability fusion already routes it to
``exploited_unknown_reach`` / ``insufficient_evidence`` — verdicts the console
renders.
"""

from __future__ import annotations

import pytest

from core.brain_pipeline import BrainPipeline


class _FakeEngine:
    """Records what was asked, and answers from a fixed call graph.

    ``stats`` matters as much as the answers: a rule-out is only sound if the
    graph could have contained the code, so the tests must state what the graph
    actually covers.
    """

    def __init__(self, known_callers: dict[str, list[str]], by_language=None, nodes=1000):
        self.known = known_callers
        self.asked: list[str] = []
        self._stats = {
            "node_count": nodes,
            "by_language": {"python": nodes} if by_language is None else by_language,
        }

    def stats(self, org_id):
        return self._stats

    def vulnerable_reachability(self, org_id, cve_id, pattern):
        self.asked.append(pattern)
        return self.known.get(pattern, [])

    def record_finding_verdict(self, *a, **k):
        return None


def _python_finding(**kw) -> dict:
    """Findings carry their ecosystem via the tool that produced them."""
    base = {"source_tool": "pip-audit"}
    base.update(kw)
    return base


def _run(monkeypatch, finding: dict, engine: _FakeEngine) -> dict:
    import core.function_reachability_engine as fre

    monkeypatch.setattr(fre, "get_engine", lambda *a, **k: engine)
    pipeline = BrainPipeline()
    ctx = {"org_id": "t1", "findings": [finding]}
    pipeline._apply_reachability_verdicts(ctx)
    return ctx["findings"][0]


def test_the_symbol_is_used_when_ingest_recovered_one(monkeypatch) -> None:
    engine = _FakeEngine({"cryptography.%pkcs7_decrypt_der%": ["app.mod.f"]})
    finding = _python_finding(
        cve_id="PYSEC-2026-3552",
        package_name="cryptography",
        vulnerable_symbols=["pkcs7_decrypt_der"],
    )
    result = _run(monkeypatch, finding, engine)

    assert any("pkcs7_decrypt_der" in q for q in engine.asked), (
        f"the pipeline never asked about the symbol; it asked {engine.asked}"
    )
    assert result["reachability_verdict"] == "reachable"
    assert result["reachability_evidence"] == "symbol"


def test_a_symbol_query_with_no_callers_rules_the_finding_out(monkeypatch) -> None:
    """A specific question that comes back empty IS evidence of absence."""
    engine = _FakeEngine({})
    finding = _python_finding(
        cve_id="PYSEC-2026-3552",
        package_name="cryptography",
        vulnerable_symbols=["pkcs7_decrypt_der"],
        consensus_priority=1,
    )
    result = _run(monkeypatch, finding, engine)
    assert result["reachability_verdict"] == "unreachable"
    assert result["consensus_priority"] == 2, "an established rule-out should downgrade"


def test_no_symbol_but_the_package_IS_used_is_undetermined(monkeypatch) -> None:
    """The case that was silently deleting findings.

    We use the library, and the advisory never told us where the flaw is. There
    is no question here that a call graph can answer, so the honest verdict is
    "undetermined" — and it must NOT downgrade priority.
    """
    engine = _FakeEngine({"cryptography.%": ["app.mod.uses_crypto"]})
    finding = _python_finding(
        cve_id="PYSEC-2026-3554", package_name="cryptography", consensus_priority=1
    )
    result = _run(monkeypatch, finding, engine)

    assert result["reachability_verdict"] == "undetermined"
    assert result["consensus_priority"] == 1, (
        "an unanswerable question downgraded a real finding — this is the bug"
    )


def test_a_package_we_never_call_is_still_ruled_out(monkeypatch) -> None:
    """The blunt filter must keep working: it does most of the elimination.

    Measured at scale, 95 of 119 findings were eliminated purely because the
    package is never called from our code at all.
    """
    engine = _FakeEngine({})
    finding = _python_finding(cve_id="PYSEC-1", package_name="somelib", consensus_priority=1)
    result = _run(monkeypatch, finding, engine)
    assert result["reachability_verdict"] == "unreachable"
    assert result["consensus_priority"] == 2


def test_undetermined_reaches_the_exploitability_fusion_as_unknown(monkeypatch) -> None:
    """Adding a third state must not fall through the fusion's branches."""
    pipeline = BrainPipeline()
    ctx = {
        "org_id": "t1",
        "findings": [
            {
                "cve_id": "CVE-2024-1",
                "reachability_verdict": "undetermined",
                "kev": True,
            }
        ],
    }
    pipeline._apply_exploitability_verdict(ctx)
    verdict = ctx["findings"][0].get("exploitability")
    assert verdict in {"exploited_unknown_reach", "insufficient_evidence"}, verdict


def test_a_graph_that_cannot_contain_the_code_rules_nothing_out(monkeypatch) -> None:
    """The worst failure this system had, found on a real 96-finding ingest.

    Every finding came back "unreachable" and was deprioritised. The tenant's
    graph held 4,852 nodes — 4,850 of them JAVA, from test fixtures. Querying
    `aiohttp.%` against a Java graph finds nothing, and the product reported
    that nothing as proof of safety for 96 Python findings.

    Absence of evidence is evidence of absence only if you looked somewhere the
    thing could have been.
    """
    engine = _FakeEngine({}, by_language={"java": 4850, "python": 0}, nodes=4852)
    finding = _python_finding(
        cve_id="PYSEC-2026-237", package_name="aiohttp", consensus_priority=1
    )
    result = _run(monkeypatch, finding, engine)

    assert result["reachability_verdict"] == "undetermined", (
        "a Python finding was ruled out against a Java call graph"
    )
    assert result["consensus_priority"] == 1, "and it was deprioritised on that basis"


def test_no_graph_at_all_rules_nothing_out(monkeypatch) -> None:
    """A tenant that has never parsed a repo must not have every finding closed."""
    engine = _FakeEngine({}, by_language={}, nodes=0)
    finding = _python_finding(cve_id="PYSEC-1", package_name="aiohttp", consensus_priority=1)
    result = _run(monkeypatch, finding, engine)
    assert result["reachability_verdict"] == "undetermined"
    assert result["consensus_priority"] == 1


# --- how old the evidence is, not just whether it was measured --------------


def _kev_finding() -> dict:
    return {"cve_id": "CVE-2024-1", "in_kev": True, "reachability_verdict": "reachable"}


def test_a_measured_verdict_records_how_old_its_evidence_is() -> None:
    """"act now, measured" read identically whether KEV was refreshed this
    morning or six months ago.

    The pipeline already computed the feed bundle's age and flagged staleness
    for the RUN — but the run summary is not what an operator reads at 2am. It
    matters most in an air-gapped site, which ships with the bundle it was
    installed with and never refreshes it.
    """
    pipeline = BrainPipeline()
    ctx = {"org_id": "t", "_enrich_bundle_age_days": 2, "findings": [_kev_finding()]}
    pipeline._apply_exploitability_verdict(ctx)
    finding = ctx["findings"][0]

    assert finding["exploitability"] == "act_now"
    assert finding["exploitability_confidence"] == "measured"
    assert finding["exploitability_evidence_age_days"] == 2
    assert "exploitability_evidence_stale" not in finding


def test_stale_evidence_is_flagged() -> None:
    pipeline = BrainPipeline()
    ctx = {"org_id": "t", "_enrich_bundle_age_days": 400, "findings": [_kev_finding()]}
    pipeline._apply_exploitability_verdict(ctx)
    finding = ctx["findings"][0]

    assert finding["exploitability_evidence_age_days"] == 400
    assert finding["exploitability_evidence_stale"] is True


def test_an_unknown_bundle_age_makes_no_claim() -> None:
    """Absence of the age is not freshness. Say nothing rather than imply new."""
    pipeline = BrainPipeline()
    ctx = {"org_id": "t", "findings": [_kev_finding()]}
    pipeline._apply_exploitability_verdict(ctx)
    finding = ctx["findings"][0]

    assert "exploitability_evidence_age_days" not in finding
    assert "exploitability_evidence_stale" not in finding


def test_a_java_package_query_is_undetermined_not_unreachable(monkeypatch) -> None:
    """The Java graph cannot contain the answer, so it must not supply one.

    Measured on spring-petclinic: 835 nodes, ZERO beginning with any dependency
    package path, because a Java call site is named by its receiver
    (``Assert.notNull``) while the package lives in an import the parser drops.
    The pipeline's ``postgresql.%`` fallback therefore returns nothing whether
    or not the driver is used.

    Before this guard the empty result became "unreachable" WITH a priority
    downgrade — 14 of 21 real Maven advisories silently eliminated on a question
    that could never have answered. The engine below returns nothing for every
    pattern, exactly like the real one.
    """
    engine = _FakeEngine({}, by_language={"java": 835}, nodes=835)
    finding = _run(
        monkeypatch,
        {"source_tool": "maven", "cve_id": "GHSA-h86w-m5rm-xr33",
         "package_name": "postgresql", "consensus_priority": 1},
        engine,
    )
    assert finding["reachability_verdict"] == "undetermined", (
        "a Java package query returned a safety claim it cannot support"
    )
    # Observed pre-fix: verdict "unreachable" and consensus_priority 1 -> 2.
    # The downgrade is the part that actually hurt — it moved a real finding
    # down the queue on no evidence.
    assert finding["consensus_priority"] == 1, "an unanswerable query moved priority"


def test_the_java_guard_does_not_disarm_python_elimination(monkeypatch) -> None:
    """Same shape of query, an ecosystem that CAN answer it, still eliminated.

    84% of Python findings rest on this path. A fix for Java that turned it off
    everywhere would be a worse regression than the bug it closed.
    """
    engine = _FakeEngine({}, by_language={"python": 1000})
    finding = _run(
        monkeypatch,
        _python_finding(cve_id="CVE-2026-1", package_name="requests", priority=1),
        engine,
    )
    assert finding["reachability_verdict"] == "unreachable"


# --- an unscoped symbol must never earn "reachable" -------------------------


def test_a_bare_symbol_with_no_package_is_not_answerable(monkeypatch) -> None:
    """The worst output this product can produce, and it was reachable.

    Findings from SARIF carry no package_name, and ingest attaches symbols from
    advisory prose. The pattern builder fell back to `%{symbol}%` — unanchored —
    so a bare symbol matched any function whose NAME merely contained it.

    Measured against the real 72,050-node FixOps graph with the symbol "fetch":

        pattern %fetch%   ->  reachable, 5 callers
        with in_kev       ->  ACT_NOW

    "Drop everything, this is reachable and being exploited", manufactured from
    a common word appearing inside unrelated function names. A false act_now
    spends the customer's night and their trust at once.
    """
    engine = _FakeEngine({"%fetch%": ["a.b.c", "d.e.f"]})
    finding = _run(
        monkeypatch,
        _python_finding(
            cve_id="CVE-2026-1", vulnerable_symbols=["fetch"], package_name=""
        ),
        engine,
    )
    assert finding.get("reachability_verdict") in (None, "", "undetermined"), (
        "an unscoped substring query produced a reachability claim"
    )
    assert "%fetch%" not in engine.asked, (
        f"the unanchored pattern was still issued: {engine.asked}"
    )


def test_a_bare_symbol_scoped_by_a_package_is_still_asked(monkeypatch) -> None:
    """The fix must not disarm the case that works: with a package to scope it,
    a bare symbol is answerable and its absence is a real elimination."""
    engine = _FakeEngine({})
    finding = _run(
        monkeypatch,
        _python_finding(
            cve_id="CVE-2026-2", vulnerable_symbols=["fetch"], package_name="requests"
        ),
        engine,
    )
    assert engine.asked == ["requests.%fetch%"]
    assert finding["reachability_verdict"] == "unreachable"


def test_a_dotted_symbol_is_self_anchoring_and_still_earns_reachable(monkeypatch) -> None:
    """`cryptography.fernet.Fernet` names its own package, so it needs no
    scoping — and this is the path that produces a genuine act_now."""
    engine = _FakeEngine({"cryptography.fernet.Fernet%": ["core.crypto.encrypt_data"]})
    finding = _run(
        monkeypatch,
        _python_finding(
            cve_id="CVE-2026-3",
            vulnerable_symbols=["cryptography.fernet.Fernet"],
            package_name="",
        ),
        engine,
    )
    assert finding["reachability_verdict"] == "reachable"


def test_a_finding_whose_symbols_are_all_unscoped_stays_undetermined(monkeypatch) -> None:
    """When nothing survives the filter the question was unanswerable, so the
    finding must not be ruled either way — not reachable, not eliminated."""
    engine = _FakeEngine({"%read%": ["x.y"], "%write%": ["x.z"]})
    finding = _run(
        monkeypatch,
        _python_finding(
            cve_id="CVE-2026-4", vulnerable_symbols=["read", "write"], package_name=""
        ),
        engine,
    )
    assert finding.get("reachability_verdict") in (None, "", "undetermined")
    assert engine.asked == []
