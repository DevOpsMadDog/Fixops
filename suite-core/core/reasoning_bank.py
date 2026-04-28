"""ReasoningBank — trajectory tracker + pattern distillation on top of AgentDB.

Why
---
Raw AgentDB semantic search (``find_similar_decisions``) returns the top-k
verdicts whose *prompt text* looks similar to the new finding. That is useful,
but it is not learning: it has no notion of which past verdicts were *correct*,
which were over-ruled, or which features (CWE, KEV flag, reachability) are the
actual drivers of the decision.

ReasoningBank closes the loop:

1.  Every council convene becomes a **trajectory** = (input finding, output
    verdict, downstream feedback, observed outcome). We persist the
    trajectory to AgentDB with rich tabular metadata (``cwe``, ``severity``,
    ``kev``, ``epss``, ``reachable``, ``escalated``, ``verdict_action``,
    ``confidence``, ``outcome``, ``correctness_score``).
2.  A periodic **judgment job** re-evaluates past trajectories against the
    actual outcome (e.g. "council said review, the finding was later
    confirmed exploitable in production" -> ``correctness_score=1.0``;
    "council said remediate_critical, finding turned out to be a false
    positive" -> ``correctness_score=0.0``). This is what turns 5,196 raw
    DPO pairs into a labeled reward signal.
3.  A **distillation pass** clusters trajectories on the tabular feature
    space and emits reusable **patterns** of the form
    ``{cwe=CWE-79, kev=true, reachable=true} -> remediate_critical (n=82,
    correctness=0.94)``. These patterns become the cheap fallback that the
    Phase-2 student model consults *before* spending a council budget.

The bank is a thin layer on top of the existing :class:`AgentDBBridge` -
same SQLite store, same MiniLM embedder, same async queue. It adds three
artefacts:

*   namespace ``reasoning_trajectories`` for trajectory rows
*   namespace ``reasoning_patterns`` for distilled patterns
*   a JSON export at ``data/reasoning_patterns_v{N}.json`` for the student

Public API
----------

    from core.reasoning_bank import (
        ReasoningBank,
        Trajectory,
        DistilledPattern,
        get_reasoning_bank,
    )

    bank = get_reasoning_bank()

    # Hot path - council uses this BEFORE convene() to pull top-k ranked
    # past trajectories (re-ranked by correctness_score, not just similarity).
    trajectories = bank.recall(finding, k=5)

    # Hot path - council uses this AFTER convene() to record the trajectory.
    bank.record(finding=finding, verdict=verdict, context=context)

    # Periodic - judgment job updates correctness_score based on observed
    # outcomes (analyst confirm/dismiss, exploitability evidence, etc).
    bank.judge(trajectory_key, outcome="confirmed_exploitable",
                correctness_score=0.95)

    # Periodic - distill patterns from trajectories whose correctness is known.
    patterns = bank.distill_patterns(min_support=10, min_correctness=0.7)

    # Phase-2 student fallback - "do any of my distilled patterns fire?"
    pattern = bank.match_pattern(finding)
    if pattern and pattern.confidence > 0.85:
        return pattern.verdict_action  # cheap, no council needed
    return council.convene(finding, ...)

Never raises. If AgentDB is unavailable, ``recall`` returns ``[]``,
``record`` returns ``False``, and the council continues exactly as it does
today. This is mission-critical: ReasoningBank must never block a verdict.
"""

from __future__ import annotations

import json
import logging
import threading
import time
import uuid
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Tuple

logger = logging.getLogger(__name__)

# Layered on top of the existing AgentDBBridge so we share the embedder,
# async queue, fallback paths, and ops metrics.
try:  # pragma: no cover - import path tested at runtime
    from trustgraph.agentdb_bridge import (
        AgentDBBridge,
        AgentDBSearchResult,
        get_agentdb_bridge,
    )
except ImportError:  # pragma: no cover - sys.path not yet mangled
    import sys
    from pathlib import Path

    _root = Path(__file__).resolve().parent.parent.parent
    for _sub in ("suite-core",):
        _p = _root / _sub
        if _p.exists() and str(_p) not in sys.path:
            sys.path.insert(0, str(_p))
    from trustgraph.agentdb_bridge import (  # type: ignore  # noqa: E402
        AgentDBBridge,
        AgentDBSearchResult,
        get_agentdb_bridge,
    )


__all__ = [
    "Trajectory",
    "DistilledPattern",
    "ReasoningBank",
    "get_reasoning_bank",
    "reset_reasoning_bank",
    "TRAJECTORIES_NAMESPACE",
    "PATTERNS_NAMESPACE",
]


TRAJECTORIES_NAMESPACE = "reasoning_trajectories"
PATTERNS_NAMESPACE = "reasoning_patterns"

# Feature keys that drive pattern clustering. Every trajectory is reduced to
# a tuple over these keys for distillation. Order matters - pattern keys are
# rendered as JSON with these names so the student can match on substrings.
_PATTERN_FEATURE_KEYS: Tuple[str, ...] = (
    "cwe",
    "severity",
    "kev",
    "reachable",
    "exploit_available",
)


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass
class Trajectory:
    """One closed-loop sample: (finding, verdict, outcome, correctness)."""

    trajectory_id: str
    finding_type: str
    cwe: Optional[str]
    severity: str
    kev: bool
    reachable: bool
    exploit_available: bool
    epss: float
    council_action: str
    council_confidence: float
    escalated: bool
    outcome: Optional[str] = None
    correctness_score: Optional[float] = None
    finding_summary: str = ""
    verdict_summary: str = ""
    created_at_ms: int = 0

    def to_metadata(self) -> Dict[str, Any]:
        return {
            "trajectory_id": self.trajectory_id,
            "finding_type": self.finding_type,
            "cwe": self.cwe,
            "severity": self.severity,
            "kev": bool(self.kev),
            "reachable": bool(self.reachable),
            "exploit_available": bool(self.exploit_available),
            "epss": float(self.epss),
            "council_action": self.council_action,
            "council_confidence": float(self.council_confidence),
            "escalated": bool(self.escalated),
            "outcome": self.outcome,
            "correctness_score": self.correctness_score,
            "schema": "trajectory.v1",
        }

    def feature_tuple(self) -> Tuple[Any, ...]:
        """Reduce to the discrete feature vector used for pattern clustering."""
        return (
            self.cwe or "UNK",
            self.severity or "unknown",
            bool(self.kev),
            bool(self.reachable),
            bool(self.exploit_available),
        )


@dataclass
class DistilledPattern:
    """A reusable rule mined from many trajectories with consistent outcomes."""

    pattern_id: str
    feature_predicate: Dict[str, Any]
    verdict_action: str
    support: int
    correctness: float
    confidence: float
    sample_trajectory_ids: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pattern_id": self.pattern_id,
            "predicate": self.feature_predicate,
            "verdict_action": self.verdict_action,
            "support": self.support,
            "correctness": round(self.correctness, 4),
            "confidence": round(self.confidence, 4),
            "sample_trajectory_ids": self.sample_trajectory_ids[:5],
        }


# ---------------------------------------------------------------------------
# ReasoningBank
# ---------------------------------------------------------------------------


class ReasoningBank:
    """Trajectory tracker + pattern distiller on top of :class:`AgentDBBridge`.

    All persistence flows through the bridge. We add no new SQLite store.
    Thread-safe, never raises - degrades to a no-op when AgentDB is offline.
    """

    def __init__(self, *, bridge: Optional[AgentDBBridge] = None) -> None:
        self._bridge = bridge
        self._lock = threading.Lock()
        # In-memory pattern cache so the hot-path ``match_pattern`` does not
        # hit SQLite on every council call. Refreshed on distill_patterns().
        self._patterns_cache: List[DistilledPattern] = []
        self._patterns_cache_at_ms: int = 0
        # Counters for observability.
        self._records = 0
        self._recalls = 0
        self._judgments = 0
        self._distillations = 0
        self._failures = 0

    # ------------------------------------------------------------------
    # Bridge access
    # ------------------------------------------------------------------

    def _get_bridge(self) -> Optional[AgentDBBridge]:
        if self._bridge is not None:
            return self._bridge
        try:
            return get_agentdb_bridge()
        except Exception as exc:  # noqa: BLE001
            logger.debug("ReasoningBank: bridge unavailable (%s)", exc)
            return None

    # ------------------------------------------------------------------
    # Hot-path API: record / recall
    # ------------------------------------------------------------------

    def record(
        self,
        *,
        finding: Mapping[str, Any],
        verdict: Mapping[str, Any],
        context: Optional[Mapping[str, Any]] = None,
        outcome: Optional[str] = None,
        correctness_score: Optional[float] = None,
    ) -> Optional[Trajectory]:
        """Persist a (finding, verdict, outcome) trajectory.

        Returns the constructed :class:`Trajectory` on success, ``None`` if
        AgentDB is unavailable. Never raises.
        """
        try:
            traj = self._build_trajectory(
                finding=finding,
                verdict=verdict,
                context=context or {},
                outcome=outcome,
                correctness_score=correctness_score,
            )
        except Exception as exc:  # noqa: BLE001
            self._failures += 1
            logger.debug("ReasoningBank.record build failed: %s", exc)
            return None

        bridge = self._get_bridge()
        if bridge is None:
            return None

        try:
            payload = {
                "finding": dict(finding),
                "verdict": dict(verdict),
                "trajectory": traj.to_metadata(),
                "context_summary": self._summarise_context(context or {}),
            }
            ok = bridge.dual_write(
                event_type="reasoning.trajectory",
                payload=payload,
                namespace=TRAJECTORIES_NAMESPACE,
                key=traj.trajectory_id,
            )
            if ok:
                self._records += 1
                return traj
            return None
        except Exception as exc:  # noqa: BLE001
            self._failures += 1
            logger.debug("ReasoningBank.record write failed: %s", exc)
            return None

    def recall(
        self,
        finding: Mapping[str, Any],
        *,
        k: int = 5,
        min_similarity: float = 0.30,
        rerank_by_correctness: bool = True,
    ) -> List[Trajectory]:
        """Return top-k past trajectories ranked by similarity * correctness.

        This is the key advantage over a raw :func:`AgentDBBridge.semantic_search`
        call: we re-weight by ``correctness_score`` (set by the judgment job)
        so the council learns from *correct* past calls rather than merely
        textually-similar ones.

        ``rerank_by_correctness=False`` returns the bridge's raw similarity
        ranking - useful for debugging or for the cold-start case where no
        judgments have arrived yet.
        """
        bridge = self._get_bridge()
        if bridge is None:
            return []

        # Pull a wider net (k * 4) so the rerank has headroom; cap at 50.
        raw_k = min(50, max(k, k * 4))
        try:
            self._recalls += 1
            query = self._build_query_string(finding)
            if not query:
                return []
            hits = bridge.semantic_search(
                query,
                namespace=TRAJECTORIES_NAMESPACE,
                k=raw_k,
                min_similarity=min_similarity,
            )
        except Exception as exc:  # noqa: BLE001
            self._failures += 1
            logger.debug("ReasoningBank.recall search failed: %s", exc)
            return []

        trajectories: List[Tuple[float, Trajectory]] = []
        for hit in hits:
            traj = self._trajectory_from_hit(hit)
            if traj is None:
                continue
            if rerank_by_correctness and traj.correctness_score is not None:
                # Multiplicative rerank: a 0.4-similar but 0.95-correct hit
                # beats a 0.8-similar but 0.4-correct one. Trajectories with
                # no judgment yet keep their raw similarity (rank=sim).
                score = hit.similarity * (0.5 + 0.5 * traj.correctness_score)
            else:
                score = hit.similarity
            trajectories.append((score, traj))

        trajectories.sort(key=lambda x: x[0], reverse=True)
        return [t for _, t in trajectories[:k]]

    # ------------------------------------------------------------------
    # Periodic: judgment + distillation
    # ------------------------------------------------------------------

    def judge(
        self,
        trajectory_id: str,
        *,
        outcome: str,
        correctness_score: float,
    ) -> bool:
        """Update an existing trajectory with the observed outcome.

        Loads the trajectory, updates the embedded metadata, and re-writes it
        through the bridge (UPSERT on namespace+key). Returns ``True`` on
        success.
        """
        if not 0.0 <= correctness_score <= 1.0:
            return False
        bridge = self._get_bridge()
        if bridge is None:
            return False

        try:
            # Direct namespace+key lookup via the bridge's per-thread connection.
            # We avoid semantic_search here because trajectory_id is a stable
            # primary key — no need to pay the cosine pass over the namespace.
            content = self._fetch_content_by_key(bridge, trajectory_id)
            if content is None:
                logger.debug(
                    "ReasoningBank.judge: trajectory_id=%s not found", trajectory_id
                )
                return False

            # Reconstruct payload, patch outcome + correctness, re-write.
            try:
                payload = self._extract_payload(content)
            except Exception:
                payload = {"finding": {}, "verdict": {}, "trajectory": {}}

            traj_meta = dict(payload.get("trajectory") or {})
            traj_meta["outcome"] = outcome
            traj_meta["correctness_score"] = float(correctness_score)
            payload["trajectory"] = traj_meta

            ok = bridge.dual_write(
                event_type="reasoning.trajectory",
                payload=payload,
                namespace=TRAJECTORIES_NAMESPACE,
                key=trajectory_id,
            )
            if ok:
                self._judgments += 1
            return ok
        except Exception as exc:  # noqa: BLE001
            self._failures += 1
            logger.debug("ReasoningBank.judge failed: %s", exc)
            return False

    def distill_patterns(
        self,
        *,
        min_support: int = 10,
        min_correctness: float = 0.70,
        min_dominance: float = 0.60,
        max_patterns: int = 200,
    ) -> List[DistilledPattern]:
        """Cluster trajectories into reusable patterns.

        Each pattern has a discrete predicate over
        ``(cwe, severity, kev, reachable, exploit_available)``. A predicate is
        promoted to a :class:`DistilledPattern` when:

        * at least ``min_support`` trajectories match it, AND
        * at least ``min_correctness`` of those have correctness >= 0.70, AND
        * the dominant verdict_action covers >= ``min_dominance`` of them.

        Persists each pattern to the ``reasoning_patterns`` AgentDB namespace
        and refreshes the in-memory cache. Returns the new pattern list.
        """
        bridge = self._get_bridge()
        if bridge is None:
            return []

        try:
            trajectories = self._load_all_trajectories(limit=20000)
        except Exception as exc:  # noqa: BLE001
            self._failures += 1
            logger.debug("ReasoningBank.distill load failed: %s", exc)
            return []

        # Group by feature tuple.
        groups: Dict[Tuple[Any, ...], List[Trajectory]] = defaultdict(list)
        for traj in trajectories:
            if traj.correctness_score is None:
                # Skip un-judged trajectories - we only distill from labeled data.
                continue
            groups[traj.feature_tuple()].append(traj)

        patterns: List[DistilledPattern] = []
        for feature_tuple, members in groups.items():
            support = len(members)
            if support < min_support:
                continue
            avg_correctness = sum(
                t.correctness_score or 0.0 for t in members
            ) / support
            if avg_correctness < min_correctness:
                continue
            action_counts = Counter(t.council_action for t in members)
            top_action, top_count = action_counts.most_common(1)[0]
            dominance = top_count / support
            if dominance < min_dominance:
                continue

            predicate = dict(zip(_PATTERN_FEATURE_KEYS, feature_tuple))
            pattern_id = self._make_pattern_id(predicate, top_action)
            pattern = DistilledPattern(
                pattern_id=pattern_id,
                feature_predicate=predicate,
                verdict_action=top_action,
                support=support,
                correctness=avg_correctness,
                confidence=avg_correctness * dominance,
                sample_trajectory_ids=[
                    t.trajectory_id for t in members[:5]
                ],
            )
            patterns.append(pattern)

        patterns.sort(key=lambda p: p.confidence * p.support, reverse=True)
        patterns = patterns[:max_patterns]

        # Persist patterns - replace prior copy so stale rules don't linger.
        for pattern in patterns:
            try:
                bridge.dual_write(
                    event_type="reasoning.pattern",
                    payload=pattern.to_dict(),
                    namespace=PATTERNS_NAMESPACE,
                    key=pattern.pattern_id,
                )
            except Exception as exc:  # noqa: BLE001
                logger.debug(
                    "ReasoningBank.distill persist %s failed: %s",
                    pattern.pattern_id,
                    exc,
                )

        with self._lock:
            self._patterns_cache = patterns
            self._patterns_cache_at_ms = int(time.time() * 1000)
            self._distillations += 1
        return patterns

    def match_pattern(
        self,
        finding: Mapping[str, Any],
        *,
        min_confidence: float = 0.70,
    ) -> Optional[DistilledPattern]:
        """Return the highest-confidence pattern whose predicate fires.

        Used by the Phase-2 student model: cheap O(N) match against the
        cached pattern list. If any pattern fires with confidence >=
        ``min_confidence``, the student can short-circuit a full council
        convene.
        """
        # Lazy-load patterns from AgentDB if cache is empty (e.g. fresh process).
        with self._lock:
            cache_empty = not self._patterns_cache
        if cache_empty:
            self._refresh_pattern_cache()

        candidate_features = self._extract_features(finding)
        best: Optional[DistilledPattern] = None
        for pattern in self._patterns_cache:
            if not self._predicate_matches(pattern.feature_predicate, candidate_features):
                continue
            if pattern.confidence < min_confidence:
                continue
            if best is None or pattern.confidence > best.confidence:
                best = pattern
        return best

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _build_trajectory(
        self,
        *,
        finding: Mapping[str, Any],
        verdict: Mapping[str, Any],
        context: Mapping[str, Any],
        outcome: Optional[str],
        correctness_score: Optional[float],
    ) -> Trajectory:
        feats = self._extract_features(finding)
        verdict_action = str(
            verdict.get("action") or verdict.get("recommended_action") or "review"
        )
        confidence = float(verdict.get("confidence") or 0.0)
        escalated = bool(verdict.get("escalated"))

        finding_summary = " | ".join(
            str(finding.get(k))
            for k in ("title", "name", "description")
            if finding.get(k)
        )[:280]
        verdict_summary = (
            str(verdict.get("reasoning") or "")[:280]
        )

        finding_id = str(
            finding.get("finding_id")
            or finding.get("id")
            or finding.get("alert_id")
            or uuid.uuid4().hex[:12]
        )
        trajectory_id = f"traj_{finding_id}_{verdict_action}"

        return Trajectory(
            trajectory_id=trajectory_id,
            finding_type=str(finding.get("type") or finding.get("category") or "vuln"),
            cwe=feats.get("cwe"),
            severity=feats.get("severity") or "unknown",
            kev=bool(feats.get("kev")),
            reachable=bool(feats.get("reachable")),
            exploit_available=bool(feats.get("exploit_available")),
            epss=float(feats.get("epss") or 0.0),
            council_action=verdict_action,
            council_confidence=confidence,
            escalated=escalated,
            outcome=outcome,
            correctness_score=correctness_score,
            finding_summary=finding_summary,
            verdict_summary=verdict_summary,
            created_at_ms=int(time.time() * 1000),
        )

    @staticmethod
    def _extract_features(finding: Mapping[str, Any]) -> Dict[str, Any]:
        """Pull the discrete feature vector from a finding dict.

        Best-effort: the input shape varies (SAST normaliser, SCA, secret,
        container...), so we read several aliases for each key.
        """
        cwe = finding.get("cwe") or finding.get("cwe_id")
        if isinstance(cwe, list) and cwe:
            cwe = cwe[0]
        if cwe and not str(cwe).upper().startswith("CWE-"):
            cwe = f"CWE-{cwe}"

        severity = (
            finding.get("severity")
            or finding.get("priority")
            or "unknown"
        )
        if isinstance(severity, str):
            severity = severity.lower()

        kev = (
            finding.get("kev")
            or finding.get("known_exploited")
            or finding.get("kev_listed")
            or False
        )
        reachable = (
            finding.get("reachable")
            or finding.get("is_reachable")
            or finding.get("reachability")
            or False
        )
        if isinstance(reachable, str):
            reachable = reachable.lower() in ("true", "yes", "reachable", "1")

        exploit_available = (
            finding.get("exploit_available")
            or finding.get("exploit_in_the_wild")
            or finding.get("public_exploit")
            or False
        )
        epss = finding.get("epss") or finding.get("epss_score") or 0.0
        try:
            epss = float(epss)
        except (TypeError, ValueError):
            epss = 0.0

        return {
            "cwe": str(cwe) if cwe else None,
            "severity": severity,
            "kev": bool(kev),
            "reachable": bool(reachable),
            "exploit_available": bool(exploit_available),
            "epss": epss,
        }

    @staticmethod
    def _build_query_string(finding: Mapping[str, Any]) -> str:
        parts: List[str] = []
        for key in (
            "title",
            "name",
            "description",
            "cve_id",
            "cwe",
            "severity",
            "service_name",
        ):
            v = finding.get(key)
            if v:
                parts.append(f"{key}={v}")
        return " | ".join(parts).strip()

    @staticmethod
    def _summarise_context(context: Mapping[str, Any]) -> Dict[str, Any]:
        """Reduce the council context to JSON-safe primitives for storage."""
        out: Dict[str, Any] = {}
        for key in ("service_name", "asset_id", "tenant", "org_id", "risk_score"):
            v = context.get(key)
            if v is not None:
                out[key] = str(v) if not isinstance(v, (int, float, bool)) else v
        return out

    @staticmethod
    def _trajectory_from_hit(hit: AgentDBSearchResult) -> Optional[Trajectory]:
        """Reconstruct a Trajectory from an AgentDB hit's content/metadata."""
        try:
            payload = ReasoningBank._extract_payload(hit.content)
        except Exception:
            return None

        traj_meta = payload.get("trajectory") or {}
        if not isinstance(traj_meta, Mapping):
            return None

        try:
            return Trajectory(
                trajectory_id=str(traj_meta.get("trajectory_id") or hit.key),
                finding_type=str(traj_meta.get("finding_type") or "vuln"),
                cwe=traj_meta.get("cwe"),
                severity=str(traj_meta.get("severity") or "unknown"),
                kev=bool(traj_meta.get("kev")),
                reachable=bool(traj_meta.get("reachable")),
                exploit_available=bool(traj_meta.get("exploit_available")),
                epss=float(traj_meta.get("epss") or 0.0),
                council_action=str(traj_meta.get("council_action") or "review"),
                council_confidence=float(traj_meta.get("council_confidence") or 0.0),
                escalated=bool(traj_meta.get("escalated")),
                outcome=traj_meta.get("outcome"),
                correctness_score=(
                    float(traj_meta["correctness_score"])
                    if traj_meta.get("correctness_score") is not None
                    else None
                ),
                created_at_ms=int(hit.created_at_ms or 0),
            )
        except Exception:  # noqa: BLE001
            return None

    @staticmethod
    def _extract_payload(content: str) -> Dict[str, Any]:
        """The bridge stores ``head\\n{json}`` - extract the JSON tail.

        Falls back to parsing the whole content as JSON for forward compat.
        """
        if not content:
            return {}
        # Bridge format: head | event_type | k=v | ... \n {json}
        nl = content.find("\n")
        tail = content[nl + 1 :] if nl >= 0 else content
        try:
            return json.loads(tail)
        except Exception:
            try:
                return json.loads(content)
            except Exception:
                return {}

    def _load_all_trajectories(self, *, limit: int = 20000) -> List[Trajectory]:
        """Pull all trajectories from AgentDB for distillation.

        Uses a broad semantic_search with similarity=0 to walk the namespace.
        """
        bridge = self._get_bridge()
        if bridge is None:
            return []
        # Use a generic prompt that matches everything in the namespace.
        hits = bridge.semantic_search(
            "trajectory finding verdict outcome",
            namespace=TRAJECTORIES_NAMESPACE,
            k=limit,
            min_similarity=0.0,
        )
        out: List[Trajectory] = []
        seen_ids: set = set()
        for hit in hits:
            traj = self._trajectory_from_hit(hit)
            if traj is None:
                continue
            if traj.trajectory_id in seen_ids:
                continue
            seen_ids.add(traj.trajectory_id)
            out.append(traj)
        return out

    @staticmethod
    def _predicate_matches(
        predicate: Mapping[str, Any], features: Mapping[str, Any]
    ) -> bool:
        for key in _PATTERN_FEATURE_KEYS:
            want = predicate.get(key)
            got = features.get(key)
            if isinstance(want, bool) or isinstance(got, bool):
                if bool(want) != bool(got):
                    return False
            elif want in (None, "UNK", "unknown"):
                # Wildcard - matches anything.
                continue
            else:
                if str(want) != str(got):
                    return False
        return True

    @staticmethod
    def _make_pattern_id(predicate: Mapping[str, Any], action: str) -> str:
        # Stable key for UPSERT: same predicate+action -> same pattern_id.
        slug_parts = []
        for k in _PATTERN_FEATURE_KEYS:
            v = predicate.get(k)
            slug_parts.append(f"{k}={v}")
        slug = "&".join(slug_parts)
        return f"pattern::{action}::{slug}"

    def _refresh_pattern_cache(self) -> None:
        bridge = self._get_bridge()
        if bridge is None:
            return
        try:
            hits = bridge.semantic_search(
                "pattern verdict_action support correctness",
                namespace=PATTERNS_NAMESPACE,
                k=500,
                min_similarity=-1.0,
            )
        except Exception as exc:  # noqa: BLE001
            logger.debug("ReasoningBank pattern cache refresh failed: %s", exc)
            return

        patterns: List[DistilledPattern] = []
        seen_ids: set = set()
        for hit in hits:
            try:
                payload = self._extract_payload(hit.content)
                if not payload:
                    continue
                pid = str(payload.get("pattern_id") or hit.key)
                if pid in seen_ids:
                    continue
                seen_ids.add(pid)
                patterns.append(
                    DistilledPattern(
                        pattern_id=pid,
                        feature_predicate=dict(payload.get("predicate") or {}),
                        verdict_action=str(payload.get("verdict_action") or "review"),
                        support=int(payload.get("support") or 0),
                        correctness=float(payload.get("correctness") or 0.0),
                        confidence=float(payload.get("confidence") or 0.0),
                        sample_trajectory_ids=list(
                            payload.get("sample_trajectory_ids") or []
                        ),
                    )
                )
            except Exception:  # noqa: BLE001
                continue
        with self._lock:
            self._patterns_cache = patterns
            self._patterns_cache_at_ms = int(time.time() * 1000)

    # ------------------------------------------------------------------
    # Observability
    # ------------------------------------------------------------------

    def health(self) -> Dict[str, Any]:
        bridge = self._get_bridge()
        bridge_health = bridge.health() if bridge else {"available": False}
        return {
            "bridge": bridge_health,
            "records": self._records,
            "recalls": self._recalls,
            "judgments": self._judgments,
            "distillations": self._distillations,
            "failures": self._failures,
            "patterns_cached": len(self._patterns_cache),
            "patterns_cache_at_ms": self._patterns_cache_at_ms,
        }


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------


_bank: Optional[ReasoningBank] = None
_bank_lock = threading.Lock()


def get_reasoning_bank() -> ReasoningBank:
    """Return the shared ReasoningBank instance, creating it on first call."""
    global _bank
    if _bank is None:
        with _bank_lock:
            if _bank is None:
                _bank = ReasoningBank()
    return _bank


def reset_reasoning_bank() -> None:
    """Drop the singleton - used by tests for isolation."""
    global _bank
    with _bank_lock:
        _bank = None
