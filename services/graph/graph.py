"""Provenance graph construction utilities backed by SQLite and NetworkX."""

from __future__ import annotations

import json
import logging
import sqlite3
import subprocess
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Mapping, MutableMapping, Sequence

try:  # NetworkX provides the richest graph experience but is optional
    import networkx as nx  # type: ignore[import]
except Exception:  # pragma: no cover - optional dependency
    nx = None  # type: ignore[assignment]

from packaging.version import InvalidVersion, Version

from services.provenance.attestation import ProvenanceAttestation, load_attestation
from telemetry import get_meter, get_tracer


@dataclass
class GraphSources:
    """Container for filesystem locations consumed when building the graph."""

    repo_path: Path
    attestation_dir: Path
    normalized_sbom: Path | None
    risk_report: Path | None
    releases_path: Path | None


logger = logging.getLogger(__name__)

_TRACER = get_tracer("fixops.graph")
_METER = get_meter("fixops.graph")
_INGEST_COUNTER = _METER.create_counter(
    "fixops_graph_ingest",
    description="Graph ingestion operations",
)
_QUERY_COUNTER = _METER.create_counter(
    "fixops_graph_queries",
    description="Graph query executions",
)


def _ensure_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value))
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    return None


def _component_key(component: Mapping[str, Any]) -> str:
    purl = component.get("purl")
    if isinstance(purl, str) and purl:
        return purl
    name = component.get("name") or "component"
    version = component.get("version") or "unspecified"
    return f"{name}@{version}"


def _component_slug(component: Mapping[str, Any]) -> str:
    slug_source = component.get("slug") or _component_key(component)
    slug = slug_source.lower()
    for char in ("/", ":", " ", "@", "|"):
        slug = slug.replace(char, "-")
    while "--" in slug:
        slug = slug.replace("--", "-")
    return slug.strip("-") or "component"


class _SimpleNodeView:
    def __init__(self, storage: dict[str, MutableMapping[str, Any]]) -> None:
        self._storage = storage

    def get(
        self, node_id: str, default: MutableMapping[str, Any] | None = None
    ) -> MutableMapping[str, Any] | None:
        return self._storage.get(node_id, default)

    def __getitem__(self, node_id: str) -> MutableMapping[str, Any]:
        return self._storage[node_id]

    def __iter__(self):
        return iter(self._storage)

    def items(self):
        return self._storage.items()

    def __call__(self, data: bool = False):
        if data:
            for item in self._storage.items():
                yield item
        else:
            for key in self._storage:
                yield key


class _SimpleEdgeView:
    def __init__(
        self, storage: list[tuple[str, str, MutableMapping[str, Any]]]
    ) -> None:
        self._storage = storage

    def __call__(self, data: bool = False):
        if data:
            for source, target, payload in self._storage:
                yield source, target, payload
        else:
            for source, target, _ in self._storage:
                yield source, target

    def __iter__(self):
        return self.__call__(data=False)


class _SimpleMultiDiGraph:
    def __init__(self) -> None:
        self._nodes: dict[str, MutableMapping[str, Any]] = {}
        self._edges: list[tuple[str, str, MutableMapping[str, Any]]] = []
        self.nodes = _SimpleNodeView(self._nodes)
        self.edges = _SimpleEdgeView(self._edges)

    def add_node(self, node_id: str, **attrs: Any) -> None:
        payload = self._nodes.setdefault(node_id, {})
        for key, value in attrs.items():
            if value is not None:
                payload[key] = value

    def add_edge(self, source: str, target: str, relation: str, **attrs: Any) -> None:
        payload: MutableMapping[str, Any] = dict(attrs)
        payload["relation"] = relation
        self._edges.append((source, target, payload))

    def has_node(self, node_id: str) -> bool:
        return node_id in self._nodes

    def number_of_nodes(self) -> int:
        return len(self._nodes)

    def number_of_edges(self) -> int:
        return len(self._edges)

    def ancestors(self, node_id: str) -> set[str]:
        visited: set[str] = set()
        stack = [node_id]
        while stack:
            current = stack.pop()
            for source, target, _ in self._edges:
                if target == current and source not in visited:
                    visited.add(source)
                    stack.append(source)
        return visited


def _ancestors(graph: Any, node_id: str) -> set[str]:
    if nx is not None:
        try:
            return nx.ancestors(graph, node_id)
        except Exception:  # pragma: no cover - defensive guard
            return set()
    if hasattr(graph, "ancestors"):
        return set(graph.ancestors(node_id))
    return set()


class ProvenanceGraph:
    """Manage a provenance graph persisted in SQLite and exposed via NetworkX."""

    def __init__(self, *, db_path: str | Path = ":memory:") -> None:
        self.db_path = str(db_path)
        self.connection = sqlite3.connect(self.db_path)
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS nodes (
                id TEXT PRIMARY KEY,
                type TEXT NOT NULL,
                data TEXT NOT NULL
            )
            """
        )
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS edges (
                source TEXT NOT NULL,
                target TEXT NOT NULL,
                type TEXT NOT NULL,
                data TEXT NOT NULL,
                UNIQUE(source, target, type)
            )
            """
        )
        if nx is None:
            logger.warning(
                "networkx unavailable; falling back to simplified provenance graph implementation"
            )
            self.graph = _SimpleMultiDiGraph()
        else:
            self.graph = nx.MultiDiGraph()

    def close(self) -> None:
        self.connection.close()

    # ------------------------------------------------------------------
    # Internal helpers
    def _upsert_node(self, node_id: str, node_type: str, **attrs: Any) -> None:
        existing = self.graph.nodes.get(node_id, {})
        merged = {**existing, **attrs, "type": node_type}  # type: ignore[dict-item]
        self.graph.add_node(node_id, **merged)
        self.connection.execute(
            "REPLACE INTO nodes(id, type, data) VALUES (?, ?, ?)",
            (node_id, node_type, json.dumps(merged, sort_keys=True)),
        )
        self.connection.commit()

    def _add_edge(self, source: str, target: str, relation: str, **attrs: Any) -> None:
        payload = {**attrs, "relation": relation}
        self.graph.add_edge(source, target, relation=relation, **attrs)
        self.connection.execute(
            "REPLACE INTO edges(source, target, type, data) VALUES (?, ?, ?, ?)",
            (source, target, relation, json.dumps(payload, sort_keys=True)),
        )
        self.connection.commit()

    # ------------------------------------------------------------------
    # Ingestion methods
    def ingest_commits(self, commits: Sequence[Mapping[str, Any]]) -> None:
        with _TRACER.start_as_current_span("graph.ingest_commits") as span:
            count = 0
            for entry in commits:
                sha = entry.get("sha")
                if not isinstance(sha, str):
                    continue
                count += 1
                node_id = f"commit:{sha}"
                self._upsert_node(
                    node_id,
                    "commit",
                    sha=sha,
                    author=entry.get("author"),
                    message=entry.get("message"),
                    timestamp=entry.get("timestamp"),
                )
                parents = entry.get("parents") or []
                if isinstance(parents, (list, tuple)):
                    for parent in parents:
                        if isinstance(parent, str) and parent:
                            parent_id = f"commit:{parent}"
                            self._upsert_node(parent_id, "commit", sha=parent)
                            self._add_edge(parent_id, node_id, "parent_of")
            span.set_attribute("fixops.graph.commit_count", count)
            if count:
                _INGEST_COUNTER.add(count, {"type": "commits"})

    def ingest_attestations(
        self, attestations: Iterable[ProvenanceAttestation]
    ) -> None:
        with _TRACER.start_as_current_span("graph.ingest_attestations") as span:
            count = 0
            for attestation in attestations:
                count += 1
                attestation_id = f"attestation:{attestation.metadata.get('buildInvocationID', attestation.metadata.get('buildStartedOn', 'unknown'))}"
                self._upsert_node(
                    attestation_id,
                    "attestation",
                    builder=attestation.builder.get("id"),
                    build_type=attestation.buildType,
                    source=attestation.source.get("uri"),
                    metadata=attestation.metadata,
                )
                builder_id = attestation.builder.get("id")
                if isinstance(builder_id, str) and builder_id:
                    builder_node = f"builder:{builder_id}"
                    self._upsert_node(builder_node, "builder", id=builder_id)
                    self._add_edge(builder_node, attestation_id, "built")
                source_uri = attestation.source.get("uri")
                if isinstance(source_uri, str) and source_uri:
                    source_node = f"source:{source_uri}"
                    self._upsert_node(source_node, "source", uri=source_uri)
                    self._add_edge(source_node, attestation_id, "triggered")
                for subject in attestation.subject:
                    artifact_node = f"artifact:{subject.name}"
                    self._upsert_node(
                        artifact_node,
                        "artifact",
                        name=subject.name,
                        digest=subject.digest,
                    )
                    self._add_edge(attestation_id, artifact_node, "produced")
                for material in attestation.materials:
                    material_node = f"material:{material.uri}"
                    self._upsert_node(
                        material_node,
                        "material",
                        uri=material.uri,
                        digest=material.digest,
                    )
                    self._add_edge(material_node, attestation_id, "consumed")
            span.set_attribute("fixops.graph.attestation_count", count)
            if count:
                _INGEST_COUNTER.add(count, {"type": "attestation"})

    def ingest_normalized_sbom(self, normalized_path: Path) -> None:
        if not normalized_path.is_file():
            return
        with _TRACER.start_as_current_span("graph.ingest_sbom") as span:
            payload = json.loads(normalized_path.read_text(encoding="utf-8"))
            sbom_id = f"sbom:{normalized_path.name}"
            self._upsert_node(
                sbom_id,
                "sbom",
                path=str(normalized_path),
                metadata=payload.get("metadata"),
            )
            component_count = 0
            for component in payload.get("components", []):
                if not isinstance(component, Mapping):
                    continue
                component_count += 1
                slug = _component_slug(component)
                node_id = f"component:{slug}"
                key = _component_key(component)
                attributes = {
                    "slug": slug,
                    "key": key,
                    "name": component.get("name"),
                    "version": component.get("version"),
                    "purl": component.get("purl"),
                    "licenses": component.get("licenses"),
                    "hashes": component.get("hashes"),
                    "generators": component.get("generators"),
                }
                self._upsert_node(node_id, "component", **attributes)
                self._add_edge(sbom_id, node_id, "includes")
            span.set_attribute("fixops.graph.sbom_components", component_count)
            if component_count:
                _INGEST_COUNTER.add(component_count, {"type": "sbom"})

    def ingest_risk_report(self, report_path: Path) -> None:
        if not report_path.is_file():
            return
        with _TRACER.start_as_current_span("graph.ingest_risk") as span:
            payload = json.loads(report_path.read_text(encoding="utf-8"))
            component_count = 0
            for component in payload.get("components", []):
                if not isinstance(component, Mapping):
                    continue
                component_count += 1
                slug = component.get("slug") or _component_slug(component)
                node_id = f"component:{slug}"
                self._upsert_node(
                    node_id,
                    "component",
                    slug=slug,
                    key=component.get("id") or _component_key(component),
                    name=component.get("name"),
                    version=component.get("version"),
                    purl=component.get("purl"),
                    exposure_flags=component.get("exposure_flags"),
                    component_risk=component.get("component_risk"),
                )
                for vulnerability in component.get("vulnerabilities", []):
                    if not isinstance(vulnerability, Mapping):
                        continue
                    cve = vulnerability.get("cve")
                    if not isinstance(cve, str):
                        continue
                    cve_id = cve.upper()
                    cve_node = f"cve:{cve_id}"
                    self._upsert_node(
                        cve_node,
                        "cve",
                        cve=cve_id,
                        kev=bool(vulnerability.get("kev")),
                        epss=vulnerability.get("epss"),
                    )
                    self._add_edge(
                        node_id,
                        cve_node,
                        "affects",
                        kev=bool(vulnerability.get("kev")),
                        risk=vulnerability.get("fixops_risk"),
                    )
            cves = payload.get("cves", {})
            if isinstance(cves, Mapping):
                for cve_id, details in cves.items():
                    if not isinstance(details, Mapping):
                        continue
                    node_id = f"cve:{str(cve_id).upper()}"
                    attrs = {
                        "cve": str(cve_id).upper(),
                        "max_risk": details.get("max_risk"),
                        "components": details.get("components"),
                    }
                    existing = self.graph.nodes.get(node_id, {})
                    attrs.setdefault("kev", existing.get("kev", False))  # type: ignore[union-attr]
                    attrs.setdefault("epss", existing.get("epss"))  # type: ignore[union-attr]
                    self._upsert_node(node_id, "cve", **attrs)
            span.set_attribute("fixops.graph.risk_components", component_count)
            if component_count:
                _INGEST_COUNTER.add(component_count, {"type": "risk"})

    def ingest_releases(self, releases: Sequence[Mapping[str, Any]]) -> None:
        with _TRACER.start_as_current_span("graph.ingest_releases") as span:
            release_count = 0
            for index, release in enumerate(releases):
                tag = release.get("tag")
                if not isinstance(tag, str):
                    continue
                release_count += 1
                release_node = f"release:{tag}"
                released_at = _ensure_datetime(release.get("date"))
                if released_at is None and isinstance(
                    release.get("date"), (int, float)
                ):
                    released_at = _ensure_datetime(float(release["date"]))
                iso_date = (
                    released_at.isoformat() if released_at else release.get("date")
                )
                self._upsert_node(
                    release_node,
                    "release",
                    tag=tag,
                    date=iso_date,
                    order=index,
                )
                for artifact in release.get("artifacts", []) or []:
                    if not isinstance(artifact, str):
                        continue
                    artifact_node = f"artifact:{artifact}"
                    self._upsert_node(artifact_node, "artifact", name=artifact)
                    self._add_edge(release_node, artifact_node, "ships")
                for component in release.get("components", []) or []:
                    if isinstance(component, Mapping):
                        slug = component.get("slug") or _component_slug(component)
                        node_id = f"component:{slug}"
                        self._upsert_node(
                            node_id,
                            "component",
                            slug=slug,
                            name=component.get("name"),
                            version=component.get("version"),
                            purl=component.get("purl"),
                        )
                        self._add_edge(
                            release_node,
                            node_id,
                            "includes_component",
                            version=component.get("version"),
                        )
            span.set_attribute("fixops.graph.release_count", release_count)
            if release_count:
                _INGEST_COUNTER.add(release_count, {"type": "release"})

    # ------------------------------------------------------------------
    # Queries
    def lineage(self, artifact_name: str) -> dict[str, Any]:
        with _TRACER.start_as_current_span("graph.lineage") as span:
            span.set_attribute("fixops.graph.artifact", artifact_name)
            target_node = None
            for node_id, attrs in self.graph.nodes(data=True):
                if attrs.get("type") == "artifact":
                    stored_name = attrs.get("name", "")
                    if (
                        stored_name == artifact_name
                        or node_id == f"artifact:{artifact_name}"
                        or (
                            isinstance(stored_name, str)
                            and stored_name.endswith(f"/{artifact_name}")
                        )
                    ):
                        target_node = node_id
                        break
            if target_node is None:
                return {"artifact": artifact_name, "nodes": [], "edges": []}
            ancestors = _ancestors(self.graph, target_node)
            relevant = ancestors | {target_node}
            nodes = [
                {"id": node_id, **self.graph.nodes[node_id]}
                for node_id in sorted(relevant)
            ]
            edges = []
            for source, target, data in self.graph.edges(data=True):
                if source in relevant and target in relevant:
                    edges.append({"source": source, "target": target, **data})
            edges.sort(
                key=lambda item: (
                    item["source"],
                    item["target"],
                    item.get("relation", ""),
                )
            )
            _QUERY_COUNTER.add(1, {"type": "lineage"})
            span.set_attribute("fixops.graph.lineage_nodes", len(nodes))
            return {"artifact": artifact_name, "nodes": nodes, "edges": edges}

    def components_with_kev(self, last_releases: int = 1) -> list[dict[str, Any]]:
        with _TRACER.start_as_current_span("graph.components_with_kev") as span:
            span.set_attribute("fixops.graph.release_window", last_releases)
            releases = [
                (node_id, attrs)
                for node_id, attrs in self.graph.nodes(data=True)
                if attrs.get("type") == "release"
            ]
            if not releases:
                return []

            def _sort_key(
                item: tuple[str, MutableMapping[str, Any]],
            ) -> tuple[Any, int]:
                attrs = item[1]
                parsed = _ensure_datetime(attrs.get("date"))
                return (parsed or datetime.min, attrs.get("order", 0))

            releases.sort(key=_sort_key)
            selected = releases[-last_releases:]
            results: list[dict[str, Any]] = []
            for node_id, attrs in selected:
                entry = {
                    "release": attrs.get("tag"),
                    "date": attrs.get("date"),
                    "components": [],
                }
                for _, component_node, edge_data in self.graph.out_edges(  # type: ignore[attr-defined]
                    node_id, data=True
                ):
                    if edge_data.get("relation") != "includes_component":
                        continue
                    component_attrs = self.graph.nodes[component_node]
                    kev_cves: set[str] = set()
                    for _, cve_node, vulnerability in self.graph.out_edges(  # type: ignore[attr-defined]
                        component_node, data=True
                    ):
                        if vulnerability.get("relation") != "affects":
                            continue
                        if vulnerability.get("kev") or self.graph.nodes[cve_node].get(
                            "kev"
                        ):
                            kev_cves.add(
                                self.graph.nodes[cve_node].get("cve", cve_node)
                            )
                    if kev_cves:
                        entry["components"].append(
                            {
                                "component": component_attrs.get("slug")
                                or component_attrs.get("name"),
                                "version": edge_data.get("version")
                                or component_attrs.get("version"),
                                "cves": sorted(kev_cves),
                            }
                        )
                if entry["components"]:
                    results.append(entry)
            _QUERY_COUNTER.add(1, {"type": "kev_components"})
            span.set_attribute("fixops.graph.kev_results", len(results))
            return results

    def detect_version_anomalies(self) -> list[dict[str, Any]]:
        with _TRACER.start_as_current_span("graph.detect_anomalies") as span:
            releases_by_component: MutableMapping[
                str, list[tuple[datetime, str, str | None]]
            ] = defaultdict(list)
            for release_node, component_node, edge_data in self.graph.edges(data=True):
                if edge_data.get("relation") != "includes_component":
                    continue
                release_attrs = self.graph.nodes.get(release_node, {})
                if release_attrs.get("type") != "release":  # type: ignore[union-attr]
                    continue
                component_attrs = self.graph.nodes.get(component_node, {})
                if component_attrs.get("type") != "component":  # type: ignore[union-attr]
                    continue
                released_at = (
                    _ensure_datetime(release_attrs.get("date")) or datetime.min  # type: ignore[union-attr]
                )
                releases_by_component[component_node].append(
                    (released_at, release_attrs.get("tag"), edge_data.get("version"))  # type: ignore[arg-type,union-attr]
                )
            anomalies: list[dict[str, Any]] = []
            for component_node, entries in releases_by_component.items():
                entries.sort(key=lambda item: item[0])
                previous_version: Version | None = None
                previous_release: str | None = None
                for released_at, release_tag, version_str in entries:
                    try:
                        current_version = Version(version_str) if version_str else None
                    except InvalidVersion:
                        current_version = None
                    if (
                        previous_version
                        and current_version
                        and current_version < previous_version
                    ):
                        component_attrs = self.graph.nodes[component_node]
                        anomalies.append(
                            {
                                "component": component_attrs.get("slug")
                                or component_attrs.get("name"),
                                "release": release_tag,
                                "version": version_str,
                                "previous_release": previous_release,
                                "previous_version": str(previous_version),
                            }
                        )
                    if current_version is not None:
                        previous_version = current_version
                        previous_release = release_tag
            _QUERY_COUNTER.add(1, {"type": "anomalies"})
            span.set_attribute("fixops.graph.anomaly_count", len(anomalies))
            return anomalies


def collect_git_history(repo_path: Path, *, limit: int = 100) -> list[dict[str, Any]]:
    """Collect commit metadata using ``git`` commands."""

    if not repo_path.exists():
        return []
    format_token = "%H%x1f%P%x1f%an%x1f%ad%x1f%s%x1e"
    with _TRACER.start_as_current_span("graph.collect_git_history") as span:
        span.set_attribute("fixops.graph.limit", limit)
        span.set_attribute("fixops.graph.repo", str(repo_path))
        try:
            completed = subprocess.run(
                [
                    "git",
                    "-C",
                    str(repo_path),
                    "log",
                    f"--max-count={limit}",
                    f"--pretty=format:{format_token}",
                    "--date=iso-strict",
                ],
                check=True,
                capture_output=True,
                text=True,
            )
        except subprocess.CalledProcessError:
            return []
        commits: list[dict[str, Any]] = []
        for entry in completed.stdout.strip("\n\x1e").split("\x1e"):
            if not entry:
                continue
            sha, parents, author, timestamp, message = (entry.split("\x1f") + [""])[:5]
            commits.append(
                {
                    "sha": sha,
                    "parents": [p for p in parents.split() if p],
                    "author": author,
                    "timestamp": timestamp,
                    "message": message,
                }
            )
        span.set_attribute("fixops.graph.git_commits", len(commits))
        return commits


def _load_attestations(attestation_dir: Path) -> list[ProvenanceAttestation]:
    if not attestation_dir.is_dir():
        return []
    attestations: list[ProvenanceAttestation] = []
    for path in sorted(attestation_dir.glob("*.json")):
        try:
            attestations.append(load_attestation(path))
        except Exception:  # pragma: no cover - defensive against user supplied files
            continue
    return attestations


def _load_releases(path: Path) -> list[Mapping[str, Any]]:
    if not path or not path.is_file():
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []
    releases = payload.get("releases")
    if isinstance(releases, Sequence):
        return [release for release in releases if isinstance(release, Mapping)]
    if isinstance(payload, Sequence):
        return [release for release in payload if isinstance(release, Mapping)]
    return []


def build_graph_from_sources(sources: GraphSources) -> ProvenanceGraph:
    """Construct a provenance graph by ingesting known FixOps artefacts."""

    with _TRACER.start_as_current_span("graph.build_from_sources") as span:
        graph = ProvenanceGraph()
        commits = collect_git_history(sources.repo_path)
        graph.ingest_commits(commits)
        attestations = _load_attestations(sources.attestation_dir)
        graph.ingest_attestations(attestations)
        if sources.normalized_sbom:
            graph.ingest_normalized_sbom(sources.normalized_sbom)
        if sources.risk_report:
            graph.ingest_risk_report(sources.risk_report)
        releases = (
            _load_releases(sources.releases_path) if sources.releases_path else []
        )
        graph.ingest_releases(releases)
        span.set_attribute("fixops.graph.nodes", graph.graph.number_of_nodes())
        span.set_attribute("fixops.graph.edges", graph.graph.number_of_edges())
        return graph


__all__ = [
    "GraphSources",
    "ProvenanceGraph",
    "build_graph_from_sources",
    "collect_git_history",
]
