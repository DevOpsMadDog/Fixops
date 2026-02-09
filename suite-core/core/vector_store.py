"""Security pattern similarity search powered by vector stores."""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence

try:  # Optional dependency – available when enterprise extras installed
    import chromadb  # type: ignore
    from chromadb.config import Settings as ChromaSettings  # type: ignore
except Exception:  # pragma: no cover - environment without chromadb
    chromadb = None  # type: ignore[assignment]
    ChromaSettings = None  # type: ignore[assignment]

try:  # Optional dependency for richer embeddings
    from sentence_transformers import SentenceTransformer  # type: ignore
except Exception:  # pragma: no cover - keep optional
    SentenceTransformer = None  # type: ignore[assignment]


Vector = List[float]


class VectorStoreError(RuntimeError):
    """Raised when the configured vector store cannot be initialised."""


@dataclass
class VectorRecord:
    """Security pattern indexed inside a vector store."""

    identifier: str
    text: str
    metadata: Dict[str, Any]
    embedding: Optional[Vector] = None


@dataclass
class VectorMatch:
    """Result returned from a vector similarity query."""

    identifier: str
    similarity: float
    metadata: Dict[str, Any]


class BaseVectorStore:
    """Abstract interface used by the pipeline for similarity search."""

    provider: str = "base"

    def index(
        self, records: Sequence[VectorRecord]
    ) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    def search(
        self, query: str, *, top_k: int = 3
    ) -> list[VectorMatch]:  # pragma: no cover
        raise NotImplementedError


class InMemoryVectorStore(BaseVectorStore):
    """Deterministic fallback that stores embeddings in memory."""

    provider = "in_memory"

    def __init__(self, *, dimensions: int = 32) -> None:
        self.dimensions = max(8, dimensions)
        self._records: list[VectorRecord] = []

    @staticmethod
    def _tokenise(text: str) -> list[str]:
        return re.findall(r"[a-z0-9]+", text.lower())

    def _embed(self, text: str) -> Vector:
        tokens = self._tokenise(text)
        vector = [0.0] * self.dimensions
        if not tokens:
            return vector
        for token in tokens:
            digest = hashlib.sha256(token.encode("utf-8")).digest()
            for index in range(self.dimensions):
                vector[index] += digest[index % len(digest)] / 255.0  # type: ignore[arg-type]
        norm = math.sqrt(sum(value * value for value in vector))  # type: ignore[arg-type]
        if norm:  # type: ignore[arg-type]
            vector = [value / norm for value in vector]  # type: ignore[arg-type]
        return vector

    def index(self, records: Sequence[VectorRecord]) -> None:
        self._records = []
        for record in records:
            embedding = self._embed(record.text)
            self._records.append(
                VectorRecord(
                    identifier=record.identifier,
                    text=record.text,
                    metadata=dict(record.metadata),
                    embedding=embedding,
                )
            )

    def search(self, query: str, *, top_k: int = 3) -> list[VectorMatch]:
        if not self._records:
            return []
        query_embedding = self._embed(query)
        if not any(query_embedding):
            return []
        matches: list[VectorMatch] = []
        for record in self._records:
            if not record.embedding:
                continue
            similarity = _cosine_similarity(query_embedding, record.embedding)
            matches.append(
                VectorMatch(
                    identifier=record.identifier,
                    similarity=similarity,
                    metadata=dict(record.metadata),
                )
            )
        matches.sort(key=lambda match: match.similarity, reverse=True)
        return matches[: max(1, top_k)]


class ChromaVectorStore(BaseVectorStore):
    """ChromaDB-backed store with graceful fallback when dependencies missing."""

    provider = "chromadb"

    def __init__(
        self,
        *,
        collection_name: str = "fixops-security-patterns",
        persist_directory: Optional[Path] = None,
    ) -> None:
        if (
            chromadb is None or ChromaSettings is None
        ):  # pragma: no cover - optional dependency
            raise VectorStoreError("ChromaDB dependencies are not installed")
        settings = ChromaSettings(
            anonymized_telemetry=False,
            persist_directory=str(persist_directory) if persist_directory else None,
        )
        self._client = chromadb.Client(settings)
        self._collection = self._client.get_or_create_collection(collection_name)
        self._embedder = self._resolve_embedder()

    @staticmethod
    def _resolve_embedder():
        if SentenceTransformer is None:  # pragma: no cover - optional dependency
            return None
        try:
            return SentenceTransformer("all-MiniLM-L6-v2")
        except Exception:  # pragma: no cover - model download failures
            return None

    def _embed(self, text: str) -> Vector:
        if self._embedder is None:  # pragma: no cover - deterministic fallback
            fallback = InMemoryVectorStore()
            return fallback._embed(text)
        sentence = text if text.strip() else "generic security insight"
        vector = self._embedder.encode(sentence, normalize_embeddings=True)  # type: ignore[operator]
        return vector.tolist() if hasattr(vector, "tolist") else list(vector)

    def index(self, records: Sequence[VectorRecord]) -> None:
        if not records:
            return
        ids = [record.identifier for record in records]
        embeddings = [self._embed(record.text) for record in records]
        metadatas = [dict(record.metadata) for record in records]
        documents = [record.text for record in records]
        self._collection.delete(ids=ids)
        self._collection.add(
            ids=ids, embeddings=embeddings, metadatas=metadatas, documents=documents
        )

    def search(self, query: str, *, top_k: int = 3) -> list[VectorMatch]:
        if not query.strip():
            return []
        embedding = self._embed(query)
        results = self._collection.query(
            query_embeddings=[embedding],
            n_results=max(1, top_k),
            include=["metadatas", "distances"],
        )
        metadatas = results.get("metadatas") or []
        distances = results.get("distances") or []
        matches: list[VectorMatch] = []
        if not metadatas:
            return matches
        first_meta = metadatas[0]
        first_distances = distances[0] if distances else []
        for index, metadata in enumerate(first_meta):
            distance = first_distances[index] if index < len(first_distances) else 1.0
            similarity = max(0.0, 1.0 - float(distance))
            matches.append(
                VectorMatch(
                    identifier=str(
                        metadata.get("id") or metadata.get("pattern_id") or index
                    ),
                    similarity=similarity,
                    metadata=dict(metadata),
                )
            )
        matches.sort(key=lambda match: match.similarity, reverse=True)
        return matches[: max(1, top_k)]


def _cosine_similarity(a: Sequence[float], b: Sequence[float]) -> float:
    numerator = sum(x * y for x, y in zip(a, b))
    if not numerator:
        return 0.0
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(y * y for y in b))
    if not norm_a or not norm_b:
        return 0.0
    return max(0.0, min(1.0, numerator / (norm_a * norm_b)))


class SecurityPatternMatcher:
    """High-level helper that loads patterns and executes similarity search."""

    def __init__(
        self,
        settings: Mapping[str, Any] | None = None,
        *,
        root: Optional[Path] = None,
    ) -> None:
        self.settings = dict(settings or {})
        self.root = root or Path.cwd()
        self.patterns = self._load_patterns()
        self._store, self._store_metadata = self._initialise_store()
        self._store.index(self.patterns)

    # ------------------------------------------------------------------
    # Pattern loading helpers
    # ------------------------------------------------------------------
    def _resolve_path(self, value: str) -> Path:
        path = Path(value)
        if not path.is_absolute():
            candidate = (self.root / path).resolve()
        else:
            candidate = path
        return candidate

    def _load_patterns(self) -> list[VectorRecord]:
        path_value = (
            self.settings.get("patterns_path") or "fixtures/security_patterns.json"
        )
        path = self._resolve_path(str(path_value))
        if not path.exists():
            raise FileNotFoundError(f"Security pattern catalogue not found at {path}")
        payload = json.loads(path.read_text(encoding="utf-8"))
        records: list[VectorRecord] = []
        for entry in payload:
            if not isinstance(entry, Mapping):
                continue
            identifier = str(entry.get("id") or entry.get("pattern_id") or len(records))
            title = str(entry.get("title") or "Security Pattern")
            description = str(entry.get("description") or title)
            metadata = {
                "id": identifier,
                "title": title,
                "description": description,
                "category": entry.get("category"),
                "controls": entry.get("controls") or [],
                "tags": entry.get("tags") or [],
            }
            text = " ".join(
                [
                    title,
                    description,
                    " ".join(metadata.get("controls", [])),  # type: ignore[arg-type]
                    " ".join(metadata.get("tags", [])),  # type: ignore[arg-type]
                ]
            )
            records.append(
                VectorRecord(identifier=identifier, text=text, metadata=metadata)
            )
        if not records:
            raise ValueError("Security pattern catalogue was empty")
        return records

    # ------------------------------------------------------------------
    # Store initialisation
    # ------------------------------------------------------------------
    def _initialise_store(self) -> tuple[BaseVectorStore, Dict[str, Any]]:
        provider = str(
            self.settings.get("provider") or self.settings.get("mode") or "auto"
        ).lower()
        metadata: Dict[str, Any] = {}
        try:
            if provider in {"chroma", "chromadb"}:
                store = ChromaVectorStore(
                    collection_name=str(
                        self.settings.get("collection", "fixops-security-patterns")
                    ),
                    persist_directory=self._resolve_persist_directory(),
                )
            elif provider in {"memory", "demo"}:
                store = InMemoryVectorStore(  # type: ignore[assignment]
                    dimensions=int(self.settings.get("dimensions", 32))
                )
            else:  # auto
                store = ChromaVectorStore(
                    collection_name=str(
                        self.settings.get("collection", "fixops-security-patterns")
                    ),
                    persist_directory=self._resolve_persist_directory(),
                )
        except VectorStoreError as exc:
            store = InMemoryVectorStore(  # type: ignore[assignment]
                dimensions=int(self.settings.get("dimensions", 32))
            )
            metadata["fallback_reason"] = str(exc)
        metadata.setdefault("provider", store.provider)
        metadata.setdefault(
            "collection", self.settings.get("collection", "fixops-security-patterns")
        )
        metadata.setdefault("patterns_indexed", len(self.patterns))
        return store, metadata

    def _resolve_persist_directory(self) -> Optional[Path]:
        persist = self.settings.get("persist_directory")
        if not persist:
            return None
        return self._resolve_path(str(persist))

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------
    @property
    def provider_metadata(self) -> Dict[str, Any]:
        return dict(self._store_metadata)

    def recommend_for_crosswalk(
        self,
        crosswalk: Iterable[Mapping[str, Any]],
        *,
        top_k: Optional[int] = None,
    ) -> list[Dict[str, Any]]:
        matches: list[Dict[str, Any]] = []
        limit = int(self.settings.get("top_k", 3)) if top_k is None else top_k
        for entry in crosswalk:
            if not isinstance(entry, Mapping):
                continue
            query = self._build_query(entry)
            if not query:
                continue
            results = self._store.search(query, top_k=limit)
            if not results:
                continue
            component = self._resolve_component(entry)
            findings = [
                finding.get("rule_id")
                for finding in entry.get("findings", [])
                if isinstance(finding, Mapping)
            ]
            patterns = [
                {
                    "pattern_id": match.metadata.get("id", match.identifier),
                    "title": match.metadata.get("title"),
                    "category": match.metadata.get("category"),
                    "controls": match.metadata.get("controls", []),
                    "similarity": round(match.similarity, 4),
                }
                for match in results
            ]
            matches.append(
                {
                    "component": component,
                    "query": query[:4000],
                    "finding_rules": [value for value in findings if value],
                    "patterns": patterns,
                }
            )
        return matches

    @staticmethod
    def _resolve_component(entry: Mapping[str, Any]) -> Optional[str]:
        design = entry.get("design_row")
        if isinstance(design, Mapping):
            component = (
                design.get("component") or design.get("service") or design.get("name")
            )
            if component:
                return str(component)
        sbom_component = entry.get("sbom_component")
        if isinstance(sbom_component, Mapping):
            name = sbom_component.get("name")
            if name:
                return str(name)
        return None

    @staticmethod
    def _build_query(entry: Mapping[str, Any]) -> str:
        parts: list[str] = []
        design = entry.get("design_row")
        if isinstance(design, Mapping):
            for key in (
                "component",
                "customer_impact",
                "data_classification",
                "exposure",
            ):
                value = design.get(key)
                if isinstance(value, str) and value:
                    parts.append(value)
        for finding in entry.get("findings", []) or []:
            if not isinstance(finding, Mapping):
                continue
            for key in ("rule_id", "message", "file"):
                value = finding.get(key)
                if isinstance(value, str) and value:
                    parts.append(value)
        for record in entry.get("cves", []) or []:
            if not isinstance(record, Mapping):
                continue
            for key in ("cve_id", "title", "severity"):
                value = record.get(key)
                if isinstance(value, str) and value:
                    parts.append(value)
            raw = record.get("raw")
            if isinstance(raw, Mapping):
                description = raw.get("shortDescription") or raw.get("description")
                if isinstance(description, str) and description:
                    parts.append(description)
        return " ".join(parts).strip()


__all__ = [
    "BaseVectorStore",
    "ChromaVectorStore",
    "InMemoryVectorStore",
    "SecurityPatternMatcher",
    "VectorMatch",
    "VectorRecord",
    "VectorStoreError",
]
