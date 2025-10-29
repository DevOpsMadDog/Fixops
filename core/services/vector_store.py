"""Vector Store - Local file-backed evidence storage with similarity search."""

import json
import re
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


class VectorStore:
    """Simple file-backed vector store using TF-IDF for similarity."""

    def __init__(self, storage_dir: Path):
        """Initialize vector store with storage directory."""
        self.storage_dir = storage_dir
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.index_path = self.storage_dir / "index.json"
        self.index = self._load_index()

    def _load_index(self) -> Dict[str, Any]:
        """Load index from disk."""
        if self.index_path.exists():
            with self.index_path.open("r") as f:
                return json.load(f)
        return {"documents": {}, "idf": {}}

    def _save_index(self):
        """Save index to disk."""
        with self.index_path.open("w") as f:
            json.dump(self.index, f, indent=2)

    def upsert(
        self,
        doc_id: str,
        content: str,
        metadata: Dict[str, Any],
    ):
        """Insert or update a document."""
        terms = self._tokenize(content)
        tf = self._compute_tf(terms)

        doc_path = self.storage_dir / f"{self._sanitize_id(doc_id)}.json"
        doc_data = {
            "doc_id": doc_id,
            "content": content,
            "metadata": metadata,
            "tf": tf,
            "term_count": len(terms),
        }

        with doc_path.open("w") as f:
            json.dump(doc_data, f, indent=2)

        self.index["documents"][doc_id] = {
            "path": str(doc_path),
            "metadata": metadata,
        }

        for term in set(terms):
            self.index["idf"][term] = self.index["idf"].get(term, 0) + 1

        self._save_index()

    def query(
        self,
        content: str,
        k: int = 5,
        filter_metadata: Optional[Dict[str, Any]] = None,
    ) -> List[Tuple[str, float, Dict[str, Any]]]:
        """Query for similar documents."""
        query_terms = self._tokenize(content)
        query_tf = self._compute_tf(query_terms)

        results = []
        for doc_id, doc_info in self.index["documents"].items():
            if filter_metadata:
                if not self._matches_filter(doc_info["metadata"], filter_metadata):
                    continue

            doc_path = Path(doc_info["path"])
            if not doc_path.exists():
                continue

            with doc_path.open("r") as f:
                doc_data = json.load(f)

            similarity = self._cosine_similarity(
                query_tf, doc_data["tf"], query_terms, doc_data["term_count"]
            )

            results.append((doc_id, similarity, doc_data["metadata"]))

        results.sort(key=lambda x: x[1], reverse=True)
        return results[:k]

    def delete_namespace(self, namespace: str):
        """Delete all documents in a namespace (org_id/app_id prefix)."""
        to_delete = []
        for doc_id in self.index["documents"]:
            if doc_id.startswith(namespace):
                to_delete.append(doc_id)

        for doc_id in to_delete:
            doc_info = self.index["documents"][doc_id]
            doc_path = Path(doc_info["path"])
            if doc_path.exists():
                doc_path.unlink()
            del self.index["documents"][doc_id]

        self._save_index()

    def _tokenize(self, text: str) -> List[str]:
        """Tokenize text into terms."""
        text = text.lower()
        terms = re.findall(r"\b[a-z0-9]+\b", text)
        return terms

    def _compute_tf(self, terms: List[str]) -> Dict[str, float]:
        """Compute term frequency."""
        if not terms:
            return {}

        counts = Counter(terms)
        total = len(terms)
        return {term: count / total for term, count in counts.items()}

    def _compute_idf(self, term: str) -> float:
        """Compute inverse document frequency."""
        total_docs = len(self.index["documents"])
        if total_docs == 0:
            return 0.0

        doc_freq = self.index["idf"].get(term, 0)
        if doc_freq == 0:
            return 0.0

        import math

        return math.log(total_docs / doc_freq)

    def _cosine_similarity(
        self,
        tf1: Dict[str, float],
        tf2: Dict[str, float],
        terms1: List[str],
        term_count2: int,
    ) -> float:
        """Compute cosine similarity between two TF vectors."""
        if not tf1 or not tf2:
            return 0.0

        vec1 = {}
        vec2 = {}
        all_terms = set(tf1.keys()) | set(tf2.keys())

        for term in all_terms:
            idf = self._compute_idf(term)
            vec1[term] = tf1.get(term, 0.0) * idf
            vec2[term] = tf2.get(term, 0.0) * idf

        dot_product = sum(vec1.get(t, 0.0) * vec2.get(t, 0.0) for t in all_terms)
        mag1 = sum(v * v for v in vec1.values()) ** 0.5
        mag2 = sum(v * v for v in vec2.values()) ** 0.5

        if mag1 == 0.0 or mag2 == 0.0:
            return 0.0

        return dot_product / (mag1 * mag2)

    def _matches_filter(
        self, metadata: Dict[str, Any], filter_metadata: Dict[str, Any]
    ) -> bool:
        """Check if metadata matches filter."""
        for key, value in filter_metadata.items():
            if key not in metadata:
                return False
            if metadata[key] != value:
                return False
        return True

    def _sanitize_id(self, doc_id: str) -> str:
        """Sanitize document ID for filesystem."""
        return re.sub(r"[^a-zA-Z0-9_-]", "_", doc_id)
