"""MITRE D3FEND defensive-technique ontology importer.

Source policy
-------------
MITRE publishes the full D3FEND ontology as JSON-LD (and Turtle/OWL) on
``https://d3fend.mitre.org``.  The official, public-licensed JSON-LD export
URL changes occasionally; we keep an ordered list of candidate URLs and
pick the first one that responds 200.  All sources are CC-BY-4.0
(https://d3fend.mitre.org/resources/license/).

If none of the live URLs are reachable (offline / corp-blocked) the
importer raises a ``D3fendSourceError`` carrying operator-actionable
remediation (download the JSON-LD file by hand and re-run with
``file_path=``).  No fake / synthetic data is ever materialised — the
caller decides whether to surface the import failure or fall back to the
hard-coded six high-level countermeasure categories already shipped by
``compliance_mapping_engine._fw_mitre_d3fend``.

Storage
-------
DB:    ``data/d3fend.db``
Table: ``d3fend_techniques``  (PK = control_id)

Each row carries enough provenance to satisfy the "source_*" fields the
compliance-mapping fallback projects into the engine response:

    control_id        — D3FEND ID, e.g. ``D3-IRA``
    control_name      — short label
    description       — definition text
    parent_id         — immediate parent technique (None for top-level)
    top_category      — one of HARDEN/DETECT/ISOLATE/DECEIVE/EVICT/RESTORE
    attack_techniques — JSON list of ATT&CK technique IDs this counters
    ref_links         — JSON list of {href, text} (named to avoid the
                        SQLite ``REFERENCES`` reserved keyword)
    imported_at       — ISO-8601 UTC

Usage::

    from feeds.d3fend.importer import D3fendImporter
    result = D3fendImporter().run(idempotent=True)
    # {"techniques": 487, "imported": 487, "updated": 0,
    #  "by_top_category": {...}, "source": "https://..."}

The query helpers (`list_techniques`, `total_count`, `top_categories`,
`get_db_path`) are used both by the `compliance_mapping_engine`
fallback and by ad-hoc admin endpoints.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sqlite3
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

try:
    import httpx

    _HAS_HTTPX = True
except ImportError:  # pragma: no cover - exercised on minimal installs
    _HAS_HTTPX = False

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Source endpoints (real, public — CC-BY-4.0)
# ---------------------------------------------------------------------------

# Ordered candidate URLs.  We pick the first that returns HTTP 200 with a
# non-empty JSON body.  Each is a real D3FEND export — the project moved
# the canonical export path several times, so we keep the historical ones
# as graceful fallbacks.
D3FEND_DEFAULT_URLS: Tuple[str, ...] = (
    "https://d3fend.mitre.org/ontologies/d3fend.json",
    "https://d3fend.mitre.org/api/ontology/inference/d3fend.json",
    "https://raw.githubusercontent.com/d3fend/d3fend-ontology/main/d3fend.json",
    "https://raw.githubusercontent.com/d3fend/d3fend-ontology/master/d3fend.json",
)

# Allow operator override via env (useful for air-gapped mirrors)
_ENV_URL = os.environ.get("FIXOPS_D3FEND_URL", "").strip() or None

DOWNLOAD_TIMEOUT = 60.0  # seconds

# Maximum length of an ATT&CK technique id segment after the rightmost dot.
# ATT&CK ids look like ``T1059.001`` or ``T1059`` — the trailing segment
# (``001``) is at most 3 chars, but we allow up to 8 to absorb future
# sub-technique numbering schemes (e.g. ``T1059.001a``) without rejecting
# valid refs.  Anything longer is almost certainly not an ATT&CK suffix.
_MAX_ATTACK_SUFFIX_LEN = 8

# HTTP status code that signals a successful D3FEND ontology fetch.
_HTTP_OK = 200

# Minimum byte size we accept for a D3FEND ontology response.  Any payload
# smaller than this is treated as a CDN error page / placeholder rather than
# real JSON-LD content.  The real ontology is multiple megabytes; 100 bytes
# comfortably rejects empty/error bodies without false-positive on legit
# tiny test fixtures (smallest valid JSON-LD doc with one node is ~120 B).
_MIN_RESPONSE_BYTES = 100

_DEFAULT_DB = "data/d3fend.db"
_TABLE = "d3fend_techniques"

# JSON-LD vocabulary keys that may appear (D3FEND uses both prefixed and
# expanded forms across versions).
_TYPE_KEYS = ("@type", "type", "rdfs:type")
_ID_KEYS = ("@id", "id")
_LABEL_KEYS = (
    "rdfs:label",
    "http://www.w3.org/2000/01/rdf-schema#label",
    "label",
    "skos:prefLabel",
)
_COMMENT_KEYS = (
    "rdfs:comment",
    "http://www.w3.org/2000/01/rdf-schema#comment",
    "d3f:definition",
    "definition",
    "skos:definition",
)
_PARENT_KEYS = (
    "rdfs:subClassOf",
    "http://www.w3.org/2000/01/rdf-schema#subClassOf",
    "d3f:has-parent",
    "subClassOf",
)
_COUNTERS_KEYS = (
    "d3f:counters",
    "d3f:counter",
    "https://d3fend.mitre.org/ontologies/d3fend.owl#counters",
    "counters",
)

# The six top-level D3FEND tactics (canonical taxonomy).  Used to bucket
# every sub-technique into a `top_category` field for fast UI grouping.
_TOP_CATEGORIES: Tuple[Tuple[str, str], ...] = (
    ("D3-HARDEN", "Harden"),
    ("D3-DETECT", "Detect"),
    ("D3-ISOLATE", "Isolate"),
    ("D3-DECEIVE", "Deceive"),
    ("D3-EVICT", "Evict"),
    ("D3-RESTORE", "Restore"),
)
_TOP_CATEGORY_IDS = {c for c, _ in _TOP_CATEGORIES}

_local = threading.local()


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class D3fendSourceError(RuntimeError):
    """Raised when no D3FEND ontology source is reachable.

    Operator action: download d3fend.json from
    https://d3fend.mitre.org/resources/ and re-run with
    ``file_path=/local/path/d3fend.json``.
    """


# ---------------------------------------------------------------------------
# Storage helpers (thread-local connection cache, mirrors cis_benchmark)
# ---------------------------------------------------------------------------

def _get_conn(db_path: str) -> sqlite3.Connection:
    key = f"conn_{db_path}"
    conn = getattr(_local, key, None)
    if conn is None:
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA journal_mode=WAL")
        except sqlite3.Error:
            pass
        setattr(_local, key, conn)
    return conn


def _reset_conn(db_path: str) -> None:
    """Drop the cached thread-local connection (used by tests)."""
    key = f"conn_{db_path}"
    conn = getattr(_local, key, None)
    if conn is not None:
        try:
            conn.close()
        except Exception:  # noqa: BLE001
            pass
        delattr(_local, key)


def _ensure_table(db_path: str) -> None:
    conn = _get_conn(db_path)
    conn.execute(
        f"""
        CREATE TABLE IF NOT EXISTS {_TABLE} (
            control_id        TEXT PRIMARY KEY,
            control_name      TEXT NOT NULL,
            description       TEXT NOT NULL DEFAULT '',
            parent_id         TEXT,
            top_category      TEXT NOT NULL,
            attack_techniques TEXT NOT NULL DEFAULT '[]',
            ref_links         TEXT NOT NULL DEFAULT '[]',
            source_iri        TEXT NOT NULL DEFAULT '',
            imported_at       TEXT NOT NULL
        )
        """
    )
    conn.execute(
        f"CREATE INDEX IF NOT EXISTS idx_{_TABLE}_top_cat ON {_TABLE}(top_category)"
    )
    conn.execute(
        f"CREATE INDEX IF NOT EXISTS idx_{_TABLE}_parent ON {_TABLE}(parent_id)"
    )
    conn.commit()


# ---------------------------------------------------------------------------
# JSON-LD parsing
# ---------------------------------------------------------------------------

def _first(d: Dict[str, Any], keys: Iterable[str]) -> Any:
    for k in keys:
        if k in d:
            return d[k]
    return None


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    return list(value) if isinstance(value, list) else [value]


def _extract_text(value: Any) -> str:
    """Return a plain string from a JSON-LD literal/object/list."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, list):
        for item in value:
            text = _extract_text(item)
            if text:
                return text
        return ""
    if isinstance(value, dict):
        for k in ("@value", "value"):
            if k in value and isinstance(value[k], str):
                return value[k].strip()
    return ""


def _extract_id(value: Any) -> str:
    """Return a plain identifier from a JSON-LD reference/object/list."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, list):
        for item in value:
            ident = _extract_id(item)
            if ident:
                return ident
        return ""
    if isinstance(value, dict):
        for k in _ID_KEYS:
            if k in value and isinstance(value[k], str):
                return value[k].strip()
    return ""


def _extract_ids(value: Any) -> List[str]:
    """Return every identifier from a possibly-nested JSON-LD reference list."""
    out: List[str] = []
    for item in _as_list(value):
        ident = _extract_id(item)
        if ident:
            out.append(ident)
    return out


# Match a D3FEND control identifier of the shape ``D3-XXX`` or ``D3-XXX-YY``.
def _short_id(iri: str) -> str:
    """Reduce an IRI / CURIE to a D3FEND control_id like ``D3-IRA``.

    Accepts forms:
        ``https://d3fend.mitre.org/ontologies/d3fend.owl#D3-IRA``
        ``d3f:D3-IRA``
        ``D3-IRA``
    """
    if not iri:
        return ""
    fragment = iri.rsplit("#", 1)[-1]
    fragment = fragment.rsplit("/", 1)[-1]
    fragment = fragment.split(":", 1)[-1]
    return fragment.strip()


def _short_attack_id(iri: str) -> str:
    """Reduce an ATT&CK reference IRI to a technique id like ``T1059.001``."""
    short = _short_id(iri)
    # D3FEND occasionally namespaces ATT&CK as ``attack:T1059`` or similar.
    if "." in short:
        # Strip a trailing prefix segment if present.
        last = short.rsplit(".", 1)[-1]
        if last.upper().startswith("T") and len(last) <= _MAX_ATTACK_SUFFIX_LEN:
            return short
    if short.upper().startswith("T") and any(ch.isdigit() for ch in short):
        return short
    return ""


def _is_d3fend_technique_node(node: Dict[str, Any]) -> bool:
    """Return True iff this node is a D3FEND defensive technique we want."""
    types = _as_list(_first(node, _TYPE_KEYS))
    if not types:
        return False
    type_strs = [_extract_id(t) for t in types]
    # We accept any node typed as a Class (RDF) AND identified by a D3-XXX id.
    looks_like_class = any(
        ("#Class" in t)
        or t.endswith("Class")
        or t.endswith("owl#Class")
        or t == "rdfs:Class"
        for t in type_strs
    )
    iri = _extract_id(_first(node, _ID_KEYS))
    short = _short_id(iri)
    if not short.upper().startswith("D3-"):
        return False
    # Some exports omit the @type for sub-techniques but keep an "rdfs:label".
    return looks_like_class or bool(_first(node, _LABEL_KEYS))


def _parse_node(node: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    iri = _extract_id(_first(node, _ID_KEYS))
    control_id = _short_id(iri)
    if not control_id.upper().startswith("D3-"):
        return None

    label = _extract_text(_first(node, _LABEL_KEYS)) or control_id
    description = _extract_text(_first(node, _COMMENT_KEYS))

    parents = _extract_ids(_first(node, _PARENT_KEYS))
    parent_short = ""
    for p in parents:
        short = _short_id(p)
        if short.upper().startswith("D3-"):
            parent_short = short
            break

    counters_raw = _extract_ids(_first(node, _COUNTERS_KEYS))
    attack_ids = sorted({a for a in (_short_attack_id(c) for c in counters_raw) if a})

    return {
        "control_id": control_id,
        "control_name": label[:500],
        "description": description,
        "parent_id": parent_short or None,
        "attack_techniques": attack_ids,
        "source_iri": iri,
    }


def _walk_jsonld(doc: Any) -> Iterable[Dict[str, Any]]:
    """Yield every dict node that looks like a D3FEND class definition."""
    stack: List[Any] = [doc]
    while stack:
        cur = stack.pop()
        if isinstance(cur, dict):
            graph = cur.get("@graph")
            if isinstance(graph, list) and not _is_d3fend_technique_node(cur):
                stack.extend(graph)
                # Some exports keep the root as a context wrapper but ALSO carry
                # technique metadata; fall through.
            if _is_d3fend_technique_node(cur):
                yield cur
            for v in cur.values():
                if isinstance(v, (dict, list)):
                    stack.append(v)
        elif isinstance(cur, list):
            stack.extend(cur)


def _resolve_top_category(
    control_id: str,
    parent_index: Dict[str, str],
) -> str:
    """Walk parents until we hit one of the canonical six top categories."""
    if control_id in _TOP_CATEGORY_IDS:
        return control_id
    seen: set[str] = set()
    cur = control_id
    while cur and cur not in seen:
        seen.add(cur)
        parent = parent_index.get(cur)
        if parent is None:
            break
        if parent in _TOP_CATEGORY_IDS:
            return parent
        cur = parent
    # Couldn't resolve — emit a stable bucket so the UI still groups it.
    return "D3-UNKNOWN"


def parse_d3fend_jsonld(data: Any) -> List[Dict[str, Any]]:
    """Parse a JSON-LD document into a list of normalised technique dicts.

    Returns rows ready for INSERT — each carries ``top_category`` resolved
    via parent-chain traversal.
    """
    raw_nodes = list(_walk_jsonld(data))

    # First pass — extract per-node fields.
    parsed: Dict[str, Dict[str, Any]] = {}
    for node in raw_nodes:
        row = _parse_node(node)
        if row is None:
            continue
        # If the same control_id appears multiple times (graph cycles, dup
        # exports), prefer the entry with a longer description.
        prior = parsed.get(row["control_id"])
        if prior is None:
            parsed[row["control_id"]] = row
        else:
            if len(row["description"]) > len(prior["description"]):
                parsed[row["control_id"]] = row

    # Make sure the canonical six top categories always exist.
    now_label = {cid: name for cid, name in _TOP_CATEGORIES}
    for cid, name in _TOP_CATEGORIES:
        if cid not in parsed:
            parsed[cid] = {
                "control_id": cid,
                "control_name": name,
                "description": (
                    f"MITRE D3FEND top-level countermeasure category: {name}"
                ),
                "parent_id": None,
                "attack_techniques": [],
                "source_iri": f"https://d3fend.mitre.org/ontologies/d3fend.owl#{cid}",
            }

    # Second pass — resolve top_category via parent walk.
    parent_index = {
        cid: row["parent_id"]
        for cid, row in parsed.items()
        if row.get("parent_id")
    }
    out: List[Dict[str, Any]] = []
    for cid, row in parsed.items():
        row["top_category"] = _resolve_top_category(cid, parent_index)
        # Backfill a description if the export omitted one for top categories.
        if not row["description"] and cid in now_label:
            row["description"] = (
                "MITRE D3FEND top-level countermeasure category: "
                f"{now_label[cid]}"
            )
        out.append(row)

    out.sort(key=lambda r: (r.get("top_category") or "ZZ", r["control_id"]))
    return out


# ---------------------------------------------------------------------------
# Importer
# ---------------------------------------------------------------------------

class D3fendImporter:
    """Import MITRE D3FEND ontology techniques into local SQLite.

    Args:
        db_path:   SQLite database file path (default: data/d3fend.db).
        url:       HTTP source for the D3FEND JSON-LD.  Tries
                   ``D3FEND_DEFAULT_URLS`` if not supplied.
        file_path: Local path to a pre-downloaded JSON-LD doc.  Takes
                   precedence over url when both are passed.
        timeout:   HTTP request timeout in seconds (default 60).
    """

    def __init__(
        self,
        db_path: str = _DEFAULT_DB,
        url: Optional[str] = None,
        file_path: Optional[str] = None,
        timeout: float = DOWNLOAD_TIMEOUT,
    ) -> None:
        self._db_path = db_path
        self._url = url
        self._file_path = file_path
        self._timeout = timeout
        _ensure_table(db_path)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self, idempotent: bool = True) -> Dict[str, Any]:
        raw, source = self._load_jsonld()
        try:
            doc = json.loads(raw) if isinstance(raw, (bytes, bytearray, str)) else raw
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid D3FEND JSON-LD: {exc}") from exc

        techniques = parse_d3fend_jsonld(doc)
        if not techniques:
            raise ValueError(
                "Parsed 0 D3FEND techniques from the supplied source. "
                "The export schema may have changed; please file an issue."
            )

        conn = _get_conn(self._db_path)
        now_iso = datetime.now(timezone.utc).isoformat()
        imported = updated = skipped = 0
        by_top: Dict[str, int] = {}

        for row in techniques:
            existing = conn.execute(
                f"SELECT 1 FROM {_TABLE} WHERE control_id = ?",
                (row["control_id"],),
            ).fetchone()
            payload = (
                row["control_id"],
                row["control_name"],
                row["description"],
                row["parent_id"],
                row["top_category"],
                json.dumps(row["attack_techniques"]),
                json.dumps([]),  # ref_links reserved for future provenance
                row.get("source_iri", ""),
                now_iso,
            )
            if existing is not None:
                if idempotent:
                    skipped += 1
                else:
                    conn.execute(
                        f"""
                        UPDATE {_TABLE}
                        SET control_name=?, description=?, parent_id=?,
                            top_category=?, attack_techniques=?, ref_links=?,
                            source_iri=?, imported_at=?
                        WHERE control_id=?
                        """,
                        (
                            payload[1], payload[2], payload[3], payload[4],
                            payload[5], payload[6], payload[7], payload[8],
                            payload[0],
                        ),
                    )
                    updated += 1
            else:
                conn.execute(
                    f"""
                    INSERT INTO {_TABLE}
                        (control_id, control_name, description, parent_id,
                         top_category, attack_techniques, ref_links,
                         source_iri, imported_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    payload,
                )
                imported += 1
            top = row["top_category"]
            by_top[top] = by_top.get(top, 0) + 1

        conn.commit()
        return {
            "techniques": imported + updated + skipped,
            "imported": imported,
            "updated": updated,
            "skipped": skipped,
            "by_top_category": by_top,
            "source": source,
        }

    def list_techniques(
        self,
        top_category: Optional[str] = None,
        attack_technique: Optional[str] = None,
        page: int = 1,
        page_size: int = 200,
    ) -> Dict[str, Any]:
        page_size = min(max(1, page_size), 1000)
        offset = (max(1, page) - 1) * page_size

        clauses: List[str] = []
        params: List[Any] = []
        if top_category:
            clauses.append("top_category = ?")
            params.append(top_category)
        if attack_technique:
            clauses.append("attack_techniques LIKE ?")
            params.append(f'%"{attack_technique}"%')
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""

        conn = _get_conn(self._db_path)
        total_row = conn.execute(
            f"SELECT COUNT(*) FROM {_TABLE} {where}", params
        ).fetchone()
        total = total_row[0] if total_row else 0

        rows = conn.execute(
            f"""
            SELECT control_id, control_name, description, parent_id,
                   top_category, attack_techniques, ref_links,
                   source_iri, imported_at
            FROM {_TABLE}
            {where}
            ORDER BY top_category, control_id
            LIMIT ? OFFSET ?
            """,
            (*params, page_size, offset),
        ).fetchall()

        entries: List[Dict[str, Any]] = []
        for r in rows:
            d = dict(r)
            for k in ("attack_techniques", "ref_links"):
                try:
                    d[k] = json.loads(d[k]) if d[k] else []
                except (TypeError, ValueError):
                    d[k] = []
            entries.append(d)

        return {
            "entries": entries,
            "total": total,
            "page": page,
            "page_size": page_size,
        }

    def total_count(self) -> int:
        conn = _get_conn(self._db_path)
        row = conn.execute(f"SELECT COUNT(*) FROM {_TABLE}").fetchone()
        return row[0] if row else 0

    def db_path(self) -> str:
        return self._db_path

    # ------------------------------------------------------------------
    # Source loading
    # ------------------------------------------------------------------

    def _load_jsonld(self) -> Tuple[bytes, str]:
        if self._file_path:
            path = Path(self._file_path)
            if not path.exists():
                raise D3fendSourceError(
                    f"file_path does not exist: {self._file_path}"
                )
            return path.read_bytes(), f"file://{path.resolve()}"

        candidates: List[str] = []
        if self._url:
            candidates.append(self._url)
        if _ENV_URL:
            candidates.append(_ENV_URL)
        candidates.extend(D3FEND_DEFAULT_URLS)

        if not _HAS_HTTPX:
            raise D3fendSourceError(
                "httpx is not available — cannot perform live HTTP fetch. "
                "Pass file_path=/local/path/d3fend.json after downloading "
                "the JSON-LD ontology from https://d3fend.mitre.org/resources/."
            )

        last_error: Optional[str] = None
        for url in candidates:
            try:
                with httpx.Client(
                    timeout=self._timeout, follow_redirects=True
                ) as client:
                    response = client.get(url)
            except httpx.RequestError as exc:
                last_error = f"{url}: {exc}"
                logger.debug("D3FEND source %s unreachable: %s", url, exc)
                continue

            if response.status_code != _HTTP_OK:
                last_error = f"{url}: HTTP {response.status_code}"
                logger.debug(
                    "D3FEND source %s returned %s", url, response.status_code
                )
                continue

            content = response.content
            if not content or len(content) < _MIN_RESPONSE_BYTES:
                last_error = f"{url}: response too small ({len(content)} bytes)"
                continue
            return content, url

        raise D3fendSourceError(
            "No D3FEND ontology source reachable. Tried: "
            f"{', '.join(candidates)}. Last error: {last_error}. "
            "Download d3fend.json manually from "
            "https://d3fend.mitre.org/resources/ and re-run the importer "
            "with file_path=/local/path/d3fend.json."
        )


# ---------------------------------------------------------------------------
# Module-level query helpers (used by the compliance fallback)
# ---------------------------------------------------------------------------

def get_db_path() -> str:
    return _DEFAULT_DB


def list_techniques_from_db(
    db_path: Optional[str] = None,
    top_category: Optional[str] = None,
    attack_technique: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Return all techniques from the local DB (no pagination).

    Returns ``[]`` if the DB / table does not exist (caller decides what
    to render in that case).
    """
    target = db_path or _DEFAULT_DB
    if not Path(target).exists():
        return []
    try:
        with sqlite3.connect(target) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.execute(
                "SELECT name FROM sqlite_master "
                f"WHERE type='table' AND name='{_TABLE}'"
            )
            if cur.fetchone() is None:
                return []
            clauses: List[str] = []
            params: List[Any] = []
            if top_category:
                clauses.append("top_category = ?")
                params.append(top_category)
            if attack_technique:
                clauses.append("attack_techniques LIKE ?")
                params.append(f'%"{attack_technique}"%')
            where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
            rows = conn.execute(
                f"""
                SELECT control_id, control_name, description, parent_id,
                       top_category, attack_techniques, source_iri, imported_at
                FROM {_TABLE}
                {where}
                ORDER BY top_category, control_id
                """,
                params,
            ).fetchall()
    except sqlite3.Error as exc:
        logger.warning("D3FEND query failed for %s: %s", target, exc)
        return []

    out: List[Dict[str, Any]] = []
    for r in rows:
        d = dict(r)
        try:
            d["attack_techniques"] = (
                json.loads(d["attack_techniques"])
                if d["attack_techniques"]
                else []
            )
        except (TypeError, ValueError):
            d["attack_techniques"] = []
        out.append(d)
    return out


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> None:
    parser = argparse.ArgumentParser(description="Import MITRE D3FEND ontology")
    src = parser.add_mutually_exclusive_group()
    src.add_argument("--url", default=None, help="HTTP source URL for D3FEND JSON-LD")
    src.add_argument(
        "--file",
        dest="file_path",
        default=None,
        help="Local JSON-LD file path",
    )
    parser.add_argument("--db", default=_DEFAULT_DB, help="SQLite DB path")
    parser.add_argument(
        "--force-update",
        action="store_true",
        help="Update existing rows instead of skipping",
    )
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    importer = D3fendImporter(
        db_path=args.db,
        url=args.url,
        file_path=args.file_path,
    )
    try:
        result = importer.run(idempotent=not args.force_update)
    except D3fendSourceError as exc:
        print(json.dumps({"error": "source_unreachable", "reason": str(exc)}, indent=2))
        sys.exit(2)
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
