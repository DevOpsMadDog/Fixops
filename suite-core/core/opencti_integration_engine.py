"""
ALDECI OpenCTI Integration Engine.

Thin singleton client around the OpenCTI GraphQL/REST API.  OpenCTI is the
upstream system of record for CTI (threat-actors, indicators, intrusion-sets,
malware, STIX bundles), so this engine is intentionally cache-free — every
call proxies through to OPENCTI_URL.

Configuration (read fresh on every call so monkeypatch.setenv works in tests):
    OPENCTI_URL            — required, e.g. "https://opencti.local"
    OPENCTI_TOKEN          — required, OpenCTI API bearer token
    OPENCTI_TIMEOUT_SEC    — optional, default 30

Status:
    "ok"           — both OPENCTI_URL and OPENCTI_TOKEN present
    "unavailable"  — either env var missing

Vision Pillars: V2 (Threat Intelligence), V3 (Detection)
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)


class OpenCTIUnavailableError(RuntimeError):
    """Raised when OPENCTI_URL or OPENCTI_TOKEN is unset."""


class OpenCTIUpstreamError(RuntimeError):
    """Raised when the OpenCTI upstream returns a non-2xx response."""

    def __init__(self, status_code: int, body: str) -> None:
        super().__init__(f"OpenCTI upstream returned {status_code}: {body[:200]}")
        self.status_code = status_code
        self.body = body


# Map STIX 2.1 indicator type → OpenCTI observable entity_type filter
_INDICATOR_TYPE_MAP = {
    "ipv4-addr": "IPv4-Addr",
    "ipv6-addr": "IPv6-Addr",
    "domain-name": "Domain-Name",
    "file-sha256": "StixFile",
    "file-md5": "StixFile",
    "url": "Url",
}


class OpenCTIIntegrationEngine:
    """
    Stateless proxy to an OpenCTI deployment.  Uses GraphQL `/graphql` for
    list queries and REST `/api/stix/import` for STIX bundle imports.
    """

    SUPPORTED_ENDPOINTS = (
        "/api/threat-actors",
        "/api/indicators",
        "/api/stix-import",
        "/api/intrusion-sets",
        "/api/malware",
    )

    SUPPORTED_INDICATOR_TYPES = tuple(_INDICATOR_TYPE_MAP.keys())

    def __init__(self) -> None:
        self._client: Optional[httpx.Client] = None

    # ---- configuration helpers ----------------------------------------

    def opencti_url(self) -> Optional[str]:
        v = os.environ.get("OPENCTI_URL", "").strip()
        return v or None

    def opencti_token(self) -> Optional[str]:
        v = os.environ.get("OPENCTI_TOKEN", "").strip()
        return v or None

    def status(self) -> str:
        if self.opencti_url() and self.opencti_token():
            return "ok"
        return "unavailable"

    def is_available(self) -> bool:
        return self.opencti_url() is not None and self.opencti_token() is not None

    def _timeout(self) -> float:
        try:
            return float(os.environ.get("OPENCTI_TIMEOUT_SEC", "30"))
        except ValueError:
            return 30.0

    def _headers(self) -> Dict[str, str]:
        token = self.opencti_token() or ""
        return {
            "User-Agent": "ALDECI-OpenCTIClient/1.0",
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

    def _client_or_new(self) -> httpx.Client:
        # New client per call keeps tests with monkeypatched httpx simple.
        return httpx.Client(timeout=self._timeout())

    def _require_config(self) -> str:
        url = self.opencti_url()
        token = self.opencti_token()
        if not url or not token:
            raise OpenCTIUnavailableError(
                "OPENCTI_URL or OPENCTI_TOKEN environment variable is not set"
            )
        return url.rstrip("/")

    # ---- low-level transport ------------------------------------------

    def _post_graphql(self, query: str, variables: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        base = self._require_config()
        url = f"{base}/graphql"
        body = {"query": query, "variables": variables or {}}
        with self._client_or_new() as c:
            try:
                resp = c.post(url, json=body, headers=self._headers())
            except httpx.RequestError as exc:
                logger.warning("opencti_graphql_transport_error url=%s err=%s", url, exc)
                raise OpenCTIUpstreamError(502, f"transport error: {exc}") from exc
        if resp.status_code >= 400:
            raise OpenCTIUpstreamError(resp.status_code, resp.text)
        try:
            payload = resp.json()
        except ValueError:
            raise OpenCTIUpstreamError(502, f"invalid JSON from upstream: {resp.text[:200]}")
        if isinstance(payload, dict) and payload.get("errors"):
            raise OpenCTIUpstreamError(502, f"graphql errors: {payload['errors']!r}")
        return payload

    def _post_json(self, path: str, body: Dict[str, Any]) -> Dict[str, Any]:
        base = self._require_config()
        url = f"{base}{path}"
        with self._client_or_new() as c:
            try:
                resp = c.post(url, json=body, headers=self._headers())
            except httpx.RequestError as exc:
                logger.warning("opencti_post_transport_error url=%s err=%s", url, exc)
                raise OpenCTIUpstreamError(502, f"transport error: {exc}") from exc
        if resp.status_code >= 400:
            raise OpenCTIUpstreamError(resp.status_code, resp.text)
        if resp.status_code == 204 or not resp.content:
            return {}
        try:
            return resp.json()
        except ValueError:
            raise OpenCTIUpstreamError(502, f"invalid JSON from upstream: {resp.text[:200]}")

    # ---- public API: threat actors ------------------------------------

    _THREAT_ACTORS_QUERY = """
    query ThreatActors($first: Int, $offset: Int) {
      threatActors(first: $first, offset: $offset) {
        edges { node {
          id name description aliases first_seen last_seen
          sophistication resource_level primary_motivation
        } }
        pageInfo { globalCount }
      }
    }
    """

    def list_threat_actors(self, limit: int = 50, offset: int = 0) -> Dict[str, Any]:
        payload = self._post_graphql(
            self._THREAT_ACTORS_QUERY,
            {"first": int(limit), "offset": int(offset)},
        )
        data = (payload.get("data") or {}).get("threatActors") or {}
        edges = data.get("edges") or []
        actors = []
        for edge in edges:
            node = (edge or {}).get("node") or {}
            actors.append({
                "id": node.get("id"),
                "name": node.get("name"),
                "description": node.get("description"),
                "aliases": node.get("aliases") or [],
                "first_seen": node.get("first_seen"),
                "last_seen": node.get("last_seen"),
                "sophistication": node.get("sophistication"),
                "resource_level": node.get("resource_level"),
                "primary_motivation": node.get("primary_motivation"),
            })
        total = ((data.get("pageInfo") or {}).get("globalCount")) or len(actors)
        return {"threat_actors": actors, "total": int(total)}

    # ---- public API: indicators ---------------------------------------

    _INDICATORS_QUERY = """
    query Indicators($entityType: String, $value: String) {
      indicators(filters: [
        {key: "x_opencti_main_observable_type", values: [$entityType]},
        {key: "pattern", values: [$value], operator: "match"}
      ]) {
        edges { node {
          id pattern valid_from valid_until
          objectLabel { edges { node { value } } }
          killChainPhases { edges { node { kill_chain_name phase_name } } }
        } }
        pageInfo { globalCount }
      }
    }
    """

    def lookup_indicators(self, type_: str, value: str) -> Dict[str, Any]:
        if type_ not in _INDICATOR_TYPE_MAP:
            raise ValueError(
                f"unsupported indicator type '{type_}'; allowed: {list(_INDICATOR_TYPE_MAP.keys())}"
            )
        if not value or not value.strip():
            raise ValueError("indicator value must be non-empty")
        entity = _INDICATOR_TYPE_MAP[type_]
        payload = self._post_graphql(
            self._INDICATORS_QUERY,
            {"entityType": entity, "value": value.strip()},
        )
        data = (payload.get("data") or {}).get("indicators") or {}
        edges = data.get("edges") or []
        indicators: List[Dict[str, Any]] = []
        for edge in edges:
            node = (edge or {}).get("node") or {}
            labels = [
                (le.get("node") or {}).get("value")
                for le in ((node.get("objectLabel") or {}).get("edges") or [])
                if (le.get("node") or {}).get("value")
            ]
            phases = []
            for ke in ((node.get("killChainPhases") or {}).get("edges") or []):
                kn = ke.get("node") or {}
                phases.append({
                    "kill_chain_name": kn.get("kill_chain_name"),
                    "phase_name": kn.get("phase_name"),
                })
            indicators.append({
                "id": node.get("id"),
                "pattern": node.get("pattern"),
                "valid_from": node.get("valid_from"),
                "valid_until": node.get("valid_until"),
                "labels": labels,
                "kill_chain_phases": phases,
            })
        total = ((data.get("pageInfo") or {}).get("globalCount")) or len(indicators)
        return {"indicators": indicators, "total": int(total)}

    # ---- public API: STIX import --------------------------------------

    def import_stix_bundle(self, bundle: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(bundle, dict):
            raise ValueError("bundle must be a STIX 2.1 dict")
        if bundle.get("type") != "bundle":
            raise ValueError("bundle.type must be 'bundle'")
        objects = bundle.get("objects") or []
        if not isinstance(objects, list):
            raise ValueError("bundle.objects must be a list")
        # Per OpenCTI docs the platform exposes /api/stix/import for bundle ingestion.
        result = self._post_json("/api/stix/import", bundle)
        # Normalise response: OpenCTI returns either a Work object or an
        # import summary depending on deployment version.
        imported = (
            result.get("imported_objects")
            or result.get("imported_count")
            or len(objects)
        )
        relationships = (
            result.get("created_relationships")
            or result.get("relationship_count")
            or sum(1 for o in objects if isinstance(o, dict) and o.get("type") == "relationship")
        )
        work_id = result.get("work_id") or result.get("id") or result.get("workId")
        return {
            "imported_objects": int(imported),
            "created_relationships": int(relationships),
            "work_id": work_id,
        }

    # ---- public API: intrusion sets -----------------------------------

    _INTRUSION_SETS_QUERY = """
    query IntrusionSets($first: Int, $offset: Int) {
      intrusionSets(first: $first, offset: $offset) {
        edges { node {
          id name description aliases first_seen last_seen
          sophistication resource_level primary_motivation
        } }
        pageInfo { globalCount }
      }
    }
    """

    def list_intrusion_sets(self, limit: int = 50, offset: int = 0) -> Dict[str, Any]:
        payload = self._post_graphql(
            self._INTRUSION_SETS_QUERY,
            {"first": int(limit), "offset": int(offset)},
        )
        data = (payload.get("data") or {}).get("intrusionSets") or {}
        edges = data.get("edges") or []
        sets = []
        for edge in edges:
            node = (edge or {}).get("node") or {}
            sets.append({
                "id": node.get("id"),
                "name": node.get("name"),
                "description": node.get("description"),
                "aliases": node.get("aliases") or [],
                "first_seen": node.get("first_seen"),
                "last_seen": node.get("last_seen"),
                "sophistication": node.get("sophistication"),
                "resource_level": node.get("resource_level"),
                "primary_motivation": node.get("primary_motivation"),
            })
        total = ((data.get("pageInfo") or {}).get("globalCount")) or len(sets)
        return {"intrusion_sets": sets, "total": int(total)}

    # ---- public API: malware ------------------------------------------

    _MALWARE_QUERY = """
    query Malware($family: String) {
      malwares(filters: [{key: "name", values: [$family], operator: "match"}]) {
        edges { node {
          id name malware_types
          x_opencti_aliases
        } }
        pageInfo { globalCount }
      }
    }
    """

    def lookup_malware(self, family: Optional[str] = None) -> Dict[str, Any]:
        payload = self._post_graphql(
            self._MALWARE_QUERY,
            {"family": (family or "").strip()},
        )
        data = (payload.get("data") or {}).get("malwares") or {}
        edges = data.get("edges") or []
        items = []
        for edge in edges:
            node = (edge or {}).get("node") or {}
            items.append({
                "id": node.get("id"),
                "name": node.get("name"),
                "family": node.get("name"),
                "types": node.get("malware_types") or [],
            })
        total = ((data.get("pageInfo") or {}).get("globalCount")) or len(items)
        return {"malware": items, "total": int(total)}


# ---------------------------------------------------------------------------
# Singleton accessor
# ---------------------------------------------------------------------------

_engine_singleton: Optional[OpenCTIIntegrationEngine] = None


def get_opencti_integration_engine() -> OpenCTIIntegrationEngine:
    global _engine_singleton
    if _engine_singleton is None:
        _engine_singleton = OpenCTIIntegrationEngine()
    return _engine_singleton


__all__ = [
    "OpenCTIIntegrationEngine",
    "OpenCTIUnavailableError",
    "OpenCTIUpstreamError",
    "get_opencti_integration_engine",
]
