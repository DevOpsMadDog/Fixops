"""MISP Threat-Sharing Integration Engine — ALDECI.

Wraps the MISP REST API (https://www.misp-project.org/) so ALDECI agents and
routers can pull events, attributes, feeds, and tags from a tenant-supplied
MISP instance. MISP is an authoritative threat-sharing platform, so this
engine treats it as the source of truth — there is NO local SQLite cache.

Endpoint coverage
-----------------
* GET  /events/index                      — paginated event list
* GET  /events/view/{event_id}            — single event with attributes
* POST /attributes/restSearch             — flexible attribute search
* GET  /feeds                              — enabled feeds catalog
* GET  /tags?searchall={substr}           — tag lookup

NO MOCKS rule
-------------
* MISP_URL or MISP_AUTH_KEY env unset → engine reports
  ``status="unavailable"`` and any lookup raises :class:`MISPUnavailableError`
  which the router translates to HTTP 503.
* No fabricated payloads — every response is whatever MISP actually returned.
"""

from __future__ import annotations

import logging
import os
import threading
from typing import Any, Dict, List, Optional

import httpx

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except ImportError:
    _get_tg_bus = None  # type: ignore

_logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT_SECONDS = 12.0


class MISPUnavailableError(RuntimeError):
    """Raised when MISP credentials are missing, network failed, or upstream
    returned an unrecoverable status."""


class MISPIntegrationEngine:
    """Thread-safe MISP REST client. No SQLite cache (MISP is source-of-truth)."""

    def __init__(
        self,
        misp_url: Optional[str] = None,
        auth_key: Optional[str] = None,
        client: Optional[httpx.Client] = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        verify_tls: bool = True,
    ) -> None:
        # Explicit overrides win over env (re-read each call so tests can monkeypatch).
        self._explicit_url = misp_url
        self._explicit_key = auth_key
        self._verify_tls = verify_tls

        # HTTP client
        self._client = client or httpx.Client(timeout=timeout, verify=verify_tls)
        self._owns_client = client is None
        self._timeout = timeout

        self._lock = threading.RLock()

    # ----------------------------------------------------------- helpers

    def misp_url(self) -> Optional[str]:
        if self._explicit_url:
            return self._explicit_url.rstrip("/")
        v = os.environ.get("MISP_URL")
        return v.rstrip("/") if v else None

    def auth_key(self) -> Optional[str]:
        if self._explicit_key:
            return self._explicit_key
        v = os.environ.get("MISP_AUTH_KEY")
        return v or None

    def url_present(self) -> bool:
        return bool(self.misp_url())

    def auth_key_present(self) -> bool:
        return bool(self.auth_key())

    def is_configured(self) -> bool:
        return self.url_present() and self.auth_key_present()

    # ----------------------------------------------------------- request

    def _headers(self) -> Dict[str, str]:
        key = self.auth_key()
        if not key:
            raise MISPUnavailableError(
                "MISP_AUTH_KEY is not configured (Authorization header required)"
            )
        return {
            "Authorization": key,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None,
    ) -> Any:
        base = self.misp_url()
        if not base:
            raise MISPUnavailableError(
                "MISP_URL is not configured (engine cannot dispatch requests)"
            )
        headers = self._headers()
        url = f"{base}{path}"
        try:
            resp = self._client.request(
                method, url, headers=headers, params=params, json=json_body
            )
        except httpx.HTTPError as exc:
            raise MISPUnavailableError(f"MISP request failed: {exc}") from exc

        if resp.status_code in (401, 403):
            raise MISPUnavailableError(
                f"MISP rejected credentials (HTTP {resp.status_code})"
            )
        if resp.status_code == 404:
            raise MISPUnavailableError(
                f"MISP returned 404 for {path}"
            )
        if resp.status_code == 429:
            raise MISPUnavailableError("MISP rate-limit exceeded (HTTP 429)")
        if resp.status_code >= 400:
            raise MISPUnavailableError(
                f"MISP returned HTTP {resp.status_code}: {resp.text[:200]}"
            )
        try:
            return resp.json()
        except ValueError as exc:
            raise MISPUnavailableError(
                f"MISP returned non-JSON response: {exc}"
            ) from exc

    # ----------------------------------------------------------- events

    def list_events(self, limit: int = 50, page: int = 1) -> Dict[str, Any]:
        """Paginated event index."""
        if limit < 1 or limit > 1000:
            raise ValueError("limit must be between 1 and 1000")
        if page < 1:
            raise ValueError("page must be >= 1")
        raw = self._request(
            "GET",
            "/events/index",
            params={"limit": limit, "page": page},
        )
        result = self._normalize_events(raw)
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    count = result.get("count", 0) if isinstance(result, dict) else 0
                    _bus.emit(
                        "threat.detected",
                        {
                            "entity_id": f"misp_events_page_{page}",
                            "type": "misp_threat_events",
                            "severity": "medium",
                            "source_engine": "misp_integration",
                            "event_count": count,
                        },
                    )
            except Exception:
                pass
        return result

    def get_event(self, event_id: str) -> Dict[str, Any]:
        """Single event view."""
        if not event_id:
            raise ValueError("event_id must not be empty")
        raw = self._request("GET", f"/events/view/{event_id}")
        return self._normalize_event(raw, event_id)

    # -------------------------------------------------------- attributes

    def attributes_rest_search(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """POST /attributes/restSearch — flexible search."""
        if not isinstance(body, dict):
            raise ValueError("body must be a dict")
        # Apply MISP defaults if caller omitted them.
        payload = dict(body)
        payload.setdefault("returnFormat", "json")
        payload.setdefault("last", "24h")
        raw = self._request(
            "POST", "/attributes/restSearch", json_body=payload
        )
        return self._normalize_rest_search(raw)

    # ----------------------------------------------------------- feeds

    def list_feeds(self) -> List[Dict[str, Any]]:
        """List configured feeds (returns enabled feeds only by default)."""
        raw = self._request("GET", "/feeds")
        return self._normalize_feeds(raw)

    # ------------------------------------------------------------ tags

    def list_tags(self, searchall: Optional[str] = None) -> Dict[str, Any]:
        """List tags (optionally filtered by substring match)."""
        params: Dict[str, Any] = {}
        if searchall:
            params["searchall"] = searchall
        raw = self._request("GET", "/tags", params=params or None)
        return self._normalize_tags(raw)

    # -------------------------------------------------------- normalize

    @staticmethod
    def _normalize_events(raw: Any) -> Dict[str, Any]:
        # MISP /events/index returns either a list of {Event:{...}} envelopes
        # or a top-level list of events (varies by version).
        items: List[Dict[str, Any]] = []
        if isinstance(raw, list):
            iterable = raw
        elif isinstance(raw, dict):
            iterable = raw.get("response") or raw.get("Event") or []
            if isinstance(iterable, dict):
                iterable = [iterable]
        else:
            iterable = []

        for entry in iterable:
            if not isinstance(entry, dict):
                continue
            event = entry.get("Event") if "Event" in entry else entry
            if not isinstance(event, dict):
                continue
            org = event.get("Org") or {}
            org_name = (
                org.get("name")
                if isinstance(org, dict)
                else event.get("org_name") or ""
            )
            attribute_count = event.get("attribute_count")
            if attribute_count is None and isinstance(event.get("Attribute"), list):
                attribute_count = len(event["Attribute"])
            items.append(
                {
                    "id": str(event.get("id") or ""),
                    "info": event.get("info") or "",
                    "threat_level_id": str(event.get("threat_level_id") or ""),
                    "analysis": str(event.get("analysis") or ""),
                    "distribution": str(event.get("distribution") or ""),
                    "date": event.get("date") or "",
                    "timestamp": str(event.get("timestamp") or ""),
                    "published": bool(event.get("published", False)),
                    "org_name": org_name or "",
                    "attribute_count": int(attribute_count or 0),
                }
            )
        return {"events": items, "total": len(items)}

    @staticmethod
    def _normalize_event(raw: Any, event_id: str) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        event = raw.get("Event") if "Event" in raw else raw
        if not isinstance(event, dict):
            event = {}

        attributes_raw = event.get("Attribute") or []
        attributes: List[Dict[str, Any]] = []
        if isinstance(attributes_raw, list):
            for attr in attributes_raw:
                if not isinstance(attr, dict):
                    continue
                attributes.append(
                    {
                        "id": str(attr.get("id") or ""),
                        "type": attr.get("type") or "",
                        "category": attr.get("category") or "",
                        "value": attr.get("value") or "",
                        "to_ids": bool(attr.get("to_ids", False)),
                        "distribution": str(attr.get("distribution") or ""),
                    }
                )

        objects_raw = event.get("Object") or []
        objects: List[Dict[str, Any]] = []
        if isinstance(objects_raw, list):
            for obj in objects_raw:
                if isinstance(obj, dict):
                    objects.append(obj)

        related_raw = event.get("RelatedEvent") or []
        related: List[Dict[str, Any]] = []
        if isinstance(related_raw, list):
            for rel in related_raw:
                if isinstance(rel, dict):
                    related.append(rel)

        normalized_event: Dict[str, Any] = {
            "id": str(event.get("id") or event_id or ""),
            "info": event.get("info") or "",
            "attributes": attributes,
            "objects": objects,
            "related_events": related,
        }
        # Preserve a few common top-level fields when present (helpful but
        # not required by callers).
        for k in ("threat_level_id", "analysis", "distribution", "date",
                  "timestamp", "published", "uuid"):
            if k in event:
                normalized_event[k] = event[k]
        return {"Event": normalized_event}

    @staticmethod
    def _normalize_rest_search(raw: Any) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            return {"response": {"Attribute": []}}
        # MISP commonly returns either {"response": {"Attribute": [...]}} or
        # {"response": [{"Attribute": {...}}, ...]}.
        response = raw.get("response", raw)
        attributes: List[Dict[str, Any]] = []

        if isinstance(response, dict) and "Attribute" in response:
            inner = response["Attribute"]
            if isinstance(inner, list):
                for attr in inner:
                    if isinstance(attr, dict):
                        attributes.append(MISPIntegrationEngine._normalize_attr(attr))
        elif isinstance(response, list):
            for entry in response:
                if isinstance(entry, dict):
                    attr = entry.get("Attribute") if "Attribute" in entry else entry
                    if isinstance(attr, dict):
                        attributes.append(MISPIntegrationEngine._normalize_attr(attr))

        return {"response": {"Attribute": attributes}}

    @staticmethod
    def _normalize_attr(attr: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "id": str(attr.get("id") or ""),
            "type": attr.get("type") or "",
            "category": attr.get("category") or "",
            "value": attr.get("value") or "",
            "event_id": str(attr.get("event_id") or ""),
            "timestamp": str(attr.get("timestamp") or ""),
        }

    @staticmethod
    def _normalize_feeds(raw: Any) -> List[Dict[str, Any]]:
        feeds: List[Dict[str, Any]] = []
        if not isinstance(raw, list):
            return feeds
        for entry in raw:
            if not isinstance(entry, dict):
                continue
            feed = entry.get("Feed") if "Feed" in entry else entry
            if not isinstance(feed, dict):
                continue
            # Default behavior: surface enabled feeds only.
            enabled = feed.get("enabled")
            if enabled is False:
                continue
            feeds.append(
                {
                    "id": str(feed.get("id") or ""),
                    "name": feed.get("name") or "",
                    "provider": feed.get("provider") or "",
                    "url": feed.get("url") or "",
                    "enabled": bool(enabled if enabled is not None else True),
                    "source_format": feed.get("source_format") or "",
                    "distribution": str(feed.get("distribution") or ""),
                }
            )
        return feeds

    @staticmethod
    def _normalize_tags(raw: Any) -> Dict[str, Any]:
        tags: List[Dict[str, Any]] = []
        if isinstance(raw, dict):
            iterable = raw.get("Tag") or raw.get("tags") or []
        elif isinstance(raw, list):
            iterable = raw
        else:
            iterable = []
        if isinstance(iterable, dict):
            iterable = [iterable]
        for entry in iterable:
            if not isinstance(entry, dict):
                continue
            tag = entry.get("Tag") if "Tag" in entry else entry
            if not isinstance(tag, dict):
                continue
            tags.append(
                {
                    "id": str(tag.get("id") or ""),
                    "name": tag.get("name") or "",
                    "colour": tag.get("colour") or "",
                    "exportable": bool(tag.get("exportable", False)),
                }
            )
        return {"Tag": tags}

    # ----------------------------------------------------------- cleanup

    def close(self) -> None:
        if self._owns_client:
            try:
                self._client.close()
            except Exception:
                pass


# --------------------------------------------------------------- singleton

_singleton: Optional[MISPIntegrationEngine] = None
_singleton_lock = threading.Lock()


def get_misp_integration_engine(
    misp_url: Optional[str] = None,
    auth_key: Optional[str] = None,
    client: Optional[httpx.Client] = None,
    verify_tls: bool = True,
) -> MISPIntegrationEngine:
    """Return the process-wide MISPIntegrationEngine singleton."""
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            _singleton = MISPIntegrationEngine(
                misp_url=misp_url,
                auth_key=auth_key,
                client=client,
                verify_tls=verify_tls,
            )
        return _singleton


def reset_misp_integration_engine() -> None:
    """Tear down the singleton — used by tests."""
    global _singleton
    with _singleton_lock:
        if _singleton is not None:
            _singleton.close()
        _singleton = None


__all__ = [
    "MISPIntegrationEngine",
    "MISPUnavailableError",
    "get_misp_integration_engine",
    "reset_misp_integration_engine",
]
