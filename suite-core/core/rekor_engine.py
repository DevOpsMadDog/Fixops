"""Sigstore Rekor transparency log engine — read-through proxy.

Wraps the public Sigstore Rekor v1 transparency log API
(https://rekor.sigstore.dev by default).

Design:
  * NO cache, NO SQLite — pure read-through proxy onto upstream Rekor.
  * Public Rekor needs no auth; if a private Rekor instance is used the
    URL alone (REKOR_URL) is sufficient — Rekor v1 is unauthenticated.
  * NO MOCKS — when the upstream is unreachable we surface a 503 plus
    ``status="unavailable"`` on the capability summary; we never fabricate
    transparency-log responses.

Endpoints proxied:
  * GET    /api/v1/log
  * GET    /api/v1/log/proof
  * GET    /api/v1/log/entries/{uuid}
  * GET    /api/v1/log/entries          (by logIndex)
  * POST   /api/v1/log/entries
  * POST   /api/v1/index/retrieve

Spec: https://www.sigstore.dev/swagger/?urls.primaryName=Rekor
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

import httpx

_logger = logging.getLogger(__name__)

DEFAULT_REKOR_URL = "https://rekor.sigstore.dev"


class RekorUnavailable(RuntimeError):
    """Raised when the upstream Rekor instance is unreachable."""


class RekorEngine:
    """Thin read-through proxy onto a Sigstore Rekor v1 transparency log."""

    def __init__(
        self,
        rekor_url: Optional[str] = None,
        client: Optional[httpx.Client] = None,
        timeout: float = 10.0,
    ) -> None:
        self.rekor_url = (
            rekor_url
            or os.environ.get("REKOR_URL")
            or DEFAULT_REKOR_URL
        ).rstrip("/")
        self._timeout = timeout
        self._client = client or httpx.Client(
            timeout=timeout,
            follow_redirects=True,
            headers={
                "User-Agent": "ALDECI-Fixops-Rekor/1.0",
                "Accept": "application/json",
            },
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _full(self, path: str) -> str:
        if not path.startswith("/"):
            path = "/" + path
        return f"{self.rekor_url}{path}"

    def _get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        try:
            resp = self._client.get(self._full(path), params=params)
        except httpx.HTTPError as exc:
            raise RekorUnavailable(
                f"Rekor upstream unreachable at {self.rekor_url}: {exc}"
            ) from exc
        return self._decode(resp)

    def _post(self, path: str, body: Dict[str, Any]) -> Dict[str, Any]:
        try:
            resp = self._client.post(
                self._full(path),
                json=body,
                headers={"Content-Type": "application/json"},
            )
        except httpx.HTTPError as exc:
            raise RekorUnavailable(
                f"Rekor upstream unreachable at {self.rekor_url}: {exc}"
            ) from exc
        return self._decode(resp)

    @staticmethod
    def _decode(resp: httpx.Response) -> Dict[str, Any]:
        if resp.status_code >= 500:
            raise RekorUnavailable(
                f"Rekor upstream {resp.request.url} returned {resp.status_code}: "
                f"{resp.text[:200]}"
            )
        if resp.status_code >= 400:
            return {
                "_error": True,
                "status": resp.status_code,
                "detail": _safe_json(resp) or resp.text[:500],
            }
        return _safe_json(resp) or {}

    # ------------------------------------------------------------------
    # Public API mapped 1-1 to router endpoints
    # ------------------------------------------------------------------

    def health(self) -> Dict[str, Any]:
        """Return capability summary including reachability of the upstream."""
        status = "ok"
        try:
            head = self._client.get(self._full("/api/v1/log"))
            if head.status_code >= 500:
                status = "degraded"
        except httpx.HTTPError:
            status = "unavailable"
        return {
            "service": "Sigstore Rekor",
            "endpoints": [
                "/api/v1/log",
                "/api/v1/log/entries",
                "/api/v1/log/proof",
                "/api/v1/index/retrieve",
            ],
            "rekor_url": self.rekor_url,
            "status": status,
        }

    def get_log(self) -> Dict[str, Any]:
        """GET /api/v1/log — current state of the transparency tree."""
        return self._get("/api/v1/log")

    def get_proof(
        self,
        last_size: int,
        first_size: Optional[int] = None,
        tree_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """GET /api/v1/log/proof — consistency proof between two tree sizes."""
        params: Dict[str, Any] = {"lastSize": last_size}
        if first_size is not None:
            params["firstSize"] = first_size
        if tree_id is not None:
            params["treeID"] = tree_id
        return self._get("/api/v1/log/proof", params=params)

    def get_entry_by_uuid(self, uuid: str) -> Dict[str, Any]:
        """GET /api/v1/log/entries/{uuid} — single transparency log entry."""
        return self._get(f"/api/v1/log/entries/{uuid}")

    def get_entry_by_index(self, log_index: int) -> Dict[str, Any]:
        """GET /api/v1/log/entries?logIndex={n}."""
        return self._get("/api/v1/log/entries", params={"logIndex": log_index})

    def create_entry(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """POST /api/v1/log/entries — submit a new entry to the tree."""
        return self._post("/api/v1/log/entries", body=body)

    def index_retrieve(self, body: Dict[str, Any]) -> List[str]:
        """POST /api/v1/index/retrieve — search by hash/email/publicKey."""
        result = self._post("/api/v1/index/retrieve", body=body)
        # Upstream returns a JSON array; httpx returns it as a list.
        if isinstance(result, list):
            return result
        if isinstance(result, dict) and result.get("_error"):
            return []
        return []

    def close(self) -> None:
        try:
            self._client.close()
        except Exception:  # pragma: no cover - defensive
            pass


def _safe_json(resp: httpx.Response) -> Any:
    try:
        return resp.json()
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Singleton accessor
# ---------------------------------------------------------------------------

_singleton: Optional[RekorEngine] = None


def get_rekor_engine(
    rekor_url: Optional[str] = None,
    client: Optional[httpx.Client] = None,
) -> RekorEngine:
    """Return a process-wide :class:`RekorEngine` singleton.

    Parameters
    ----------
    rekor_url:
        Override URL — primarily for tests / private Rekor instances.
    client:
        Override httpx.Client — primarily for tests with a stubbed transport.
    """
    global _singleton
    if rekor_url is not None or client is not None:
        # Explicit override always builds a fresh engine, no cache pollution.
        return RekorEngine(rekor_url=rekor_url, client=client)
    if _singleton is None:
        _singleton = RekorEngine()
    return _singleton


def reset_rekor_engine() -> None:
    """Test helper — drop the cached singleton."""
    global _singleton
    if _singleton is not None:
        _singleton.close()
    _singleton = None
