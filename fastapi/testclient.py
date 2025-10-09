"""Extremely small subset of the real FastAPI TestClient."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

from . import HTTPException, RequestValidationError


@dataclass
class _Response:
    status_code: int
    _json: Any

    def json(self) -> Any:
        return self._json

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise HTTPException(status_code=self.status_code, detail=self._json)


class TestClient:
    def __init__(self, app) -> None:  # type: ignore[annotation-unchecked]
        self.app = app

    def post(
        self,
        path: str,
        json: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, Any]] = None,
    ) -> _Response:
        return self._request("POST", path, json or {}, headers=headers)

    def get(self, path: str, headers: Optional[Dict[str, Any]] = None) -> _Response:
        return self._request("GET", path, None, headers=headers)

    def _request(
        self,
        method: str,
        path: str,
        body: Optional[Dict[str, Any]],
        headers: Optional[Dict[str, Any]] = None,
    ) -> _Response:
        try:
            payload = self.app._handle(method, path, body, headers=headers)  # type: ignore[attr-defined]
            status = 200
        except RequestValidationError as exc:
            payload = {"detail": exc.errors}
            status = 422
        except HTTPException as exc:
            payload = {"detail": exc.detail}
            status = exc.status_code
        if hasattr(payload, "model_dump"):
            payload = payload.model_dump()
        elif hasattr(payload, "dict"):
            payload = payload.dict()
        return _Response(status_code=status, _json=payload)
