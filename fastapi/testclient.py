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


class TestClient:
    def __init__(self, app) -> None:  # type: ignore[annotation-unchecked]
        self.app = app

    def post(self, path: str, json: Optional[Dict[str, Any]] = None) -> _Response:
        return self._request("POST", path, json or {})

    def get(self, path: str) -> _Response:
        return self._request("GET", path, None)

    def _request(self, method: str, path: str, body: Optional[Dict[str, Any]]) -> _Response:
        try:
            payload = self.app._handle(method, path, body)  # type: ignore[attr-defined]
            status = 200
        except RequestValidationError as exc:
            payload = {"detail": exc.errors}
            status = 422
        except HTTPException as exc:
            payload = {"detail": exc.detail}
            status = exc.status_code
        return _Response(status_code=status, _json=payload)
