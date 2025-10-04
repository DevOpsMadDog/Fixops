"""Tiny FastAPI-compatible façade for unit tests."""
from __future__ import annotations

import inspect
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple, Type, get_type_hints

try:  # pragma: no cover - optional dependency for typing checks
    from pydantic import BaseModel, ValidationError
except ModuleNotFoundError:  # pragma: no cover - the stub ships alongside
    from pydantic import BaseModel, ValidationError  # type: ignore


class HTTPException(Exception):
    def __init__(self, status_code: int, detail: Any) -> None:
        super().__init__(str(detail))
        self.status_code = status_code
        self.detail = detail


class RequestValidationError(Exception):
    def __init__(self, errors: List[Dict[str, Any]]) -> None:
        super().__init__("Validation failed")
        self.errors = errors


@dataclass
class _Route:
    method: str
    path: str
    endpoint: Callable[..., Any]

    def __post_init__(self) -> None:
        self.signature = inspect.signature(self.endpoint)
        raw_segments = [segment for segment in self.path.strip("/").split("/") if segment]
        self._segments: List[Tuple[str, Optional[str]]] = []
        for segment in raw_segments:
            if segment.startswith("{") and segment.endswith("}"):
                self._segments.append(("param", segment[1:-1]))
            else:
                self._segments.append(("literal", segment))
        try:
            self._type_hints = get_type_hints(self.endpoint)
        except Exception:  # pragma: no cover - fallback for dynamic globals
            self._type_hints = {}

    def match(self, method: str, path: str) -> Optional[Mapping[str, str]]:
        if method != self.method:
            return None
        segments = [segment for segment in path.strip("/").split("/") if segment]
        if len(segments) != len(self._segments):
            return None
        params: Dict[str, str] = {}
        for (kind, value), segment in zip(self._segments, segments):
            if kind == "literal" and value != segment:
                return None
            if kind == "param":
                params[value] = segment
        return params

    def invoke(self, params: Mapping[str, str], body: Optional[Dict[str, Any]]) -> Any:
        kwargs: Dict[str, Any] = {}
        for name, parameter in self.signature.parameters.items():
            annotation = self._type_hints.get(name, parameter.annotation)
            if name in params:
                kwargs[name] = params[name]
                continue

            if isinstance(annotation, type) and issubclass(annotation, BaseModel):
                model_data = body or {}
                try:
                    kwargs[name] = annotation(**model_data)
                except ValidationError as exc:
                    raise RequestValidationError(exc.errors()) from exc
                continue

            if name == "body":
                kwargs[name] = body
            elif parameter.default is not inspect._empty:
                kwargs[name] = parameter.default
            else:
                kwargs[name] = None

        return self.endpoint(**kwargs)


class FastAPI:
    def __init__(self, title: str | None = None, version: str | None = None) -> None:
        self.title = title
        self.version = version
        self._routes: List[_Route] = []

    def post(self, path: str, summary: str | None = None) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        return self._register("POST", path)

    def get(self, path: str, summary: str | None = None) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        return self._register("GET", path)

    def _register(self, method: str, path: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            self._routes.append(_Route(method, path, func))
            return func

        return decorator

    # Internal helpers for the TestClient
    def _handle(self, method: str, path: str, body: Optional[Dict[str, Any]]) -> Any:
        for route in self._routes:
            params = route.match(method, path)
            if params is not None:
                return route.invoke(params, body)
        raise HTTPException(status_code=404, detail="Not Found")


from .testclient import TestClient  # noqa: E402  (import after FastAPI definition)

__all__ = ["FastAPI", "HTTPException", "RequestValidationError", "TestClient"]
