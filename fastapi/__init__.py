"""Tiny FastAPI-compatible façade for unit tests."""

from __future__ import annotations

import inspect
from dataclasses import dataclass
from typing import (
    Any,
    Callable,
    Dict,
    List,
    Mapping,
    Optional,
    Tuple,
    Type,
    get_type_hints,
)
from types import SimpleNamespace

try:  # pragma: no cover - optional dependency for typing checks
    from pydantic import BaseModel, ValidationError
except ModuleNotFoundError:  # pragma: no cover - the stub ships alongside
    from pydantic import BaseModel, ValidationError  # type: ignore


class Request:
    def __init__(self, headers: Optional[Mapping[str, str]] | None = None, body: bytes | None = None) -> None:
        self.headers = dict(headers or {})
        self._body = body or b""

    async def body(self) -> bytes:
        return self._body


class HTTPException(Exception):
    def __init__(self, status_code: int, detail: Any) -> None:
        super().__init__(str(detail))
        self.status_code = status_code
        self.detail = detail


def Depends(dependency: Callable[..., Any] | None = None) -> Callable[..., Any] | None:
    return dependency


def Query(default: Any = None, description: str | None = None) -> Any:
    return default


def File(default: Any = None, **_: Any) -> Any:
    return default


def Form(default: Any = None, **_: Any) -> Any:
    return default


class UploadFile:
    def __init__(
        self, filename: str | None = None, content_type: str | None = None
    ) -> None:
        self.filename = filename or ""
        self.content_type = content_type
        self._buffer = bytearray()

    async def read(self, size: int = -1) -> bytes:  # pragma: no cover - simple stub
        if size is None or size < 0:
            size = len(self._buffer)
        data = self._buffer[:size]
        if size >= len(self._buffer):
            self._buffer.clear()
        else:
            del self._buffer[:size]
        return bytes(data)


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
        raw_segments = [
            segment for segment in self.path.strip("/").split("/") if segment
        ]
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

        result = self.endpoint(**kwargs)
        if inspect.iscoroutine(result):
            import asyncio

            return asyncio.run(result)
        return result


class APIRouter:
    def __init__(
        self, prefix: str = "", tags: Optional[List[str]] | None = None
    ) -> None:
        self.prefix = prefix or ""
        self.tags = tags or []
        self._routes: List[_Route] = []

    def _register(
        self, method: str, path: str
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        full_path = f"{self.prefix}{path}"

        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            self._routes.append(_Route(method, full_path, func))
            return func

        return decorator

    def post(
        self, path: str, **_: Any
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        return self._register("POST", path)

    def get(
        self, path: str, **_: Any
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        return self._register("GET", path)

    def include_router(self, router: "APIRouter", prefix: str = "") -> None:
        for route in router._routes:
            combined_path = f"{prefix}{route.path}" if prefix else route.path
            self._routes.append(_Route(route.method, combined_path, route.endpoint))

    def add_api_route(
        self,
        path: str,
        endpoint: Callable[..., Any],
        methods: Optional[List[str]] = None,
        **_: Any,
    ) -> None:
        for method in methods or ["GET"]:
            self._routes.append(_Route(method, f"{self.prefix}{path}", endpoint))


class FastAPI:
    def __init__(
        self,
        title: str | None = None,
        version: str | None = None,
        lifespan: Any | None = None,
    ) -> None:
        self.title = title
        self.version = version
        self._routes: List[_Route] = []
        self._middleware: List[tuple[Any, Dict[str, Any]]] = []
        self.user_middleware: List[SimpleNamespace] = []
        self._lifespan = lifespan

    def post(
        self, path: str, summary: str | None = None, **_: Any
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        return self._register("POST", path)

    def get(
        self, path: str, summary: str | None = None, **_: Any
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        return self._register("GET", path)

    def add_middleware(self, middleware_class: Any, **options: Any) -> None:
        self._middleware.append((middleware_class, options))
        self.user_middleware.append(
            SimpleNamespace(cls=middleware_class, options=options)
        )

    def _register(
        self, method: str, path: str
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            self._routes.append(_Route(method, path, func))
            return func

        return decorator

    def include_router(self, router: APIRouter, prefix: str = "") -> None:
        for route in router._routes:
            combined_path = f"{prefix}{route.path}" if prefix else route.path
            self._routes.append(_Route(route.method, combined_path, route.endpoint))

    # Internal helpers for the TestClient
    def _handle(
        self,
        method: str,
        path: str,
        body: Optional[Dict[str, Any]],
        headers: Optional[Dict[str, Any]] = None,
    ) -> Any:
        for route in self._routes:
            params = route.match(method, path)
            if params is not None:
                return route.invoke(params, body)
        raise HTTPException(status_code=404, detail="Not Found")


class _StatusCodes:
    HTTP_201_CREATED = 201
    HTTP_200_OK = 200
    HTTP_400_BAD_REQUEST = 400
    HTTP_401_UNAUTHORIZED = 401
    HTTP_403_FORBIDDEN = 403
    HTTP_404_NOT_FOUND = 404
    HTTP_413_REQUEST_ENTITY_TOO_LARGE = 413
    HTTP_415_UNSUPPORTED_MEDIA_TYPE = 415
    HTTP_422_UNPROCESSABLE_ENTITY = 422


status = _StatusCodes()


from .testclient import TestClient  # noqa: E402  (import after FastAPI definition)

__all__ = [
    "FastAPI",
    "APIRouter",
    "HTTPException",
    "Request",
    "Depends",
    "Query",
    "File",
    "UploadFile",
    "RequestValidationError",
    "status",
    "TestClient",
]
