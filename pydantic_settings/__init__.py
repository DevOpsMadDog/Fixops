"""Minimal shim for :mod:`pydantic_settings` compatible with in-repo stubs."""
from __future__ import annotations

import os
from typing import Any, Dict, Iterable, Tuple, Type, Union, get_origin, get_args
import types

from pydantic import FieldInfo


class BaseSettings:
    """Tiny drop-in replacement that reads values from environment variables."""

    class Config:
        env_prefix = ""
        case_sensitive = True

    def __init__(self, **overrides: Any) -> None:
        config = getattr(self, "Config", None)
        env_prefix = getattr(config, "env_prefix", "") if config else ""
        case_sensitive = getattr(config, "case_sensitive", True) if config else True

        for name, annotation in self.__annotations__.items():  # type: ignore[attr-defined]
            default_value = self._default_for(name)
            env_key = f"{env_prefix}{name}" if case_sensitive else f"{env_prefix}{name}".upper()
            raw_env = os.getenv(env_key)
            if raw_env is not None:
                value = self._coerce(annotation, raw_env)
            elif name in overrides:
                value = overrides[name]
            else:
                value = default_value
            setattr(self, name, value)

    @classmethod
    def _default_for(cls, name: str) -> Any:
        candidate = getattr(cls, name, None)
        if isinstance(candidate, FieldInfo):
            value = candidate.default
        else:
            value = candidate
        if isinstance(value, list):
            return list(value)
        if isinstance(value, dict):
            return dict(value)
        return value

    @staticmethod
    def _coerce(annotation: Type[Any], raw: str) -> Any:
        target, optional = BaseSettings._unwrap_optional(annotation)
        if raw == "" and optional:
            return None
        if target is bool:
            lowered = raw.lower()
            if lowered in {"1", "true", "yes", "on"}:
                return True
            if lowered in {"0", "false", "no", "off"}:
                return False
            raise ValueError(f"Cannot coerce '{raw}' to bool")
        if target is int:
            return int(raw)
        if target is float:
            return float(raw)
        origin = get_origin(target)
        if origin in (list, Iterable):
            if not raw:
                return []
            element_type = get_args(target)[0] if get_args(target) else str
            return [BaseSettings._coerce(element_type, item.strip()) for item in raw.split(",")]
        return raw

    @staticmethod
    def _unwrap_optional(annotation: Type[Any]) -> Tuple[Type[Any], bool]:
        origin = get_origin(annotation)
        if origin in (Union, types.UnionType):
            args = [arg for arg in get_args(annotation) if arg is not type(None)]
            if len(args) == 1:
                return args[0], True
        return annotation, False

    def model_dump(self) -> Dict[str, Any]:
        return {name: getattr(self, name) for name in self.__annotations__}  # type: ignore[attr-defined]

    def dict(self) -> Dict[str, Any]:
        return self.model_dump()
