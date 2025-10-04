"""Very small subset of Pydantic for local tests."""
from __future__ import annotations

from dataclasses import dataclass
import sys
import types
from typing import Any, Dict, List, Optional, Tuple, Type, Union, get_args, get_origin, get_type_hints


@dataclass
class FieldInfo:
    default: Any = ...
    min_length: Optional[int] = None
    max_length: Optional[int] = None
    ge: Optional[float] = None
    le: Optional[float] = None
    description: Optional[str] = None


def Field(
    default: Any = ...,
    *,
    min_length: Optional[int] = None,
    max_length: Optional[int] = None,
    ge: Optional[float] = None,
    le: Optional[float] = None,
    description: Optional[str] = None,
) -> FieldInfo:
    return FieldInfo(
        default=default,
        min_length=min_length,
        max_length=max_length,
        ge=ge,
        le=le,
        description=description,
    )


class ValidationError(Exception):
    def __init__(self, errors: List[Dict[str, Any]]) -> None:
        super().__init__("Validation failed")
        self._errors = errors

    def errors(self) -> List[Dict[str, Any]]:
        return self._errors


class BaseModelMeta(type):
    def __new__(mcls, name, bases, namespace):
        annotations = namespace.get("__annotations__", {})
        fields: Dict[str, Tuple[Any, FieldInfo]] = {}
        cleaned_namespace = dict(namespace)

        module_name = namespace.get("__module__")
        module = sys.modules.get(module_name)
        eval_globals = dict(module.__dict__) if module else {}
        eval_globals.setdefault("Dict", Dict)
        eval_globals.setdefault("List", List)
        eval_globals.setdefault("Tuple", Tuple)
        eval_globals.setdefault("Optional", Optional)
        eval_globals.setdefault("Any", Any)

        for field_name, annotation in annotations.items():
            if isinstance(annotation, str):
                try:
                    annotation = eval(annotation, eval_globals)
                except Exception:
                    pass
            default = cleaned_namespace.get(field_name, ...)
            if isinstance(default, FieldInfo):
                field_info = default
                cleaned_namespace.pop(field_name)
            else:
                field_info = FieldInfo(default=default)
            fields[field_name] = (annotation, field_info)

        cleaned_namespace["__fields__"] = fields
        return super().__new__(mcls, name, bases, cleaned_namespace)


class BaseModel(metaclass=BaseModelMeta):
    __fields__: Dict[str, Tuple[Any, FieldInfo]]

    def __init__(self, **data: Any) -> None:
        cls = self.__class__
        if not hasattr(cls, "__resolved_fields__"):
            module = sys.modules.get(cls.__module__)
            base_globals = module.__dict__ if module else {}
            if base_globals is not None:
                globalns = dict(base_globals)
            else:
                globalns = {}
            globalns.setdefault("Dict", Dict)
            globalns.setdefault("List", List)
            globalns.setdefault("Tuple", Tuple)
            globalns.setdefault("Optional", Optional)
            globalns.setdefault("Any", Any)
            try:
                resolved = get_type_hints(cls, globalns=globalns)
            except Exception:
                resolved = {}
            updated: Dict[str, Tuple[Any, FieldInfo]] = {}
            for name, (annotation, field_info) in cls.__fields__.items():
                updated[name] = (resolved.get(name, annotation), field_info)
            cls.__fields__ = updated
            setattr(cls, "__resolved_fields__", True)

        values: Dict[str, Any] = {}
        errors: List[Dict[str, Any]] = []

        for name, (annotation, field_info) in cls.__fields__.items():
            present = name in data
            value = data.get(name, field_info.default)

            if value is ...:
                errors.append(self._error(name, "Field required", "value_error.missing"))
                continue

            try:
                coerced = self._coerce(name, value, annotation, field_info)
            except ValueError as exc:
                errors.append(self._error(name, str(exc), "value_error"))
                continue

            values[name] = coerced

        if errors:
            raise ValidationError(errors)

        for key, value in values.items():
            setattr(self, key, value)

    def dict(self) -> Dict[str, Any]:
        return {name: getattr(self, name) for name in self.__class__.__fields__}

    # ------------------------------------------------------------------
    # Validation helpers
    # ------------------------------------------------------------------
    def _coerce(self, name: str, value: Any, annotation: Any, field_info: FieldInfo) -> Any:
        annotation, optional = self._unwrap_optional(annotation)
        if value is None:
            if optional:
                return None
            raise ValueError("None is not an allowed value")

        origin = get_origin(annotation)
        if origin is list:
            if not isinstance(value, list):
                raise ValueError("Value must be a list")
            return value
        if origin is dict or annotation is dict:
            if not isinstance(value, dict):
                raise ValueError("Value must be a mapping")
            return value

        if annotation in (str,):
            if not isinstance(value, str):
                raise ValueError("Value must be a string")
            if field_info.min_length is not None and len(value) < field_info.min_length:
                raise ValueError(f"String should have at least {field_info.min_length} characters")
            if field_info.max_length is not None and len(value) > field_info.max_length:
                raise ValueError(f"String should have at most {field_info.max_length} characters")
            return value

        if annotation in (float, int):
            try:
                numeric = float(value)
            except (TypeError, ValueError) as exc:
                raise ValueError("Value must be numeric") from exc
            if field_info.ge is not None and numeric < field_info.ge:
                raise ValueError(f"Value must be >= {field_info.ge}")
            if field_info.le is not None and numeric > field_info.le:
                raise ValueError(f"Value must be <= {field_info.le}")
            return numeric

        if annotation is bool:
            if isinstance(value, bool):
                return value
            if isinstance(value, str):
                lowered = value.lower()
                if lowered in {"true", "1", "yes"}:
                    return True
                if lowered in {"false", "0", "no"}:
                    return False
            raise ValueError("Value must be a boolean")

        return value

    @staticmethod
    def _unwrap_optional(annotation: Any) -> Tuple[Any, bool]:
        origin = get_origin(annotation)
        if origin in (Union, types.UnionType):
            args = [arg for arg in get_args(annotation) if arg is not type(None)]
            if len(args) == 1:
                return args[0], True
        return annotation, False

    @staticmethod
    def _error(name: str, message: str, err_type: str) -> Dict[str, Any]:
        return {"loc": ("body", name), "msg": message, "type": err_type}


__all__ = ["BaseModel", "Field", "ValidationError"]
