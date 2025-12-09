"""Runtime customizations for test compatibility."""

try:  # pragma: no cover - defensive shim
    import pydantic
    from pydantic.fields import FieldInfo as _FieldInfo

    if not hasattr(pydantic, "FieldInfo"):
        pydantic.FieldInfo = _FieldInfo  # type: ignore[attr-defined]
except Exception:
    pass
