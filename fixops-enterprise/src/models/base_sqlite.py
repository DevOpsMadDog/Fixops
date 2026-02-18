"""Shared SQLAlchemy base for sqlite-backed models."""

from __future__ import annotations

from sqlalchemy.orm import DeclarativeBase, MappedAsDataclass, declared_attr


class Base(MappedAsDataclass, DeclarativeBase):
    """Declarative base that automatically derives table names."""

    __abstract__ = True

    @declared_attr.directive
    def __tablename__(cls) -> str:  # type: ignore[override]
        return cls.__name__.lower()

    def __repr__(self) -> str:
        columns = ", ".join(
            f"{key}={getattr(self, key)!r}" for key in self.__mapper__.c.keys()
        )
        return f"{self.__class__.__name__}({columns})"


__all__ = ["Base"]
