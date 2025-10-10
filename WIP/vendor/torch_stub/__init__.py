"""Lightweight stub of the :mod:`torch` package for pgmpy integration in tests."""

from __future__ import annotations

from dataclasses import dataclass


class _TorchDTypeMeta(type):
    def __instancecheck__(cls, instance) -> bool:  # pragma: no cover - simple helper
        return isinstance(instance, _TorchDType)


class dtype(metaclass=_TorchDTypeMeta):
    """Placeholder base type mimicking :class:`torch.dtype`."""


@dataclass(frozen=True)
class _TorchDType:
    name: str

    def __repr__(self) -> str:  # pragma: no cover - trivial representation
        return f"torch.{self.name}"


@dataclass(frozen=True)
class device:
    identifier: str

    def __repr__(self) -> str:  # pragma: no cover - trivial representation
        return f"device(type='{self.identifier}')"


float64 = _TorchDType("float64")


class _CudaModule:
    @staticmethod
    def is_available() -> bool:
        return False


cuda = _CudaModule()


class _OptimModule:
    def __getattr__(self, name: str):  # pragma: no cover - defensive fallback
        raise NotImplementedError(
            "torch.optim is unavailable in the lightweight stub"
        )


optim = _OptimModule()


def tensor(*_, **__):  # pragma: no cover - defensive stub
    raise NotImplementedError(
        "Tensor operations are not supported in the stub torch module"
    )
