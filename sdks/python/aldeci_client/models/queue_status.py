from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="QueueStatus")


@_attrs_define
class QueueStatus:
    """
    Attributes:
        backend (str):
        depth (int):
        workers (int):
    """

    backend: str
    depth: int
    workers: int
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        backend = self.backend

        depth = self.depth

        workers = self.workers

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "backend": backend,
                "depth": depth,
                "workers": workers,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        backend = d.pop("backend")

        depth = d.pop("depth")

        workers = d.pop("workers")

        queue_status = cls(
            backend=backend,
            depth=depth,
            workers=workers,
        )

        queue_status.additional_properties = d
        return queue_status

    @property
    def additional_keys(self) -> list[str]:
        return list(self.additional_properties.keys())

    def __getitem__(self, key: str) -> Any:
        return self.additional_properties[key]

    def __setitem__(self, key: str, value: Any) -> None:
        self.additional_properties[key] = value

    def __delitem__(self, key: str) -> None:
        del self.additional_properties[key]

    def __contains__(self, key: str) -> bool:
        return key in self.additional_properties
