from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="SightingAdd")


@_attrs_define
class SightingAdd:
    """
    Attributes:
        source_system (str | Unset):  Default: ''.
        context (str | Unset):  Default: ''.
        severity (str | Unset):  Default: 'medium'.
    """

    source_system: str | Unset = ""
    context: str | Unset = ""
    severity: str | Unset = "medium"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        source_system = self.source_system

        context = self.context

        severity = self.severity

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if source_system is not UNSET:
            field_dict["source_system"] = source_system
        if context is not UNSET:
            field_dict["context"] = context
        if severity is not UNSET:
            field_dict["severity"] = severity

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        source_system = d.pop("source_system", UNSET)

        context = d.pop("context", UNSET)

        severity = d.pop("severity", UNSET)

        sighting_add = cls(
            source_system=source_system,
            context=context,
            severity=severity,
        )

        sighting_add.additional_properties = d
        return sighting_add

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
