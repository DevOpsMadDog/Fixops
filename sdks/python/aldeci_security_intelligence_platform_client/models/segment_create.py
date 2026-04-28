from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="SegmentCreate")


@_attrs_define
class SegmentCreate:
    """
    Attributes:
        name (str):
        segment_type (str):
        cidr_range (str | Unset):  Default: ''.
        description (str | Unset):  Default: ''.
        enforcement_mode (str | Unset):  Default: 'monitoring'.
    """

    name: str
    segment_type: str
    cidr_range: str | Unset = ""
    description: str | Unset = ""
    enforcement_mode: str | Unset = "monitoring"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        segment_type = self.segment_type

        cidr_range = self.cidr_range

        description = self.description

        enforcement_mode = self.enforcement_mode

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
                "segment_type": segment_type,
            }
        )
        if cidr_range is not UNSET:
            field_dict["cidr_range"] = cidr_range
        if description is not UNSET:
            field_dict["description"] = description
        if enforcement_mode is not UNSET:
            field_dict["enforcement_mode"] = enforcement_mode

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        segment_type = d.pop("segment_type")

        cidr_range = d.pop("cidr_range", UNSET)

        description = d.pop("description", UNSET)

        enforcement_mode = d.pop("enforcement_mode", UNSET)

        segment_create = cls(
            name=name,
            segment_type=segment_type,
            cidr_range=cidr_range,
            description=description,
            enforcement_mode=enforcement_mode,
        )

        segment_create.additional_properties = d
        return segment_create

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
