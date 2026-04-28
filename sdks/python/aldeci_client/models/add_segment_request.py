from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AddSegmentRequest")


@_attrs_define
class AddSegmentRequest:
    """
    Attributes:
        name (str):
        cidr (str | Unset):  Default: ''.
        segment_type (str | Unset): dmz/internal/cloud/ot/guest Default: 'internal'.
        sensitivity (str | Unset): critical/high/medium/low Default: 'medium'.
    """

    name: str
    cidr: str | Unset = ""
    segment_type: str | Unset = "internal"
    sensitivity: str | Unset = "medium"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        cidr = self.cidr

        segment_type = self.segment_type

        sensitivity = self.sensitivity

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
            }
        )
        if cidr is not UNSET:
            field_dict["cidr"] = cidr
        if segment_type is not UNSET:
            field_dict["segment_type"] = segment_type
        if sensitivity is not UNSET:
            field_dict["sensitivity"] = sensitivity

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        cidr = d.pop("cidr", UNSET)

        segment_type = d.pop("segment_type", UNSET)

        sensitivity = d.pop("sensitivity", UNSET)

        add_segment_request = cls(
            name=name,
            cidr=cidr,
            segment_type=segment_type,
            sensitivity=sensitivity,
        )

        add_segment_request.additional_properties = d
        return add_segment_request

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
