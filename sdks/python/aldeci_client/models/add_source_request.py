from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AddSourceRequest")


@_attrs_define
class AddSourceRequest:
    """
    Attributes:
        name (str):
        source_type (str | Unset):  Default: 'osint'.
        reliability (int | Unset):  Default: 5.
        tlp_level (str | Unset):  Default: 'white'.
    """

    name: str
    source_type: str | Unset = "osint"
    reliability: int | Unset = 5
    tlp_level: str | Unset = "white"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        source_type = self.source_type

        reliability = self.reliability

        tlp_level = self.tlp_level

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
            }
        )
        if source_type is not UNSET:
            field_dict["source_type"] = source_type
        if reliability is not UNSET:
            field_dict["reliability"] = reliability
        if tlp_level is not UNSET:
            field_dict["tlp_level"] = tlp_level

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        source_type = d.pop("source_type", UNSET)

        reliability = d.pop("reliability", UNSET)

        tlp_level = d.pop("tlp_level", UNSET)

        add_source_request = cls(
            name=name,
            source_type=source_type,
            reliability=reliability,
            tlp_level=tlp_level,
        )

        add_source_request.additional_properties = d
        return add_source_request

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
