from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="WipeRequest")


@_attrs_define
class WipeRequest:
    """
    Attributes:
        wiped_by (str):
        wipe_type (str | Unset):  Default: 'full'.
    """

    wiped_by: str
    wipe_type: str | Unset = "full"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        wiped_by = self.wiped_by

        wipe_type = self.wipe_type

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "wiped_by": wiped_by,
            }
        )
        if wipe_type is not UNSET:
            field_dict["wipe_type"] = wipe_type

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        wiped_by = d.pop("wiped_by")

        wipe_type = d.pop("wipe_type", UNSET)

        wipe_request = cls(
            wiped_by=wiped_by,
            wipe_type=wipe_type,
        )

        wipe_request.additional_properties = d
        return wipe_request

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
