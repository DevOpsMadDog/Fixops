from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ScanCreate")


@_attrs_define
class ScanCreate:
    """
    Attributes:
        scan_name (str):
        scan_target (str):
        org_id (str | Unset):  Default: 'default'.
        scan_type (str | Unset):  Default: 'passive'.
    """

    scan_name: str
    scan_target: str
    org_id: str | Unset = "default"
    scan_type: str | Unset = "passive"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        scan_name = self.scan_name

        scan_target = self.scan_target

        org_id = self.org_id

        scan_type = self.scan_type

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "scan_name": scan_name,
                "scan_target": scan_target,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if scan_type is not UNSET:
            field_dict["scan_type"] = scan_type

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        scan_name = d.pop("scan_name")

        scan_target = d.pop("scan_target")

        org_id = d.pop("org_id", UNSET)

        scan_type = d.pop("scan_type", UNSET)

        scan_create = cls(
            scan_name=scan_name,
            scan_target=scan_target,
            org_id=org_id,
            scan_type=scan_type,
        )

        scan_create.additional_properties = d
        return scan_create

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
