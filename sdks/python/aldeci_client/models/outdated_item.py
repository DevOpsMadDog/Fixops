from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="OutdatedItem")


@_attrs_define
class OutdatedItem:
    """
    Attributes:
        package (str):
        installed_version (str):
        latest_version (str):
        latest_filetype (str | Unset):  Default: 'wheel'.
    """

    package: str
    installed_version: str
    latest_version: str
    latest_filetype: str | Unset = "wheel"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        package = self.package

        installed_version = self.installed_version

        latest_version = self.latest_version

        latest_filetype = self.latest_filetype

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "package": package,
                "installed_version": installed_version,
                "latest_version": latest_version,
            }
        )
        if latest_filetype is not UNSET:
            field_dict["latest_filetype"] = latest_filetype

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        package = d.pop("package")

        installed_version = d.pop("installed_version")

        latest_version = d.pop("latest_version")

        latest_filetype = d.pop("latest_filetype", UNSET)

        outdated_item = cls(
            package=package,
            installed_version=installed_version,
            latest_version=latest_version,
            latest_filetype=latest_filetype,
        )

        outdated_item.additional_properties = d
        return outdated_item

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
