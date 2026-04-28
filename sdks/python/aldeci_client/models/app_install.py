from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AppInstall")


@_attrs_define
class AppInstall:
    """
    Attributes:
        app_name (str):
        app_version (str | Unset):  Default: ''.
        is_approved (bool | Unset):  Default: True.
    """

    app_name: str
    app_version: str | Unset = ""
    is_approved: bool | Unset = True
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        app_name = self.app_name

        app_version = self.app_version

        is_approved = self.is_approved

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "app_name": app_name,
            }
        )
        if app_version is not UNSET:
            field_dict["app_version"] = app_version
        if is_approved is not UNSET:
            field_dict["is_approved"] = is_approved

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        app_name = d.pop("app_name")

        app_version = d.pop("app_version", UNSET)

        is_approved = d.pop("is_approved", UNSET)

        app_install = cls(
            app_name=app_name,
            app_version=app_version,
            is_approved=is_approved,
        )

        app_install.additional_properties = d
        return app_install

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
