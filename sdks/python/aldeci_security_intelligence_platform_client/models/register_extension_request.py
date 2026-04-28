from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RegisterExtensionRequest")


@_attrs_define
class RegisterExtensionRequest:
    """
    Attributes:
        extension_id (str):
        name (str):
        version (str | Unset):  Default: ''.
        browser_type (str | Unset):  Default: 'all'.
        risk_level (str | Unset):  Default: 'medium'.
        permissions (list[str] | Unset):
        status (str | Unset):  Default: 'under_review'.
        publisher (str | Unset):  Default: ''.
    """

    extension_id: str
    name: str
    version: str | Unset = ""
    browser_type: str | Unset = "all"
    risk_level: str | Unset = "medium"
    permissions: list[str] | Unset = UNSET
    status: str | Unset = "under_review"
    publisher: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        extension_id = self.extension_id

        name = self.name

        version = self.version

        browser_type = self.browser_type

        risk_level = self.risk_level

        permissions: list[str] | Unset = UNSET
        if not isinstance(self.permissions, Unset):
            permissions = self.permissions

        status = self.status

        publisher = self.publisher

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "extension_id": extension_id,
                "name": name,
            }
        )
        if version is not UNSET:
            field_dict["version"] = version
        if browser_type is not UNSET:
            field_dict["browser_type"] = browser_type
        if risk_level is not UNSET:
            field_dict["risk_level"] = risk_level
        if permissions is not UNSET:
            field_dict["permissions"] = permissions
        if status is not UNSET:
            field_dict["status"] = status
        if publisher is not UNSET:
            field_dict["publisher"] = publisher

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        extension_id = d.pop("extension_id")

        name = d.pop("name")

        version = d.pop("version", UNSET)

        browser_type = d.pop("browser_type", UNSET)

        risk_level = d.pop("risk_level", UNSET)

        permissions = cast(list[str], d.pop("permissions", UNSET))

        status = d.pop("status", UNSET)

        publisher = d.pop("publisher", UNSET)

        register_extension_request = cls(
            extension_id=extension_id,
            name=name,
            version=version,
            browser_type=browser_type,
            risk_level=risk_level,
            permissions=permissions,
            status=status,
            publisher=publisher,
        )

        register_extension_request.additional_properties = d
        return register_extension_request

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
