from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RegisterCloudAppRequest")


@_attrs_define
class RegisterCloudAppRequest:
    """
    Attributes:
        name (str):
        org_id (str | Unset):  Default: 'default'.
        app_category (str | Unset):  Default: 'saas'.
        vendor (str | Unset):  Default: ''.
        risk_level (str | Unset):  Default: 'medium'.
        data_exposure_level (str | Unset):  Default: 'internal'.
        sanctioned (bool | Unset):  Default: True.
        discovered_at (None | str | Unset):
    """

    name: str
    org_id: str | Unset = "default"
    app_category: str | Unset = "saas"
    vendor: str | Unset = ""
    risk_level: str | Unset = "medium"
    data_exposure_level: str | Unset = "internal"
    sanctioned: bool | Unset = True
    discovered_at: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        org_id = self.org_id

        app_category = self.app_category

        vendor = self.vendor

        risk_level = self.risk_level

        data_exposure_level = self.data_exposure_level

        sanctioned = self.sanctioned

        discovered_at: None | str | Unset
        if isinstance(self.discovered_at, Unset):
            discovered_at = UNSET
        else:
            discovered_at = self.discovered_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if app_category is not UNSET:
            field_dict["app_category"] = app_category
        if vendor is not UNSET:
            field_dict["vendor"] = vendor
        if risk_level is not UNSET:
            field_dict["risk_level"] = risk_level
        if data_exposure_level is not UNSET:
            field_dict["data_exposure_level"] = data_exposure_level
        if sanctioned is not UNSET:
            field_dict["sanctioned"] = sanctioned
        if discovered_at is not UNSET:
            field_dict["discovered_at"] = discovered_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        org_id = d.pop("org_id", UNSET)

        app_category = d.pop("app_category", UNSET)

        vendor = d.pop("vendor", UNSET)

        risk_level = d.pop("risk_level", UNSET)

        data_exposure_level = d.pop("data_exposure_level", UNSET)

        sanctioned = d.pop("sanctioned", UNSET)

        def _parse_discovered_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        discovered_at = _parse_discovered_at(d.pop("discovered_at", UNSET))

        register_cloud_app_request = cls(
            name=name,
            org_id=org_id,
            app_category=app_category,
            vendor=vendor,
            risk_level=risk_level,
            data_exposure_level=data_exposure_level,
            sanctioned=sanctioned,
            discovered_at=discovered_at,
        )

        register_cloud_app_request.additional_properties = d
        return register_cloud_app_request

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
