from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="EndpointCreate")


@_attrs_define
class EndpointCreate:
    """
    Attributes:
        service_name (str):
        endpoint_path (str):
        http_method (str):
        org_id (str | Unset):  Default: 'default'.
        version (str | Unset):  Default: ''.
        api_type (str | Unset):  Default: 'rest'.
        auth_required (bool | Unset):  Default: True.
        is_documented (bool | Unset):  Default: False.
        is_shadow (bool | Unset):  Default: False.
        risk_level (str | Unset):  Default: 'none'.
    """

    service_name: str
    endpoint_path: str
    http_method: str
    org_id: str | Unset = "default"
    version: str | Unset = ""
    api_type: str | Unset = "rest"
    auth_required: bool | Unset = True
    is_documented: bool | Unset = False
    is_shadow: bool | Unset = False
    risk_level: str | Unset = "none"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        service_name = self.service_name

        endpoint_path = self.endpoint_path

        http_method = self.http_method

        org_id = self.org_id

        version = self.version

        api_type = self.api_type

        auth_required = self.auth_required

        is_documented = self.is_documented

        is_shadow = self.is_shadow

        risk_level = self.risk_level

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "service_name": service_name,
                "endpoint_path": endpoint_path,
                "http_method": http_method,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if version is not UNSET:
            field_dict["version"] = version
        if api_type is not UNSET:
            field_dict["api_type"] = api_type
        if auth_required is not UNSET:
            field_dict["auth_required"] = auth_required
        if is_documented is not UNSET:
            field_dict["is_documented"] = is_documented
        if is_shadow is not UNSET:
            field_dict["is_shadow"] = is_shadow
        if risk_level is not UNSET:
            field_dict["risk_level"] = risk_level

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        service_name = d.pop("service_name")

        endpoint_path = d.pop("endpoint_path")

        http_method = d.pop("http_method")

        org_id = d.pop("org_id", UNSET)

        version = d.pop("version", UNSET)

        api_type = d.pop("api_type", UNSET)

        auth_required = d.pop("auth_required", UNSET)

        is_documented = d.pop("is_documented", UNSET)

        is_shadow = d.pop("is_shadow", UNSET)

        risk_level = d.pop("risk_level", UNSET)

        endpoint_create = cls(
            service_name=service_name,
            endpoint_path=endpoint_path,
            http_method=http_method,
            org_id=org_id,
            version=version,
            api_type=api_type,
            auth_required=auth_required,
            is_documented=is_documented,
            is_shadow=is_shadow,
            risk_level=risk_level,
        )

        endpoint_create.additional_properties = d
        return endpoint_create

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
