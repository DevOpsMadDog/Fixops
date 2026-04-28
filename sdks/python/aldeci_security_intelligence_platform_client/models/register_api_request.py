from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RegisterApiRequest")


@_attrs_define
class RegisterApiRequest:
    """
    Attributes:
        org_id (str): Organisation identifier
        gateway_id (str): Parent gateway UUID
        name (str): API name
        path_prefix (str): URL path prefix (e.g. /api/v1/payments)
        version (str | Unset): API version string Default: 'v1'.
        auth_type (str | Unset): api_key | oauth2 | jwt | none Default: 'api_key'.
        rate_limit_rps (int | Unset): Requests per second rate limit Default: 100.
    """

    org_id: str
    gateway_id: str
    name: str
    path_prefix: str
    version: str | Unset = "v1"
    auth_type: str | Unset = "api_key"
    rate_limit_rps: int | Unset = 100
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        gateway_id = self.gateway_id

        name = self.name

        path_prefix = self.path_prefix

        version = self.version

        auth_type = self.auth_type

        rate_limit_rps = self.rate_limit_rps

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "gateway_id": gateway_id,
                "name": name,
                "path_prefix": path_prefix,
            }
        )
        if version is not UNSET:
            field_dict["version"] = version
        if auth_type is not UNSET:
            field_dict["auth_type"] = auth_type
        if rate_limit_rps is not UNSET:
            field_dict["rate_limit_rps"] = rate_limit_rps

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        gateway_id = d.pop("gateway_id")

        name = d.pop("name")

        path_prefix = d.pop("path_prefix")

        version = d.pop("version", UNSET)

        auth_type = d.pop("auth_type", UNSET)

        rate_limit_rps = d.pop("rate_limit_rps", UNSET)

        register_api_request = cls(
            org_id=org_id,
            gateway_id=gateway_id,
            name=name,
            path_prefix=path_prefix,
            version=version,
            auth_type=auth_type,
            rate_limit_rps=rate_limit_rps,
        )

        register_api_request.additional_properties = d
        return register_api_request

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
