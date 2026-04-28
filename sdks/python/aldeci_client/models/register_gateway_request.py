from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RegisterGatewayRequest")


@_attrs_define
class RegisterGatewayRequest:
    """
    Attributes:
        org_id (str): Organisation identifier
        name (str): Gateway name
        base_url (str): Base URL of the gateway
        gateway_type (str): kong | apigee | aws_api_gw | nginx | custom
        environment (str | Unset): prod | staging | dev Default: 'prod'.
    """

    org_id: str
    name: str
    base_url: str
    gateway_type: str
    environment: str | Unset = "prod"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        name = self.name

        base_url = self.base_url

        gateway_type = self.gateway_type

        environment = self.environment

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "name": name,
                "base_url": base_url,
                "gateway_type": gateway_type,
            }
        )
        if environment is not UNSET:
            field_dict["environment"] = environment

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        name = d.pop("name")

        base_url = d.pop("base_url")

        gateway_type = d.pop("gateway_type")

        environment = d.pop("environment", UNSET)

        register_gateway_request = cls(
            org_id=org_id,
            name=name,
            base_url=base_url,
            gateway_type=gateway_type,
            environment=environment,
        )

        register_gateway_request.additional_properties = d
        return register_gateway_request

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
