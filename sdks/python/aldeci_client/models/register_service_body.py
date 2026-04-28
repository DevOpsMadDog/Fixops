from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RegisterServiceBody")


@_attrs_define
class RegisterServiceBody:
    """
    Attributes:
        service_name (str): Unique service name
        service_type (str | Unset): application | database | api | queue | cache | auth | monitoring | storage | network
            | external Default: 'application'.
        criticality (str | Unset): critical | high | medium | low Default: 'medium'.
        owner (str | Unset): Owning team or person Default: ''.
        environment (str | Unset): production | staging | development | dr Default: 'production'.
        data_classification (str | Unset): public | internal | confidential | restricted Default: 'internal'.
    """

    service_name: str
    service_type: str | Unset = "application"
    criticality: str | Unset = "medium"
    owner: str | Unset = ""
    environment: str | Unset = "production"
    data_classification: str | Unset = "internal"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        service_name = self.service_name

        service_type = self.service_type

        criticality = self.criticality

        owner = self.owner

        environment = self.environment

        data_classification = self.data_classification

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "service_name": service_name,
            }
        )
        if service_type is not UNSET:
            field_dict["service_type"] = service_type
        if criticality is not UNSET:
            field_dict["criticality"] = criticality
        if owner is not UNSET:
            field_dict["owner"] = owner
        if environment is not UNSET:
            field_dict["environment"] = environment
        if data_classification is not UNSET:
            field_dict["data_classification"] = data_classification

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        service_name = d.pop("service_name")

        service_type = d.pop("service_type", UNSET)

        criticality = d.pop("criticality", UNSET)

        owner = d.pop("owner", UNSET)

        environment = d.pop("environment", UNSET)

        data_classification = d.pop("data_classification", UNSET)

        register_service_body = cls(
            service_name=service_name,
            service_type=service_type,
            criticality=criticality,
            owner=owner,
            environment=environment,
            data_classification=data_classification,
        )

        register_service_body.additional_properties = d
        return register_service_body

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
