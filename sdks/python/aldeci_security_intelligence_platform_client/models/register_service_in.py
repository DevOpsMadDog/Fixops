from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RegisterServiceIn")


@_attrs_define
class RegisterServiceIn:
    """
    Attributes:
        org_id (str):
        service_name (str):
        service_category (str | Unset):  Default: 'monitoring'.
        description (str | Unset):  Default: ''.
        owner_team (str | Unset):  Default: ''.
        sla_response_hours (int | Unset):  Default: 24.
        sla_resolution_hours (int | Unset):  Default: 72.
        cost_center (str | Unset):  Default: ''.
        availability_pct (float | Unset):  Default: 99.0.
    """

    org_id: str
    service_name: str
    service_category: str | Unset = "monitoring"
    description: str | Unset = ""
    owner_team: str | Unset = ""
    sla_response_hours: int | Unset = 24
    sla_resolution_hours: int | Unset = 72
    cost_center: str | Unset = ""
    availability_pct: float | Unset = 99.0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        service_name = self.service_name

        service_category = self.service_category

        description = self.description

        owner_team = self.owner_team

        sla_response_hours = self.sla_response_hours

        sla_resolution_hours = self.sla_resolution_hours

        cost_center = self.cost_center

        availability_pct = self.availability_pct

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "service_name": service_name,
            }
        )
        if service_category is not UNSET:
            field_dict["service_category"] = service_category
        if description is not UNSET:
            field_dict["description"] = description
        if owner_team is not UNSET:
            field_dict["owner_team"] = owner_team
        if sla_response_hours is not UNSET:
            field_dict["sla_response_hours"] = sla_response_hours
        if sla_resolution_hours is not UNSET:
            field_dict["sla_resolution_hours"] = sla_resolution_hours
        if cost_center is not UNSET:
            field_dict["cost_center"] = cost_center
        if availability_pct is not UNSET:
            field_dict["availability_pct"] = availability_pct

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        service_name = d.pop("service_name")

        service_category = d.pop("service_category", UNSET)

        description = d.pop("description", UNSET)

        owner_team = d.pop("owner_team", UNSET)

        sla_response_hours = d.pop("sla_response_hours", UNSET)

        sla_resolution_hours = d.pop("sla_resolution_hours", UNSET)

        cost_center = d.pop("cost_center", UNSET)

        availability_pct = d.pop("availability_pct", UNSET)

        register_service_in = cls(
            org_id=org_id,
            service_name=service_name,
            service_category=service_category,
            description=description,
            owner_team=owner_team,
            sla_response_hours=sla_response_hours,
            sla_resolution_hours=sla_resolution_hours,
            cost_center=cost_center,
            availability_pct=availability_pct,
        )

        register_service_in.additional_properties = d
        return register_service_in

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
