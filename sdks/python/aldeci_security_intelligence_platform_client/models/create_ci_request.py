from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CreateCIRequest")


@_attrs_define
class CreateCIRequest:
    """
    Attributes:
        org_id (str): Organisation identifier
        name (str): CI display name
        ci_type (str): server | vm | container | database | application | network_device | storage | cloud_resource
        category (str | Unset): Free-form category label Default: ''.
        owner (str | Unset): Owning team or individual Default: ''.
        status (str | Unset): active | decommissioned | maintenance Default: 'active'.
        environment (str | Unset): prod | staging | dev | dr Default: 'prod'.
        location (str | Unset): Physical or logical location Default: ''.
        ip_address (str | Unset): Primary IP address Default: ''.
        os (str | Unset): Operating system or platform Default: ''.
        version (str | Unset): Software/firmware version Default: ''.
        criticality (str | Unset): low | medium | high | critical Default: 'medium'.
        support_tier (str | Unset): Support tier / SLA tier Default: ''.
        tags (list[str] | Unset): Arbitrary tags
    """

    org_id: str
    name: str
    ci_type: str
    category: str | Unset = ""
    owner: str | Unset = ""
    status: str | Unset = "active"
    environment: str | Unset = "prod"
    location: str | Unset = ""
    ip_address: str | Unset = ""
    os: str | Unset = ""
    version: str | Unset = ""
    criticality: str | Unset = "medium"
    support_tier: str | Unset = ""
    tags: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        name = self.name

        ci_type = self.ci_type

        category = self.category

        owner = self.owner

        status = self.status

        environment = self.environment

        location = self.location

        ip_address = self.ip_address

        os = self.os

        version = self.version

        criticality = self.criticality

        support_tier = self.support_tier

        tags: list[str] | Unset = UNSET
        if not isinstance(self.tags, Unset):
            tags = self.tags

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "name": name,
                "ci_type": ci_type,
            }
        )
        if category is not UNSET:
            field_dict["category"] = category
        if owner is not UNSET:
            field_dict["owner"] = owner
        if status is not UNSET:
            field_dict["status"] = status
        if environment is not UNSET:
            field_dict["environment"] = environment
        if location is not UNSET:
            field_dict["location"] = location
        if ip_address is not UNSET:
            field_dict["ip_address"] = ip_address
        if os is not UNSET:
            field_dict["os"] = os
        if version is not UNSET:
            field_dict["version"] = version
        if criticality is not UNSET:
            field_dict["criticality"] = criticality
        if support_tier is not UNSET:
            field_dict["support_tier"] = support_tier
        if tags is not UNSET:
            field_dict["tags"] = tags

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        name = d.pop("name")

        ci_type = d.pop("ci_type")

        category = d.pop("category", UNSET)

        owner = d.pop("owner", UNSET)

        status = d.pop("status", UNSET)

        environment = d.pop("environment", UNSET)

        location = d.pop("location", UNSET)

        ip_address = d.pop("ip_address", UNSET)

        os = d.pop("os", UNSET)

        version = d.pop("version", UNSET)

        criticality = d.pop("criticality", UNSET)

        support_tier = d.pop("support_tier", UNSET)

        tags = cast(list[str], d.pop("tags", UNSET))

        create_ci_request = cls(
            org_id=org_id,
            name=name,
            ci_type=ci_type,
            category=category,
            owner=owner,
            status=status,
            environment=environment,
            location=location,
            ip_address=ip_address,
            os=os,
            version=version,
            criticality=criticality,
            support_tier=support_tier,
            tags=tags,
        )

        create_ci_request.additional_properties = d
        return create_ci_request

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
