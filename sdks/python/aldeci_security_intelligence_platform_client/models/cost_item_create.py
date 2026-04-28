from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.cost_item_create_tags import CostItemCreateTags


T = TypeVar("T", bound="CostItemCreate")


@_attrs_define
class CostItemCreate:
    """
    Attributes:
        org_id (str | Unset):  Default: 'default'.
        cloud_provider (str | Unset):  Default: 'aws'.
        service (str | Unset):  Default: ''.
        resource_id (str | Unset):  Default: ''.
        monthly_cost_usd (float | Unset):  Default: 0.0.
        security_relevance (str | Unset):  Default: 'low'.
        tags (CostItemCreateTags | Unset):
    """

    org_id: str | Unset = "default"
    cloud_provider: str | Unset = "aws"
    service: str | Unset = ""
    resource_id: str | Unset = ""
    monthly_cost_usd: float | Unset = 0.0
    security_relevance: str | Unset = "low"
    tags: CostItemCreateTags | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        cloud_provider = self.cloud_provider

        service = self.service

        resource_id = self.resource_id

        monthly_cost_usd = self.monthly_cost_usd

        security_relevance = self.security_relevance

        tags: dict[str, Any] | Unset = UNSET
        if not isinstance(self.tags, Unset):
            tags = self.tags.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if cloud_provider is not UNSET:
            field_dict["cloud_provider"] = cloud_provider
        if service is not UNSET:
            field_dict["service"] = service
        if resource_id is not UNSET:
            field_dict["resource_id"] = resource_id
        if monthly_cost_usd is not UNSET:
            field_dict["monthly_cost_usd"] = monthly_cost_usd
        if security_relevance is not UNSET:
            field_dict["security_relevance"] = security_relevance
        if tags is not UNSET:
            field_dict["tags"] = tags

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.cost_item_create_tags import CostItemCreateTags

        d = dict(src_dict)
        org_id = d.pop("org_id", UNSET)

        cloud_provider = d.pop("cloud_provider", UNSET)

        service = d.pop("service", UNSET)

        resource_id = d.pop("resource_id", UNSET)

        monthly_cost_usd = d.pop("monthly_cost_usd", UNSET)

        security_relevance = d.pop("security_relevance", UNSET)

        _tags = d.pop("tags", UNSET)
        tags: CostItemCreateTags | Unset
        if isinstance(_tags, Unset):
            tags = UNSET
        else:
            tags = CostItemCreateTags.from_dict(_tags)

        cost_item_create = cls(
            org_id=org_id,
            cloud_provider=cloud_provider,
            service=service,
            resource_id=resource_id,
            monthly_cost_usd=monthly_cost_usd,
            security_relevance=security_relevance,
            tags=tags,
        )

        cost_item_create.additional_properties = d
        return cost_item_create

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
