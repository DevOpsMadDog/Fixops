from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.resource_create_tags import ResourceCreateTags


T = TypeVar("T", bound="ResourceCreate")


@_attrs_define
class ResourceCreate:
    """
    Attributes:
        resource_id (str): Cloud provider resource identifier
        resource_name (str | Unset): Human-readable resource name Default: ''.
        provider (str | Unset): aws/azure/gcp/alibaba/oracle/ibm/digitalocean Default: 'aws'.
        resource_type (str | Unset): compute/storage/database/network/iam/container/serverless/cdn/dns/load_balancer
            Default: 'compute'.
        region (str | Unset): Cloud region Default: ''.
        account_id (str | Unset): Cloud account/subscription ID Default: ''.
        tags (ResourceCreateTags | Unset): Resource tags
        resource_state (str | Unset): running/stopped/terminated/unknown/pending Default: 'running'.
    """

    resource_id: str
    resource_name: str | Unset = ""
    provider: str | Unset = "aws"
    resource_type: str | Unset = "compute"
    region: str | Unset = ""
    account_id: str | Unset = ""
    tags: ResourceCreateTags | Unset = UNSET
    resource_state: str | Unset = "running"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        resource_id = self.resource_id

        resource_name = self.resource_name

        provider = self.provider

        resource_type = self.resource_type

        region = self.region

        account_id = self.account_id

        tags: dict[str, Any] | Unset = UNSET
        if not isinstance(self.tags, Unset):
            tags = self.tags.to_dict()

        resource_state = self.resource_state

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "resource_id": resource_id,
            }
        )
        if resource_name is not UNSET:
            field_dict["resource_name"] = resource_name
        if provider is not UNSET:
            field_dict["provider"] = provider
        if resource_type is not UNSET:
            field_dict["resource_type"] = resource_type
        if region is not UNSET:
            field_dict["region"] = region
        if account_id is not UNSET:
            field_dict["account_id"] = account_id
        if tags is not UNSET:
            field_dict["tags"] = tags
        if resource_state is not UNSET:
            field_dict["resource_state"] = resource_state

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.resource_create_tags import ResourceCreateTags

        d = dict(src_dict)
        resource_id = d.pop("resource_id")

        resource_name = d.pop("resource_name", UNSET)

        provider = d.pop("provider", UNSET)

        resource_type = d.pop("resource_type", UNSET)

        region = d.pop("region", UNSET)

        account_id = d.pop("account_id", UNSET)

        _tags = d.pop("tags", UNSET)
        tags: ResourceCreateTags | Unset
        if isinstance(_tags, Unset):
            tags = UNSET
        else:
            tags = ResourceCreateTags.from_dict(_tags)

        resource_state = d.pop("resource_state", UNSET)

        resource_create = cls(
            resource_id=resource_id,
            resource_name=resource_name,
            provider=provider,
            resource_type=resource_type,
            region=region,
            account_id=account_id,
            tags=tags,
            resource_state=resource_state,
        )

        resource_create.additional_properties = d
        return resource_create

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
