from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.resource_response_metadata import ResourceResponseMetadata
    from ..models.resource_response_tags import ResourceResponseTags


T = TypeVar("T", bound="ResourceResponse")


@_attrs_define
class ResourceResponse:
    """
    Attributes:
        resource_id (str):
        provider (str):
        resource_type (str):
        name (str):
        region (str):
        account_id (str):
        tags (ResourceResponseTags | Unset):
        public_exposure (bool | Unset):  Default: False.
        security_groups (list[str] | Unset):
        metadata (ResourceResponseMetadata | Unset):
    """

    resource_id: str
    provider: str
    resource_type: str
    name: str
    region: str
    account_id: str
    tags: ResourceResponseTags | Unset = UNSET
    public_exposure: bool | Unset = False
    security_groups: list[str] | Unset = UNSET
    metadata: ResourceResponseMetadata | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        resource_id = self.resource_id

        provider = self.provider

        resource_type = self.resource_type

        name = self.name

        region = self.region

        account_id = self.account_id

        tags: dict[str, Any] | Unset = UNSET
        if not isinstance(self.tags, Unset):
            tags = self.tags.to_dict()

        public_exposure = self.public_exposure

        security_groups: list[str] | Unset = UNSET
        if not isinstance(self.security_groups, Unset):
            security_groups = self.security_groups

        metadata: dict[str, Any] | Unset = UNSET
        if not isinstance(self.metadata, Unset):
            metadata = self.metadata.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "resource_id": resource_id,
                "provider": provider,
                "resource_type": resource_type,
                "name": name,
                "region": region,
                "account_id": account_id,
            }
        )
        if tags is not UNSET:
            field_dict["tags"] = tags
        if public_exposure is not UNSET:
            field_dict["public_exposure"] = public_exposure
        if security_groups is not UNSET:
            field_dict["security_groups"] = security_groups
        if metadata is not UNSET:
            field_dict["metadata"] = metadata

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.resource_response_metadata import ResourceResponseMetadata
        from ..models.resource_response_tags import ResourceResponseTags

        d = dict(src_dict)
        resource_id = d.pop("resource_id")

        provider = d.pop("provider")

        resource_type = d.pop("resource_type")

        name = d.pop("name")

        region = d.pop("region")

        account_id = d.pop("account_id")

        _tags = d.pop("tags", UNSET)
        tags: ResourceResponseTags | Unset
        if isinstance(_tags, Unset):
            tags = UNSET
        else:
            tags = ResourceResponseTags.from_dict(_tags)

        public_exposure = d.pop("public_exposure", UNSET)

        security_groups = cast(list[str], d.pop("security_groups", UNSET))

        _metadata = d.pop("metadata", UNSET)
        metadata: ResourceResponseMetadata | Unset
        if isinstance(_metadata, Unset):
            metadata = UNSET
        else:
            metadata = ResourceResponseMetadata.from_dict(_metadata)

        resource_response = cls(
            resource_id=resource_id,
            provider=provider,
            resource_type=resource_type,
            name=name,
            region=region,
            account_id=account_id,
            tags=tags,
            public_exposure=public_exposure,
            security_groups=security_groups,
            metadata=metadata,
        )

        resource_response.additional_properties = d
        return resource_response

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
