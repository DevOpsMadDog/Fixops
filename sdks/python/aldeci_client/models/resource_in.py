from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.resource_in_tags import ResourceInTags


T = TypeVar("T", bound="ResourceIn")


@_attrs_define
class ResourceIn:
    """
    Attributes:
        account_id (str):
        resource_id (str | Unset):  Default: ''.
        resource_type (str | Unset):  Default: ''.
        resource_name (str | Unset):  Default: ''.
        region (str | Unset):  Default: ''.
        tags (ResourceInTags | Unset):
        security_score (float | Unset):  Default: 100.0.
        finding_count (int | Unset):  Default: 0.
        is_public (bool | Unset):  Default: False.
        is_encrypted (bool | Unset):  Default: True.
    """

    account_id: str
    resource_id: str | Unset = ""
    resource_type: str | Unset = ""
    resource_name: str | Unset = ""
    region: str | Unset = ""
    tags: ResourceInTags | Unset = UNSET
    security_score: float | Unset = 100.0
    finding_count: int | Unset = 0
    is_public: bool | Unset = False
    is_encrypted: bool | Unset = True
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        account_id = self.account_id

        resource_id = self.resource_id

        resource_type = self.resource_type

        resource_name = self.resource_name

        region = self.region

        tags: dict[str, Any] | Unset = UNSET
        if not isinstance(self.tags, Unset):
            tags = self.tags.to_dict()

        security_score = self.security_score

        finding_count = self.finding_count

        is_public = self.is_public

        is_encrypted = self.is_encrypted

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "account_id": account_id,
            }
        )
        if resource_id is not UNSET:
            field_dict["resource_id"] = resource_id
        if resource_type is not UNSET:
            field_dict["resource_type"] = resource_type
        if resource_name is not UNSET:
            field_dict["resource_name"] = resource_name
        if region is not UNSET:
            field_dict["region"] = region
        if tags is not UNSET:
            field_dict["tags"] = tags
        if security_score is not UNSET:
            field_dict["security_score"] = security_score
        if finding_count is not UNSET:
            field_dict["finding_count"] = finding_count
        if is_public is not UNSET:
            field_dict["is_public"] = is_public
        if is_encrypted is not UNSET:
            field_dict["is_encrypted"] = is_encrypted

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.resource_in_tags import ResourceInTags

        d = dict(src_dict)
        account_id = d.pop("account_id")

        resource_id = d.pop("resource_id", UNSET)

        resource_type = d.pop("resource_type", UNSET)

        resource_name = d.pop("resource_name", UNSET)

        region = d.pop("region", UNSET)

        _tags = d.pop("tags", UNSET)
        tags: ResourceInTags | Unset
        if isinstance(_tags, Unset):
            tags = UNSET
        else:
            tags = ResourceInTags.from_dict(_tags)

        security_score = d.pop("security_score", UNSET)

        finding_count = d.pop("finding_count", UNSET)

        is_public = d.pop("is_public", UNSET)

        is_encrypted = d.pop("is_encrypted", UNSET)

        resource_in = cls(
            account_id=account_id,
            resource_id=resource_id,
            resource_type=resource_type,
            resource_name=resource_name,
            region=region,
            tags=tags,
            security_score=security_score,
            finding_count=finding_count,
            is_public=is_public,
            is_encrypted=is_encrypted,
        )

        resource_in.additional_properties = d
        return resource_in

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
