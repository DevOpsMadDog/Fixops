from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.sync_resource_request_resources_item import SyncResourceRequestResourcesItem


T = TypeVar("T", bound="SyncResourceRequest")


@_attrs_define
class SyncResourceRequest:
    """
    Attributes:
        provider (str):
        resources (list[SyncResourceRequestResourcesItem]):
        org_id (str | Unset):  Default: 'default'.
    """

    provider: str
    resources: list[SyncResourceRequestResourcesItem]
    org_id: str | Unset = "default"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        provider = self.provider

        resources = []
        for resources_item_data in self.resources:
            resources_item = resources_item_data.to_dict()
            resources.append(resources_item)

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "provider": provider,
                "resources": resources,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.sync_resource_request_resources_item import SyncResourceRequestResourcesItem

        d = dict(src_dict)
        provider = d.pop("provider")

        resources = []
        _resources = d.pop("resources")
        for resources_item_data in _resources:
            resources_item = SyncResourceRequestResourcesItem.from_dict(resources_item_data)

            resources.append(resources_item)

        org_id = d.pop("org_id", UNSET)

        sync_resource_request = cls(
            provider=provider,
            resources=resources,
            org_id=org_id,
        )

        sync_resource_request.additional_properties = d
        return sync_resource_request

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
