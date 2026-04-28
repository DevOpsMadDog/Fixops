from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.build_graph_request_resources_item import BuildGraphRequestResourcesItem


T = TypeVar("T", bound="BuildGraphRequest")


@_attrs_define
class BuildGraphRequest:
    """
    Attributes:
        resources (list[BuildGraphRequestResourcesItem]): List of raw cloud resource dicts
        org_id (str | Unset): Organisation ID Default: 'default'.
    """

    resources: list[BuildGraphRequestResourcesItem]
    org_id: str | Unset = "default"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        resources = []
        for resources_item_data in self.resources:
            resources_item = resources_item_data.to_dict()
            resources.append(resources_item)

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "resources": resources,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.build_graph_request_resources_item import BuildGraphRequestResourcesItem

        d = dict(src_dict)
        resources = []
        _resources = d.pop("resources")
        for resources_item_data in _resources:
            resources_item = BuildGraphRequestResourcesItem.from_dict(resources_item_data)

            resources.append(resources_item)

        org_id = d.pop("org_id", UNSET)

        build_graph_request = cls(
            resources=resources,
            org_id=org_id,
        )

        build_graph_request.additional_properties = d
        return build_graph_request

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
