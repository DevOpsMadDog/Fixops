from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.node_create_request_properties import NodeCreateRequestProperties


T = TypeVar("T", bound="NodeCreateRequest")


@_attrs_define
class NodeCreateRequest:
    """Validated request for creating/updating a Knowledge Graph node.

    Attributes:
        node_id (str):
        node_type (str):
        org_id (None | str | Unset):
        properties (NodeCreateRequestProperties | Unset):
    """

    node_id: str
    node_type: str
    org_id: None | str | Unset = UNSET
    properties: NodeCreateRequestProperties | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        node_id = self.node_id

        node_type = self.node_type

        org_id: None | str | Unset
        if isinstance(self.org_id, Unset):
            org_id = UNSET
        else:
            org_id = self.org_id

        properties: dict[str, Any] | Unset = UNSET
        if not isinstance(self.properties, Unset):
            properties = self.properties.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "node_id": node_id,
                "node_type": node_type,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if properties is not UNSET:
            field_dict["properties"] = properties

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.node_create_request_properties import NodeCreateRequestProperties

        d = dict(src_dict)
        node_id = d.pop("node_id")

        node_type = d.pop("node_type")

        def _parse_org_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        org_id = _parse_org_id(d.pop("org_id", UNSET))

        _properties = d.pop("properties", UNSET)
        properties: NodeCreateRequestProperties | Unset
        if isinstance(_properties, Unset):
            properties = UNSET
        else:
            properties = NodeCreateRequestProperties.from_dict(_properties)

        node_create_request = cls(
            node_id=node_id,
            node_type=node_type,
            org_id=org_id,
            properties=properties,
        )

        node_create_request.additional_properties = d
        return node_create_request

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
