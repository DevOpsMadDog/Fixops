from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.infrastructure_node_properties import InfrastructureNodeProperties


T = TypeVar("T", bound="InfrastructureNode")


@_attrs_define
class InfrastructureNode:
    """Infrastructure node for attack graph.

    Attributes:
        id (str):
        type_ (str | Unset): Node type: compute, storage, network, identity, service, etc. Default: 'compute'.
        properties (InfrastructureNodeProperties | Unset):
        risk_score (float | Unset):  Default: 0.0.
    """

    id: str
    type_: str | Unset = "compute"
    properties: InfrastructureNodeProperties | Unset = UNSET
    risk_score: float | Unset = 0.0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        id = self.id

        type_ = self.type_

        properties: dict[str, Any] | Unset = UNSET
        if not isinstance(self.properties, Unset):
            properties = self.properties.to_dict()

        risk_score = self.risk_score

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "id": id,
            }
        )
        if type_ is not UNSET:
            field_dict["type"] = type_
        if properties is not UNSET:
            field_dict["properties"] = properties
        if risk_score is not UNSET:
            field_dict["risk_score"] = risk_score

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.infrastructure_node_properties import InfrastructureNodeProperties

        d = dict(src_dict)
        id = d.pop("id")

        type_ = d.pop("type", UNSET)

        _properties = d.pop("properties", UNSET)
        properties: InfrastructureNodeProperties | Unset
        if isinstance(_properties, Unset):
            properties = UNSET
        else:
            properties = InfrastructureNodeProperties.from_dict(_properties)

        risk_score = d.pop("risk_score", UNSET)

        infrastructure_node = cls(
            id=id,
            type_=type_,
            properties=properties,
            risk_score=risk_score,
        )

        infrastructure_node.additional_properties = d
        return infrastructure_node

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
