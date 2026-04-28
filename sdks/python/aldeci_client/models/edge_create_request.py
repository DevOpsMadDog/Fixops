from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.edge_create_request_properties import EdgeCreateRequestProperties


T = TypeVar("T", bound="EdgeCreateRequest")


@_attrs_define
class EdgeCreateRequest:
    """Validated request for creating a Knowledge Graph edge.

    Attributes:
        source_id (str):
        target_id (str):
        edge_type (str):
        properties (EdgeCreateRequestProperties | Unset):
        confidence (float | Unset):  Default: 1.0.
    """

    source_id: str
    target_id: str
    edge_type: str
    properties: EdgeCreateRequestProperties | Unset = UNSET
    confidence: float | Unset = 1.0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        source_id = self.source_id

        target_id = self.target_id

        edge_type = self.edge_type

        properties: dict[str, Any] | Unset = UNSET
        if not isinstance(self.properties, Unset):
            properties = self.properties.to_dict()

        confidence = self.confidence

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "source_id": source_id,
                "target_id": target_id,
                "edge_type": edge_type,
            }
        )
        if properties is not UNSET:
            field_dict["properties"] = properties
        if confidence is not UNSET:
            field_dict["confidence"] = confidence

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.edge_create_request_properties import EdgeCreateRequestProperties

        d = dict(src_dict)
        source_id = d.pop("source_id")

        target_id = d.pop("target_id")

        edge_type = d.pop("edge_type")

        _properties = d.pop("properties", UNSET)
        properties: EdgeCreateRequestProperties | Unset
        if isinstance(_properties, Unset):
            properties = UNSET
        else:
            properties = EdgeCreateRequestProperties.from_dict(_properties)

        confidence = d.pop("confidence", UNSET)

        edge_create_request = cls(
            source_id=source_id,
            target_id=target_id,
            edge_type=edge_type,
            properties=properties,
            confidence=confidence,
        )

        edge_create_request.additional_properties = d
        return edge_create_request

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
