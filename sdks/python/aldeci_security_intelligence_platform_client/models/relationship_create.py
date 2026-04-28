from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RelationshipCreate")


@_attrs_define
class RelationshipCreate:
    """
    Attributes:
        indicator_a_id (str):
        indicator_b_id (str):
        relationship_type (str | Unset):  Default: 'communicates_with'.
        confidence (float | Unset):  Default: 0.5.
        source_id (str | Unset):  Default: ''.
    """

    indicator_a_id: str
    indicator_b_id: str
    relationship_type: str | Unset = "communicates_with"
    confidence: float | Unset = 0.5
    source_id: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        indicator_a_id = self.indicator_a_id

        indicator_b_id = self.indicator_b_id

        relationship_type = self.relationship_type

        confidence = self.confidence

        source_id = self.source_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "indicator_a_id": indicator_a_id,
                "indicator_b_id": indicator_b_id,
            }
        )
        if relationship_type is not UNSET:
            field_dict["relationship_type"] = relationship_type
        if confidence is not UNSET:
            field_dict["confidence"] = confidence
        if source_id is not UNSET:
            field_dict["source_id"] = source_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        indicator_a_id = d.pop("indicator_a_id")

        indicator_b_id = d.pop("indicator_b_id")

        relationship_type = d.pop("relationship_type", UNSET)

        confidence = d.pop("confidence", UNSET)

        source_id = d.pop("source_id", UNSET)

        relationship_create = cls(
            indicator_a_id=indicator_a_id,
            indicator_b_id=indicator_b_id,
            relationship_type=relationship_type,
            confidence=confidence,
            source_id=source_id,
        )

        relationship_create.additional_properties = d
        return relationship_create

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
