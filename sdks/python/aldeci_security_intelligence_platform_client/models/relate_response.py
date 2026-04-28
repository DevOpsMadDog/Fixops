from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="RelateResponse")


@_attrs_define
class RelateResponse:
    """Relationship creation response.

    Attributes:
        status (str):
        rel_id (str):
        source_id (str):
        target_id (str):
        rel_type (str):
        confidence (float):
    """

    status: str
    rel_id: str
    source_id: str
    target_id: str
    rel_type: str
    confidence: float
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        status = self.status

        rel_id = self.rel_id

        source_id = self.source_id

        target_id = self.target_id

        rel_type = self.rel_type

        confidence = self.confidence

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "status": status,
                "rel_id": rel_id,
                "source_id": source_id,
                "target_id": target_id,
                "rel_type": rel_type,
                "confidence": confidence,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        status = d.pop("status")

        rel_id = d.pop("rel_id")

        source_id = d.pop("source_id")

        target_id = d.pop("target_id")

        rel_type = d.pop("rel_type")

        confidence = d.pop("confidence")

        relate_response = cls(
            status=status,
            rel_id=rel_id,
            source_id=source_id,
            target_id=target_id,
            rel_type=rel_type,
            confidence=confidence,
        )

        relate_response.additional_properties = d
        return relate_response

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
