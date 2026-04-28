from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CorrelationCreate")


@_attrs_define
class CorrelationCreate:
    """
    Attributes:
        incident_id (str):
        primary_event_id (str):
        correlated_event_id (str):
        correlation_type (str):
        confidence (float | Unset):  Default: 0.5.
    """

    incident_id: str
    primary_event_id: str
    correlated_event_id: str
    correlation_type: str
    confidence: float | Unset = 0.5
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        incident_id = self.incident_id

        primary_event_id = self.primary_event_id

        correlated_event_id = self.correlated_event_id

        correlation_type = self.correlation_type

        confidence = self.confidence

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "incident_id": incident_id,
                "primary_event_id": primary_event_id,
                "correlated_event_id": correlated_event_id,
                "correlation_type": correlation_type,
            }
        )
        if confidence is not UNSET:
            field_dict["confidence"] = confidence

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        incident_id = d.pop("incident_id")

        primary_event_id = d.pop("primary_event_id")

        correlated_event_id = d.pop("correlated_event_id")

        correlation_type = d.pop("correlation_type")

        confidence = d.pop("confidence", UNSET)

        correlation_create = cls(
            incident_id=incident_id,
            primary_event_id=primary_event_id,
            correlated_event_id=correlated_event_id,
            correlation_type=correlation_type,
            confidence=confidence,
        )

        correlation_create.additional_properties = d
        return correlation_create

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
