from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AddIndicatorRequest")


@_attrs_define
class AddIndicatorRequest:
    """
    Attributes:
        indicator_type (str):
        incident_id (str | Unset):  Default: ''.
        value (str | Unset):  Default: ''.
        confidence_score (float | Unset):  Default: 50.0.
    """

    indicator_type: str
    incident_id: str | Unset = ""
    value: str | Unset = ""
    confidence_score: float | Unset = 50.0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        indicator_type = self.indicator_type

        incident_id = self.incident_id

        value = self.value

        confidence_score = self.confidence_score

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "indicator_type": indicator_type,
            }
        )
        if incident_id is not UNSET:
            field_dict["incident_id"] = incident_id
        if value is not UNSET:
            field_dict["value"] = value
        if confidence_score is not UNSET:
            field_dict["confidence_score"] = confidence_score

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        indicator_type = d.pop("indicator_type")

        incident_id = d.pop("incident_id", UNSET)

        value = d.pop("value", UNSET)

        confidence_score = d.pop("confidence_score", UNSET)

        add_indicator_request = cls(
            indicator_type=indicator_type,
            incident_id=incident_id,
            value=value,
            confidence_score=confidence_score,
        )

        add_indicator_request.additional_properties = d
        return add_indicator_request

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
