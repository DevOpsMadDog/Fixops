from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="IntelligenceLink")


@_attrs_define
class IntelligenceLink:
    """
    Attributes:
        source_suite (str):
        target_suite (str):
        data_flow (str):
        events_per_min (float | Unset):  Default: 0.0.
        status (str | Unset):  Default: 'active'.
    """

    source_suite: str
    target_suite: str
    data_flow: str
    events_per_min: float | Unset = 0.0
    status: str | Unset = "active"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        source_suite = self.source_suite

        target_suite = self.target_suite

        data_flow = self.data_flow

        events_per_min = self.events_per_min

        status = self.status

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "source_suite": source_suite,
                "target_suite": target_suite,
                "data_flow": data_flow,
            }
        )
        if events_per_min is not UNSET:
            field_dict["events_per_min"] = events_per_min
        if status is not UNSET:
            field_dict["status"] = status

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        source_suite = d.pop("source_suite")

        target_suite = d.pop("target_suite")

        data_flow = d.pop("data_flow")

        events_per_min = d.pop("events_per_min", UNSET)

        status = d.pop("status", UNSET)

        intelligence_link = cls(
            source_suite=source_suite,
            target_suite=target_suite,
            data_flow=data_flow,
            events_per_min=events_per_min,
            status=status,
        )

        intelligence_link.additional_properties = d
        return intelligence_link

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
