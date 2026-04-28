from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="MarkDoneRequest")


@_attrs_define
class MarkDoneRequest:
    """
    Attributes:
        schedule_id (str): Schedule ID
        findings_delta (int | Unset): Change in findings count Default: 0.
    """

    schedule_id: str
    findings_delta: int | Unset = 0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        schedule_id = self.schedule_id

        findings_delta = self.findings_delta

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "schedule_id": schedule_id,
            }
        )
        if findings_delta is not UNSET:
            field_dict["findings_delta"] = findings_delta

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        schedule_id = d.pop("schedule_id")

        findings_delta = d.pop("findings_delta", UNSET)

        mark_done_request = cls(
            schedule_id=schedule_id,
            findings_delta=findings_delta,
        )

        mark_done_request.additional_properties = d
        return mark_done_request

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
