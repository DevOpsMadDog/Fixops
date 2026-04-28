from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RetentionRequest")


@_attrs_define
class RetentionRequest:
    """
    Attributes:
        employee_id (str):
        retention_score (float):
        days_since_training (int | Unset):  Default: 0.
    """

    employee_id: str
    retention_score: float
    days_since_training: int | Unset = 0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        employee_id = self.employee_id

        retention_score = self.retention_score

        days_since_training = self.days_since_training

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "employee_id": employee_id,
                "retention_score": retention_score,
            }
        )
        if days_since_training is not UNSET:
            field_dict["days_since_training"] = days_since_training

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        employee_id = d.pop("employee_id")

        retention_score = d.pop("retention_score")

        days_since_training = d.pop("days_since_training", UNSET)

        retention_request = cls(
            employee_id=employee_id,
            retention_score=retention_score,
            days_since_training=days_since_training,
        )

        retention_request.additional_properties = d
        return retention_request

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
