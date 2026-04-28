from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CompletionRequest")


@_attrs_define
class CompletionRequest:
    """
    Attributes:
        employee_id (str):
        pre_score (float):
        post_score (float):
        time_spent_mins (int | Unset):  Default: 0.
    """

    employee_id: str
    pre_score: float
    post_score: float
    time_spent_mins: int | Unset = 0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        employee_id = self.employee_id

        pre_score = self.pre_score

        post_score = self.post_score

        time_spent_mins = self.time_spent_mins

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "employee_id": employee_id,
                "pre_score": pre_score,
                "post_score": post_score,
            }
        )
        if time_spent_mins is not UNSET:
            field_dict["time_spent_mins"] = time_spent_mins

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        employee_id = d.pop("employee_id")

        pre_score = d.pop("pre_score")

        post_score = d.pop("post_score")

        time_spent_mins = d.pop("time_spent_mins", UNSET)

        completion_request = cls(
            employee_id=employee_id,
            pre_score=pre_score,
            post_score=post_score,
            time_spent_mins=time_spent_mins,
        )

        completion_request.additional_properties = d
        return completion_request

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
