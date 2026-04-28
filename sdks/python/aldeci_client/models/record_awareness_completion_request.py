from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="RecordAwarenessCompletionRequest")


@_attrs_define
class RecordAwarenessCompletionRequest:
    """
    Attributes:
        user_id (str): User ID
        assignment_id (str): Assignment ID returned from /assign
        score (float): Quiz score (0–100)
    """

    user_id: str
    assignment_id: str
    score: float
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        user_id = self.user_id

        assignment_id = self.assignment_id

        score = self.score

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "user_id": user_id,
                "assignment_id": assignment_id,
                "score": score,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        user_id = d.pop("user_id")

        assignment_id = d.pop("assignment_id")

        score = d.pop("score")

        record_awareness_completion_request = cls(
            user_id=user_id,
            assignment_id=assignment_id,
            score=score,
        )

        record_awareness_completion_request.additional_properties = d
        return record_awareness_completion_request

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
