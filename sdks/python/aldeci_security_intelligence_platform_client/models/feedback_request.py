from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="FeedbackRequest")


@_attrs_define
class FeedbackRequest:
    """Submit actual outcome for a council verdict to drive calibration.

    Attributes:
        verdict_id (str): verdict_id from CouncilVerdict
        actual_outcome (str): Ground-truth label: TRUE_POSITIVE | FALSE_POSITIVE | NEEDS_REVIEW
    """

    verdict_id: str
    actual_outcome: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        verdict_id = self.verdict_id

        actual_outcome = self.actual_outcome

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "verdict_id": verdict_id,
                "actual_outcome": actual_outcome,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        verdict_id = d.pop("verdict_id")

        actual_outcome = d.pop("actual_outcome")

        feedback_request = cls(
            verdict_id=verdict_id,
            actual_outcome=actual_outcome,
        )

        feedback_request.additional_properties = d
        return feedback_request

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
