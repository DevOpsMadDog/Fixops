from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="TriageFeedbackResponse")


@_attrs_define
class TriageFeedbackResponse:
    """Response after recording analyst feedback.

    Attributes:
        feedback_id (str):
        finding_id (str):
        verdict (str):
        recorded_at (str):
        confidence_updated (bool | Unset):  Default: False.
        updated_confidence (float | None | Unset):
    """

    feedback_id: str
    finding_id: str
    verdict: str
    recorded_at: str
    confidence_updated: bool | Unset = False
    updated_confidence: float | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        feedback_id = self.feedback_id

        finding_id = self.finding_id

        verdict = self.verdict

        recorded_at = self.recorded_at

        confidence_updated = self.confidence_updated

        updated_confidence: float | None | Unset
        if isinstance(self.updated_confidence, Unset):
            updated_confidence = UNSET
        else:
            updated_confidence = self.updated_confidence

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "feedback_id": feedback_id,
                "finding_id": finding_id,
                "verdict": verdict,
                "recorded_at": recorded_at,
            }
        )
        if confidence_updated is not UNSET:
            field_dict["confidence_updated"] = confidence_updated
        if updated_confidence is not UNSET:
            field_dict["updated_confidence"] = updated_confidence

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        feedback_id = d.pop("feedback_id")

        finding_id = d.pop("finding_id")

        verdict = d.pop("verdict")

        recorded_at = d.pop("recorded_at")

        confidence_updated = d.pop("confidence_updated", UNSET)

        def _parse_updated_confidence(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        updated_confidence = _parse_updated_confidence(d.pop("updated_confidence", UNSET))

        triage_feedback_response = cls(
            feedback_id=feedback_id,
            finding_id=finding_id,
            verdict=verdict,
            recorded_at=recorded_at,
            confidence_updated=confidence_updated,
            updated_confidence=updated_confidence,
        )

        triage_feedback_response.additional_properties = d
        return triage_feedback_response

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
