from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.decision_feedback_request_context import DecisionFeedbackRequestContext


T = TypeVar("T", bound="DecisionFeedbackRequest")


@_attrs_define
class DecisionFeedbackRequest:
    """
    Attributes:
        decision_id (str): AI decision ID
        finding_id (str): Finding ID
        predicted_action (str): What AI decided
        actual_outcome (str): What actually happened
        confidence (float | Unset):  Default: 0.0.
        context (DecisionFeedbackRequestContext | Unset):
    """

    decision_id: str
    finding_id: str
    predicted_action: str
    actual_outcome: str
    confidence: float | Unset = 0.0
    context: DecisionFeedbackRequestContext | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        decision_id = self.decision_id

        finding_id = self.finding_id

        predicted_action = self.predicted_action

        actual_outcome = self.actual_outcome

        confidence = self.confidence

        context: dict[str, Any] | Unset = UNSET
        if not isinstance(self.context, Unset):
            context = self.context.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "decision_id": decision_id,
                "finding_id": finding_id,
                "predicted_action": predicted_action,
                "actual_outcome": actual_outcome,
            }
        )
        if confidence is not UNSET:
            field_dict["confidence"] = confidence
        if context is not UNSET:
            field_dict["context"] = context

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.decision_feedback_request_context import DecisionFeedbackRequestContext

        d = dict(src_dict)
        decision_id = d.pop("decision_id")

        finding_id = d.pop("finding_id")

        predicted_action = d.pop("predicted_action")

        actual_outcome = d.pop("actual_outcome")

        confidence = d.pop("confidence", UNSET)

        _context = d.pop("context", UNSET)
        context: DecisionFeedbackRequestContext | Unset
        if isinstance(_context, Unset):
            context = UNSET
        else:
            context = DecisionFeedbackRequestContext.from_dict(_context)

        decision_feedback_request = cls(
            decision_id=decision_id,
            finding_id=finding_id,
            predicted_action=predicted_action,
            actual_outcome=actual_outcome,
            confidence=confidence,
            context=context,
        )

        decision_feedback_request.additional_properties = d
        return decision_feedback_request

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
