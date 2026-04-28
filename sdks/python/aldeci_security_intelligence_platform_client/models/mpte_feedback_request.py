from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.mpte_feedback_request_context import MPTEFeedbackRequestContext


T = TypeVar("T", bound="MPTEFeedbackRequest")


@_attrs_define
class MPTEFeedbackRequest:
    """
    Attributes:
        finding_id (str): Finding ID
        predicted_exploitable (bool): Was it predicted exploitable?
        actual_exploitable (bool): Was it actually exploitable?
        mpte_confidence (float | Unset):  Default: 0.0.
        context (MPTEFeedbackRequestContext | Unset):
    """

    finding_id: str
    predicted_exploitable: bool
    actual_exploitable: bool
    mpte_confidence: float | Unset = 0.0
    context: MPTEFeedbackRequestContext | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        finding_id = self.finding_id

        predicted_exploitable = self.predicted_exploitable

        actual_exploitable = self.actual_exploitable

        mpte_confidence = self.mpte_confidence

        context: dict[str, Any] | Unset = UNSET
        if not isinstance(self.context, Unset):
            context = self.context.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "finding_id": finding_id,
                "predicted_exploitable": predicted_exploitable,
                "actual_exploitable": actual_exploitable,
            }
        )
        if mpte_confidence is not UNSET:
            field_dict["mpte_confidence"] = mpte_confidence
        if context is not UNSET:
            field_dict["context"] = context

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.mpte_feedback_request_context import MPTEFeedbackRequestContext

        d = dict(src_dict)
        finding_id = d.pop("finding_id")

        predicted_exploitable = d.pop("predicted_exploitable")

        actual_exploitable = d.pop("actual_exploitable")

        mpte_confidence = d.pop("mpte_confidence", UNSET)

        _context = d.pop("context", UNSET)
        context: MPTEFeedbackRequestContext | Unset
        if isinstance(_context, Unset):
            context = UNSET
        else:
            context = MPTEFeedbackRequestContext.from_dict(_context)

        mpte_feedback_request = cls(
            finding_id=finding_id,
            predicted_exploitable=predicted_exploitable,
            actual_exploitable=actual_exploitable,
            mpte_confidence=mpte_confidence,
            context=context,
        )

        mpte_feedback_request.additional_properties = d
        return mpte_feedback_request

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
