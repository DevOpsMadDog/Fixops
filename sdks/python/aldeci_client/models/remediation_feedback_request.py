from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.remediation_feedback_request_context import RemediationFeedbackRequestContext


T = TypeVar("T", bound="RemediationFeedbackRequest")


@_attrs_define
class RemediationFeedbackRequest:
    """
    Attributes:
        finding_id (str): Finding ID
        fix_type (str): Fix type (CODE_PATCH, CONFIG, etc.)
        fix_applied (str): Description of fix applied
        resolved (bool): Did the fix resolve the issue?
        time_to_fix_hours (float | Unset):  Default: 0.0.
        context (RemediationFeedbackRequestContext | Unset):
    """

    finding_id: str
    fix_type: str
    fix_applied: str
    resolved: bool
    time_to_fix_hours: float | Unset = 0.0
    context: RemediationFeedbackRequestContext | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        finding_id = self.finding_id

        fix_type = self.fix_type

        fix_applied = self.fix_applied

        resolved = self.resolved

        time_to_fix_hours = self.time_to_fix_hours

        context: dict[str, Any] | Unset = UNSET
        if not isinstance(self.context, Unset):
            context = self.context.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "finding_id": finding_id,
                "fix_type": fix_type,
                "fix_applied": fix_applied,
                "resolved": resolved,
            }
        )
        if time_to_fix_hours is not UNSET:
            field_dict["time_to_fix_hours"] = time_to_fix_hours
        if context is not UNSET:
            field_dict["context"] = context

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.remediation_feedback_request_context import RemediationFeedbackRequestContext

        d = dict(src_dict)
        finding_id = d.pop("finding_id")

        fix_type = d.pop("fix_type")

        fix_applied = d.pop("fix_applied")

        resolved = d.pop("resolved")

        time_to_fix_hours = d.pop("time_to_fix_hours", UNSET)

        _context = d.pop("context", UNSET)
        context: RemediationFeedbackRequestContext | Unset
        if isinstance(_context, Unset):
            context = UNSET
        else:
            context = RemediationFeedbackRequestContext.from_dict(_context)

        remediation_feedback_request = cls(
            finding_id=finding_id,
            fix_type=fix_type,
            fix_applied=fix_applied,
            resolved=resolved,
            time_to_fix_hours=time_to_fix_hours,
            context=context,
        )

        remediation_feedback_request.additional_properties = d
        return remediation_feedback_request

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
