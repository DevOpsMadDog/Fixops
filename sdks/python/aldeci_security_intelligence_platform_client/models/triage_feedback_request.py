from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="TriageFeedbackRequest")


@_attrs_define
class TriageFeedbackRequest:
    """Analyst feedback on a triaged finding.

    Attributes:
        finding_id (str):
        analyst_verdict (str): accept, reject, escalate, or false_positive
        reason (None | str | Unset):
        analyst_id (None | str | Unset):
    """

    finding_id: str
    analyst_verdict: str
    reason: None | str | Unset = UNSET
    analyst_id: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        finding_id = self.finding_id

        analyst_verdict = self.analyst_verdict

        reason: None | str | Unset
        if isinstance(self.reason, Unset):
            reason = UNSET
        else:
            reason = self.reason

        analyst_id: None | str | Unset
        if isinstance(self.analyst_id, Unset):
            analyst_id = UNSET
        else:
            analyst_id = self.analyst_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "finding_id": finding_id,
                "analyst_verdict": analyst_verdict,
            }
        )
        if reason is not UNSET:
            field_dict["reason"] = reason
        if analyst_id is not UNSET:
            field_dict["analyst_id"] = analyst_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        finding_id = d.pop("finding_id")

        analyst_verdict = d.pop("analyst_verdict")

        def _parse_reason(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        reason = _parse_reason(d.pop("reason", UNSET))

        def _parse_analyst_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        analyst_id = _parse_analyst_id(d.pop("analyst_id", UNSET))

        triage_feedback_request = cls(
            finding_id=finding_id,
            analyst_verdict=analyst_verdict,
            reason=reason,
            analyst_id=analyst_id,
        )

        triage_feedback_request.additional_properties = d
        return triage_feedback_request

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
