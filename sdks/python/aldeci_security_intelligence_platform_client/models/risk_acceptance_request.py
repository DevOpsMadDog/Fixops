from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..models.review_priority import ReviewPriority
from ..types import UNSET, Unset

T = TypeVar("T", bound="RiskAcceptanceRequest")


@_attrs_define
class RiskAcceptanceRequest:
    """Payload for requesting a new risk acceptance.

    Attributes:
        finding_id (str):
        justification (str):
        business_reason (str):
        requested_by (str):
        expires_at (datetime.datetime):
        compensating_controls (str | Unset):  Default: ''.
        priority (ReviewPriority | Unset): Priority classification for the review queue.
        conditions (list[str] | Unset):
        risk_score_at_acceptance (float | Unset):  Default: 0.0.
    """

    finding_id: str
    justification: str
    business_reason: str
    requested_by: str
    expires_at: datetime.datetime
    compensating_controls: str | Unset = ""
    priority: ReviewPriority | Unset = UNSET
    conditions: list[str] | Unset = UNSET
    risk_score_at_acceptance: float | Unset = 0.0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        finding_id = self.finding_id

        justification = self.justification

        business_reason = self.business_reason

        requested_by = self.requested_by

        expires_at = self.expires_at.isoformat()

        compensating_controls = self.compensating_controls

        priority: str | Unset = UNSET
        if not isinstance(self.priority, Unset):
            priority = self.priority.value

        conditions: list[str] | Unset = UNSET
        if not isinstance(self.conditions, Unset):
            conditions = self.conditions

        risk_score_at_acceptance = self.risk_score_at_acceptance

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "finding_id": finding_id,
                "justification": justification,
                "business_reason": business_reason,
                "requested_by": requested_by,
                "expires_at": expires_at,
            }
        )
        if compensating_controls is not UNSET:
            field_dict["compensating_controls"] = compensating_controls
        if priority is not UNSET:
            field_dict["priority"] = priority
        if conditions is not UNSET:
            field_dict["conditions"] = conditions
        if risk_score_at_acceptance is not UNSET:
            field_dict["risk_score_at_acceptance"] = risk_score_at_acceptance

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        finding_id = d.pop("finding_id")

        justification = d.pop("justification")

        business_reason = d.pop("business_reason")

        requested_by = d.pop("requested_by")

        expires_at = isoparse(d.pop("expires_at"))

        compensating_controls = d.pop("compensating_controls", UNSET)

        _priority = d.pop("priority", UNSET)
        priority: ReviewPriority | Unset
        if isinstance(_priority, Unset):
            priority = UNSET
        else:
            priority = ReviewPriority(_priority)

        conditions = cast(list[str], d.pop("conditions", UNSET))

        risk_score_at_acceptance = d.pop("risk_score_at_acceptance", UNSET)

        risk_acceptance_request = cls(
            finding_id=finding_id,
            justification=justification,
            business_reason=business_reason,
            requested_by=requested_by,
            expires_at=expires_at,
            compensating_controls=compensating_controls,
            priority=priority,
            conditions=conditions,
            risk_score_at_acceptance=risk_score_at_acceptance,
        )

        risk_acceptance_request.additional_properties = d
        return risk_acceptance_request

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
