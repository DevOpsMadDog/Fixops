from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..models.acceptance_status import AcceptanceStatus
from ..models.review_priority import ReviewPriority
from ..types import UNSET, Unset

T = TypeVar("T", bound="RiskAcceptance")


@_attrs_define
class RiskAcceptance:
    """A formal risk acceptance record.

    Attributes:
        finding_id (str):
        org_id (str):
        justification (str):
        business_reason (str):
        requested_by (str):
        expires_at (datetime.datetime):
        review_date (datetime.datetime):
        id (str | Unset):
        compensating_controls (str | Unset):  Default: ''.
        requested_at (datetime.datetime | Unset):
        approved_by (None | str | Unset):
        approved_at (datetime.datetime | None | Unset):
        status (AcceptanceStatus | Unset): Lifecycle states for a risk acceptance record.
        priority (ReviewPriority | Unset): Priority classification for the review queue.
        conditions (list[str] | Unset):
        risk_score_at_acceptance (float | Unset):  Default: 0.0.
    """

    finding_id: str
    org_id: str
    justification: str
    business_reason: str
    requested_by: str
    expires_at: datetime.datetime
    review_date: datetime.datetime
    id: str | Unset = UNSET
    compensating_controls: str | Unset = ""
    requested_at: datetime.datetime | Unset = UNSET
    approved_by: None | str | Unset = UNSET
    approved_at: datetime.datetime | None | Unset = UNSET
    status: AcceptanceStatus | Unset = UNSET
    priority: ReviewPriority | Unset = UNSET
    conditions: list[str] | Unset = UNSET
    risk_score_at_acceptance: float | Unset = 0.0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        finding_id = self.finding_id

        org_id = self.org_id

        justification = self.justification

        business_reason = self.business_reason

        requested_by = self.requested_by

        expires_at = self.expires_at.isoformat()

        review_date = self.review_date.isoformat()

        id = self.id

        compensating_controls = self.compensating_controls

        requested_at: str | Unset = UNSET
        if not isinstance(self.requested_at, Unset):
            requested_at = self.requested_at.isoformat()

        approved_by: None | str | Unset
        if isinstance(self.approved_by, Unset):
            approved_by = UNSET
        else:
            approved_by = self.approved_by

        approved_at: None | str | Unset
        if isinstance(self.approved_at, Unset):
            approved_at = UNSET
        elif isinstance(self.approved_at, datetime.datetime):
            approved_at = self.approved_at.isoformat()
        else:
            approved_at = self.approved_at

        status: str | Unset = UNSET
        if not isinstance(self.status, Unset):
            status = self.status.value

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
                "org_id": org_id,
                "justification": justification,
                "business_reason": business_reason,
                "requested_by": requested_by,
                "expires_at": expires_at,
                "review_date": review_date,
            }
        )
        if id is not UNSET:
            field_dict["id"] = id
        if compensating_controls is not UNSET:
            field_dict["compensating_controls"] = compensating_controls
        if requested_at is not UNSET:
            field_dict["requested_at"] = requested_at
        if approved_by is not UNSET:
            field_dict["approved_by"] = approved_by
        if approved_at is not UNSET:
            field_dict["approved_at"] = approved_at
        if status is not UNSET:
            field_dict["status"] = status
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

        org_id = d.pop("org_id")

        justification = d.pop("justification")

        business_reason = d.pop("business_reason")

        requested_by = d.pop("requested_by")

        expires_at = isoparse(d.pop("expires_at"))

        review_date = isoparse(d.pop("review_date"))

        id = d.pop("id", UNSET)

        compensating_controls = d.pop("compensating_controls", UNSET)

        _requested_at = d.pop("requested_at", UNSET)
        requested_at: datetime.datetime | Unset
        if isinstance(_requested_at, Unset):
            requested_at = UNSET
        else:
            requested_at = isoparse(_requested_at)

        def _parse_approved_by(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        approved_by = _parse_approved_by(d.pop("approved_by", UNSET))

        def _parse_approved_at(data: object) -> datetime.datetime | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                approved_at_type_0 = isoparse(data)

                return approved_at_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(datetime.datetime | None | Unset, data)

        approved_at = _parse_approved_at(d.pop("approved_at", UNSET))

        _status = d.pop("status", UNSET)
        status: AcceptanceStatus | Unset
        if isinstance(_status, Unset):
            status = UNSET
        else:
            status = AcceptanceStatus(_status)

        _priority = d.pop("priority", UNSET)
        priority: ReviewPriority | Unset
        if isinstance(_priority, Unset):
            priority = UNSET
        else:
            priority = ReviewPriority(_priority)

        conditions = cast(list[str], d.pop("conditions", UNSET))

        risk_score_at_acceptance = d.pop("risk_score_at_acceptance", UNSET)

        risk_acceptance = cls(
            finding_id=finding_id,
            org_id=org_id,
            justification=justification,
            business_reason=business_reason,
            requested_by=requested_by,
            expires_at=expires_at,
            review_date=review_date,
            id=id,
            compensating_controls=compensating_controls,
            requested_at=requested_at,
            approved_by=approved_by,
            approved_at=approved_at,
            status=status,
            priority=priority,
            conditions=conditions,
            risk_score_at_acceptance=risk_score_at_acceptance,
        )

        risk_acceptance.additional_properties = d
        return risk_acceptance

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
