from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..types import UNSET, Unset

T = TypeVar("T", bound="AcceptanceReview")


@_attrs_define
class AcceptanceReview:
    """A single review action against a RiskAcceptance.

    Attributes:
        acceptance_id (str):
        reviewer (str):
        decision (str):
        id (str | Unset):
        comment (str | Unset):  Default: ''.
        reviewed_at (datetime.datetime | Unset):
    """

    acceptance_id: str
    reviewer: str
    decision: str
    id: str | Unset = UNSET
    comment: str | Unset = ""
    reviewed_at: datetime.datetime | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        acceptance_id = self.acceptance_id

        reviewer = self.reviewer

        decision = self.decision

        id = self.id

        comment = self.comment

        reviewed_at: str | Unset = UNSET
        if not isinstance(self.reviewed_at, Unset):
            reviewed_at = self.reviewed_at.isoformat()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "acceptance_id": acceptance_id,
                "reviewer": reviewer,
                "decision": decision,
            }
        )
        if id is not UNSET:
            field_dict["id"] = id
        if comment is not UNSET:
            field_dict["comment"] = comment
        if reviewed_at is not UNSET:
            field_dict["reviewed_at"] = reviewed_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        acceptance_id = d.pop("acceptance_id")

        reviewer = d.pop("reviewer")

        decision = d.pop("decision")

        id = d.pop("id", UNSET)

        comment = d.pop("comment", UNSET)

        _reviewed_at = d.pop("reviewed_at", UNSET)
        reviewed_at: datetime.datetime | Unset
        if isinstance(_reviewed_at, Unset):
            reviewed_at = UNSET
        else:
            reviewed_at = isoparse(_reviewed_at)

        acceptance_review = cls(
            acceptance_id=acceptance_id,
            reviewer=reviewer,
            decision=decision,
            id=id,
            comment=comment,
            reviewed_at=reviewed_at,
        )

        acceptance_review.additional_properties = d
        return acceptance_review

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
