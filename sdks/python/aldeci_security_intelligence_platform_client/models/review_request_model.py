from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ReviewRequestModel")


@_attrs_define
class ReviewRequestModel:
    """
    Attributes:
        reviewer (str):
        decision (str):
        conditions (str | Unset):  Default: ''.
        risk_rating (str | Unset):  Default: 'medium'.
        comments (str | Unset):  Default: ''.
        org_id (str | Unset):  Default: 'default'.
    """

    reviewer: str
    decision: str
    conditions: str | Unset = ""
    risk_rating: str | Unset = "medium"
    comments: str | Unset = ""
    org_id: str | Unset = "default"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        reviewer = self.reviewer

        decision = self.decision

        conditions = self.conditions

        risk_rating = self.risk_rating

        comments = self.comments

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "reviewer": reviewer,
                "decision": decision,
            }
        )
        if conditions is not UNSET:
            field_dict["conditions"] = conditions
        if risk_rating is not UNSET:
            field_dict["risk_rating"] = risk_rating
        if comments is not UNSET:
            field_dict["comments"] = comments
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        reviewer = d.pop("reviewer")

        decision = d.pop("decision")

        conditions = d.pop("conditions", UNSET)

        risk_rating = d.pop("risk_rating", UNSET)

        comments = d.pop("comments", UNSET)

        org_id = d.pop("org_id", UNSET)

        review_request_model = cls(
            reviewer=reviewer,
            decision=decision,
            conditions=conditions,
            risk_rating=risk_rating,
            comments=comments,
            org_id=org_id,
        )

        review_request_model.additional_properties = d
        return review_request_model

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
