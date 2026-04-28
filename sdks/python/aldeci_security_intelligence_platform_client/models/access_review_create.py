from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AccessReviewCreate")


@_attrs_define
class AccessReviewCreate:
    """
    Attributes:
        policy_id (str): Policy being reviewed
        reviewer (str): Reviewer identity
        outcome (str | Unset): approved / revoked / modified Default: 'approved'.
        action_taken (str | Unset): Description of action taken Default: ''.
        review_date (None | str | Unset): ISO 8601 review date (defaults to now)
    """

    policy_id: str
    reviewer: str
    outcome: str | Unset = "approved"
    action_taken: str | Unset = ""
    review_date: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        policy_id = self.policy_id

        reviewer = self.reviewer

        outcome = self.outcome

        action_taken = self.action_taken

        review_date: None | str | Unset
        if isinstance(self.review_date, Unset):
            review_date = UNSET
        else:
            review_date = self.review_date

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "policy_id": policy_id,
                "reviewer": reviewer,
            }
        )
        if outcome is not UNSET:
            field_dict["outcome"] = outcome
        if action_taken is not UNSET:
            field_dict["action_taken"] = action_taken
        if review_date is not UNSET:
            field_dict["review_date"] = review_date

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        policy_id = d.pop("policy_id")

        reviewer = d.pop("reviewer")

        outcome = d.pop("outcome", UNSET)

        action_taken = d.pop("action_taken", UNSET)

        def _parse_review_date(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        review_date = _parse_review_date(d.pop("review_date", UNSET))

        access_review_create = cls(
            policy_id=policy_id,
            reviewer=reviewer,
            outcome=outcome,
            action_taken=action_taken,
            review_date=review_date,
        )

        access_review_create.additional_properties = d
        return access_review_create

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
