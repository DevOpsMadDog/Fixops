from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ReviewCreate")


@_attrs_define
class ReviewCreate:
    """
    Attributes:
        reviewer (str): Name of the reviewer
        review_outcome (str): approved | rejected | approved_with_changes | deferred
        comments (str | Unset):  Default: ''.
        review_date (None | str | Unset):
        next_review_date (None | str | Unset):
    """

    reviewer: str
    review_outcome: str
    comments: str | Unset = ""
    review_date: None | str | Unset = UNSET
    next_review_date: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        reviewer = self.reviewer

        review_outcome = self.review_outcome

        comments = self.comments

        review_date: None | str | Unset
        if isinstance(self.review_date, Unset):
            review_date = UNSET
        else:
            review_date = self.review_date

        next_review_date: None | str | Unset
        if isinstance(self.next_review_date, Unset):
            next_review_date = UNSET
        else:
            next_review_date = self.next_review_date

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "reviewer": reviewer,
                "review_outcome": review_outcome,
            }
        )
        if comments is not UNSET:
            field_dict["comments"] = comments
        if review_date is not UNSET:
            field_dict["review_date"] = review_date
        if next_review_date is not UNSET:
            field_dict["next_review_date"] = next_review_date

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        reviewer = d.pop("reviewer")

        review_outcome = d.pop("review_outcome")

        comments = d.pop("comments", UNSET)

        def _parse_review_date(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        review_date = _parse_review_date(d.pop("review_date", UNSET))

        def _parse_next_review_date(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        next_review_date = _parse_next_review_date(d.pop("next_review_date", UNSET))

        review_create = cls(
            reviewer=reviewer,
            review_outcome=review_outcome,
            comments=comments,
            review_date=review_date,
            next_review_date=next_review_date,
        )

        review_create.additional_properties = d
        return review_create

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
