from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ReviewIn")


@_attrs_define
class ReviewIn:
    """
    Attributes:
        name (str):
        review_type (str | Unset):  Default: 'quarterly'.
        reviewer_id (str | Unset):  Default: ''.
        start_date (str | Unset):  Default: ''.
        due_date (str | Unset):  Default: ''.
    """

    name: str
    review_type: str | Unset = "quarterly"
    reviewer_id: str | Unset = ""
    start_date: str | Unset = ""
    due_date: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        review_type = self.review_type

        reviewer_id = self.reviewer_id

        start_date = self.start_date

        due_date = self.due_date

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
            }
        )
        if review_type is not UNSET:
            field_dict["review_type"] = review_type
        if reviewer_id is not UNSET:
            field_dict["reviewer_id"] = reviewer_id
        if start_date is not UNSET:
            field_dict["start_date"] = start_date
        if due_date is not UNSET:
            field_dict["due_date"] = due_date

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        review_type = d.pop("review_type", UNSET)

        reviewer_id = d.pop("reviewer_id", UNSET)

        start_date = d.pop("start_date", UNSET)

        due_date = d.pop("due_date", UNSET)

        review_in = cls(
            name=name,
            review_type=review_type,
            reviewer_id=reviewer_id,
            start_date=start_date,
            due_date=due_date,
        )

        review_in.additional_properties = d
        return review_in

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
