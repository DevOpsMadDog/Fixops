from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CreateReviewBody")


@_attrs_define
class CreateReviewBody:
    """
    Attributes:
        review_name (str): Name of this architecture review
        system_name (str): System or service being reviewed
        review_type (str | Unset): full | partial | threat-model | compliance | vendor Default: 'full'.
        reviewer (str | Unset): Reviewer name or ID Default: ''.
    """

    review_name: str
    system_name: str
    review_type: str | Unset = "full"
    reviewer: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        review_name = self.review_name

        system_name = self.system_name

        review_type = self.review_type

        reviewer = self.reviewer

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "review_name": review_name,
                "system_name": system_name,
            }
        )
        if review_type is not UNSET:
            field_dict["review_type"] = review_type
        if reviewer is not UNSET:
            field_dict["reviewer"] = reviewer

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        review_name = d.pop("review_name")

        system_name = d.pop("system_name")

        review_type = d.pop("review_type", UNSET)

        reviewer = d.pop("reviewer", UNSET)

        create_review_body = cls(
            review_name=review_name,
            system_name=system_name,
            review_type=review_type,
            reviewer=reviewer,
        )

        create_review_body.additional_properties = d
        return create_review_body

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
