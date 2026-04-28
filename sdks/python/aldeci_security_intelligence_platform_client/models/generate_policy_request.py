from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.policy_type import PolicyType
from ..types import UNSET, Unset

T = TypeVar("T", bound="GeneratePolicyRequest")


@_attrs_define
class GeneratePolicyRequest:
    """Request body for generating a new policy.

    Attributes:
        type_ (PolicyType): Supported security policy types.
        org_id (str | Unset):  Default: 'default'.
        custom_title (None | str | Unset): Override the default policy title
        review_days (int | Unset): Days until next review (default 365) Default: 365.
    """

    type_: PolicyType
    org_id: str | Unset = "default"
    custom_title: None | str | Unset = UNSET
    review_days: int | Unset = 365
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        type_ = self.type_.value

        org_id = self.org_id

        custom_title: None | str | Unset
        if isinstance(self.custom_title, Unset):
            custom_title = UNSET
        else:
            custom_title = self.custom_title

        review_days = self.review_days

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "type": type_,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if custom_title is not UNSET:
            field_dict["custom_title"] = custom_title
        if review_days is not UNSET:
            field_dict["review_days"] = review_days

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        type_ = PolicyType(d.pop("type"))

        org_id = d.pop("org_id", UNSET)

        def _parse_custom_title(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        custom_title = _parse_custom_title(d.pop("custom_title", UNSET))

        review_days = d.pop("review_days", UNSET)

        generate_policy_request = cls(
            type_=type_,
            org_id=org_id,
            custom_title=custom_title,
            review_days=review_days,
        )

        generate_policy_request.additional_properties = d
        return generate_policy_request

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
