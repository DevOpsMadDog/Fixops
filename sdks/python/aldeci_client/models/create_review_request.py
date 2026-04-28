from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CreateReviewRequest")


@_attrs_define
class CreateReviewRequest:
    """Body for creating an access review campaign.

    Attributes:
        name (str): Human-readable review campaign name
        reviewer_id (str): User ID of the reviewer
        deadline (str): ISO 8601 deadline, e.g. '2026-05-01T00:00:00Z'
        scope (str | Unset): Scope description, e.g. 'Q2 privileged access review' Default: 'all'.
        access_type (str | Unset): Which accounts to include: 'privileged', 'service_accounts', or 'all' Default: 'all'.
        org_id (str | Unset): Organisation ID Default: 'default'.
    """

    name: str
    reviewer_id: str
    deadline: str
    scope: str | Unset = "all"
    access_type: str | Unset = "all"
    org_id: str | Unset = "default"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        reviewer_id = self.reviewer_id

        deadline = self.deadline

        scope = self.scope

        access_type = self.access_type

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
                "reviewer_id": reviewer_id,
                "deadline": deadline,
            }
        )
        if scope is not UNSET:
            field_dict["scope"] = scope
        if access_type is not UNSET:
            field_dict["access_type"] = access_type
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        reviewer_id = d.pop("reviewer_id")

        deadline = d.pop("deadline")

        scope = d.pop("scope", UNSET)

        access_type = d.pop("access_type", UNSET)

        org_id = d.pop("org_id", UNSET)

        create_review_request = cls(
            name=name,
            reviewer_id=reviewer_id,
            deadline=deadline,
            scope=scope,
            access_type=access_type,
            org_id=org_id,
        )

        create_review_request.additional_properties = d
        return create_review_request

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
