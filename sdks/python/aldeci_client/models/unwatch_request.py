from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="UnwatchRequest")


@_attrs_define
class UnwatchRequest:
    """
    Attributes:
        author_email (str):
        org_id (str | Unset):  Default: 'default'.
        unwatched_by (str | Unset):  Default: ''.
    """

    author_email: str
    org_id: str | Unset = "default"
    unwatched_by: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        author_email = self.author_email

        org_id = self.org_id

        unwatched_by = self.unwatched_by

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "author_email": author_email,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if unwatched_by is not UNSET:
            field_dict["unwatched_by"] = unwatched_by

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        author_email = d.pop("author_email")

        org_id = d.pop("org_id", UNSET)

        unwatched_by = d.pop("unwatched_by", UNSET)

        unwatch_request = cls(
            author_email=author_email,
            org_id=org_id,
            unwatched_by=unwatched_by,
        )

        unwatch_request.additional_properties = d
        return unwatch_request

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
