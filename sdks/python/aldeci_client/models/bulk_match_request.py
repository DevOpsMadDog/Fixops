from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="BulkMatchRequest")


@_attrs_define
class BulkMatchRequest:
    """
    Attributes:
        org_id (str):
        since_minutes (int | Unset):  Default: 60.
    """

    org_id: str
    since_minutes: int | Unset = 60
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        since_minutes = self.since_minutes

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
            }
        )
        if since_minutes is not UNSET:
            field_dict["since_minutes"] = since_minutes

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        since_minutes = d.pop("since_minutes", UNSET)

        bulk_match_request = cls(
            org_id=org_id,
            since_minutes=since_minutes,
        )

        bulk_match_request.additional_properties = d
        return bulk_match_request

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
