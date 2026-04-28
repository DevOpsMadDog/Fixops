from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RefreshSessionRequest")


@_attrs_define
class RefreshSessionRequest:
    """Request body for refreshing a session.

    Attributes:
        ttl_hours (int | None | Unset): New TTL from now (hours). Omit to keep existing expiry.
    """

    ttl_hours: int | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        ttl_hours: int | None | Unset
        if isinstance(self.ttl_hours, Unset):
            ttl_hours = UNSET
        else:
            ttl_hours = self.ttl_hours

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if ttl_hours is not UNSET:
            field_dict["ttl_hours"] = ttl_hours

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_ttl_hours(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        ttl_hours = _parse_ttl_hours(d.pop("ttl_hours", UNSET))

        refresh_session_request = cls(
            ttl_hours=ttl_hours,
        )

        refresh_session_request.additional_properties = d
        return refresh_session_request

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
