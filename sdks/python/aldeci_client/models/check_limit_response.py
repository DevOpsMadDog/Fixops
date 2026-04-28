from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="CheckLimitResponse")


@_attrs_define
class CheckLimitResponse:
    """
    Attributes:
        allowed (bool):
        denied_reason (None | str):
        org_id (str):
        tier (str):
        remaining_minute (int):
        remaining_hour (int):
        remaining_day (int):
        limit_minute (int):
        limit_hour (int):
        limit_day (int):
        burst_limit (int):
    """

    allowed: bool
    denied_reason: None | str
    org_id: str
    tier: str
    remaining_minute: int
    remaining_hour: int
    remaining_day: int
    limit_minute: int
    limit_hour: int
    limit_day: int
    burst_limit: int
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        allowed = self.allowed

        denied_reason: None | str
        denied_reason = self.denied_reason

        org_id = self.org_id

        tier = self.tier

        remaining_minute = self.remaining_minute

        remaining_hour = self.remaining_hour

        remaining_day = self.remaining_day

        limit_minute = self.limit_minute

        limit_hour = self.limit_hour

        limit_day = self.limit_day

        burst_limit = self.burst_limit

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "allowed": allowed,
                "denied_reason": denied_reason,
                "org_id": org_id,
                "tier": tier,
                "remaining_minute": remaining_minute,
                "remaining_hour": remaining_hour,
                "remaining_day": remaining_day,
                "limit_minute": limit_minute,
                "limit_hour": limit_hour,
                "limit_day": limit_day,
                "burst_limit": burst_limit,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        allowed = d.pop("allowed")

        def _parse_denied_reason(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        denied_reason = _parse_denied_reason(d.pop("denied_reason"))

        org_id = d.pop("org_id")

        tier = d.pop("tier")

        remaining_minute = d.pop("remaining_minute")

        remaining_hour = d.pop("remaining_hour")

        remaining_day = d.pop("remaining_day")

        limit_minute = d.pop("limit_minute")

        limit_hour = d.pop("limit_hour")

        limit_day = d.pop("limit_day")

        burst_limit = d.pop("burst_limit")

        check_limit_response = cls(
            allowed=allowed,
            denied_reason=denied_reason,
            org_id=org_id,
            tier=tier,
            remaining_minute=remaining_minute,
            remaining_hour=remaining_hour,
            remaining_day=remaining_day,
            limit_minute=limit_minute,
            limit_hour=limit_hour,
            limit_day=limit_day,
            burst_limit=burst_limit,
        )

        check_limit_response.additional_properties = d
        return check_limit_response

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
