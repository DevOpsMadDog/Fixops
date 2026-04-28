from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RateLimitBody")


@_attrs_define
class RateLimitBody:
    """
    Attributes:
        endpoint_pattern (str | Unset):  Default: '/*'.
        requests_per_minute (int | Unset):  Default: 60.
        burst_size (int | Unset):  Default: 10.
        action (str | Unset):  Default: 'block'.
    """

    endpoint_pattern: str | Unset = "/*"
    requests_per_minute: int | Unset = 60
    burst_size: int | Unset = 10
    action: str | Unset = "block"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        endpoint_pattern = self.endpoint_pattern

        requests_per_minute = self.requests_per_minute

        burst_size = self.burst_size

        action = self.action

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if endpoint_pattern is not UNSET:
            field_dict["endpoint_pattern"] = endpoint_pattern
        if requests_per_minute is not UNSET:
            field_dict["requests_per_minute"] = requests_per_minute
        if burst_size is not UNSET:
            field_dict["burst_size"] = burst_size
        if action is not UNSET:
            field_dict["action"] = action

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        endpoint_pattern = d.pop("endpoint_pattern", UNSET)

        requests_per_minute = d.pop("requests_per_minute", UNSET)

        burst_size = d.pop("burst_size", UNSET)

        action = d.pop("action", UNSET)

        rate_limit_body = cls(
            endpoint_pattern=endpoint_pattern,
            requests_per_minute=requests_per_minute,
            burst_size=burst_size,
            action=action,
        )

        rate_limit_body.additional_properties = d
        return rate_limit_body

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
