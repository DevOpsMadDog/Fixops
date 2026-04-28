from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RateLimitConfig")


@_attrs_define
class RateLimitConfig:
    """Rate limiting configuration.

    Attributes:
        window_seconds (int | Unset):  Default: 60.
        max_requests (int | Unset):  Default: 200.
        max_violations (int | Unset):  Default: 5.
        auto_block_duration (int | Unset):  Default: 300.
    """

    window_seconds: int | Unset = 60
    max_requests: int | Unset = 200
    max_violations: int | Unset = 5
    auto_block_duration: int | Unset = 300
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        window_seconds = self.window_seconds

        max_requests = self.max_requests

        max_violations = self.max_violations

        auto_block_duration = self.auto_block_duration

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if window_seconds is not UNSET:
            field_dict["window_seconds"] = window_seconds
        if max_requests is not UNSET:
            field_dict["max_requests"] = max_requests
        if max_violations is not UNSET:
            field_dict["max_violations"] = max_violations
        if auto_block_duration is not UNSET:
            field_dict["auto_block_duration"] = auto_block_duration

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        window_seconds = d.pop("window_seconds", UNSET)

        max_requests = d.pop("max_requests", UNSET)

        max_violations = d.pop("max_violations", UNSET)

        auto_block_duration = d.pop("auto_block_duration", UNSET)

        rate_limit_config = cls(
            window_seconds=window_seconds,
            max_requests=max_requests,
            max_violations=max_violations,
            auto_block_duration=auto_block_duration,
        )

        rate_limit_config.additional_properties = d
        return rate_limit_config

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
