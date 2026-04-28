from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.rate_limit_tier import RateLimitTier
from ..types import UNSET, Unset

T = TypeVar("T", bound="EndpointConfigUpdate")


@_attrs_define
class EndpointConfigUpdate:
    """Body for updating an endpoint tier mapping or per-key override.

    Attributes:
        path_pattern (None | str | Unset): Regex pattern for the endpoint path (e.g. '^/api/v1/custom').
        tier (None | RateLimitTier | Unset): Rate limit tier to assign to the path pattern.
        api_key_id (None | str | Unset): API key ID to apply a per-key request-per-minute override.
        requests_per_minute (int | None | Unset): Requests per minute for the per-key override. 0 removes override.
    """

    path_pattern: None | str | Unset = UNSET
    tier: None | RateLimitTier | Unset = UNSET
    api_key_id: None | str | Unset = UNSET
    requests_per_minute: int | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        path_pattern: None | str | Unset
        if isinstance(self.path_pattern, Unset):
            path_pattern = UNSET
        else:
            path_pattern = self.path_pattern

        tier: None | str | Unset
        if isinstance(self.tier, Unset):
            tier = UNSET
        elif isinstance(self.tier, RateLimitTier):
            tier = self.tier.value
        else:
            tier = self.tier

        api_key_id: None | str | Unset
        if isinstance(self.api_key_id, Unset):
            api_key_id = UNSET
        else:
            api_key_id = self.api_key_id

        requests_per_minute: int | None | Unset
        if isinstance(self.requests_per_minute, Unset):
            requests_per_minute = UNSET
        else:
            requests_per_minute = self.requests_per_minute

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if path_pattern is not UNSET:
            field_dict["path_pattern"] = path_pattern
        if tier is not UNSET:
            field_dict["tier"] = tier
        if api_key_id is not UNSET:
            field_dict["api_key_id"] = api_key_id
        if requests_per_minute is not UNSET:
            field_dict["requests_per_minute"] = requests_per_minute

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_path_pattern(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        path_pattern = _parse_path_pattern(d.pop("path_pattern", UNSET))

        def _parse_tier(data: object) -> None | RateLimitTier | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                tier_type_0 = RateLimitTier(data)

                return tier_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | RateLimitTier | Unset, data)

        tier = _parse_tier(d.pop("tier", UNSET))

        def _parse_api_key_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        api_key_id = _parse_api_key_id(d.pop("api_key_id", UNSET))

        def _parse_requests_per_minute(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        requests_per_minute = _parse_requests_per_minute(d.pop("requests_per_minute", UNSET))

        endpoint_config_update = cls(
            path_pattern=path_pattern,
            tier=tier,
            api_key_id=api_key_id,
            requests_per_minute=requests_per_minute,
        )

        endpoint_config_update.additional_properties = d
        return endpoint_config_update

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
