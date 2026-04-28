from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.rasp_mode import RaspMode
from ..models.threat_category import ThreatCategory
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.rate_limit_config import RateLimitConfig


T = TypeVar("T", bound="RaspConfig")


@_attrs_define
class RaspConfig:
    """Full RASP engine configuration.

    Attributes:
        mode (RaspMode | Unset): Operating mode for the RASP engine.
        honeypot_url (str | Unset):  Default: 'http://honeypot.internal/trap'.
        rate_limit (RateLimitConfig | Unset): Rate limiting configuration.
        max_body_inspect_bytes (int | Unset):  Default: 65536.
        inspect_request_body (bool | Unset):  Default: True.
        inspect_headers (bool | Unset):  Default: True.
        inspect_query_params (bool | Unset):  Default: True.
        trusted_ips (list[str] | Unset):
        enabled_categories (list[ThreatCategory] | Unset):
    """

    mode: RaspMode | Unset = UNSET
    honeypot_url: str | Unset = "http://honeypot.internal/trap"
    rate_limit: RateLimitConfig | Unset = UNSET
    max_body_inspect_bytes: int | Unset = 65536
    inspect_request_body: bool | Unset = True
    inspect_headers: bool | Unset = True
    inspect_query_params: bool | Unset = True
    trusted_ips: list[str] | Unset = UNSET
    enabled_categories: list[ThreatCategory] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        mode: str | Unset = UNSET
        if not isinstance(self.mode, Unset):
            mode = self.mode.value

        honeypot_url = self.honeypot_url

        rate_limit: dict[str, Any] | Unset = UNSET
        if not isinstance(self.rate_limit, Unset):
            rate_limit = self.rate_limit.to_dict()

        max_body_inspect_bytes = self.max_body_inspect_bytes

        inspect_request_body = self.inspect_request_body

        inspect_headers = self.inspect_headers

        inspect_query_params = self.inspect_query_params

        trusted_ips: list[str] | Unset = UNSET
        if not isinstance(self.trusted_ips, Unset):
            trusted_ips = self.trusted_ips

        enabled_categories: list[str] | Unset = UNSET
        if not isinstance(self.enabled_categories, Unset):
            enabled_categories = []
            for enabled_categories_item_data in self.enabled_categories:
                enabled_categories_item = enabled_categories_item_data.value
                enabled_categories.append(enabled_categories_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if mode is not UNSET:
            field_dict["mode"] = mode
        if honeypot_url is not UNSET:
            field_dict["honeypot_url"] = honeypot_url
        if rate_limit is not UNSET:
            field_dict["rate_limit"] = rate_limit
        if max_body_inspect_bytes is not UNSET:
            field_dict["max_body_inspect_bytes"] = max_body_inspect_bytes
        if inspect_request_body is not UNSET:
            field_dict["inspect_request_body"] = inspect_request_body
        if inspect_headers is not UNSET:
            field_dict["inspect_headers"] = inspect_headers
        if inspect_query_params is not UNSET:
            field_dict["inspect_query_params"] = inspect_query_params
        if trusted_ips is not UNSET:
            field_dict["trusted_ips"] = trusted_ips
        if enabled_categories is not UNSET:
            field_dict["enabled_categories"] = enabled_categories

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.rate_limit_config import RateLimitConfig

        d = dict(src_dict)
        _mode = d.pop("mode", UNSET)
        mode: RaspMode | Unset
        if isinstance(_mode, Unset):
            mode = UNSET
        else:
            mode = RaspMode(_mode)

        honeypot_url = d.pop("honeypot_url", UNSET)

        _rate_limit = d.pop("rate_limit", UNSET)
        rate_limit: RateLimitConfig | Unset
        if isinstance(_rate_limit, Unset):
            rate_limit = UNSET
        else:
            rate_limit = RateLimitConfig.from_dict(_rate_limit)

        max_body_inspect_bytes = d.pop("max_body_inspect_bytes", UNSET)

        inspect_request_body = d.pop("inspect_request_body", UNSET)

        inspect_headers = d.pop("inspect_headers", UNSET)

        inspect_query_params = d.pop("inspect_query_params", UNSET)

        trusted_ips = cast(list[str], d.pop("trusted_ips", UNSET))

        _enabled_categories = d.pop("enabled_categories", UNSET)
        enabled_categories: list[ThreatCategory] | Unset = UNSET
        if _enabled_categories is not UNSET:
            enabled_categories = []
            for enabled_categories_item_data in _enabled_categories:
                enabled_categories_item = ThreatCategory(enabled_categories_item_data)

                enabled_categories.append(enabled_categories_item)

        rasp_config = cls(
            mode=mode,
            honeypot_url=honeypot_url,
            rate_limit=rate_limit,
            max_body_inspect_bytes=max_body_inspect_bytes,
            inspect_request_body=inspect_request_body,
            inspect_headers=inspect_headers,
            inspect_query_params=inspect_query_params,
            trusted_ips=trusted_ips,
            enabled_categories=enabled_categories,
        )

        rasp_config.additional_properties = d
        return rasp_config

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
