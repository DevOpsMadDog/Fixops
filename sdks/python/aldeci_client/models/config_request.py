from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ConfigRequest")


@_attrs_define
class ConfigRequest:
    """
    Attributes:
        enabled (bool | None | Unset): Master enable/disable switch
        enable_event_types (list[str] | None | Unset): Event types to enable
        disable_event_types (list[str] | None | Unset): Event types to disable
    """

    enabled: bool | None | Unset = UNSET
    enable_event_types: list[str] | None | Unset = UNSET
    disable_event_types: list[str] | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        enabled: bool | None | Unset
        if isinstance(self.enabled, Unset):
            enabled = UNSET
        else:
            enabled = self.enabled

        enable_event_types: list[str] | None | Unset
        if isinstance(self.enable_event_types, Unset):
            enable_event_types = UNSET
        elif isinstance(self.enable_event_types, list):
            enable_event_types = self.enable_event_types

        else:
            enable_event_types = self.enable_event_types

        disable_event_types: list[str] | None | Unset
        if isinstance(self.disable_event_types, Unset):
            disable_event_types = UNSET
        elif isinstance(self.disable_event_types, list):
            disable_event_types = self.disable_event_types

        else:
            disable_event_types = self.disable_event_types

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if enabled is not UNSET:
            field_dict["enabled"] = enabled
        if enable_event_types is not UNSET:
            field_dict["enable_event_types"] = enable_event_types
        if disable_event_types is not UNSET:
            field_dict["disable_event_types"] = disable_event_types

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_enabled(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        enabled = _parse_enabled(d.pop("enabled", UNSET))

        def _parse_enable_event_types(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                enable_event_types_type_0 = cast(list[str], data)

                return enable_event_types_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        enable_event_types = _parse_enable_event_types(d.pop("enable_event_types", UNSET))

        def _parse_disable_event_types(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                disable_event_types_type_0 = cast(list[str], data)

                return disable_event_types_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        disable_event_types = _parse_disable_event_types(d.pop("disable_event_types", UNSET))

        config_request = cls(
            enabled=enabled,
            enable_event_types=enable_event_types,
            disable_event_types=disable_event_types,
        )

        config_request.additional_properties = d
        return config_request

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
