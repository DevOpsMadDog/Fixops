from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="UpdatePenTestConfigModel")


@_attrs_define
class UpdatePenTestConfigModel:
    """Model for updating MPTE configuration.

    Attributes:
        mpte_url (None | str | Unset):
        api_key (None | str | Unset):
        enabled (bool | None | Unset):
        max_concurrent_tests (int | None | Unset):
        timeout_seconds (int | None | Unset):
        auto_trigger (bool | None | Unset):
        target_environments (list[str] | None | Unset):
    """

    mpte_url: None | str | Unset = UNSET
    api_key: None | str | Unset = UNSET
    enabled: bool | None | Unset = UNSET
    max_concurrent_tests: int | None | Unset = UNSET
    timeout_seconds: int | None | Unset = UNSET
    auto_trigger: bool | None | Unset = UNSET
    target_environments: list[str] | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        mpte_url: None | str | Unset
        if isinstance(self.mpte_url, Unset):
            mpte_url = UNSET
        else:
            mpte_url = self.mpte_url

        api_key: None | str | Unset
        if isinstance(self.api_key, Unset):
            api_key = UNSET
        else:
            api_key = self.api_key

        enabled: bool | None | Unset
        if isinstance(self.enabled, Unset):
            enabled = UNSET
        else:
            enabled = self.enabled

        max_concurrent_tests: int | None | Unset
        if isinstance(self.max_concurrent_tests, Unset):
            max_concurrent_tests = UNSET
        else:
            max_concurrent_tests = self.max_concurrent_tests

        timeout_seconds: int | None | Unset
        if isinstance(self.timeout_seconds, Unset):
            timeout_seconds = UNSET
        else:
            timeout_seconds = self.timeout_seconds

        auto_trigger: bool | None | Unset
        if isinstance(self.auto_trigger, Unset):
            auto_trigger = UNSET
        else:
            auto_trigger = self.auto_trigger

        target_environments: list[str] | None | Unset
        if isinstance(self.target_environments, Unset):
            target_environments = UNSET
        elif isinstance(self.target_environments, list):
            target_environments = self.target_environments

        else:
            target_environments = self.target_environments

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if mpte_url is not UNSET:
            field_dict["mpte_url"] = mpte_url
        if api_key is not UNSET:
            field_dict["api_key"] = api_key
        if enabled is not UNSET:
            field_dict["enabled"] = enabled
        if max_concurrent_tests is not UNSET:
            field_dict["max_concurrent_tests"] = max_concurrent_tests
        if timeout_seconds is not UNSET:
            field_dict["timeout_seconds"] = timeout_seconds
        if auto_trigger is not UNSET:
            field_dict["auto_trigger"] = auto_trigger
        if target_environments is not UNSET:
            field_dict["target_environments"] = target_environments

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_mpte_url(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        mpte_url = _parse_mpte_url(d.pop("mpte_url", UNSET))

        def _parse_api_key(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        api_key = _parse_api_key(d.pop("api_key", UNSET))

        def _parse_enabled(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        enabled = _parse_enabled(d.pop("enabled", UNSET))

        def _parse_max_concurrent_tests(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        max_concurrent_tests = _parse_max_concurrent_tests(d.pop("max_concurrent_tests", UNSET))

        def _parse_timeout_seconds(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        timeout_seconds = _parse_timeout_seconds(d.pop("timeout_seconds", UNSET))

        def _parse_auto_trigger(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        auto_trigger = _parse_auto_trigger(d.pop("auto_trigger", UNSET))

        def _parse_target_environments(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                target_environments_type_0 = cast(list[str], data)

                return target_environments_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        target_environments = _parse_target_environments(d.pop("target_environments", UNSET))

        update_pen_test_config_model = cls(
            mpte_url=mpte_url,
            api_key=api_key,
            enabled=enabled,
            max_concurrent_tests=max_concurrent_tests,
            timeout_seconds=timeout_seconds,
            auto_trigger=auto_trigger,
            target_environments=target_environments,
        )

        update_pen_test_config_model.additional_properties = d
        return update_pen_test_config_model

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
