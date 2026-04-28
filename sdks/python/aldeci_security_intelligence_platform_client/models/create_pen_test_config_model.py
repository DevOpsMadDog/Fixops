from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CreatePenTestConfigModel")


@_attrs_define
class CreatePenTestConfigModel:
    """Model for creating MPTE configuration.

    Attributes:
        name (str):
        mpte_url (str):
        api_key (None | str | Unset):
        enabled (bool | Unset):  Default: True.
        max_concurrent_tests (int | Unset):  Default: 5.
        timeout_seconds (int | Unset):  Default: 300.
        auto_trigger (bool | Unset):  Default: False.
        target_environments (list[str] | Unset):
    """

    name: str
    mpte_url: str
    api_key: None | str | Unset = UNSET
    enabled: bool | Unset = True
    max_concurrent_tests: int | Unset = 5
    timeout_seconds: int | Unset = 300
    auto_trigger: bool | Unset = False
    target_environments: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        mpte_url = self.mpte_url

        api_key: None | str | Unset
        if isinstance(self.api_key, Unset):
            api_key = UNSET
        else:
            api_key = self.api_key

        enabled = self.enabled

        max_concurrent_tests = self.max_concurrent_tests

        timeout_seconds = self.timeout_seconds

        auto_trigger = self.auto_trigger

        target_environments: list[str] | Unset = UNSET
        if not isinstance(self.target_environments, Unset):
            target_environments = self.target_environments

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
                "mpte_url": mpte_url,
            }
        )
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
        name = d.pop("name")

        mpte_url = d.pop("mpte_url")

        def _parse_api_key(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        api_key = _parse_api_key(d.pop("api_key", UNSET))

        enabled = d.pop("enabled", UNSET)

        max_concurrent_tests = d.pop("max_concurrent_tests", UNSET)

        timeout_seconds = d.pop("timeout_seconds", UNSET)

        auto_trigger = d.pop("auto_trigger", UNSET)

        target_environments = cast(list[str], d.pop("target_environments", UNSET))

        create_pen_test_config_model = cls(
            name=name,
            mpte_url=mpte_url,
            api_key=api_key,
            enabled=enabled,
            max_concurrent_tests=max_concurrent_tests,
            timeout_seconds=timeout_seconds,
            auto_trigger=auto_trigger,
            target_environments=target_environments,
        )

        create_pen_test_config_model.additional_properties = d
        return create_pen_test_config_model

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
