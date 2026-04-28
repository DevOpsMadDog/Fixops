from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="LLMProviderStatus")


@_attrs_define
class LLMProviderStatus:
    """Status of an LLM provider.

    Attributes:
        name (str):
        enabled (bool):
        configured (bool):
        api_key_set (bool):
        model (str):
        status (str):
        error (None | str | Unset):
    """

    name: str
    enabled: bool
    configured: bool
    api_key_set: bool
    model: str
    status: str
    error: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        enabled = self.enabled

        configured = self.configured

        api_key_set = self.api_key_set

        model = self.model

        status = self.status

        error: None | str | Unset
        if isinstance(self.error, Unset):
            error = UNSET
        else:
            error = self.error

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
                "enabled": enabled,
                "configured": configured,
                "api_key_set": api_key_set,
                "model": model,
                "status": status,
            }
        )
        if error is not UNSET:
            field_dict["error"] = error

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        enabled = d.pop("enabled")

        configured = d.pop("configured")

        api_key_set = d.pop("api_key_set")

        model = d.pop("model")

        status = d.pop("status")

        def _parse_error(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        error = _parse_error(d.pop("error", UNSET))

        llm_provider_status = cls(
            name=name,
            enabled=enabled,
            configured=configured,
            api_key_set=api_key_set,
            model=model,
            status=status,
            error=error,
        )

        llm_provider_status.additional_properties = d
        return llm_provider_status

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
