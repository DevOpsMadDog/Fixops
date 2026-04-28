from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="LLMSettings")


@_attrs_define
class LLMSettings:
    """Current LLM settings.

    Attributes:
        default_provider (str):
        timeout_seconds (int):
        max_tokens (int):
        temperature (float):
    """

    default_provider: str
    timeout_seconds: int
    max_tokens: int
    temperature: float
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        default_provider = self.default_provider

        timeout_seconds = self.timeout_seconds

        max_tokens = self.max_tokens

        temperature = self.temperature

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "default_provider": default_provider,
                "timeout_seconds": timeout_seconds,
                "max_tokens": max_tokens,
                "temperature": temperature,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        default_provider = d.pop("default_provider")

        timeout_seconds = d.pop("timeout_seconds")

        max_tokens = d.pop("max_tokens")

        temperature = d.pop("temperature")

        llm_settings = cls(
            default_provider=default_provider,
            timeout_seconds=timeout_seconds,
            max_tokens=max_tokens,
            temperature=temperature,
        )

        llm_settings.additional_properties = d
        return llm_settings

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
