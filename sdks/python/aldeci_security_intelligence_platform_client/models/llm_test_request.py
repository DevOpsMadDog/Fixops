from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="LLMTestRequest")


@_attrs_define
class LLMTestRequest:
    """Request to test an LLM provider.

    Attributes:
        provider (str): Provider name: openai, anthropic, google
        prompt (str | Unset): Test prompt to send Default: "Hello, respond with 'LLM is working' to confirm
            connectivity.".
    """

    provider: str
    prompt: str | Unset = "Hello, respond with 'LLM is working' to confirm connectivity."
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        provider = self.provider

        prompt = self.prompt

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "provider": provider,
            }
        )
        if prompt is not UNSET:
            field_dict["prompt"] = prompt

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        provider = d.pop("provider")

        prompt = d.pop("prompt", UNSET)

        llm_test_request = cls(
            provider=provider,
            prompt=prompt,
        )

        llm_test_request.additional_properties = d
        return llm_test_request

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
