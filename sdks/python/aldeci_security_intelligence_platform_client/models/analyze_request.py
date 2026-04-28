from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AnalyzeRequest")


@_attrs_define
class AnalyzeRequest:
    """
    Attributes:
        prompt (str | Unset):  Default: ''.
        response (str | Unset):  Default: ''.
        model (str | Unset):  Default: 'unknown'.
        max_tokens (int | Unset):  Default: 0.
    """

    prompt: str | Unset = ""
    response: str | Unset = ""
    model: str | Unset = "unknown"
    max_tokens: int | Unset = 0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        prompt = self.prompt

        response = self.response

        model = self.model

        max_tokens = self.max_tokens

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if prompt is not UNSET:
            field_dict["prompt"] = prompt
        if response is not UNSET:
            field_dict["response"] = response
        if model is not UNSET:
            field_dict["model"] = model
        if max_tokens is not UNSET:
            field_dict["max_tokens"] = max_tokens

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        prompt = d.pop("prompt", UNSET)

        response = d.pop("response", UNSET)

        model = d.pop("model", UNSET)

        max_tokens = d.pop("max_tokens", UNSET)

        analyze_request = cls(
            prompt=prompt,
            response=response,
            model=model,
            max_tokens=max_tokens,
        )

        analyze_request.additional_properties = d
        return analyze_request

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
