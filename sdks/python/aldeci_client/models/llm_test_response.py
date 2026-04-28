from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="LLMTestResponse")


@_attrs_define
class LLMTestResponse:
    """Response from LLM test.

    Attributes:
        success (bool):
        provider (str):
        response (None | str | Unset):
        latency_ms (float | None | Unset):
        error (None | str | Unset):
    """

    success: bool
    provider: str
    response: None | str | Unset = UNSET
    latency_ms: float | None | Unset = UNSET
    error: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        success = self.success

        provider = self.provider

        response: None | str | Unset
        if isinstance(self.response, Unset):
            response = UNSET
        else:
            response = self.response

        latency_ms: float | None | Unset
        if isinstance(self.latency_ms, Unset):
            latency_ms = UNSET
        else:
            latency_ms = self.latency_ms

        error: None | str | Unset
        if isinstance(self.error, Unset):
            error = UNSET
        else:
            error = self.error

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "success": success,
                "provider": provider,
            }
        )
        if response is not UNSET:
            field_dict["response"] = response
        if latency_ms is not UNSET:
            field_dict["latency_ms"] = latency_ms
        if error is not UNSET:
            field_dict["error"] = error

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        success = d.pop("success")

        provider = d.pop("provider")

        def _parse_response(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        response = _parse_response(d.pop("response", UNSET))

        def _parse_latency_ms(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        latency_ms = _parse_latency_ms(d.pop("latency_ms", UNSET))

        def _parse_error(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        error = _parse_error(d.pop("error", UNSET))

        llm_test_response = cls(
            success=success,
            provider=provider,
            response=response,
            latency_ms=latency_ms,
            error=error,
        )

        llm_test_response.additional_properties = d
        return llm_test_response

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
