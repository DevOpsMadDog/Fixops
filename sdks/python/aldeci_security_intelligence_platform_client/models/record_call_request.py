from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RecordCallRequest")


@_attrs_define
class RecordCallRequest:
    """Request body for recording an API call.

    Attributes:
        endpoint (str):
        method (str):
        status_code (int):
        response_ms (float):
        api_key_id (None | str | Unset):
    """

    endpoint: str
    method: str
    status_code: int
    response_ms: float
    api_key_id: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        endpoint = self.endpoint

        method = self.method

        status_code = self.status_code

        response_ms = self.response_ms

        api_key_id: None | str | Unset
        if isinstance(self.api_key_id, Unset):
            api_key_id = UNSET
        else:
            api_key_id = self.api_key_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "endpoint": endpoint,
                "method": method,
                "status_code": status_code,
                "response_ms": response_ms,
            }
        )
        if api_key_id is not UNSET:
            field_dict["api_key_id"] = api_key_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        endpoint = d.pop("endpoint")

        method = d.pop("method")

        status_code = d.pop("status_code")

        response_ms = d.pop("response_ms")

        def _parse_api_key_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        api_key_id = _parse_api_key_id(d.pop("api_key_id", UNSET))

        record_call_request = cls(
            endpoint=endpoint,
            method=method,
            status_code=status_code,
            response_ms=response_ms,
            api_key_id=api_key_id,
        )

        record_call_request.additional_properties = d
        return record_call_request

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
