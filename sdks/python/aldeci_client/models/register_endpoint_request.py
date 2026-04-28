from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RegisterEndpointRequest")


@_attrs_define
class RegisterEndpointRequest:
    """
    Attributes:
        path (str):
        method (str):
        service_name (str | Unset):  Default: ''.
        rate_limit (int | Unset):  Default: 1000.
        abuse_score (float | Unset):  Default: 0.0.
        status (str | Unset):  Default: 'monitored'.
    """

    path: str
    method: str
    service_name: str | Unset = ""
    rate_limit: int | Unset = 1000
    abuse_score: float | Unset = 0.0
    status: str | Unset = "monitored"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        path = self.path

        method = self.method

        service_name = self.service_name

        rate_limit = self.rate_limit

        abuse_score = self.abuse_score

        status = self.status

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "path": path,
                "method": method,
            }
        )
        if service_name is not UNSET:
            field_dict["service_name"] = service_name
        if rate_limit is not UNSET:
            field_dict["rate_limit"] = rate_limit
        if abuse_score is not UNSET:
            field_dict["abuse_score"] = abuse_score
        if status is not UNSET:
            field_dict["status"] = status

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        path = d.pop("path")

        method = d.pop("method")

        service_name = d.pop("service_name", UNSET)

        rate_limit = d.pop("rate_limit", UNSET)

        abuse_score = d.pop("abuse_score", UNSET)

        status = d.pop("status", UNSET)

        register_endpoint_request = cls(
            path=path,
            method=method,
            service_name=service_name,
            rate_limit=rate_limit,
            abuse_score=abuse_score,
            status=status,
        )

        register_endpoint_request.additional_properties = d
        return register_endpoint_request

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
