from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ThreatAssessmentRequest")


@_attrs_define
class ThreatAssessmentRequest:
    """Input for threat assessment.

    Attributes:
        method (str | Unset):  Default: 'GET'.
        path (str | Unset):  Default: '/'.
        client_ip (str | Unset):  Default: ''.
        status_code (int | Unset):  Default: 200.
        duration_ms (float | Unset):  Default: 100.0.
        user_agent (str | Unset):  Default: ''.
    """

    method: str | Unset = "GET"
    path: str | Unset = "/"
    client_ip: str | Unset = ""
    status_code: int | Unset = 200
    duration_ms: float | Unset = 100.0
    user_agent: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        method = self.method

        path = self.path

        client_ip = self.client_ip

        status_code = self.status_code

        duration_ms = self.duration_ms

        user_agent = self.user_agent

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if method is not UNSET:
            field_dict["method"] = method
        if path is not UNSET:
            field_dict["path"] = path
        if client_ip is not UNSET:
            field_dict["client_ip"] = client_ip
        if status_code is not UNSET:
            field_dict["status_code"] = status_code
        if duration_ms is not UNSET:
            field_dict["duration_ms"] = duration_ms
        if user_agent is not UNSET:
            field_dict["user_agent"] = user_agent

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        method = d.pop("method", UNSET)

        path = d.pop("path", UNSET)

        client_ip = d.pop("client_ip", UNSET)

        status_code = d.pop("status_code", UNSET)

        duration_ms = d.pop("duration_ms", UNSET)

        user_agent = d.pop("user_agent", UNSET)

        threat_assessment_request = cls(
            method=method,
            path=path,
            client_ip=client_ip,
            status_code=status_code,
            duration_ms=duration_ms,
            user_agent=user_agent,
        )

        threat_assessment_request.additional_properties = d
        return threat_assessment_request

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
