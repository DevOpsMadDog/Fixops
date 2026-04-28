from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RuntimeEventCreate")


@_attrs_define
class RuntimeEventCreate:
    """
    Attributes:
        org_id (str):
        event_ref (str):
        event_type (str):
        service_name (str | Unset):  Default: ''.
        path (str | Unset):  Default: ''.
        method (str | Unset):  Default: ''.
        status_code (int | Unset):  Default: 0.
        error_message (str | Unset):  Default: ''.
        stack_trace (str | Unset):  Default: ''.
    """

    org_id: str
    event_ref: str
    event_type: str
    service_name: str | Unset = ""
    path: str | Unset = ""
    method: str | Unset = ""
    status_code: int | Unset = 0
    error_message: str | Unset = ""
    stack_trace: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        event_ref = self.event_ref

        event_type = self.event_type

        service_name = self.service_name

        path = self.path

        method = self.method

        status_code = self.status_code

        error_message = self.error_message

        stack_trace = self.stack_trace

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "event_ref": event_ref,
                "event_type": event_type,
            }
        )
        if service_name is not UNSET:
            field_dict["service_name"] = service_name
        if path is not UNSET:
            field_dict["path"] = path
        if method is not UNSET:
            field_dict["method"] = method
        if status_code is not UNSET:
            field_dict["status_code"] = status_code
        if error_message is not UNSET:
            field_dict["error_message"] = error_message
        if stack_trace is not UNSET:
            field_dict["stack_trace"] = stack_trace

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        event_ref = d.pop("event_ref")

        event_type = d.pop("event_type")

        service_name = d.pop("service_name", UNSET)

        path = d.pop("path", UNSET)

        method = d.pop("method", UNSET)

        status_code = d.pop("status_code", UNSET)

        error_message = d.pop("error_message", UNSET)

        stack_trace = d.pop("stack_trace", UNSET)

        runtime_event_create = cls(
            org_id=org_id,
            event_ref=event_ref,
            event_type=event_type,
            service_name=service_name,
            path=path,
            method=method,
            status_code=status_code,
            error_message=error_message,
            stack_trace=stack_trace,
        )

        runtime_event_create.additional_properties = d
        return runtime_event_create

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
