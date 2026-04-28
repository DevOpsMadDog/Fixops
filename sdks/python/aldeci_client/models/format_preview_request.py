from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="FormatPreviewRequest")


@_attrs_define
class FormatPreviewRequest:
    """
    Attributes:
        event_type (str | Unset):  Default: 'scan.completed'.
        severity (str | Unset):  Default: 'medium'.
        message (str | Unset):  Default: 'Vulnerability scan completed with 5 findings'.
        format_ (str | Unset): cef, leef, json Default: 'cef'.
    """

    event_type: str | Unset = "scan.completed"
    severity: str | Unset = "medium"
    message: str | Unset = "Vulnerability scan completed with 5 findings"
    format_: str | Unset = "cef"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        event_type = self.event_type

        severity = self.severity

        message = self.message

        format_ = self.format_

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if event_type is not UNSET:
            field_dict["event_type"] = event_type
        if severity is not UNSET:
            field_dict["severity"] = severity
        if message is not UNSET:
            field_dict["message"] = message
        if format_ is not UNSET:
            field_dict["format"] = format_

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        event_type = d.pop("event_type", UNSET)

        severity = d.pop("severity", UNSET)

        message = d.pop("message", UNSET)

        format_ = d.pop("format", UNSET)

        format_preview_request = cls(
            event_type=event_type,
            severity=severity,
            message=message,
            format_=format_,
        )

        format_preview_request.additional_properties = d
        return format_preview_request

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
