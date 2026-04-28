from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.test_event_request_payload import TestEventRequestPayload


T = TypeVar("T", bound="TestEventRequest")


@_attrs_define
class TestEventRequest:
    """
    Attributes:
        severity (str | Unset):  Default: 'info'.
        payload (TestEventRequestPayload | Unset):
    """

    severity: str | Unset = "info"
    payload: TestEventRequestPayload | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        severity = self.severity

        payload: dict[str, Any] | Unset = UNSET
        if not isinstance(self.payload, Unset):
            payload = self.payload.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if severity is not UNSET:
            field_dict["severity"] = severity
        if payload is not UNSET:
            field_dict["payload"] = payload

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.test_event_request_payload import TestEventRequestPayload

        d = dict(src_dict)
        severity = d.pop("severity", UNSET)

        _payload = d.pop("payload", UNSET)
        payload: TestEventRequestPayload | Unset
        if isinstance(_payload, Unset):
            payload = UNSET
        else:
            payload = TestEventRequestPayload.from_dict(_payload)

        test_event_request = cls(
            severity=severity,
            payload=payload,
        )

        test_event_request.additional_properties = d
        return test_event_request

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
