from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.dispatch_request_payload import DispatchRequestPayload


T = TypeVar("T", bound="DispatchRequest")


@_attrs_define
class DispatchRequest:
    """
    Attributes:
        org_id (str):
        event_type (str):
        payload (DispatchRequestPayload | Unset):
    """

    org_id: str
    event_type: str
    payload: DispatchRequestPayload | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        event_type = self.event_type

        payload: dict[str, Any] | Unset = UNSET
        if not isinstance(self.payload, Unset):
            payload = self.payload.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "event_type": event_type,
            }
        )
        if payload is not UNSET:
            field_dict["payload"] = payload

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.dispatch_request_payload import DispatchRequestPayload

        d = dict(src_dict)
        org_id = d.pop("org_id")

        event_type = d.pop("event_type")

        _payload = d.pop("payload", UNSET)
        payload: DispatchRequestPayload | Unset
        if isinstance(_payload, Unset):
            payload = UNSET
        else:
            payload = DispatchRequestPayload.from_dict(_payload)

        dispatch_request = cls(
            org_id=org_id,
            event_type=event_type,
            payload=payload,
        )

        dispatch_request.additional_properties = d
        return dispatch_request

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
