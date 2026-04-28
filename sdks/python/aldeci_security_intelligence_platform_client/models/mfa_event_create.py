from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="MFAEventCreate")


@_attrs_define
class MFAEventCreate:
    """
    Attributes:
        user_id (str):
        event_type (str):
        success (bool):
        mfa_type (str | Unset):  Default: ''.
        ip_address (str | Unset):  Default: ''.
    """

    user_id: str
    event_type: str
    success: bool
    mfa_type: str | Unset = ""
    ip_address: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        user_id = self.user_id

        event_type = self.event_type

        success = self.success

        mfa_type = self.mfa_type

        ip_address = self.ip_address

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "user_id": user_id,
                "event_type": event_type,
                "success": success,
            }
        )
        if mfa_type is not UNSET:
            field_dict["mfa_type"] = mfa_type
        if ip_address is not UNSET:
            field_dict["ip_address"] = ip_address

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        user_id = d.pop("user_id")

        event_type = d.pop("event_type")

        success = d.pop("success")

        mfa_type = d.pop("mfa_type", UNSET)

        ip_address = d.pop("ip_address", UNSET)

        mfa_event_create = cls(
            user_id=user_id,
            event_type=event_type,
            success=success,
            mfa_type=mfa_type,
            ip_address=ip_address,
        )

        mfa_event_create.additional_properties = d
        return mfa_event_create

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
