from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RenewRequestModel")


@_attrs_define
class RenewRequestModel:
    """
    Attributes:
        renewed_by (str):
        new_expiry (str):
        reason (str | Unset):  Default: ''.
        org_id (str | Unset):  Default: 'default'.
    """

    renewed_by: str
    new_expiry: str
    reason: str | Unset = ""
    org_id: str | Unset = "default"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        renewed_by = self.renewed_by

        new_expiry = self.new_expiry

        reason = self.reason

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "renewed_by": renewed_by,
                "new_expiry": new_expiry,
            }
        )
        if reason is not UNSET:
            field_dict["reason"] = reason
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        renewed_by = d.pop("renewed_by")

        new_expiry = d.pop("new_expiry")

        reason = d.pop("reason", UNSET)

        org_id = d.pop("org_id", UNSET)

        renew_request_model = cls(
            renewed_by=renewed_by,
            new_expiry=new_expiry,
            reason=reason,
            org_id=org_id,
        )

        renew_request_model.additional_properties = d
        return renew_request_model

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
