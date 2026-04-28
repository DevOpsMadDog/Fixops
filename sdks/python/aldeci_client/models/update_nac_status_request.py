from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="UpdateNacStatusRequest")


@_attrs_define
class UpdateNacStatusRequest:
    """
    Attributes:
        nac_status (str): allowed/restricted/quarantined/blocked
        org_id (str | Unset):  Default: 'default'.
        reason (str | Unset):  Default: ''.
    """

    nac_status: str
    org_id: str | Unset = "default"
    reason: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        nac_status = self.nac_status

        org_id = self.org_id

        reason = self.reason

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "nac_status": nac_status,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if reason is not UNSET:
            field_dict["reason"] = reason

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        nac_status = d.pop("nac_status")

        org_id = d.pop("org_id", UNSET)

        reason = d.pop("reason", UNSET)

        update_nac_status_request = cls(
            nac_status=nac_status,
            org_id=org_id,
            reason=reason,
        )

        update_nac_status_request.additional_properties = d
        return update_nac_status_request

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
