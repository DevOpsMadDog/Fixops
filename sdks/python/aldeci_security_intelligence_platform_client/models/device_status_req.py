from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="DeviceStatusReq")


@_attrs_define
class DeviceStatusReq:
    """
    Attributes:
        org_id (str):
        status (str):
        reason (str):
        updated_by (str):
    """

    org_id: str
    status: str
    reason: str
    updated_by: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        status = self.status

        reason = self.reason

        updated_by = self.updated_by

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "status": status,
                "reason": reason,
                "updated_by": updated_by,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        status = d.pop("status")

        reason = d.pop("reason")

        updated_by = d.pop("updated_by")

        device_status_req = cls(
            org_id=org_id,
            status=status,
            reason=reason,
            updated_by=updated_by,
        )

        device_status_req.additional_properties = d
        return device_status_req

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
