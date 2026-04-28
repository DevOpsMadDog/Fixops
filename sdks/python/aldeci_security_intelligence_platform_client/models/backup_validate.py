from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="BackupValidate")


@_attrs_define
class BackupValidate:
    """
    Attributes:
        org_id (str):
        validation_status (str):
        recovery_time_mins (int | Unset):  Default: 0.
    """

    org_id: str
    validation_status: str
    recovery_time_mins: int | Unset = 0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        validation_status = self.validation_status

        recovery_time_mins = self.recovery_time_mins

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "validation_status": validation_status,
            }
        )
        if recovery_time_mins is not UNSET:
            field_dict["recovery_time_mins"] = recovery_time_mins

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        validation_status = d.pop("validation_status")

        recovery_time_mins = d.pop("recovery_time_mins", UNSET)

        backup_validate = cls(
            org_id=org_id,
            validation_status=validation_status,
            recovery_time_mins=recovery_time_mins,
        )

        backup_validate.additional_properties = d
        return backup_validate

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
