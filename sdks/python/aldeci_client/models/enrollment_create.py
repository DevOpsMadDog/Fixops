from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="EnrollmentCreate")


@_attrs_define
class EnrollmentCreate:
    """
    Attributes:
        user_id (str):
        mfa_type (str):
        backup_codes_count (int | Unset):  Default: 0.
    """

    user_id: str
    mfa_type: str
    backup_codes_count: int | Unset = 0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        user_id = self.user_id

        mfa_type = self.mfa_type

        backup_codes_count = self.backup_codes_count

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "user_id": user_id,
                "mfa_type": mfa_type,
            }
        )
        if backup_codes_count is not UNSET:
            field_dict["backup_codes_count"] = backup_codes_count

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        user_id = d.pop("user_id")

        mfa_type = d.pop("mfa_type")

        backup_codes_count = d.pop("backup_codes_count", UNSET)

        enrollment_create = cls(
            user_id=user_id,
            mfa_type=mfa_type,
            backup_codes_count=backup_codes_count,
        )

        enrollment_create.additional_properties = d
        return enrollment_create

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
