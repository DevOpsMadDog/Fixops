from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ViolationBody")


@_attrs_define
class ViolationBody:
    """
    Attributes:
        policy_id (str):
        user_id (str):
        violation_type (str):
        severity (str | Unset):  Default: 'medium'.
        status (str | Unset):  Default: 'open'.
    """

    policy_id: str
    user_id: str
    violation_type: str
    severity: str | Unset = "medium"
    status: str | Unset = "open"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        policy_id = self.policy_id

        user_id = self.user_id

        violation_type = self.violation_type

        severity = self.severity

        status = self.status

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "policy_id": policy_id,
                "user_id": user_id,
                "violation_type": violation_type,
            }
        )
        if severity is not UNSET:
            field_dict["severity"] = severity
        if status is not UNSET:
            field_dict["status"] = status

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        policy_id = d.pop("policy_id")

        user_id = d.pop("user_id")

        violation_type = d.pop("violation_type")

        severity = d.pop("severity", UNSET)

        status = d.pop("status", UNSET)

        violation_body = cls(
            policy_id=policy_id,
            user_id=user_id,
            violation_type=violation_type,
            severity=severity,
            status=status,
        )

        violation_body.additional_properties = d
        return violation_body

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
