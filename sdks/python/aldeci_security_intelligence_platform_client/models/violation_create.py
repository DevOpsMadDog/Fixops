from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ViolationCreate")


@_attrs_define
class ViolationCreate:
    """
    Attributes:
        policy_id (str):
        resource_id (str):
        resource_type (str):
        violation_details (str | Unset):  Default: ''.
        severity (str | Unset): low/medium/high/critical Default: 'medium'.
    """

    policy_id: str
    resource_id: str
    resource_type: str
    violation_details: str | Unset = ""
    severity: str | Unset = "medium"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        policy_id = self.policy_id

        resource_id = self.resource_id

        resource_type = self.resource_type

        violation_details = self.violation_details

        severity = self.severity

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "policy_id": policy_id,
                "resource_id": resource_id,
                "resource_type": resource_type,
            }
        )
        if violation_details is not UNSET:
            field_dict["violation_details"] = violation_details
        if severity is not UNSET:
            field_dict["severity"] = severity

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        policy_id = d.pop("policy_id")

        resource_id = d.pop("resource_id")

        resource_type = d.pop("resource_type")

        violation_details = d.pop("violation_details", UNSET)

        severity = d.pop("severity", UNSET)

        violation_create = cls(
            policy_id=policy_id,
            resource_id=resource_id,
            resource_type=resource_type,
            violation_details=violation_details,
            severity=severity,
        )

        violation_create.additional_properties = d
        return violation_create

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
