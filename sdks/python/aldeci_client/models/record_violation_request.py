from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RecordViolationRequest")


@_attrs_define
class RecordViolationRequest:
    """
    Attributes:
        policy_id (str): ID of the violated policy
        user (str): User who triggered the violation
        app_name (str): App involved in the violation
        org_id (str | Unset): Organisation ID Default: 'default'.
        violation_detail (str | Unset): Detailed description of violation Default: ''.
        severity (str | Unset): Severity: critical/high/medium/low/info Default: 'medium'.
    """

    policy_id: str
    user: str
    app_name: str
    org_id: str | Unset = "default"
    violation_detail: str | Unset = ""
    severity: str | Unset = "medium"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        policy_id = self.policy_id

        user = self.user

        app_name = self.app_name

        org_id = self.org_id

        violation_detail = self.violation_detail

        severity = self.severity

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "policy_id": policy_id,
                "user": user,
                "app_name": app_name,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if violation_detail is not UNSET:
            field_dict["violation_detail"] = violation_detail
        if severity is not UNSET:
            field_dict["severity"] = severity

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        policy_id = d.pop("policy_id")

        user = d.pop("user")

        app_name = d.pop("app_name")

        org_id = d.pop("org_id", UNSET)

        violation_detail = d.pop("violation_detail", UNSET)

        severity = d.pop("severity", UNSET)

        record_violation_request = cls(
            policy_id=policy_id,
            user=user,
            app_name=app_name,
            org_id=org_id,
            violation_detail=violation_detail,
            severity=severity,
        )

        record_violation_request.additional_properties = d
        return record_violation_request

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
