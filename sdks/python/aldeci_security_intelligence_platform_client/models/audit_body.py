from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="AuditBody")


@_attrs_define
class AuditBody:
    """
    Attributes:
        policy_id (str):
        users_audited (int):
        violations_found (int):
        compliance_rate (float):
    """

    policy_id: str
    users_audited: int
    violations_found: int
    compliance_rate: float
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        policy_id = self.policy_id

        users_audited = self.users_audited

        violations_found = self.violations_found

        compliance_rate = self.compliance_rate

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "policy_id": policy_id,
                "users_audited": users_audited,
                "violations_found": violations_found,
                "compliance_rate": compliance_rate,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        policy_id = d.pop("policy_id")

        users_audited = d.pop("users_audited")

        violations_found = d.pop("violations_found")

        compliance_rate = d.pop("compliance_rate")

        audit_body = cls(
            policy_id=policy_id,
            users_audited=users_audited,
            violations_found=violations_found,
            compliance_rate=compliance_rate,
        )

        audit_body.additional_properties = d
        return audit_body

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
