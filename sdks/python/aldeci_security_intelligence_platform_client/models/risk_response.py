from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="RiskResponse")


@_attrs_define
class RiskResponse:
    """
    Attributes:
        id (str):
        severity (str):
        type_ (str):
        principal (str):
        permission (str):
        resource (str):
        explanation (str):
        remediation (str):
        detected_at (str):
    """

    id: str
    severity: str
    type_: str
    principal: str
    permission: str
    resource: str
    explanation: str
    remediation: str
    detected_at: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        id = self.id

        severity = self.severity

        type_ = self.type_

        principal = self.principal

        permission = self.permission

        resource = self.resource

        explanation = self.explanation

        remediation = self.remediation

        detected_at = self.detected_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "id": id,
                "severity": severity,
                "type": type_,
                "principal": principal,
                "permission": permission,
                "resource": resource,
                "explanation": explanation,
                "remediation": remediation,
                "detected_at": detected_at,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        id = d.pop("id")

        severity = d.pop("severity")

        type_ = d.pop("type")

        principal = d.pop("principal")

        permission = d.pop("permission")

        resource = d.pop("resource")

        explanation = d.pop("explanation")

        remediation = d.pop("remediation")

        detected_at = d.pop("detected_at")

        risk_response = cls(
            id=id,
            severity=severity,
            type_=type_,
            principal=principal,
            permission=permission,
            resource=resource,
            explanation=explanation,
            remediation=remediation,
            detected_at=detected_at,
        )

        risk_response.additional_properties = d
        return risk_response

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
