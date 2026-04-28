from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="ComplianceControlResponse")


@_attrs_define
class ComplianceControlResponse:
    """Response model for a compliance control.

    Attributes:
        control_id (str):
        framework (str):
        title (str):
        description (str):
        requirements (list[str]):
        evidence_types (list[str]):
        automation_level (str):
    """

    control_id: str
    framework: str
    title: str
    description: str
    requirements: list[str]
    evidence_types: list[str]
    automation_level: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        control_id = self.control_id

        framework = self.framework

        title = self.title

        description = self.description

        requirements = self.requirements

        evidence_types = self.evidence_types

        automation_level = self.automation_level

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "control_id": control_id,
                "framework": framework,
                "title": title,
                "description": description,
                "requirements": requirements,
                "evidence_types": evidence_types,
                "automation_level": automation_level,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        control_id = d.pop("control_id")

        framework = d.pop("framework")

        title = d.pop("title")

        description = d.pop("description")

        requirements = cast(list[str], d.pop("requirements"))

        evidence_types = cast(list[str], d.pop("evidence_types"))

        automation_level = d.pop("automation_level")

        compliance_control_response = cls(
            control_id=control_id,
            framework=framework,
            title=title,
            description=description,
            requirements=requirements,
            evidence_types=evidence_types,
            automation_level=automation_level,
        )

        compliance_control_response.additional_properties = d
        return compliance_control_response

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
