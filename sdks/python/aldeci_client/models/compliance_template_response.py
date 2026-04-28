from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="ComplianceTemplateResponse")


@_attrs_define
class ComplianceTemplateResponse:
    """Response model for compliance template list.

    Attributes:
        template_id (str):
        name (str):
        description (str):
        framework (str):
        status (str):
    """

    template_id: str
    name: str
    description: str
    framework: str
    status: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        template_id = self.template_id

        name = self.name

        description = self.description

        framework = self.framework

        status = self.status

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "template_id": template_id,
                "name": name,
                "description": description,
                "framework": framework,
                "status": status,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        template_id = d.pop("template_id")

        name = d.pop("name")

        description = d.pop("description")

        framework = d.pop("framework")

        status = d.pop("status")

        compliance_template_response = cls(
            template_id=template_id,
            name=name,
            description=description,
            framework=framework,
            status=status,
        )

        compliance_template_response.additional_properties = d
        return compliance_template_response

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
