from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CreateAssessmentRequest")


@_attrs_define
class CreateAssessmentRequest:
    """
    Attributes:
        framework (str): SOC2|ISO27001|NIST|PCI-DSS|HIPAA|GDPR|CIS
        assessment_name (str): Name of the assessment
        total_controls (int | Unset): Expected control count Default: 0.
    """

    framework: str
    assessment_name: str
    total_controls: int | Unset = 0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        framework = self.framework

        assessment_name = self.assessment_name

        total_controls = self.total_controls

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "framework": framework,
                "assessment_name": assessment_name,
            }
        )
        if total_controls is not UNSET:
            field_dict["total_controls"] = total_controls

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        framework = d.pop("framework")

        assessment_name = d.pop("assessment_name")

        total_controls = d.pop("total_controls", UNSET)

        create_assessment_request = cls(
            framework=framework,
            assessment_name=assessment_name,
            total_controls=total_controls,
        )

        create_assessment_request.additional_properties = d
        return create_assessment_request

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
