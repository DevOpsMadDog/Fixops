from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.compliance_assessment_response_controls_by_automation import (
        ComplianceAssessmentResponseControlsByAutomation,
    )
    from ..models.compliance_assessment_response_gaps_item import ComplianceAssessmentResponseGapsItem


T = TypeVar("T", bound="ComplianceAssessmentResponse")


@_attrs_define
class ComplianceAssessmentResponse:
    """Response model for compliance assessment.

    Attributes:
        framework (str):
        overall_score (int):
        total_controls (int):
        controls_by_automation (ComplianceAssessmentResponseControlsByAutomation):
        gaps (list[ComplianceAssessmentResponseGapsItem]):
        recommendations (list[str]):
    """

    framework: str
    overall_score: int
    total_controls: int
    controls_by_automation: ComplianceAssessmentResponseControlsByAutomation
    gaps: list[ComplianceAssessmentResponseGapsItem]
    recommendations: list[str]
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        framework = self.framework

        overall_score = self.overall_score

        total_controls = self.total_controls

        controls_by_automation = self.controls_by_automation.to_dict()

        gaps = []
        for gaps_item_data in self.gaps:
            gaps_item = gaps_item_data.to_dict()
            gaps.append(gaps_item)

        recommendations = self.recommendations

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "framework": framework,
                "overall_score": overall_score,
                "total_controls": total_controls,
                "controls_by_automation": controls_by_automation,
                "gaps": gaps,
                "recommendations": recommendations,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.compliance_assessment_response_controls_by_automation import (
            ComplianceAssessmentResponseControlsByAutomation,
        )
        from ..models.compliance_assessment_response_gaps_item import ComplianceAssessmentResponseGapsItem

        d = dict(src_dict)
        framework = d.pop("framework")

        overall_score = d.pop("overall_score")

        total_controls = d.pop("total_controls")

        controls_by_automation = ComplianceAssessmentResponseControlsByAutomation.from_dict(
            d.pop("controls_by_automation")
        )

        gaps = []
        _gaps = d.pop("gaps")
        for gaps_item_data in _gaps:
            gaps_item = ComplianceAssessmentResponseGapsItem.from_dict(gaps_item_data)

            gaps.append(gaps_item)

        recommendations = cast(list[str], d.pop("recommendations"))

        compliance_assessment_response = cls(
            framework=framework,
            overall_score=overall_score,
            total_controls=total_controls,
            controls_by_automation=controls_by_automation,
            gaps=gaps,
            recommendations=recommendations,
        )

        compliance_assessment_response.additional_properties = d
        return compliance_assessment_response

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
