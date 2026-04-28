from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.compliance_report_response_gaps_item import ComplianceReportResponseGapsItem


T = TypeVar("T", bound="ComplianceReportResponse")


@_attrs_define
class ComplianceReportResponse:
    """Compliance framework report.

    Attributes:
        framework (str):
        compliance_percent (float):
        total_controls (int):
        compliant_controls (int):
        gaps (list[ComplianceReportResponseGapsItem]):
        evidence_collected (int):
        audit_ready (bool):
    """

    framework: str
    compliance_percent: float
    total_controls: int
    compliant_controls: int
    gaps: list[ComplianceReportResponseGapsItem]
    evidence_collected: int
    audit_ready: bool
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        framework = self.framework

        compliance_percent = self.compliance_percent

        total_controls = self.total_controls

        compliant_controls = self.compliant_controls

        gaps = []
        for gaps_item_data in self.gaps:
            gaps_item = gaps_item_data.to_dict()
            gaps.append(gaps_item)

        evidence_collected = self.evidence_collected

        audit_ready = self.audit_ready

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "framework": framework,
                "compliance_percent": compliance_percent,
                "total_controls": total_controls,
                "compliant_controls": compliant_controls,
                "gaps": gaps,
                "evidence_collected": evidence_collected,
                "audit_ready": audit_ready,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.compliance_report_response_gaps_item import ComplianceReportResponseGapsItem

        d = dict(src_dict)
        framework = d.pop("framework")

        compliance_percent = d.pop("compliance_percent")

        total_controls = d.pop("total_controls")

        compliant_controls = d.pop("compliant_controls")

        gaps = []
        _gaps = d.pop("gaps")
        for gaps_item_data in _gaps:
            gaps_item = ComplianceReportResponseGapsItem.from_dict(gaps_item_data)

            gaps.append(gaps_item)

        evidence_collected = d.pop("evidence_collected")

        audit_ready = d.pop("audit_ready")

        compliance_report_response = cls(
            framework=framework,
            compliance_percent=compliance_percent,
            total_controls=total_controls,
            compliant_controls=compliant_controls,
            gaps=gaps,
            evidence_collected=evidence_collected,
            audit_ready=audit_ready,
        )

        compliance_report_response.additional_properties = d
        return compliance_report_response

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
