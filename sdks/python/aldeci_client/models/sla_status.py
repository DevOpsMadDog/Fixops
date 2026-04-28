from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.sla_status_by_severity import SLAStatusBySeverity


T = TypeVar("T", bound="SLAStatus")


@_attrs_define
class SLAStatus:
    """SLA compliance for findings.

    Attributes:
        total_findings (int):
        findings_within_sla (int):
        findings_breaching (int):
        sla_compliance_percent (float):
        by_severity (SLAStatusBySeverity):
        findings_at_risk (list[str]):
    """

    total_findings: int
    findings_within_sla: int
    findings_breaching: int
    sla_compliance_percent: float
    by_severity: SLAStatusBySeverity
    findings_at_risk: list[str]
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        total_findings = self.total_findings

        findings_within_sla = self.findings_within_sla

        findings_breaching = self.findings_breaching

        sla_compliance_percent = self.sla_compliance_percent

        by_severity = self.by_severity.to_dict()

        findings_at_risk = self.findings_at_risk

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "total_findings": total_findings,
                "findings_within_sla": findings_within_sla,
                "findings_breaching": findings_breaching,
                "sla_compliance_percent": sla_compliance_percent,
                "by_severity": by_severity,
                "findings_at_risk": findings_at_risk,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.sla_status_by_severity import SLAStatusBySeverity

        d = dict(src_dict)
        total_findings = d.pop("total_findings")

        findings_within_sla = d.pop("findings_within_sla")

        findings_breaching = d.pop("findings_breaching")

        sla_compliance_percent = d.pop("sla_compliance_percent")

        by_severity = SLAStatusBySeverity.from_dict(d.pop("by_severity"))

        findings_at_risk = cast(list[str], d.pop("findings_at_risk"))

        sla_status = cls(
            total_findings=total_findings,
            findings_within_sla=findings_within_sla,
            findings_breaching=findings_breaching,
            sla_compliance_percent=sla_compliance_percent,
            by_severity=by_severity,
            findings_at_risk=findings_at_risk,
        )

        sla_status.additional_properties = d
        return sla_status

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
