from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="KPIResponse")


@_attrs_define
class KPIResponse:
    """Top-level KPI response.

    Attributes:
        mttd_minutes (float): Mean Time To Detect
        mttr_hours (float): Mean Time To Remediate
        false_positive_rate_percent (float): False Positive Rate
        findings_critical (int): Critical findings
        findings_high (int): High findings
        connector_uptime_percent (float): Connector uptime
        council_consensus_percent (float): LLM council consensus
        sla_compliance_percent (float): SLA compliance
    """

    mttd_minutes: float
    mttr_hours: float
    false_positive_rate_percent: float
    findings_critical: int
    findings_high: int
    connector_uptime_percent: float
    council_consensus_percent: float
    sla_compliance_percent: float
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        mttd_minutes = self.mttd_minutes

        mttr_hours = self.mttr_hours

        false_positive_rate_percent = self.false_positive_rate_percent

        findings_critical = self.findings_critical

        findings_high = self.findings_high

        connector_uptime_percent = self.connector_uptime_percent

        council_consensus_percent = self.council_consensus_percent

        sla_compliance_percent = self.sla_compliance_percent

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "mttd_minutes": mttd_minutes,
                "mttr_hours": mttr_hours,
                "false_positive_rate_percent": false_positive_rate_percent,
                "findings_critical": findings_critical,
                "findings_high": findings_high,
                "connector_uptime_percent": connector_uptime_percent,
                "council_consensus_percent": council_consensus_percent,
                "sla_compliance_percent": sla_compliance_percent,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        mttd_minutes = d.pop("mttd_minutes")

        mttr_hours = d.pop("mttr_hours")

        false_positive_rate_percent = d.pop("false_positive_rate_percent")

        findings_critical = d.pop("findings_critical")

        findings_high = d.pop("findings_high")

        connector_uptime_percent = d.pop("connector_uptime_percent")

        council_consensus_percent = d.pop("council_consensus_percent")

        sla_compliance_percent = d.pop("sla_compliance_percent")

        kpi_response = cls(
            mttd_minutes=mttd_minutes,
            mttr_hours=mttr_hours,
            false_positive_rate_percent=false_positive_rate_percent,
            findings_critical=findings_critical,
            findings_high=findings_high,
            connector_uptime_percent=connector_uptime_percent,
            council_consensus_percent=council_consensus_percent,
            sla_compliance_percent=sla_compliance_percent,
        )

        kpi_response.additional_properties = d
        return kpi_response

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
