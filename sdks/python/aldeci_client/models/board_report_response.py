from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

if TYPE_CHECKING:
    from ..models.board_report_response_compliance_summary import BoardReportResponseComplianceSummary
    from ..models.board_report_response_kpi_summary import BoardReportResponseKpiSummary
    from ..models.board_report_response_top_5_risks_item import BoardReportResponseTop5RisksItem


T = TypeVar("T", bound="BoardReportResponse")


@_attrs_define
class BoardReportResponse:
    """Board-level executive risk report.

    Attributes:
        org_id (str):
        report_period (str):
        risk_headline_usd (float):
        risk_trend (str):
        top_5_risks (list[BoardReportResponseTop5RisksItem]):
        compliance_summary (BoardReportResponseComplianceSummary):
        kpi_summary (BoardReportResponseKpiSummary):
        qoq_delta_pct (float):
        action_items (list[str]):
        generated_at (datetime.datetime):
    """

    org_id: str
    report_period: str
    risk_headline_usd: float
    risk_trend: str
    top_5_risks: list[BoardReportResponseTop5RisksItem]
    compliance_summary: BoardReportResponseComplianceSummary
    kpi_summary: BoardReportResponseKpiSummary
    qoq_delta_pct: float
    action_items: list[str]
    generated_at: datetime.datetime
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        report_period = self.report_period

        risk_headline_usd = self.risk_headline_usd

        risk_trend = self.risk_trend

        top_5_risks = []
        for top_5_risks_item_data in self.top_5_risks:
            top_5_risks_item = top_5_risks_item_data.to_dict()
            top_5_risks.append(top_5_risks_item)

        compliance_summary = self.compliance_summary.to_dict()

        kpi_summary = self.kpi_summary.to_dict()

        qoq_delta_pct = self.qoq_delta_pct

        action_items = self.action_items

        generated_at = self.generated_at.isoformat()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "report_period": report_period,
                "risk_headline_usd": risk_headline_usd,
                "risk_trend": risk_trend,
                "top_5_risks": top_5_risks,
                "compliance_summary": compliance_summary,
                "kpi_summary": kpi_summary,
                "qoq_delta_pct": qoq_delta_pct,
                "action_items": action_items,
                "generated_at": generated_at,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.board_report_response_compliance_summary import BoardReportResponseComplianceSummary
        from ..models.board_report_response_kpi_summary import BoardReportResponseKpiSummary
        from ..models.board_report_response_top_5_risks_item import BoardReportResponseTop5RisksItem

        d = dict(src_dict)
        org_id = d.pop("org_id")

        report_period = d.pop("report_period")

        risk_headline_usd = d.pop("risk_headline_usd")

        risk_trend = d.pop("risk_trend")

        top_5_risks = []
        _top_5_risks = d.pop("top_5_risks")
        for top_5_risks_item_data in _top_5_risks:
            top_5_risks_item = BoardReportResponseTop5RisksItem.from_dict(top_5_risks_item_data)

            top_5_risks.append(top_5_risks_item)

        compliance_summary = BoardReportResponseComplianceSummary.from_dict(d.pop("compliance_summary"))

        kpi_summary = BoardReportResponseKpiSummary.from_dict(d.pop("kpi_summary"))

        qoq_delta_pct = d.pop("qoq_delta_pct")

        action_items = cast(list[str], d.pop("action_items"))

        generated_at = isoparse(d.pop("generated_at"))

        board_report_response = cls(
            org_id=org_id,
            report_period=report_period,
            risk_headline_usd=risk_headline_usd,
            risk_trend=risk_trend,
            top_5_risks=top_5_risks,
            compliance_summary=compliance_summary,
            kpi_summary=kpi_summary,
            qoq_delta_pct=qoq_delta_pct,
            action_items=action_items,
            generated_at=generated_at,
        )

        board_report_response.additional_properties = d
        return board_report_response

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
