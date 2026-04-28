from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

if TYPE_CHECKING:
    from ..models.sla_report_by_asset_tier import SLAReportByAssetTier
    from ..models.sla_report_by_framework import SLAReportByFramework
    from ..models.sla_report_by_severity import SLAReportBySeverity
    from ..models.sla_report_by_team_item import SLAReportByTeamItem
    from ..models.sla_report_escalation_summary import SLAReportEscalationSummary
    from ..models.sla_report_exception_summary import SLAReportExceptionSummary
    from ..models.sla_report_leaderboard_item import SLAReportLeaderboardItem


T = TypeVar("T", bound="SLAReport")


@_attrs_define
class SLAReport:
    """Compiled SLA compliance report.

    Attributes:
        org_id (str):
        generated_at (datetime.datetime):
        period_days (int):
        overall_compliance_rate (float):
        by_severity (SLAReportBySeverity):
        by_team (list[SLAReportByTeamItem]):
        by_framework (SLAReportByFramework):
        by_asset_tier (SLAReportByAssetTier):
        escalation_summary (SLAReportEscalationSummary):
        exception_summary (SLAReportExceptionSummary):
        leaderboard (list[SLAReportLeaderboardItem]):
    """

    org_id: str
    generated_at: datetime.datetime
    period_days: int
    overall_compliance_rate: float
    by_severity: SLAReportBySeverity
    by_team: list[SLAReportByTeamItem]
    by_framework: SLAReportByFramework
    by_asset_tier: SLAReportByAssetTier
    escalation_summary: SLAReportEscalationSummary
    exception_summary: SLAReportExceptionSummary
    leaderboard: list[SLAReportLeaderboardItem]
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        generated_at = self.generated_at.isoformat()

        period_days = self.period_days

        overall_compliance_rate = self.overall_compliance_rate

        by_severity = self.by_severity.to_dict()

        by_team = []
        for by_team_item_data in self.by_team:
            by_team_item = by_team_item_data.to_dict()
            by_team.append(by_team_item)

        by_framework = self.by_framework.to_dict()

        by_asset_tier = self.by_asset_tier.to_dict()

        escalation_summary = self.escalation_summary.to_dict()

        exception_summary = self.exception_summary.to_dict()

        leaderboard = []
        for leaderboard_item_data in self.leaderboard:
            leaderboard_item = leaderboard_item_data.to_dict()
            leaderboard.append(leaderboard_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "generated_at": generated_at,
                "period_days": period_days,
                "overall_compliance_rate": overall_compliance_rate,
                "by_severity": by_severity,
                "by_team": by_team,
                "by_framework": by_framework,
                "by_asset_tier": by_asset_tier,
                "escalation_summary": escalation_summary,
                "exception_summary": exception_summary,
                "leaderboard": leaderboard,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.sla_report_by_asset_tier import SLAReportByAssetTier
        from ..models.sla_report_by_framework import SLAReportByFramework
        from ..models.sla_report_by_severity import SLAReportBySeverity
        from ..models.sla_report_by_team_item import SLAReportByTeamItem
        from ..models.sla_report_escalation_summary import SLAReportEscalationSummary
        from ..models.sla_report_exception_summary import SLAReportExceptionSummary
        from ..models.sla_report_leaderboard_item import SLAReportLeaderboardItem

        d = dict(src_dict)
        org_id = d.pop("org_id")

        generated_at = isoparse(d.pop("generated_at"))

        period_days = d.pop("period_days")

        overall_compliance_rate = d.pop("overall_compliance_rate")

        by_severity = SLAReportBySeverity.from_dict(d.pop("by_severity"))

        by_team = []
        _by_team = d.pop("by_team")
        for by_team_item_data in _by_team:
            by_team_item = SLAReportByTeamItem.from_dict(by_team_item_data)

            by_team.append(by_team_item)

        by_framework = SLAReportByFramework.from_dict(d.pop("by_framework"))

        by_asset_tier = SLAReportByAssetTier.from_dict(d.pop("by_asset_tier"))

        escalation_summary = SLAReportEscalationSummary.from_dict(d.pop("escalation_summary"))

        exception_summary = SLAReportExceptionSummary.from_dict(d.pop("exception_summary"))

        leaderboard = []
        _leaderboard = d.pop("leaderboard")
        for leaderboard_item_data in _leaderboard:
            leaderboard_item = SLAReportLeaderboardItem.from_dict(leaderboard_item_data)

            leaderboard.append(leaderboard_item)

        sla_report = cls(
            org_id=org_id,
            generated_at=generated_at,
            period_days=period_days,
            overall_compliance_rate=overall_compliance_rate,
            by_severity=by_severity,
            by_team=by_team,
            by_framework=by_framework,
            by_asset_tier=by_asset_tier,
            escalation_summary=escalation_summary,
            exception_summary=exception_summary,
            leaderboard=leaderboard,
        )

        sla_report.additional_properties = d
        return sla_report

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
