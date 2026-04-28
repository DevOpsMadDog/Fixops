from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.triage_stats_response_trending import TriageStatsResponseTrending
    from ..models.triage_stats_response_verdict_breakdown import TriageStatsResponseVerdictBreakdown


T = TypeVar("T", bound="TriageStatsResponse")


@_attrs_define
class TriageStatsResponse:
    """Response for /stats.

    Attributes:
        total_triaged (int):
        analyst_agreement_rate (float):
        average_triage_time_hours (float | None):
        false_positive_rate (float):
        verdict_breakdown (TriageStatsResponseVerdictBreakdown):
        trending (TriageStatsResponseTrending):
        timestamp (str):
    """

    total_triaged: int
    analyst_agreement_rate: float
    average_triage_time_hours: float | None
    false_positive_rate: float
    verdict_breakdown: TriageStatsResponseVerdictBreakdown
    trending: TriageStatsResponseTrending
    timestamp: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        total_triaged = self.total_triaged

        analyst_agreement_rate = self.analyst_agreement_rate

        average_triage_time_hours: float | None
        average_triage_time_hours = self.average_triage_time_hours

        false_positive_rate = self.false_positive_rate

        verdict_breakdown = self.verdict_breakdown.to_dict()

        trending = self.trending.to_dict()

        timestamp = self.timestamp

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "total_triaged": total_triaged,
                "analyst_agreement_rate": analyst_agreement_rate,
                "average_triage_time_hours": average_triage_time_hours,
                "false_positive_rate": false_positive_rate,
                "verdict_breakdown": verdict_breakdown,
                "trending": trending,
                "timestamp": timestamp,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.triage_stats_response_trending import TriageStatsResponseTrending
        from ..models.triage_stats_response_verdict_breakdown import TriageStatsResponseVerdictBreakdown

        d = dict(src_dict)
        total_triaged = d.pop("total_triaged")

        analyst_agreement_rate = d.pop("analyst_agreement_rate")

        def _parse_average_triage_time_hours(data: object) -> float | None:
            if data is None:
                return data
            return cast(float | None, data)

        average_triage_time_hours = _parse_average_triage_time_hours(d.pop("average_triage_time_hours"))

        false_positive_rate = d.pop("false_positive_rate")

        verdict_breakdown = TriageStatsResponseVerdictBreakdown.from_dict(d.pop("verdict_breakdown"))

        trending = TriageStatsResponseTrending.from_dict(d.pop("trending"))

        timestamp = d.pop("timestamp")

        triage_stats_response = cls(
            total_triaged=total_triaged,
            analyst_agreement_rate=analyst_agreement_rate,
            average_triage_time_hours=average_triage_time_hours,
            false_positive_rate=false_positive_rate,
            verdict_breakdown=verdict_breakdown,
            trending=trending,
            timestamp=timestamp,
        )

        triage_stats_response.additional_properties = d
        return triage_stats_response

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
