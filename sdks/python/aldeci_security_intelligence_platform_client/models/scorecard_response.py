from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.scorecard_response_score_trend_item import ScorecardResponseScoreTrendItem


T = TypeVar("T", bound="ScorecardResponse")


@_attrs_define
class ScorecardResponse:
    """Vendor scorecard with all component scores and trend.

    Attributes:
        vendor_id (str):
        vendor_name (str):
        tier (str):
        overall_score (float):
        grade (str):
        questionnaire_score (float):
        monitoring_score (float):
        contract_score (float):
        incident_score (float):
        active_risks (int):
        contract_gaps (int):
        score_trend (list[ScorecardResponseScoreTrendItem]):
        calculated_at (str):
    """

    vendor_id: str
    vendor_name: str
    tier: str
    overall_score: float
    grade: str
    questionnaire_score: float
    monitoring_score: float
    contract_score: float
    incident_score: float
    active_risks: int
    contract_gaps: int
    score_trend: list[ScorecardResponseScoreTrendItem]
    calculated_at: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        vendor_id = self.vendor_id

        vendor_name = self.vendor_name

        tier = self.tier

        overall_score = self.overall_score

        grade = self.grade

        questionnaire_score = self.questionnaire_score

        monitoring_score = self.monitoring_score

        contract_score = self.contract_score

        incident_score = self.incident_score

        active_risks = self.active_risks

        contract_gaps = self.contract_gaps

        score_trend = []
        for score_trend_item_data in self.score_trend:
            score_trend_item = score_trend_item_data.to_dict()
            score_trend.append(score_trend_item)

        calculated_at = self.calculated_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "vendor_id": vendor_id,
                "vendor_name": vendor_name,
                "tier": tier,
                "overall_score": overall_score,
                "grade": grade,
                "questionnaire_score": questionnaire_score,
                "monitoring_score": monitoring_score,
                "contract_score": contract_score,
                "incident_score": incident_score,
                "active_risks": active_risks,
                "contract_gaps": contract_gaps,
                "score_trend": score_trend,
                "calculated_at": calculated_at,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.scorecard_response_score_trend_item import ScorecardResponseScoreTrendItem

        d = dict(src_dict)
        vendor_id = d.pop("vendor_id")

        vendor_name = d.pop("vendor_name")

        tier = d.pop("tier")

        overall_score = d.pop("overall_score")

        grade = d.pop("grade")

        questionnaire_score = d.pop("questionnaire_score")

        monitoring_score = d.pop("monitoring_score")

        contract_score = d.pop("contract_score")

        incident_score = d.pop("incident_score")

        active_risks = d.pop("active_risks")

        contract_gaps = d.pop("contract_gaps")

        score_trend = []
        _score_trend = d.pop("score_trend")
        for score_trend_item_data in _score_trend:
            score_trend_item = ScorecardResponseScoreTrendItem.from_dict(score_trend_item_data)

            score_trend.append(score_trend_item)

        calculated_at = d.pop("calculated_at")

        scorecard_response = cls(
            vendor_id=vendor_id,
            vendor_name=vendor_name,
            tier=tier,
            overall_score=overall_score,
            grade=grade,
            questionnaire_score=questionnaire_score,
            monitoring_score=monitoring_score,
            contract_score=contract_score,
            incident_score=incident_score,
            active_risks=active_risks,
            contract_gaps=contract_gaps,
            score_trend=score_trend,
            calculated_at=calculated_at,
        )

        scorecard_response.additional_properties = d
        return scorecard_response

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
