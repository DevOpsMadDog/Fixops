from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

if TYPE_CHECKING:
    from ..models.risk_posture_response_category_scores import RiskPostureResponseCategoryScores


T = TypeVar("T", bound="RiskPostureResponse")


@_attrs_define
class RiskPostureResponse:
    """Risk posture response.

    Attributes:
        overall_score (float): Overall risk score 0-100
        category_scores (RiskPostureResponseCategoryScores): Per-category scores
        trend (str): improving/degrading/stable
        contributing_factors (list[str]): Top risk factors
        recommendations (list[str]): Mitigation recommendations
        timestamp (datetime.datetime): Assessment timestamp
    """

    overall_score: float
    category_scores: RiskPostureResponseCategoryScores
    trend: str
    contributing_factors: list[str]
    recommendations: list[str]
    timestamp: datetime.datetime
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        overall_score = self.overall_score

        category_scores = self.category_scores.to_dict()

        trend = self.trend

        contributing_factors = self.contributing_factors

        recommendations = self.recommendations

        timestamp = self.timestamp.isoformat()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "overall_score": overall_score,
                "category_scores": category_scores,
                "trend": trend,
                "contributing_factors": contributing_factors,
                "recommendations": recommendations,
                "timestamp": timestamp,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.risk_posture_response_category_scores import RiskPostureResponseCategoryScores

        d = dict(src_dict)
        overall_score = d.pop("overall_score")

        category_scores = RiskPostureResponseCategoryScores.from_dict(d.pop("category_scores"))

        trend = d.pop("trend")

        contributing_factors = cast(list[str], d.pop("contributing_factors"))

        recommendations = cast(list[str], d.pop("recommendations"))

        timestamp = isoparse(d.pop("timestamp"))

        risk_posture_response = cls(
            overall_score=overall_score,
            category_scores=category_scores,
            trend=trend,
            contributing_factors=contributing_factors,
            recommendations=recommendations,
            timestamp=timestamp,
        )

        risk_posture_response.additional_properties = d
        return risk_posture_response

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
