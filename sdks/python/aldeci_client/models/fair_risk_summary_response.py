from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

if TYPE_CHECKING:
    from ..models.fair_result_response import FAIRResultResponse


T = TypeVar("T", bound="FAIRRiskSummaryResponse")


@_attrs_define
class FAIRRiskSummaryResponse:
    """Aggregated FAIR portfolio risk summary.

    Attributes:
        scenarios (list[FAIRResultResponse]):
        total_ale_p10_usd (float):
        total_ale_p50_usd (float):
        total_ale_p90_usd (float):
        total_ale_mean_usd (float):
        computed_at (datetime.datetime):
    """

    scenarios: list[FAIRResultResponse]
    total_ale_p10_usd: float
    total_ale_p50_usd: float
    total_ale_p90_usd: float
    total_ale_mean_usd: float
    computed_at: datetime.datetime
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        scenarios = []
        for scenarios_item_data in self.scenarios:
            scenarios_item = scenarios_item_data.to_dict()
            scenarios.append(scenarios_item)

        total_ale_p10_usd = self.total_ale_p10_usd

        total_ale_p50_usd = self.total_ale_p50_usd

        total_ale_p90_usd = self.total_ale_p90_usd

        total_ale_mean_usd = self.total_ale_mean_usd

        computed_at = self.computed_at.isoformat()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "scenarios": scenarios,
                "total_ale_p10_usd": total_ale_p10_usd,
                "total_ale_p50_usd": total_ale_p50_usd,
                "total_ale_p90_usd": total_ale_p90_usd,
                "total_ale_mean_usd": total_ale_mean_usd,
                "computed_at": computed_at,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.fair_result_response import FAIRResultResponse

        d = dict(src_dict)
        scenarios = []
        _scenarios = d.pop("scenarios")
        for scenarios_item_data in _scenarios:
            scenarios_item = FAIRResultResponse.from_dict(scenarios_item_data)

            scenarios.append(scenarios_item)

        total_ale_p10_usd = d.pop("total_ale_p10_usd")

        total_ale_p50_usd = d.pop("total_ale_p50_usd")

        total_ale_p90_usd = d.pop("total_ale_p90_usd")

        total_ale_mean_usd = d.pop("total_ale_mean_usd")

        computed_at = isoparse(d.pop("computed_at"))

        fair_risk_summary_response = cls(
            scenarios=scenarios,
            total_ale_p10_usd=total_ale_p10_usd,
            total_ale_p50_usd=total_ale_p50_usd,
            total_ale_p90_usd=total_ale_p90_usd,
            total_ale_mean_usd=total_ale_mean_usd,
            computed_at=computed_at,
        )

        fair_risk_summary_response.additional_properties = d
        return fair_risk_summary_response

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
