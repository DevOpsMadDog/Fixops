from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.gap_analysis_gap_frequency import GapAnalysisGapFrequency


T = TypeVar("T", bound="GapAnalysis")


@_attrs_define
class GapAnalysis:
    """Gap analysis across all simulations for an org.

    Attributes:
        org_id (str):
        total_simulations (int):
        recurring_gaps (list[str]):
        gap_frequency (GapAnalysisGapFrequency):
        critical_gaps (list[str]):
        recommended_priorities (list[str]):
    """

    org_id: str
    total_simulations: int
    recurring_gaps: list[str]
    gap_frequency: GapAnalysisGapFrequency
    critical_gaps: list[str]
    recommended_priorities: list[str]
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        total_simulations = self.total_simulations

        recurring_gaps = self.recurring_gaps

        gap_frequency = self.gap_frequency.to_dict()

        critical_gaps = self.critical_gaps

        recommended_priorities = self.recommended_priorities

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "total_simulations": total_simulations,
                "recurring_gaps": recurring_gaps,
                "gap_frequency": gap_frequency,
                "critical_gaps": critical_gaps,
                "recommended_priorities": recommended_priorities,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.gap_analysis_gap_frequency import GapAnalysisGapFrequency

        d = dict(src_dict)
        org_id = d.pop("org_id")

        total_simulations = d.pop("total_simulations")

        recurring_gaps = cast(list[str], d.pop("recurring_gaps"))

        gap_frequency = GapAnalysisGapFrequency.from_dict(d.pop("gap_frequency"))

        critical_gaps = cast(list[str], d.pop("critical_gaps"))

        recommended_priorities = cast(list[str], d.pop("recommended_priorities"))

        gap_analysis = cls(
            org_id=org_id,
            total_simulations=total_simulations,
            recurring_gaps=recurring_gaps,
            gap_frequency=gap_frequency,
            critical_gaps=critical_gaps,
            recommended_priorities=recommended_priorities,
        )

        gap_analysis.additional_properties = d
        return gap_analysis

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
