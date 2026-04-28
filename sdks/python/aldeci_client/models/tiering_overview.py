from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.tiering_overview_assessment_requirements import TieringOverviewAssessmentRequirements
    from ..models.tiering_overview_tier_breakdown import TieringOverviewTierBreakdown


T = TypeVar("T", bound="TieringOverview")


@_attrs_define
class TieringOverview:
    """Summary of vendor tiering across the registry.

    Attributes:
        critical_count (int | Unset):  Default: 0.
        high_count (int | Unset):  Default: 0.
        medium_count (int | Unset):  Default: 0.
        low_count (int | Unset):  Default: 0.
        untiered_count (int | Unset):  Default: 0.
        tier_breakdown (TieringOverviewTierBreakdown | Unset):
        assessment_requirements (TieringOverviewAssessmentRequirements | Unset):
    """

    critical_count: int | Unset = 0
    high_count: int | Unset = 0
    medium_count: int | Unset = 0
    low_count: int | Unset = 0
    untiered_count: int | Unset = 0
    tier_breakdown: TieringOverviewTierBreakdown | Unset = UNSET
    assessment_requirements: TieringOverviewAssessmentRequirements | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        critical_count = self.critical_count

        high_count = self.high_count

        medium_count = self.medium_count

        low_count = self.low_count

        untiered_count = self.untiered_count

        tier_breakdown: dict[str, Any] | Unset = UNSET
        if not isinstance(self.tier_breakdown, Unset):
            tier_breakdown = self.tier_breakdown.to_dict()

        assessment_requirements: dict[str, Any] | Unset = UNSET
        if not isinstance(self.assessment_requirements, Unset):
            assessment_requirements = self.assessment_requirements.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if critical_count is not UNSET:
            field_dict["critical_count"] = critical_count
        if high_count is not UNSET:
            field_dict["high_count"] = high_count
        if medium_count is not UNSET:
            field_dict["medium_count"] = medium_count
        if low_count is not UNSET:
            field_dict["low_count"] = low_count
        if untiered_count is not UNSET:
            field_dict["untiered_count"] = untiered_count
        if tier_breakdown is not UNSET:
            field_dict["tier_breakdown"] = tier_breakdown
        if assessment_requirements is not UNSET:
            field_dict["assessment_requirements"] = assessment_requirements

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.tiering_overview_assessment_requirements import TieringOverviewAssessmentRequirements
        from ..models.tiering_overview_tier_breakdown import TieringOverviewTierBreakdown

        d = dict(src_dict)
        critical_count = d.pop("critical_count", UNSET)

        high_count = d.pop("high_count", UNSET)

        medium_count = d.pop("medium_count", UNSET)

        low_count = d.pop("low_count", UNSET)

        untiered_count = d.pop("untiered_count", UNSET)

        _tier_breakdown = d.pop("tier_breakdown", UNSET)
        tier_breakdown: TieringOverviewTierBreakdown | Unset
        if isinstance(_tier_breakdown, Unset):
            tier_breakdown = UNSET
        else:
            tier_breakdown = TieringOverviewTierBreakdown.from_dict(_tier_breakdown)

        _assessment_requirements = d.pop("assessment_requirements", UNSET)
        assessment_requirements: TieringOverviewAssessmentRequirements | Unset
        if isinstance(_assessment_requirements, Unset):
            assessment_requirements = UNSET
        else:
            assessment_requirements = TieringOverviewAssessmentRequirements.from_dict(_assessment_requirements)

        tiering_overview = cls(
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            untiered_count=untiered_count,
            tier_breakdown=tier_breakdown,
            assessment_requirements=assessment_requirements,
        )

        tiering_overview.additional_properties = d
        return tiering_overview

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
