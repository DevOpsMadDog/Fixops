from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ScenarioReview")


@_attrs_define
class ScenarioReview:
    """
    Attributes:
        reviewer (str):
        likelihood_adjustment (float | Unset):  Default: 0.0.
        impact_adjustment (float | Unset):  Default: 0.0.
        notes (str | Unset):  Default: ''.
    """

    reviewer: str
    likelihood_adjustment: float | Unset = 0.0
    impact_adjustment: float | Unset = 0.0
    notes: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        reviewer = self.reviewer

        likelihood_adjustment = self.likelihood_adjustment

        impact_adjustment = self.impact_adjustment

        notes = self.notes

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "reviewer": reviewer,
            }
        )
        if likelihood_adjustment is not UNSET:
            field_dict["likelihood_adjustment"] = likelihood_adjustment
        if impact_adjustment is not UNSET:
            field_dict["impact_adjustment"] = impact_adjustment
        if notes is not UNSET:
            field_dict["notes"] = notes

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        reviewer = d.pop("reviewer")

        likelihood_adjustment = d.pop("likelihood_adjustment", UNSET)

        impact_adjustment = d.pop("impact_adjustment", UNSET)

        notes = d.pop("notes", UNSET)

        scenario_review = cls(
            reviewer=reviewer,
            likelihood_adjustment=likelihood_adjustment,
            impact_adjustment=impact_adjustment,
            notes=notes,
        )

        scenario_review.additional_properties = d
        return scenario_review

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
