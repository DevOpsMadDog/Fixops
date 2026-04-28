from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ROIAssessmentCreate")


@_attrs_define
class ROIAssessmentCreate:
    """
    Attributes:
        assessment_period (str):
        incidents_prevented (int | Unset):  Default: 0.
        avg_incident_cost (float | Unset):  Default: 0.0.
        risk_reduction_pct (float | Unset):  Default: 0.0.
    """

    assessment_period: str
    incidents_prevented: int | Unset = 0
    avg_incident_cost: float | Unset = 0.0
    risk_reduction_pct: float | Unset = 0.0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        assessment_period = self.assessment_period

        incidents_prevented = self.incidents_prevented

        avg_incident_cost = self.avg_incident_cost

        risk_reduction_pct = self.risk_reduction_pct

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "assessment_period": assessment_period,
            }
        )
        if incidents_prevented is not UNSET:
            field_dict["incidents_prevented"] = incidents_prevented
        if avg_incident_cost is not UNSET:
            field_dict["avg_incident_cost"] = avg_incident_cost
        if risk_reduction_pct is not UNSET:
            field_dict["risk_reduction_pct"] = risk_reduction_pct

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        assessment_period = d.pop("assessment_period")

        incidents_prevented = d.pop("incidents_prevented", UNSET)

        avg_incident_cost = d.pop("avg_incident_cost", UNSET)

        risk_reduction_pct = d.pop("risk_reduction_pct", UNSET)

        roi_assessment_create = cls(
            assessment_period=assessment_period,
            incidents_prevented=incidents_prevented,
            avg_incident_cost=avg_incident_cost,
            risk_reduction_pct=risk_reduction_pct,
        )

        roi_assessment_create.additional_properties = d
        return roi_assessment_create

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
