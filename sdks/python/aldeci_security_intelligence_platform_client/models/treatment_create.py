from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="TreatmentCreate")


@_attrs_define
class TreatmentCreate:
    """
    Attributes:
        scenario_id (str): Parent scenario ID
        treatment_type (str | Unset): accept/mitigate/transfer/avoid Default: 'mitigate'.
        description (str | Unset): Treatment description Default: ''.
        cost (float | Unset): Implementation cost ($) Default: 0.0.
        risk_reduction_pct (float | Unset): Expected risk reduction (%) Default: 0.0.
        status (str | Unset): proposed/approved/implemented Default: 'proposed'.
    """

    scenario_id: str
    treatment_type: str | Unset = "mitigate"
    description: str | Unset = ""
    cost: float | Unset = 0.0
    risk_reduction_pct: float | Unset = 0.0
    status: str | Unset = "proposed"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        scenario_id = self.scenario_id

        treatment_type = self.treatment_type

        description = self.description

        cost = self.cost

        risk_reduction_pct = self.risk_reduction_pct

        status = self.status

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "scenario_id": scenario_id,
            }
        )
        if treatment_type is not UNSET:
            field_dict["treatment_type"] = treatment_type
        if description is not UNSET:
            field_dict["description"] = description
        if cost is not UNSET:
            field_dict["cost"] = cost
        if risk_reduction_pct is not UNSET:
            field_dict["risk_reduction_pct"] = risk_reduction_pct
        if status is not UNSET:
            field_dict["status"] = status

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        scenario_id = d.pop("scenario_id")

        treatment_type = d.pop("treatment_type", UNSET)

        description = d.pop("description", UNSET)

        cost = d.pop("cost", UNSET)

        risk_reduction_pct = d.pop("risk_reduction_pct", UNSET)

        status = d.pop("status", UNSET)

        treatment_create = cls(
            scenario_id=scenario_id,
            treatment_type=treatment_type,
            description=description,
            cost=cost,
            risk_reduction_pct=risk_reduction_pct,
            status=status,
        )

        treatment_create.additional_properties = d
        return treatment_create

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
