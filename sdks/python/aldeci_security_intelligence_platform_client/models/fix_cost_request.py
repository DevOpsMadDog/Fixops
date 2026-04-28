from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="FixCostRequest")


@_attrs_define
class FixCostRequest:
    """
    Attributes:
        finding_id (str): Finding ID being fixed
        cost (float): Cost of the fix in $
        fixed_at (str): ISO datetime when fix was deployed
        ale_reduced (float | None | Unset): Optional explicit ALE reduction $. If omitted, inferred from severity.
    """

    finding_id: str
    cost: float
    fixed_at: str
    ale_reduced: float | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        finding_id = self.finding_id

        cost = self.cost

        fixed_at = self.fixed_at

        ale_reduced: float | None | Unset
        if isinstance(self.ale_reduced, Unset):
            ale_reduced = UNSET
        else:
            ale_reduced = self.ale_reduced

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "finding_id": finding_id,
                "cost": cost,
                "fixed_at": fixed_at,
            }
        )
        if ale_reduced is not UNSET:
            field_dict["ale_reduced"] = ale_reduced

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        finding_id = d.pop("finding_id")

        cost = d.pop("cost")

        fixed_at = d.pop("fixed_at")

        def _parse_ale_reduced(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        ale_reduced = _parse_ale_reduced(d.pop("ale_reduced", UNSET))

        fix_cost_request = cls(
            finding_id=finding_id,
            cost=cost,
            fixed_at=fixed_at,
            ale_reduced=ale_reduced,
        )

        fix_cost_request.additional_properties = d
        return fix_cost_request

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
