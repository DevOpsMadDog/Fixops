from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="KPITargetRequest")


@_attrs_define
class KPITargetRequest:
    """Request body for configuring KPI thresholds.

    Attributes:
        name (str): KPI name
        target (float): Ideal target value
        yellow (float): Yellow alert threshold
        red (float): Red alert threshold
        higher_is_better (bool | Unset): True for coverage/rate KPIs; False for MTTD/MTTR Default: True.
    """

    name: str
    target: float
    yellow: float
    red: float
    higher_is_better: bool | Unset = True
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        target = self.target

        yellow = self.yellow

        red = self.red

        higher_is_better = self.higher_is_better

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
                "target": target,
                "yellow": yellow,
                "red": red,
            }
        )
        if higher_is_better is not UNSET:
            field_dict["higher_is_better"] = higher_is_better

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        target = d.pop("target")

        yellow = d.pop("yellow")

        red = d.pop("red")

        higher_is_better = d.pop("higher_is_better", UNSET)

        kpi_target_request = cls(
            name=name,
            target=target,
            yellow=yellow,
            red=red,
            higher_is_better=higher_is_better,
        )

        kpi_target_request.additional_properties = d
        return kpi_target_request

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
