from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="KPITarget")


@_attrs_define
class KPITarget:
    """Threshold configuration for a KPI.

    Attributes:
        kpi_name (str): KPI name this target applies to
        target_value (float): Ideal / goal value
        threshold_yellow (float): Value at which KPI turns yellow
        threshold_red (float): Value at which KPI turns red
        higher_is_better (bool | Unset): True = higher values are better (e.g. coverage). False = lower values are
            better (e.g. MTTD). Default: True.
    """

    kpi_name: str
    target_value: float
    threshold_yellow: float
    threshold_red: float
    higher_is_better: bool | Unset = True
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        kpi_name = self.kpi_name

        target_value = self.target_value

        threshold_yellow = self.threshold_yellow

        threshold_red = self.threshold_red

        higher_is_better = self.higher_is_better

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "kpi_name": kpi_name,
                "target_value": target_value,
                "threshold_yellow": threshold_yellow,
                "threshold_red": threshold_red,
            }
        )
        if higher_is_better is not UNSET:
            field_dict["higher_is_better"] = higher_is_better

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        kpi_name = d.pop("kpi_name")

        target_value = d.pop("target_value")

        threshold_yellow = d.pop("threshold_yellow")

        threshold_red = d.pop("threshold_red")

        higher_is_better = d.pop("higher_is_better", UNSET)

        kpi_target = cls(
            kpi_name=kpi_name,
            target_value=target_value,
            threshold_yellow=threshold_yellow,
            threshold_red=threshold_red,
            higher_is_better=higher_is_better,
        )

        kpi_target.additional_properties = d
        return kpi_target

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
