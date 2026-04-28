from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="KPIIn")


@_attrs_define
class KPIIn:
    """
    Attributes:
        kpi_name (str):
        kpi_value (float):
        target_value (float):
        kpi_unit (str | Unset):  Default: ''.
        trend (str | Unset):  Default: 'stable'.
    """

    kpi_name: str
    kpi_value: float
    target_value: float
    kpi_unit: str | Unset = ""
    trend: str | Unset = "stable"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        kpi_name = self.kpi_name

        kpi_value = self.kpi_value

        target_value = self.target_value

        kpi_unit = self.kpi_unit

        trend = self.trend

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "kpi_name": kpi_name,
                "kpi_value": kpi_value,
                "target_value": target_value,
            }
        )
        if kpi_unit is not UNSET:
            field_dict["kpi_unit"] = kpi_unit
        if trend is not UNSET:
            field_dict["trend"] = trend

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        kpi_name = d.pop("kpi_name")

        kpi_value = d.pop("kpi_value")

        target_value = d.pop("target_value")

        kpi_unit = d.pop("kpi_unit", UNSET)

        trend = d.pop("trend", UNSET)

        kpi_in = cls(
            kpi_name=kpi_name,
            kpi_value=kpi_value,
            target_value=target_value,
            kpi_unit=kpi_unit,
            trend=trend,
        )

        kpi_in.additional_properties = d
        return kpi_in

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
