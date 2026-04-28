from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="KPICreate")


@_attrs_define
class KPICreate:
    """
    Attributes:
        name (str):
        target_value (float):
        kpi_category (str | Unset):  Default: 'operational'.
        direction (str | Unset):  Default: 'higher_better'.
        unit (str | Unset):  Default: ''.
        frequency (str | Unset):  Default: 'monthly'.
        description (str | Unset):  Default: ''.
    """

    name: str
    target_value: float
    kpi_category: str | Unset = "operational"
    direction: str | Unset = "higher_better"
    unit: str | Unset = ""
    frequency: str | Unset = "monthly"
    description: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        target_value = self.target_value

        kpi_category = self.kpi_category

        direction = self.direction

        unit = self.unit

        frequency = self.frequency

        description = self.description

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
                "target_value": target_value,
            }
        )
        if kpi_category is not UNSET:
            field_dict["kpi_category"] = kpi_category
        if direction is not UNSET:
            field_dict["direction"] = direction
        if unit is not UNSET:
            field_dict["unit"] = unit
        if frequency is not UNSET:
            field_dict["frequency"] = frequency
        if description is not UNSET:
            field_dict["description"] = description

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        target_value = d.pop("target_value")

        kpi_category = d.pop("kpi_category", UNSET)

        direction = d.pop("direction", UNSET)

        unit = d.pop("unit", UNSET)

        frequency = d.pop("frequency", UNSET)

        description = d.pop("description", UNSET)

        kpi_create = cls(
            name=name,
            target_value=target_value,
            kpi_category=kpi_category,
            direction=direction,
            unit=unit,
            frequency=frequency,
            description=description,
        )

        kpi_create.additional_properties = d
        return kpi_create

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
