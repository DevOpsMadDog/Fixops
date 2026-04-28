from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="OptimizationCreate")


@_attrs_define
class OptimizationCreate:
    """
    Attributes:
        optimization_type (str):
        description (str | Unset):  Default: ''.
        estimated_savings (float | Unset):  Default: 0.0.
    """

    optimization_type: str
    description: str | Unset = ""
    estimated_savings: float | Unset = 0.0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        optimization_type = self.optimization_type

        description = self.description

        estimated_savings = self.estimated_savings

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "optimization_type": optimization_type,
            }
        )
        if description is not UNSET:
            field_dict["description"] = description
        if estimated_savings is not UNSET:
            field_dict["estimated_savings"] = estimated_savings

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        optimization_type = d.pop("optimization_type")

        description = d.pop("description", UNSET)

        estimated_savings = d.pop("estimated_savings", UNSET)

        optimization_create = cls(
            optimization_type=optimization_type,
            description=description,
            estimated_savings=estimated_savings,
        )

        optimization_create.additional_properties = d
        return optimization_create

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
