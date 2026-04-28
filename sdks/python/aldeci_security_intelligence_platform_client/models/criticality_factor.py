from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CriticalityFactor")


@_attrs_define
class CriticalityFactor:
    """
    Attributes:
        factor_name (str):
        factor_category (str | Unset):  Default: ''.
        weight (float | Unset):  Default: 1.0.
        value (float | Unset):  Default: 0.0.
    """

    factor_name: str
    factor_category: str | Unset = ""
    weight: float | Unset = 1.0
    value: float | Unset = 0.0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        factor_name = self.factor_name

        factor_category = self.factor_category

        weight = self.weight

        value = self.value

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "factor_name": factor_name,
            }
        )
        if factor_category is not UNSET:
            field_dict["factor_category"] = factor_category
        if weight is not UNSET:
            field_dict["weight"] = weight
        if value is not UNSET:
            field_dict["value"] = value

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        factor_name = d.pop("factor_name")

        factor_category = d.pop("factor_category", UNSET)

        weight = d.pop("weight", UNSET)

        value = d.pop("value", UNSET)

        criticality_factor = cls(
            factor_name=factor_name,
            factor_category=factor_category,
            weight=weight,
            value=value,
        )

        criticality_factor.additional_properties = d
        return criticality_factor

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
