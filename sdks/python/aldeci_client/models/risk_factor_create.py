from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RiskFactorCreate")


@_attrs_define
class RiskFactorCreate:
    """
    Attributes:
        factor_name (str):
        factor_type (str | Unset):  Default: 'vulnerability'.
        impact (float | Unset):  Default: 0.0.
        description (str | Unset):  Default: ''.
    """

    factor_name: str
    factor_type: str | Unset = "vulnerability"
    impact: float | Unset = 0.0
    description: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        factor_name = self.factor_name

        factor_type = self.factor_type

        impact = self.impact

        description = self.description

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "factor_name": factor_name,
            }
        )
        if factor_type is not UNSET:
            field_dict["factor_type"] = factor_type
        if impact is not UNSET:
            field_dict["impact"] = impact
        if description is not UNSET:
            field_dict["description"] = description

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        factor_name = d.pop("factor_name")

        factor_type = d.pop("factor_type", UNSET)

        impact = d.pop("impact", UNSET)

        description = d.pop("description", UNSET)

        risk_factor_create = cls(
            factor_name=factor_name,
            factor_type=factor_type,
            impact=impact,
            description=description,
        )

        risk_factor_create.additional_properties = d
        return risk_factor_create

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
