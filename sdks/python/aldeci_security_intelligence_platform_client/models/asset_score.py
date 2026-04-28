from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.criticality_factor import CriticalityFactor


T = TypeVar("T", bound="AssetScore")


@_attrs_define
class AssetScore:
    """
    Attributes:
        factors (list[CriticalityFactor]):
    """

    factors: list[CriticalityFactor]
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        factors = []
        for factors_item_data in self.factors:
            factors_item = factors_item_data.to_dict()
            factors.append(factors_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "factors": factors,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.criticality_factor import CriticalityFactor

        d = dict(src_dict)
        factors = []
        _factors = d.pop("factors")
        for factors_item_data in _factors:
            factors_item = CriticalityFactor.from_dict(factors_item_data)

            factors.append(factors_item)

        asset_score = cls(
            factors=factors,
        )

        asset_score.additional_properties = d
        return asset_score

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
