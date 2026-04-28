from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RatesUpdate")


@_attrs_define
class RatesUpdate:
    """
    Attributes:
        asset_value (float | None | Unset):
        exposure_factor (float | None | Unset):
        annual_rate_occurrence (float | None | Unset):
    """

    asset_value: float | None | Unset = UNSET
    exposure_factor: float | None | Unset = UNSET
    annual_rate_occurrence: float | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        asset_value: float | None | Unset
        if isinstance(self.asset_value, Unset):
            asset_value = UNSET
        else:
            asset_value = self.asset_value

        exposure_factor: float | None | Unset
        if isinstance(self.exposure_factor, Unset):
            exposure_factor = UNSET
        else:
            exposure_factor = self.exposure_factor

        annual_rate_occurrence: float | None | Unset
        if isinstance(self.annual_rate_occurrence, Unset):
            annual_rate_occurrence = UNSET
        else:
            annual_rate_occurrence = self.annual_rate_occurrence

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if asset_value is not UNSET:
            field_dict["asset_value"] = asset_value
        if exposure_factor is not UNSET:
            field_dict["exposure_factor"] = exposure_factor
        if annual_rate_occurrence is not UNSET:
            field_dict["annual_rate_occurrence"] = annual_rate_occurrence

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_asset_value(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        asset_value = _parse_asset_value(d.pop("asset_value", UNSET))

        def _parse_exposure_factor(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        exposure_factor = _parse_exposure_factor(d.pop("exposure_factor", UNSET))

        def _parse_annual_rate_occurrence(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        annual_rate_occurrence = _parse_annual_rate_occurrence(d.pop("annual_rate_occurrence", UNSET))

        rates_update = cls(
            asset_value=asset_value,
            exposure_factor=exposure_factor,
            annual_rate_occurrence=annual_rate_occurrence,
        )

        rates_update.additional_properties = d
        return rates_update

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
