from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ScoringFormulaUpdate")


@_attrs_define
class ScoringFormulaUpdate:
    """PUT /api/v1/scoring/formula body.

    Attributes:
        model_name (str | Unset):  Default: 'default'.
        cvss_weight (float | Unset):  Default: 0.4.
        epss_weight (float | Unset):  Default: 0.3.
        kev_bonus (float | Unset):  Default: 0.2.
        criticality_multiplier (float | Unset):  Default: 1.0.
        exposure_weight (float | Unset):  Default: 0.3.
    """

    model_name: str | Unset = "default"
    cvss_weight: float | Unset = 0.4
    epss_weight: float | Unset = 0.3
    kev_bonus: float | Unset = 0.2
    criticality_multiplier: float | Unset = 1.0
    exposure_weight: float | Unset = 0.3
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        model_name = self.model_name

        cvss_weight = self.cvss_weight

        epss_weight = self.epss_weight

        kev_bonus = self.kev_bonus

        criticality_multiplier = self.criticality_multiplier

        exposure_weight = self.exposure_weight

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if model_name is not UNSET:
            field_dict["model_name"] = model_name
        if cvss_weight is not UNSET:
            field_dict["cvss_weight"] = cvss_weight
        if epss_weight is not UNSET:
            field_dict["epss_weight"] = epss_weight
        if kev_bonus is not UNSET:
            field_dict["kev_bonus"] = kev_bonus
        if criticality_multiplier is not UNSET:
            field_dict["criticality_multiplier"] = criticality_multiplier
        if exposure_weight is not UNSET:
            field_dict["exposure_weight"] = exposure_weight

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        model_name = d.pop("model_name", UNSET)

        cvss_weight = d.pop("cvss_weight", UNSET)

        epss_weight = d.pop("epss_weight", UNSET)

        kev_bonus = d.pop("kev_bonus", UNSET)

        criticality_multiplier = d.pop("criticality_multiplier", UNSET)

        exposure_weight = d.pop("exposure_weight", UNSET)

        scoring_formula_update = cls(
            model_name=model_name,
            cvss_weight=cvss_weight,
            epss_weight=epss_weight,
            kev_bonus=kev_bonus,
            criticality_multiplier=criticality_multiplier,
            exposure_weight=exposure_weight,
        )

        scoring_formula_update.additional_properties = d
        return scoring_formula_update

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
