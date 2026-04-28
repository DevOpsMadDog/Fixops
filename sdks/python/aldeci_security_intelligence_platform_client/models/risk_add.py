from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RiskAdd")


@_attrs_define
class RiskAdd:
    """
    Attributes:
        risk_category (str):
        risk_description (str | Unset):  Default: ''.
        likelihood (str | Unset):  Default: 'medium'.
        impact (str | Unset):  Default: 'medium'.
        mitigation (str | Unset):  Default: ''.
        residual_risk (str | Unset):  Default: 'medium'.
    """

    risk_category: str
    risk_description: str | Unset = ""
    likelihood: str | Unset = "medium"
    impact: str | Unset = "medium"
    mitigation: str | Unset = ""
    residual_risk: str | Unset = "medium"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        risk_category = self.risk_category

        risk_description = self.risk_description

        likelihood = self.likelihood

        impact = self.impact

        mitigation = self.mitigation

        residual_risk = self.residual_risk

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "risk_category": risk_category,
            }
        )
        if risk_description is not UNSET:
            field_dict["risk_description"] = risk_description
        if likelihood is not UNSET:
            field_dict["likelihood"] = likelihood
        if impact is not UNSET:
            field_dict["impact"] = impact
        if mitigation is not UNSET:
            field_dict["mitigation"] = mitigation
        if residual_risk is not UNSET:
            field_dict["residual_risk"] = residual_risk

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        risk_category = d.pop("risk_category")

        risk_description = d.pop("risk_description", UNSET)

        likelihood = d.pop("likelihood", UNSET)

        impact = d.pop("impact", UNSET)

        mitigation = d.pop("mitigation", UNSET)

        residual_risk = d.pop("residual_risk", UNSET)

        risk_add = cls(
            risk_category=risk_category,
            risk_description=risk_description,
            likelihood=likelihood,
            impact=impact,
            mitigation=mitigation,
            residual_risk=residual_risk,
        )

        risk_add.additional_properties = d
        return risk_add

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
