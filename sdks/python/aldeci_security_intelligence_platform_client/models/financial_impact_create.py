from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="FinancialImpactCreate")


@_attrs_define
class FinancialImpactCreate:
    """
    Attributes:
        incident_type (str): Type of incident
        direct_cost (float | Unset):  Default: 0.0.
        regulatory_fines (float | Unset):  Default: 0.0.
        remediation_cost (float | Unset):  Default: 0.0.
        business_disruption_cost (float | Unset):  Default: 0.0.
        reputational_cost (float | Unset):  Default: 0.0.
        incident_date (None | str | Unset): ISO date string (defaults to now)
        fiscal_year (int | None | Unset): Fiscal year (defaults to current year)
    """

    incident_type: str
    direct_cost: float | Unset = 0.0
    regulatory_fines: float | Unset = 0.0
    remediation_cost: float | Unset = 0.0
    business_disruption_cost: float | Unset = 0.0
    reputational_cost: float | Unset = 0.0
    incident_date: None | str | Unset = UNSET
    fiscal_year: int | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        incident_type = self.incident_type

        direct_cost = self.direct_cost

        regulatory_fines = self.regulatory_fines

        remediation_cost = self.remediation_cost

        business_disruption_cost = self.business_disruption_cost

        reputational_cost = self.reputational_cost

        incident_date: None | str | Unset
        if isinstance(self.incident_date, Unset):
            incident_date = UNSET
        else:
            incident_date = self.incident_date

        fiscal_year: int | None | Unset
        if isinstance(self.fiscal_year, Unset):
            fiscal_year = UNSET
        else:
            fiscal_year = self.fiscal_year

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "incident_type": incident_type,
            }
        )
        if direct_cost is not UNSET:
            field_dict["direct_cost"] = direct_cost
        if regulatory_fines is not UNSET:
            field_dict["regulatory_fines"] = regulatory_fines
        if remediation_cost is not UNSET:
            field_dict["remediation_cost"] = remediation_cost
        if business_disruption_cost is not UNSET:
            field_dict["business_disruption_cost"] = business_disruption_cost
        if reputational_cost is not UNSET:
            field_dict["reputational_cost"] = reputational_cost
        if incident_date is not UNSET:
            field_dict["incident_date"] = incident_date
        if fiscal_year is not UNSET:
            field_dict["fiscal_year"] = fiscal_year

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        incident_type = d.pop("incident_type")

        direct_cost = d.pop("direct_cost", UNSET)

        regulatory_fines = d.pop("regulatory_fines", UNSET)

        remediation_cost = d.pop("remediation_cost", UNSET)

        business_disruption_cost = d.pop("business_disruption_cost", UNSET)

        reputational_cost = d.pop("reputational_cost", UNSET)

        def _parse_incident_date(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        incident_date = _parse_incident_date(d.pop("incident_date", UNSET))

        def _parse_fiscal_year(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        fiscal_year = _parse_fiscal_year(d.pop("fiscal_year", UNSET))

        financial_impact_create = cls(
            incident_type=incident_type,
            direct_cost=direct_cost,
            regulatory_fines=regulatory_fines,
            remediation_cost=remediation_cost,
            business_disruption_cost=business_disruption_cost,
            reputational_cost=reputational_cost,
            incident_date=incident_date,
            fiscal_year=fiscal_year,
        )

        financial_impact_create.additional_properties = d
        return financial_impact_create

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
