from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="SetBudgetRequest")


@_attrs_define
class SetBudgetRequest:
    """
    Attributes:
        org_id (str): Organisation identifier
        fiscal_year (str): Fiscal year (e.g. '2025')
        category (str): tools|personnel|training|compliance|infrastructure|consulting|insurance|R&D
        allocated (float): Allocated budget amount
        currency (str | Unset): USD|EUR|GBP|AUD|CAD Default: 'USD'.
    """

    org_id: str
    fiscal_year: str
    category: str
    allocated: float
    currency: str | Unset = "USD"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        fiscal_year = self.fiscal_year

        category = self.category

        allocated = self.allocated

        currency = self.currency

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "fiscal_year": fiscal_year,
                "category": category,
                "allocated": allocated,
            }
        )
        if currency is not UNSET:
            field_dict["currency"] = currency

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        fiscal_year = d.pop("fiscal_year")

        category = d.pop("category")

        allocated = d.pop("allocated")

        currency = d.pop("currency", UNSET)

        set_budget_request = cls(
            org_id=org_id,
            fiscal_year=fiscal_year,
            category=category,
            allocated=allocated,
            currency=currency,
        )

        set_budget_request.additional_properties = d
        return set_budget_request

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
