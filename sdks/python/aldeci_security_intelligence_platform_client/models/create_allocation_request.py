from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CreateAllocationRequest")


@_attrs_define
class CreateAllocationRequest:
    """
    Attributes:
        fiscal_year (int): Fiscal year (positive integer)
        category (str): tools|personnel|training|consulting|infrastructure|compliance|incident_response
        allocated_amount (float): Budget amount in currency
        currency (str | Unset): Currency code Default: 'USD'.
        notes (str | Unset): Optional notes Default: ''.
    """

    fiscal_year: int
    category: str
    allocated_amount: float
    currency: str | Unset = "USD"
    notes: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        fiscal_year = self.fiscal_year

        category = self.category

        allocated_amount = self.allocated_amount

        currency = self.currency

        notes = self.notes

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "fiscal_year": fiscal_year,
                "category": category,
                "allocated_amount": allocated_amount,
            }
        )
        if currency is not UNSET:
            field_dict["currency"] = currency
        if notes is not UNSET:
            field_dict["notes"] = notes

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        fiscal_year = d.pop("fiscal_year")

        category = d.pop("category")

        allocated_amount = d.pop("allocated_amount")

        currency = d.pop("currency", UNSET)

        notes = d.pop("notes", UNSET)

        create_allocation_request = cls(
            fiscal_year=fiscal_year,
            category=category,
            allocated_amount=allocated_amount,
            currency=currency,
            notes=notes,
        )

        create_allocation_request.additional_properties = d
        return create_allocation_request

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
