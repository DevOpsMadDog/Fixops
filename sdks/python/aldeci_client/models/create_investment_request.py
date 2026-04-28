from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CreateInvestmentRequest")


@_attrs_define
class CreateInvestmentRequest:
    """
    Attributes:
        org_id (str): Organisation identifier
        investment_name (str): Name of the investment
        investment_category (str): tools|personnel|training|compliance|infrastructure|consulting|insurance|R&D
        vendor (str | Unset): Vendor or supplier name Default: ''.
        amount (float | Unset): Investment amount Default: 0.0.
        currency (str | Unset): USD|EUR|GBP|AUD|CAD Default: 'USD'.
        start_date (str | Unset): ISO start date Default: ''.
        end_date (str | Unset): ISO end date Default: ''.
    """

    org_id: str
    investment_name: str
    investment_category: str
    vendor: str | Unset = ""
    amount: float | Unset = 0.0
    currency: str | Unset = "USD"
    start_date: str | Unset = ""
    end_date: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        investment_name = self.investment_name

        investment_category = self.investment_category

        vendor = self.vendor

        amount = self.amount

        currency = self.currency

        start_date = self.start_date

        end_date = self.end_date

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "investment_name": investment_name,
                "investment_category": investment_category,
            }
        )
        if vendor is not UNSET:
            field_dict["vendor"] = vendor
        if amount is not UNSET:
            field_dict["amount"] = amount
        if currency is not UNSET:
            field_dict["currency"] = currency
        if start_date is not UNSET:
            field_dict["start_date"] = start_date
        if end_date is not UNSET:
            field_dict["end_date"] = end_date

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        investment_name = d.pop("investment_name")

        investment_category = d.pop("investment_category")

        vendor = d.pop("vendor", UNSET)

        amount = d.pop("amount", UNSET)

        currency = d.pop("currency", UNSET)

        start_date = d.pop("start_date", UNSET)

        end_date = d.pop("end_date", UNSET)

        create_investment_request = cls(
            org_id=org_id,
            investment_name=investment_name,
            investment_category=investment_category,
            vendor=vendor,
            amount=amount,
            currency=currency,
            start_date=start_date,
            end_date=end_date,
        )

        create_investment_request.additional_properties = d
        return create_investment_request

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
