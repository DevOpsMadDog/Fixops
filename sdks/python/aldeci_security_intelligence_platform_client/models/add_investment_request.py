from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AddInvestmentRequest")


@_attrs_define
class AddInvestmentRequest:
    """Request body for adding a security investment.

    Attributes:
        name (str): Investment name
        category (str): Category: TOOLS | PERSONNEL | TRAINING | CONSULTING | INSURANCE | INFRASTRUCTURE
        amount_usd (float | Unset): One-time or initial cost (USD) Default: 0.0.
        annual_cost (float | Unset): Recurring annual cost (USD) Default: 0.0.
        start_date (None | str | Unset): Start date YYYY-MM-DD
        description (str | Unset): Investment description Default: ''.
        investment_id (None | str | Unset): Optional explicit ID
    """

    name: str
    category: str
    amount_usd: float | Unset = 0.0
    annual_cost: float | Unset = 0.0
    start_date: None | str | Unset = UNSET
    description: str | Unset = ""
    investment_id: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        category = self.category

        amount_usd = self.amount_usd

        annual_cost = self.annual_cost

        start_date: None | str | Unset
        if isinstance(self.start_date, Unset):
            start_date = UNSET
        else:
            start_date = self.start_date

        description = self.description

        investment_id: None | str | Unset
        if isinstance(self.investment_id, Unset):
            investment_id = UNSET
        else:
            investment_id = self.investment_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
                "category": category,
            }
        )
        if amount_usd is not UNSET:
            field_dict["amount_usd"] = amount_usd
        if annual_cost is not UNSET:
            field_dict["annual_cost"] = annual_cost
        if start_date is not UNSET:
            field_dict["start_date"] = start_date
        if description is not UNSET:
            field_dict["description"] = description
        if investment_id is not UNSET:
            field_dict["investment_id"] = investment_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        category = d.pop("category")

        amount_usd = d.pop("amount_usd", UNSET)

        annual_cost = d.pop("annual_cost", UNSET)

        def _parse_start_date(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        start_date = _parse_start_date(d.pop("start_date", UNSET))

        description = d.pop("description", UNSET)

        def _parse_investment_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        investment_id = _parse_investment_id(d.pop("investment_id", UNSET))

        add_investment_request = cls(
            name=name,
            category=category,
            amount_usd=amount_usd,
            annual_cost=annual_cost,
            start_date=start_date,
            description=description,
            investment_id=investment_id,
        )

        add_investment_request.additional_properties = d
        return add_investment_request

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
