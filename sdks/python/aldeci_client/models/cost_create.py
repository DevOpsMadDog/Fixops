from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CostCreate")


@_attrs_define
class CostCreate:
    """
    Attributes:
        incident_id (str):
        incident_name (str):
        incident_type (str):
        cost_category (str):
        amount (float):
        currency (str | Unset):  Default: 'USD'.
        estimated (bool | Unset):  Default: False.
        description (str | Unset):  Default: ''.
        recorded_by (str | Unset):  Default: ''.
    """

    incident_id: str
    incident_name: str
    incident_type: str
    cost_category: str
    amount: float
    currency: str | Unset = "USD"
    estimated: bool | Unset = False
    description: str | Unset = ""
    recorded_by: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        incident_id = self.incident_id

        incident_name = self.incident_name

        incident_type = self.incident_type

        cost_category = self.cost_category

        amount = self.amount

        currency = self.currency

        estimated = self.estimated

        description = self.description

        recorded_by = self.recorded_by

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "incident_id": incident_id,
                "incident_name": incident_name,
                "incident_type": incident_type,
                "cost_category": cost_category,
                "amount": amount,
            }
        )
        if currency is not UNSET:
            field_dict["currency"] = currency
        if estimated is not UNSET:
            field_dict["estimated"] = estimated
        if description is not UNSET:
            field_dict["description"] = description
        if recorded_by is not UNSET:
            field_dict["recorded_by"] = recorded_by

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        incident_id = d.pop("incident_id")

        incident_name = d.pop("incident_name")

        incident_type = d.pop("incident_type")

        cost_category = d.pop("cost_category")

        amount = d.pop("amount")

        currency = d.pop("currency", UNSET)

        estimated = d.pop("estimated", UNSET)

        description = d.pop("description", UNSET)

        recorded_by = d.pop("recorded_by", UNSET)

        cost_create = cls(
            incident_id=incident_id,
            incident_name=incident_name,
            incident_type=incident_type,
            cost_category=cost_category,
            amount=amount,
            currency=currency,
            estimated=estimated,
            description=description,
            recorded_by=recorded_by,
        )

        cost_create.additional_properties = d
        return cost_create

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
