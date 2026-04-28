from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RecordSpendRequest")


@_attrs_define
class RecordSpendRequest:
    """
    Attributes:
        allocation_id (str): ID of the budget allocation
        vendor_name (str): Vendor or payee name
        amount (float): Transaction amount
        description (str | Unset): Spend description Default: ''.
        transaction_date (None | str | Unset): ISO date of transaction
    """

    allocation_id: str
    vendor_name: str
    amount: float
    description: str | Unset = ""
    transaction_date: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        allocation_id = self.allocation_id

        vendor_name = self.vendor_name

        amount = self.amount

        description = self.description

        transaction_date: None | str | Unset
        if isinstance(self.transaction_date, Unset):
            transaction_date = UNSET
        else:
            transaction_date = self.transaction_date

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "allocation_id": allocation_id,
                "vendor_name": vendor_name,
                "amount": amount,
            }
        )
        if description is not UNSET:
            field_dict["description"] = description
        if transaction_date is not UNSET:
            field_dict["transaction_date"] = transaction_date

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        allocation_id = d.pop("allocation_id")

        vendor_name = d.pop("vendor_name")

        amount = d.pop("amount")

        description = d.pop("description", UNSET)

        def _parse_transaction_date(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        transaction_date = _parse_transaction_date(d.pop("transaction_date", UNSET))

        record_spend_request = cls(
            allocation_id=allocation_id,
            vendor_name=vendor_name,
            amount=amount,
            description=description,
            transaction_date=transaction_date,
        )

        record_spend_request.additional_properties = d
        return record_spend_request

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
