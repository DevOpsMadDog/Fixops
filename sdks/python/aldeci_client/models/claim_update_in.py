from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ClaimUpdateIn")


@_attrs_define
class ClaimUpdateIn:
    """
    Attributes:
        status (str):
        settlement_amount (float | None | Unset):
    """

    status: str
    settlement_amount: float | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        status = self.status

        settlement_amount: float | None | Unset
        if isinstance(self.settlement_amount, Unset):
            settlement_amount = UNSET
        else:
            settlement_amount = self.settlement_amount

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "status": status,
            }
        )
        if settlement_amount is not UNSET:
            field_dict["settlement_amount"] = settlement_amount

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        status = d.pop("status")

        def _parse_settlement_amount(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        settlement_amount = _parse_settlement_amount(d.pop("settlement_amount", UNSET))

        claim_update_in = cls(
            status=status,
            settlement_amount=settlement_amount,
        )

        claim_update_in.additional_properties = d
        return claim_update_in

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
