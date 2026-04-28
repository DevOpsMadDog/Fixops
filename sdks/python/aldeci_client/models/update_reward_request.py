from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.reward_status import RewardStatus
from ..types import UNSET, Unset

T = TypeVar("T", bound="UpdateRewardRequest")


@_attrs_define
class UpdateRewardRequest:
    """
    Attributes:
        status (RewardStatus):
        bonus_amount (float | Unset): Bonus amount on top of base reward (USD) Default: 0.0.
        notes (str | Unset): Reward notes (payment reference, justification, etc.) Default: ''.
    """

    status: RewardStatus
    bonus_amount: float | Unset = 0.0
    notes: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        status = self.status.value

        bonus_amount = self.bonus_amount

        notes = self.notes

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "status": status,
            }
        )
        if bonus_amount is not UNSET:
            field_dict["bonus_amount"] = bonus_amount
        if notes is not UNSET:
            field_dict["notes"] = notes

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        status = RewardStatus(d.pop("status"))

        bonus_amount = d.pop("bonus_amount", UNSET)

        notes = d.pop("notes", UNSET)

        update_reward_request = cls(
            status=status,
            bonus_amount=bonus_amount,
            notes=notes,
        )

        update_reward_request.additional_properties = d
        return update_reward_request

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
