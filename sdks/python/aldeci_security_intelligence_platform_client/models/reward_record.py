from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.reward_status import RewardStatus
from ..types import UNSET, Unset

T = TypeVar("T", bound="RewardRecord")


@_attrs_define
class RewardRecord:
    """
    Attributes:
        submission_id (str):
        reporter_id (str):
        program_id (str):
        amount (float):
        id (str | Unset):
        bonus_amount (float | Unset):  Default: 0.0.
        status (RewardStatus | Unset):
        currency (str | Unset):  Default: 'USD'.
        created_at (str | Unset):
        approved_at (None | str | Unset):
        paid_at (None | str | Unset):
        notes (str | Unset):  Default: ''.
        org_id (str | Unset):  Default: 'default'.
    """

    submission_id: str
    reporter_id: str
    program_id: str
    amount: float
    id: str | Unset = UNSET
    bonus_amount: float | Unset = 0.0
    status: RewardStatus | Unset = UNSET
    currency: str | Unset = "USD"
    created_at: str | Unset = UNSET
    approved_at: None | str | Unset = UNSET
    paid_at: None | str | Unset = UNSET
    notes: str | Unset = ""
    org_id: str | Unset = "default"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        submission_id = self.submission_id

        reporter_id = self.reporter_id

        program_id = self.program_id

        amount = self.amount

        id = self.id

        bonus_amount = self.bonus_amount

        status: str | Unset = UNSET
        if not isinstance(self.status, Unset):
            status = self.status.value

        currency = self.currency

        created_at = self.created_at

        approved_at: None | str | Unset
        if isinstance(self.approved_at, Unset):
            approved_at = UNSET
        else:
            approved_at = self.approved_at

        paid_at: None | str | Unset
        if isinstance(self.paid_at, Unset):
            paid_at = UNSET
        else:
            paid_at = self.paid_at

        notes = self.notes

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "submission_id": submission_id,
                "reporter_id": reporter_id,
                "program_id": program_id,
                "amount": amount,
            }
        )
        if id is not UNSET:
            field_dict["id"] = id
        if bonus_amount is not UNSET:
            field_dict["bonus_amount"] = bonus_amount
        if status is not UNSET:
            field_dict["status"] = status
        if currency is not UNSET:
            field_dict["currency"] = currency
        if created_at is not UNSET:
            field_dict["created_at"] = created_at
        if approved_at is not UNSET:
            field_dict["approved_at"] = approved_at
        if paid_at is not UNSET:
            field_dict["paid_at"] = paid_at
        if notes is not UNSET:
            field_dict["notes"] = notes
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        submission_id = d.pop("submission_id")

        reporter_id = d.pop("reporter_id")

        program_id = d.pop("program_id")

        amount = d.pop("amount")

        id = d.pop("id", UNSET)

        bonus_amount = d.pop("bonus_amount", UNSET)

        _status = d.pop("status", UNSET)
        status: RewardStatus | Unset
        if isinstance(_status, Unset):
            status = UNSET
        else:
            status = RewardStatus(_status)

        currency = d.pop("currency", UNSET)

        created_at = d.pop("created_at", UNSET)

        def _parse_approved_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        approved_at = _parse_approved_at(d.pop("approved_at", UNSET))

        def _parse_paid_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        paid_at = _parse_paid_at(d.pop("paid_at", UNSET))

        notes = d.pop("notes", UNSET)

        org_id = d.pop("org_id", UNSET)

        reward_record = cls(
            submission_id=submission_id,
            reporter_id=reporter_id,
            program_id=program_id,
            amount=amount,
            id=id,
            bonus_amount=bonus_amount,
            status=status,
            currency=currency,
            created_at=created_at,
            approved_at=approved_at,
            paid_at=paid_at,
            notes=notes,
            org_id=org_id,
        )

        reward_record.additional_properties = d
        return reward_record

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
