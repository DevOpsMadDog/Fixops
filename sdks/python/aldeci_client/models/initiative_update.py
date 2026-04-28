from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="InitiativeUpdate")


@_attrs_define
class InitiativeUpdate:
    """
    Attributes:
        status (None | str | Unset):
        owner (None | str | Unset):
        budget_usd (float | None | Unset):
        target_date (None | str | Unset):
    """

    status: None | str | Unset = UNSET
    owner: None | str | Unset = UNSET
    budget_usd: float | None | Unset = UNSET
    target_date: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        status: None | str | Unset
        if isinstance(self.status, Unset):
            status = UNSET
        else:
            status = self.status

        owner: None | str | Unset
        if isinstance(self.owner, Unset):
            owner = UNSET
        else:
            owner = self.owner

        budget_usd: float | None | Unset
        if isinstance(self.budget_usd, Unset):
            budget_usd = UNSET
        else:
            budget_usd = self.budget_usd

        target_date: None | str | Unset
        if isinstance(self.target_date, Unset):
            target_date = UNSET
        else:
            target_date = self.target_date

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if status is not UNSET:
            field_dict["status"] = status
        if owner is not UNSET:
            field_dict["owner"] = owner
        if budget_usd is not UNSET:
            field_dict["budget_usd"] = budget_usd
        if target_date is not UNSET:
            field_dict["target_date"] = target_date

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_status(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        status = _parse_status(d.pop("status", UNSET))

        def _parse_owner(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        owner = _parse_owner(d.pop("owner", UNSET))

        def _parse_budget_usd(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        budget_usd = _parse_budget_usd(d.pop("budget_usd", UNSET))

        def _parse_target_date(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        target_date = _parse_target_date(d.pop("target_date", UNSET))

        initiative_update = cls(
            status=status,
            owner=owner,
            budget_usd=budget_usd,
            target_date=target_date,
        )

        initiative_update.additional_properties = d
        return initiative_update

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
