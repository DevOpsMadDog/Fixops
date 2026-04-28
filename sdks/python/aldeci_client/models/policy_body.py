from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="PolicyBody")


@_attrs_define
class PolicyBody:
    """
    Attributes:
        name (str | Unset):  Default: 'Default Policy'.
        min_length (int | Unset):  Default: 8.
        require_uppercase (bool | Unset):  Default: False.
        require_lowercase (bool | Unset):  Default: False.
        require_numbers (bool | Unset):  Default: False.
        require_symbols (bool | Unset):  Default: False.
        max_age_days (int | Unset):  Default: 90.
        min_history (int | Unset):  Default: 5.
        lockout_attempts (int | Unset):  Default: 5.
    """

    name: str | Unset = "Default Policy"
    min_length: int | Unset = 8
    require_uppercase: bool | Unset = False
    require_lowercase: bool | Unset = False
    require_numbers: bool | Unset = False
    require_symbols: bool | Unset = False
    max_age_days: int | Unset = 90
    min_history: int | Unset = 5
    lockout_attempts: int | Unset = 5
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        min_length = self.min_length

        require_uppercase = self.require_uppercase

        require_lowercase = self.require_lowercase

        require_numbers = self.require_numbers

        require_symbols = self.require_symbols

        max_age_days = self.max_age_days

        min_history = self.min_history

        lockout_attempts = self.lockout_attempts

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if name is not UNSET:
            field_dict["name"] = name
        if min_length is not UNSET:
            field_dict["min_length"] = min_length
        if require_uppercase is not UNSET:
            field_dict["require_uppercase"] = require_uppercase
        if require_lowercase is not UNSET:
            field_dict["require_lowercase"] = require_lowercase
        if require_numbers is not UNSET:
            field_dict["require_numbers"] = require_numbers
        if require_symbols is not UNSET:
            field_dict["require_symbols"] = require_symbols
        if max_age_days is not UNSET:
            field_dict["max_age_days"] = max_age_days
        if min_history is not UNSET:
            field_dict["min_history"] = min_history
        if lockout_attempts is not UNSET:
            field_dict["lockout_attempts"] = lockout_attempts

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name", UNSET)

        min_length = d.pop("min_length", UNSET)

        require_uppercase = d.pop("require_uppercase", UNSET)

        require_lowercase = d.pop("require_lowercase", UNSET)

        require_numbers = d.pop("require_numbers", UNSET)

        require_symbols = d.pop("require_symbols", UNSET)

        max_age_days = d.pop("max_age_days", UNSET)

        min_history = d.pop("min_history", UNSET)

        lockout_attempts = d.pop("lockout_attempts", UNSET)

        policy_body = cls(
            name=name,
            min_length=min_length,
            require_uppercase=require_uppercase,
            require_lowercase=require_lowercase,
            require_numbers=require_numbers,
            require_symbols=require_symbols,
            max_age_days=max_age_days,
            min_history=min_history,
            lockout_attempts=lockout_attempts,
        )

        policy_body.additional_properties = d
        return policy_body

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
