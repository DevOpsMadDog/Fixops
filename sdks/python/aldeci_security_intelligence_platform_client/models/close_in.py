from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CloseIn")


@_attrs_define
class CloseIn:
    """
    Attributes:
        closed_by (str | Unset):  Default: ''.
        outcome (str | Unset):  Default: ''.
    """

    closed_by: str | Unset = ""
    outcome: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        closed_by = self.closed_by

        outcome = self.outcome

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if closed_by is not UNSET:
            field_dict["closed_by"] = closed_by
        if outcome is not UNSET:
            field_dict["outcome"] = outcome

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        closed_by = d.pop("closed_by", UNSET)

        outcome = d.pop("outcome", UNSET)

        close_in = cls(
            closed_by=closed_by,
            outcome=outcome,
        )

        close_in.additional_properties = d
        return close_in

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
