from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ObjectiveCreate")


@_attrs_define
class ObjectiveCreate:
    """Request body for creating an OKR objective.

    Attributes:
        title (str):
        quarter (str): e.g. Q2-2026
        owner (str | Unset):  Default: 'security-team'.
    """

    title: str
    quarter: str
    owner: str | Unset = "security-team"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        title = self.title

        quarter = self.quarter

        owner = self.owner

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "title": title,
                "quarter": quarter,
            }
        )
        if owner is not UNSET:
            field_dict["owner"] = owner

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        title = d.pop("title")

        quarter = d.pop("quarter")

        owner = d.pop("owner", UNSET)

        objective_create = cls(
            title=title,
            quarter=quarter,
            owner=owner,
        )

        objective_create.additional_properties = d
        return objective_create

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
