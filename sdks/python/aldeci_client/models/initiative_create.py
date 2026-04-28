from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="InitiativeCreate")


@_attrs_define
class InitiativeCreate:
    """
    Attributes:
        initiative_name (str):
        initiative_type (str):
        start_date (str):
        end_date (str):
        target_audience (str | Unset):  Default: ''.
    """

    initiative_name: str
    initiative_type: str
    start_date: str
    end_date: str
    target_audience: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        initiative_name = self.initiative_name

        initiative_type = self.initiative_type

        start_date = self.start_date

        end_date = self.end_date

        target_audience = self.target_audience

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "initiative_name": initiative_name,
                "initiative_type": initiative_type,
                "start_date": start_date,
                "end_date": end_date,
            }
        )
        if target_audience is not UNSET:
            field_dict["target_audience"] = target_audience

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        initiative_name = d.pop("initiative_name")

        initiative_type = d.pop("initiative_type")

        start_date = d.pop("start_date")

        end_date = d.pop("end_date")

        target_audience = d.pop("target_audience", UNSET)

        initiative_create = cls(
            initiative_name=initiative_name,
            initiative_type=initiative_type,
            start_date=start_date,
            end_date=end_date,
            target_audience=target_audience,
        )

        initiative_create.additional_properties = d
        return initiative_create

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
