from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CreateViewRequest")


@_attrs_define
class CreateViewRequest:
    """
    Attributes:
        view_name (str): Name for this calendar view
        frameworks (list[str] | Unset): Frameworks to include
        event_types (list[str] | Unset): Event types to include
    """

    view_name: str
    frameworks: list[str] | Unset = UNSET
    event_types: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        view_name = self.view_name

        frameworks: list[str] | Unset = UNSET
        if not isinstance(self.frameworks, Unset):
            frameworks = self.frameworks

        event_types: list[str] | Unset = UNSET
        if not isinstance(self.event_types, Unset):
            event_types = self.event_types

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "view_name": view_name,
            }
        )
        if frameworks is not UNSET:
            field_dict["frameworks"] = frameworks
        if event_types is not UNSET:
            field_dict["event_types"] = event_types

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        view_name = d.pop("view_name")

        frameworks = cast(list[str], d.pop("frameworks", UNSET))

        event_types = cast(list[str], d.pop("event_types", UNSET))

        create_view_request = cls(
            view_name=view_name,
            frameworks=frameworks,
            event_types=event_types,
        )

        create_view_request.additional_properties = d
        return create_view_request

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
