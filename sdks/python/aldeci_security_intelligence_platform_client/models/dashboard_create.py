from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="DashboardCreate")


@_attrs_define
class DashboardCreate:
    """
    Attributes:
        name (str):
        dashboard_type (str | Unset):  Default: 'operational'.
        refresh_interval (int | Unset):  Default: 60.
        widgets (list[Any] | Unset):
    """

    name: str
    dashboard_type: str | Unset = "operational"
    refresh_interval: int | Unset = 60
    widgets: list[Any] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        dashboard_type = self.dashboard_type

        refresh_interval = self.refresh_interval

        widgets: list[Any] | Unset = UNSET
        if not isinstance(self.widgets, Unset):
            widgets = self.widgets

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
            }
        )
        if dashboard_type is not UNSET:
            field_dict["dashboard_type"] = dashboard_type
        if refresh_interval is not UNSET:
            field_dict["refresh_interval"] = refresh_interval
        if widgets is not UNSET:
            field_dict["widgets"] = widgets

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        dashboard_type = d.pop("dashboard_type", UNSET)

        refresh_interval = d.pop("refresh_interval", UNSET)

        widgets = cast(list[Any], d.pop("widgets", UNSET))

        dashboard_create = cls(
            name=name,
            dashboard_type=dashboard_type,
            refresh_interval=refresh_interval,
            widgets=widgets,
        )

        dashboard_create.additional_properties = d
        return dashboard_create

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
