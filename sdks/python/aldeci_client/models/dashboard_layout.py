from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.dashboard_widget import DashboardWidget


T = TypeVar("T", bound="DashboardLayout")


@_attrs_define
class DashboardLayout:
    """A named collection of widgets for a specific persona.

    Attributes:
        name (str):
        id (str | Unset):
        widgets (list[DashboardWidget] | Unset):
        owner (str | Unset):  Default: 'system'.
        org_id (str | Unset):  Default: 'default'.
        generated_at (str | Unset):
        cached (bool | Unset):  Default: False.
    """

    name: str
    id: str | Unset = UNSET
    widgets: list[DashboardWidget] | Unset = UNSET
    owner: str | Unset = "system"
    org_id: str | Unset = "default"
    generated_at: str | Unset = UNSET
    cached: bool | Unset = False
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        id = self.id

        widgets: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.widgets, Unset):
            widgets = []
            for widgets_item_data in self.widgets:
                widgets_item = widgets_item_data.to_dict()
                widgets.append(widgets_item)

        owner = self.owner

        org_id = self.org_id

        generated_at = self.generated_at

        cached = self.cached

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
            }
        )
        if id is not UNSET:
            field_dict["id"] = id
        if widgets is not UNSET:
            field_dict["widgets"] = widgets
        if owner is not UNSET:
            field_dict["owner"] = owner
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if generated_at is not UNSET:
            field_dict["generated_at"] = generated_at
        if cached is not UNSET:
            field_dict["cached"] = cached

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.dashboard_widget import DashboardWidget

        d = dict(src_dict)
        name = d.pop("name")

        id = d.pop("id", UNSET)

        _widgets = d.pop("widgets", UNSET)
        widgets: list[DashboardWidget] | Unset = UNSET
        if _widgets is not UNSET:
            widgets = []
            for widgets_item_data in _widgets:
                widgets_item = DashboardWidget.from_dict(widgets_item_data)

                widgets.append(widgets_item)

        owner = d.pop("owner", UNSET)

        org_id = d.pop("org_id", UNSET)

        generated_at = d.pop("generated_at", UNSET)

        cached = d.pop("cached", UNSET)

        dashboard_layout = cls(
            name=name,
            id=id,
            widgets=widgets,
            owner=owner,
            org_id=org_id,
            generated_at=generated_at,
            cached=cached,
        )

        dashboard_layout.additional_properties = d
        return dashboard_layout

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
