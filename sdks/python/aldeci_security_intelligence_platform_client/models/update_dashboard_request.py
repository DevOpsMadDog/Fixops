from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.update_dashboard_request_layout_type_0 import UpdateDashboardRequestLayoutType0


T = TypeVar("T", bound="UpdateDashboardRequest")


@_attrs_define
class UpdateDashboardRequest:
    """
    Attributes:
        name (None | str | Unset):
        description (None | str | Unset):
        visibility (None | str | Unset):
        layout (None | Unset | UpdateDashboardRequestLayoutType0):
    """

    name: None | str | Unset = UNSET
    description: None | str | Unset = UNSET
    visibility: None | str | Unset = UNSET
    layout: None | Unset | UpdateDashboardRequestLayoutType0 = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.update_dashboard_request_layout_type_0 import UpdateDashboardRequestLayoutType0

        name: None | str | Unset
        if isinstance(self.name, Unset):
            name = UNSET
        else:
            name = self.name

        description: None | str | Unset
        if isinstance(self.description, Unset):
            description = UNSET
        else:
            description = self.description

        visibility: None | str | Unset
        if isinstance(self.visibility, Unset):
            visibility = UNSET
        else:
            visibility = self.visibility

        layout: dict[str, Any] | None | Unset
        if isinstance(self.layout, Unset):
            layout = UNSET
        elif isinstance(self.layout, UpdateDashboardRequestLayoutType0):
            layout = self.layout.to_dict()
        else:
            layout = self.layout

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if name is not UNSET:
            field_dict["name"] = name
        if description is not UNSET:
            field_dict["description"] = description
        if visibility is not UNSET:
            field_dict["visibility"] = visibility
        if layout is not UNSET:
            field_dict["layout"] = layout

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.update_dashboard_request_layout_type_0 import UpdateDashboardRequestLayoutType0

        d = dict(src_dict)

        def _parse_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        name = _parse_name(d.pop("name", UNSET))

        def _parse_description(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        description = _parse_description(d.pop("description", UNSET))

        def _parse_visibility(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        visibility = _parse_visibility(d.pop("visibility", UNSET))

        def _parse_layout(data: object) -> None | Unset | UpdateDashboardRequestLayoutType0:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                layout_type_0 = UpdateDashboardRequestLayoutType0.from_dict(data)

                return layout_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | Unset | UpdateDashboardRequestLayoutType0, data)

        layout = _parse_layout(d.pop("layout", UNSET))

        update_dashboard_request = cls(
            name=name,
            description=description,
            visibility=visibility,
            layout=layout,
        )

        update_dashboard_request.additional_properties = d
        return update_dashboard_request

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
