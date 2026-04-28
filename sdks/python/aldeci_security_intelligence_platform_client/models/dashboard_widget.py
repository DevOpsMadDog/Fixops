from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.widget_type import WidgetType
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.dashboard_widget_config import DashboardWidgetConfig
    from ..models.dashboard_widget_data import DashboardWidgetData


T = TypeVar("T", bound="DashboardWidget")


@_attrs_define
class DashboardWidget:
    """A single visual unit rendered on a dashboard.

    Attributes:
        title (str):
        type_ (WidgetType):
        id (str | Unset):
        data (DashboardWidgetData | Unset):
        config (DashboardWidgetConfig | Unset):
    """

    title: str
    type_: WidgetType
    id: str | Unset = UNSET
    data: DashboardWidgetData | Unset = UNSET
    config: DashboardWidgetConfig | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        title = self.title

        type_ = self.type_.value

        id = self.id

        data: dict[str, Any] | Unset = UNSET
        if not isinstance(self.data, Unset):
            data = self.data.to_dict()

        config: dict[str, Any] | Unset = UNSET
        if not isinstance(self.config, Unset):
            config = self.config.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "title": title,
                "type": type_,
            }
        )
        if id is not UNSET:
            field_dict["id"] = id
        if data is not UNSET:
            field_dict["data"] = data
        if config is not UNSET:
            field_dict["config"] = config

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.dashboard_widget_config import DashboardWidgetConfig
        from ..models.dashboard_widget_data import DashboardWidgetData

        d = dict(src_dict)
        title = d.pop("title")

        type_ = WidgetType(d.pop("type"))

        id = d.pop("id", UNSET)

        _data = d.pop("data", UNSET)
        data: DashboardWidgetData | Unset
        if isinstance(_data, Unset):
            data = UNSET
        else:
            data = DashboardWidgetData.from_dict(_data)

        _config = d.pop("config", UNSET)
        config: DashboardWidgetConfig | Unset
        if isinstance(_config, Unset):
            config = UNSET
        else:
            config = DashboardWidgetConfig.from_dict(_config)

        dashboard_widget = cls(
            title=title,
            type_=type_,
            id=id,
            data=data,
            config=config,
        )

        dashboard_widget.additional_properties = d
        return dashboard_widget

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
