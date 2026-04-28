from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.widget_create_config import WidgetCreateConfig


T = TypeVar("T", bound="WidgetCreate")


@_attrs_define
class WidgetCreate:
    """
    Attributes:
        widget_type (str):
        metric_name (str):
        data_source (str):
        config (WidgetCreateConfig | Unset):
        position_x (int | Unset):  Default: 0.
        position_y (int | Unset):  Default: 0.
    """

    widget_type: str
    metric_name: str
    data_source: str
    config: WidgetCreateConfig | Unset = UNSET
    position_x: int | Unset = 0
    position_y: int | Unset = 0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        widget_type = self.widget_type

        metric_name = self.metric_name

        data_source = self.data_source

        config: dict[str, Any] | Unset = UNSET
        if not isinstance(self.config, Unset):
            config = self.config.to_dict()

        position_x = self.position_x

        position_y = self.position_y

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "widget_type": widget_type,
                "metric_name": metric_name,
                "data_source": data_source,
            }
        )
        if config is not UNSET:
            field_dict["config"] = config
        if position_x is not UNSET:
            field_dict["position_x"] = position_x
        if position_y is not UNSET:
            field_dict["position_y"] = position_y

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.widget_create_config import WidgetCreateConfig

        d = dict(src_dict)
        widget_type = d.pop("widget_type")

        metric_name = d.pop("metric_name")

        data_source = d.pop("data_source")

        _config = d.pop("config", UNSET)
        config: WidgetCreateConfig | Unset
        if isinstance(_config, Unset):
            config = UNSET
        else:
            config = WidgetCreateConfig.from_dict(_config)

        position_x = d.pop("position_x", UNSET)

        position_y = d.pop("position_y", UNSET)

        widget_create = cls(
            widget_type=widget_type,
            metric_name=metric_name,
            data_source=data_source,
            config=config,
            position_x=position_x,
            position_y=position_y,
        )

        widget_create.additional_properties = d
        return widget_create

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
