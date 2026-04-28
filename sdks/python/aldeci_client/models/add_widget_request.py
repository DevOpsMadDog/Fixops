from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.add_widget_request_config import AddWidgetRequestConfig


T = TypeVar("T", bound="AddWidgetRequest")


@_attrs_define
class AddWidgetRequest:
    """
    Attributes:
        type_ (str):
        title (str):
        data_source (str):
        config (AddWidgetRequestConfig | Unset):
        order (int | Unset):  Default: 0.
    """

    type_: str
    title: str
    data_source: str
    config: AddWidgetRequestConfig | Unset = UNSET
    order: int | Unset = 0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        type_ = self.type_

        title = self.title

        data_source = self.data_source

        config: dict[str, Any] | Unset = UNSET
        if not isinstance(self.config, Unset):
            config = self.config.to_dict()

        order = self.order

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "type": type_,
                "title": title,
                "data_source": data_source,
            }
        )
        if config is not UNSET:
            field_dict["config"] = config
        if order is not UNSET:
            field_dict["order"] = order

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.add_widget_request_config import AddWidgetRequestConfig

        d = dict(src_dict)
        type_ = d.pop("type")

        title = d.pop("title")

        data_source = d.pop("data_source")

        _config = d.pop("config", UNSET)
        config: AddWidgetRequestConfig | Unset
        if isinstance(_config, Unset):
            config = UNSET
        else:
            config = AddWidgetRequestConfig.from_dict(_config)

        order = d.pop("order", UNSET)

        add_widget_request = cls(
            type_=type_,
            title=title,
            data_source=data_source,
            config=config,
            order=order,
        )

        add_widget_request.additional_properties = d
        return add_widget_request

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
