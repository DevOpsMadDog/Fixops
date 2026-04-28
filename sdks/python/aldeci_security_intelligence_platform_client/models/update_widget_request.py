from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.update_widget_request_config_type_0 import UpdateWidgetRequestConfigType0


T = TypeVar("T", bound="UpdateWidgetRequest")


@_attrs_define
class UpdateWidgetRequest:
    """
    Attributes:
        type_ (None | str | Unset):
        title (None | str | Unset):
        data_source (None | str | Unset):
        config (None | Unset | UpdateWidgetRequestConfigType0):
        order (int | None | Unset):
    """

    type_: None | str | Unset = UNSET
    title: None | str | Unset = UNSET
    data_source: None | str | Unset = UNSET
    config: None | Unset | UpdateWidgetRequestConfigType0 = UNSET
    order: int | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.update_widget_request_config_type_0 import UpdateWidgetRequestConfigType0

        type_: None | str | Unset
        if isinstance(self.type_, Unset):
            type_ = UNSET
        else:
            type_ = self.type_

        title: None | str | Unset
        if isinstance(self.title, Unset):
            title = UNSET
        else:
            title = self.title

        data_source: None | str | Unset
        if isinstance(self.data_source, Unset):
            data_source = UNSET
        else:
            data_source = self.data_source

        config: dict[str, Any] | None | Unset
        if isinstance(self.config, Unset):
            config = UNSET
        elif isinstance(self.config, UpdateWidgetRequestConfigType0):
            config = self.config.to_dict()
        else:
            config = self.config

        order: int | None | Unset
        if isinstance(self.order, Unset):
            order = UNSET
        else:
            order = self.order

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if type_ is not UNSET:
            field_dict["type"] = type_
        if title is not UNSET:
            field_dict["title"] = title
        if data_source is not UNSET:
            field_dict["data_source"] = data_source
        if config is not UNSET:
            field_dict["config"] = config
        if order is not UNSET:
            field_dict["order"] = order

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.update_widget_request_config_type_0 import UpdateWidgetRequestConfigType0

        d = dict(src_dict)

        def _parse_type_(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        type_ = _parse_type_(d.pop("type", UNSET))

        def _parse_title(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        title = _parse_title(d.pop("title", UNSET))

        def _parse_data_source(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        data_source = _parse_data_source(d.pop("data_source", UNSET))

        def _parse_config(data: object) -> None | Unset | UpdateWidgetRequestConfigType0:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                config_type_0 = UpdateWidgetRequestConfigType0.from_dict(data)

                return config_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | Unset | UpdateWidgetRequestConfigType0, data)

        config = _parse_config(d.pop("config", UNSET))

        def _parse_order(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        order = _parse_order(d.pop("order", UNSET))

        update_widget_request = cls(
            type_=type_,
            title=title,
            data_source=data_source,
            config=config,
            order=order,
        )

        update_widget_request.additional_properties = d
        return update_widget_request

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
