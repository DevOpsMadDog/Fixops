from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="GenerateRequest")


@_attrs_define
class GenerateRequest:
    """
    Attributes:
        name (str): Feature/system name
        description (str): Feature/system description
        components (list[str]): Component names (e.g. 'web-frontend', 'api-gateway', 'database')
        data_flows (list[str] | Unset): Data flows (e.g. 'user->api->db')
        stride_filter (list[str] | None | Unset): Filter to specific STRIDE categories
    """

    name: str
    description: str
    components: list[str]
    data_flows: list[str] | Unset = UNSET
    stride_filter: list[str] | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        description = self.description

        components = self.components

        data_flows: list[str] | Unset = UNSET
        if not isinstance(self.data_flows, Unset):
            data_flows = self.data_flows

        stride_filter: list[str] | None | Unset
        if isinstance(self.stride_filter, Unset):
            stride_filter = UNSET
        elif isinstance(self.stride_filter, list):
            stride_filter = self.stride_filter

        else:
            stride_filter = self.stride_filter

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
                "description": description,
                "components": components,
            }
        )
        if data_flows is not UNSET:
            field_dict["data_flows"] = data_flows
        if stride_filter is not UNSET:
            field_dict["stride_filter"] = stride_filter

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        description = d.pop("description")

        components = cast(list[str], d.pop("components"))

        data_flows = cast(list[str], d.pop("data_flows", UNSET))

        def _parse_stride_filter(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                stride_filter_type_0 = cast(list[str], data)

                return stride_filter_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        stride_filter = _parse_stride_filter(d.pop("stride_filter", UNSET))

        generate_request = cls(
            name=name,
            description=description,
            components=components,
            data_flows=data_flows,
            stride_filter=stride_filter,
        )

        generate_request.additional_properties = d
        return generate_request

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
