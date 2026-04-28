from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="LinkApiBody")


@_attrs_define
class LinkApiBody:
    """
    Attributes:
        endpoint_path (str): API endpoint path
        layer (str | Unset): data | api | ui | service | standalone Default: 'api'.
    """

    endpoint_path: str
    layer: str | Unset = "api"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        endpoint_path = self.endpoint_path

        layer = self.layer

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "endpoint_path": endpoint_path,
            }
        )
        if layer is not UNSET:
            field_dict["layer"] = layer

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        endpoint_path = d.pop("endpoint_path")

        layer = d.pop("layer", UNSET)

        link_api_body = cls(
            endpoint_path=endpoint_path,
            layer=layer,
        )

        link_api_body.additional_properties = d
        return link_api_body

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
