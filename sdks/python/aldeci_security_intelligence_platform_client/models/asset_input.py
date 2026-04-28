from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AssetInput")


@_attrs_define
class AssetInput:
    """
    Attributes:
        id (str | Unset):  Default: ''.
        name (str | Unset):  Default: ''.
        criticality (float | Unset):  Default: 1.0.
        url (None | str | Unset):
        endpoint (None | str | Unset):
        type_ (str | Unset):  Default: 'service'.
    """

    id: str | Unset = ""
    name: str | Unset = ""
    criticality: float | Unset = 1.0
    url: None | str | Unset = UNSET
    endpoint: None | str | Unset = UNSET
    type_: str | Unset = "service"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        id = self.id

        name = self.name

        criticality = self.criticality

        url: None | str | Unset
        if isinstance(self.url, Unset):
            url = UNSET
        else:
            url = self.url

        endpoint: None | str | Unset
        if isinstance(self.endpoint, Unset):
            endpoint = UNSET
        else:
            endpoint = self.endpoint

        type_ = self.type_

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if id is not UNSET:
            field_dict["id"] = id
        if name is not UNSET:
            field_dict["name"] = name
        if criticality is not UNSET:
            field_dict["criticality"] = criticality
        if url is not UNSET:
            field_dict["url"] = url
        if endpoint is not UNSET:
            field_dict["endpoint"] = endpoint
        if type_ is not UNSET:
            field_dict["type"] = type_

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        id = d.pop("id", UNSET)

        name = d.pop("name", UNSET)

        criticality = d.pop("criticality", UNSET)

        def _parse_url(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        url = _parse_url(d.pop("url", UNSET))

        def _parse_endpoint(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        endpoint = _parse_endpoint(d.pop("endpoint", UNSET))

        type_ = d.pop("type", UNSET)

        asset_input = cls(
            id=id,
            name=name,
            criticality=criticality,
            url=url,
            endpoint=endpoint,
            type_=type_,
        )

        asset_input.additional_properties = d
        return asset_input

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
