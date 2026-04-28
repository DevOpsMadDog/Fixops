from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ConnectorMappingRequest")


@_attrs_define
class ConnectorMappingRequest:
    """
    Attributes:
        connector_id (str):
        source_field (str):
        target_field (str):
        transform (None | str | Unset):
        enabled (bool | Unset):  Default: True.
    """

    connector_id: str
    source_field: str
    target_field: str
    transform: None | str | Unset = UNSET
    enabled: bool | Unset = True
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        connector_id = self.connector_id

        source_field = self.source_field

        target_field = self.target_field

        transform: None | str | Unset
        if isinstance(self.transform, Unset):
            transform = UNSET
        else:
            transform = self.transform

        enabled = self.enabled

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "connector_id": connector_id,
                "source_field": source_field,
                "target_field": target_field,
            }
        )
        if transform is not UNSET:
            field_dict["transform"] = transform
        if enabled is not UNSET:
            field_dict["enabled"] = enabled

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        connector_id = d.pop("connector_id")

        source_field = d.pop("source_field")

        target_field = d.pop("target_field")

        def _parse_transform(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        transform = _parse_transform(d.pop("transform", UNSET))

        enabled = d.pop("enabled", UNSET)

        connector_mapping_request = cls(
            connector_id=connector_id,
            source_field=source_field,
            target_field=target_field,
            transform=transform,
            enabled=enabled,
        )

        connector_mapping_request.additional_properties = d
        return connector_mapping_request

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
