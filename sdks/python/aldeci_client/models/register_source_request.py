from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RegisterSourceRequest")


@_attrs_define
class RegisterSourceRequest:
    """
    Attributes:
        source_name (str): Unique source name
        source_type (str): threat_intel | asset_db | vuln_db | geolocation | reputation
        priority (int | Unset): Priority (lower = higher priority) Default: 1.
        api_key (str | Unset): API key (stored as SHA-256 hash) Default: ''.
    """

    source_name: str
    source_type: str
    priority: int | Unset = 1
    api_key: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        source_name = self.source_name

        source_type = self.source_type

        priority = self.priority

        api_key = self.api_key

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "source_name": source_name,
                "source_type": source_type,
            }
        )
        if priority is not UNSET:
            field_dict["priority"] = priority
        if api_key is not UNSET:
            field_dict["api_key"] = api_key

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        source_name = d.pop("source_name")

        source_type = d.pop("source_type")

        priority = d.pop("priority", UNSET)

        api_key = d.pop("api_key", UNSET)

        register_source_request = cls(
            source_name=source_name,
            source_type=source_type,
            priority=priority,
            api_key=api_key,
        )

        register_source_request.additional_properties = d
        return register_source_request

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
