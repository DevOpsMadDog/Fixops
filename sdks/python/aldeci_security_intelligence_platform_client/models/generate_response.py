from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="GenerateResponse")


@_attrs_define
class GenerateResponse:
    """Response for /generate.

    Attributes:
        version (str):
        format_ (str):
        content (str):
        entry_count (int):
    """

    version: str
    format_: str
    content: str
    entry_count: int
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        version = self.version

        format_ = self.format_

        content = self.content

        entry_count = self.entry_count

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "version": version,
                "format": format_,
                "content": content,
                "entry_count": entry_count,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        version = d.pop("version")

        format_ = d.pop("format")

        content = d.pop("content")

        entry_count = d.pop("entry_count")

        generate_response = cls(
            version=version,
            format_=format_,
            content=content,
            entry_count=entry_count,
        )

        generate_response.additional_properties = d
        return generate_response

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
