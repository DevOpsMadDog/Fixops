from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="MarkFailedRequest")


@_attrs_define
class MarkFailedRequest:
    """
    Attributes:
        source_name (str): Enrichment source that failed
        error_msg (str): Error description
    """

    source_name: str
    error_msg: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        source_name = self.source_name

        error_msg = self.error_msg

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "source_name": source_name,
                "error_msg": error_msg,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        source_name = d.pop("source_name")

        error_msg = d.pop("error_msg")

        mark_failed_request = cls(
            source_name=source_name,
            error_msg=error_msg,
        )

        mark_failed_request.additional_properties = d
        return mark_failed_request

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
