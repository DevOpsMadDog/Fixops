from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="PreflightRequest")


@_attrs_define
class PreflightRequest:
    """
    Attributes:
        rule_keys (list[str]):
        file_count (int | Unset):  Default: 1.
    """

    rule_keys: list[str]
    file_count: int | Unset = 1
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        rule_keys = self.rule_keys

        file_count = self.file_count

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "rule_keys": rule_keys,
            }
        )
        if file_count is not UNSET:
            field_dict["file_count"] = file_count

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        rule_keys = cast(list[str], d.pop("rule_keys"))

        file_count = d.pop("file_count", UNSET)

        preflight_request = cls(
            rule_keys=rule_keys,
            file_count=file_count,
        )

        preflight_request.additional_properties = d
        return preflight_request

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
