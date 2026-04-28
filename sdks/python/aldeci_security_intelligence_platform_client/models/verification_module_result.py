from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="VerificationModuleResult")


@_attrs_define
class VerificationModuleResult:
    """
    Attributes:
        module (str):
        sqlite_count (int):
        trustgraph_count (int):
        match (bool):
    """

    module: str
    sqlite_count: int
    trustgraph_count: int
    match: bool
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        module = self.module

        sqlite_count = self.sqlite_count

        trustgraph_count = self.trustgraph_count

        match = self.match

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "module": module,
                "sqlite_count": sqlite_count,
                "trustgraph_count": trustgraph_count,
                "match": match,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        module = d.pop("module")

        sqlite_count = d.pop("sqlite_count")

        trustgraph_count = d.pop("trustgraph_count")

        match = d.pop("match")

        verification_module_result = cls(
            module=module,
            sqlite_count=sqlite_count,
            trustgraph_count=trustgraph_count,
            match=match,
        )

        verification_module_result.additional_properties = d
        return verification_module_result

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
