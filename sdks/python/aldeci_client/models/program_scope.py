from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.owasp_category import OWASPCategory
from ..types import UNSET, Unset

T = TypeVar("T", bound="ProgramScope")


@_attrs_define
class ProgramScope:
    """
    Attributes:
        in_scope (list[str] | Unset): In-scope assets (domains, IPs, repos)
        out_of_scope (list[str] | Unset): Explicitly out-of-scope assets
        vulnerability_types (list[OWASPCategory] | Unset): Accepted vulnerability categories
    """

    in_scope: list[str] | Unset = UNSET
    out_of_scope: list[str] | Unset = UNSET
    vulnerability_types: list[OWASPCategory] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        in_scope: list[str] | Unset = UNSET
        if not isinstance(self.in_scope, Unset):
            in_scope = self.in_scope

        out_of_scope: list[str] | Unset = UNSET
        if not isinstance(self.out_of_scope, Unset):
            out_of_scope = self.out_of_scope

        vulnerability_types: list[str] | Unset = UNSET
        if not isinstance(self.vulnerability_types, Unset):
            vulnerability_types = []
            for vulnerability_types_item_data in self.vulnerability_types:
                vulnerability_types_item = vulnerability_types_item_data.value
                vulnerability_types.append(vulnerability_types_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if in_scope is not UNSET:
            field_dict["in_scope"] = in_scope
        if out_of_scope is not UNSET:
            field_dict["out_of_scope"] = out_of_scope
        if vulnerability_types is not UNSET:
            field_dict["vulnerability_types"] = vulnerability_types

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        in_scope = cast(list[str], d.pop("in_scope", UNSET))

        out_of_scope = cast(list[str], d.pop("out_of_scope", UNSET))

        _vulnerability_types = d.pop("vulnerability_types", UNSET)
        vulnerability_types: list[OWASPCategory] | Unset = UNSET
        if _vulnerability_types is not UNSET:
            vulnerability_types = []
            for vulnerability_types_item_data in _vulnerability_types:
                vulnerability_types_item = OWASPCategory(vulnerability_types_item_data)

                vulnerability_types.append(vulnerability_types_item)

        program_scope = cls(
            in_scope=in_scope,
            out_of_scope=out_of_scope,
            vulnerability_types=vulnerability_types,
        )

        program_scope.additional_properties = d
        return program_scope

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
