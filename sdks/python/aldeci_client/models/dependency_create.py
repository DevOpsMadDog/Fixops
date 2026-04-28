from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="DependencyCreate")


@_attrs_define
class DependencyCreate:
    """
    Attributes:
        depends_on_asset_id (str):
        dependency_type (str | Unset):  Default: 'technical'.
        criticality_impact (str | Unset):  Default: 'medium'.
    """

    depends_on_asset_id: str
    dependency_type: str | Unset = "technical"
    criticality_impact: str | Unset = "medium"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        depends_on_asset_id = self.depends_on_asset_id

        dependency_type = self.dependency_type

        criticality_impact = self.criticality_impact

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "depends_on_asset_id": depends_on_asset_id,
            }
        )
        if dependency_type is not UNSET:
            field_dict["dependency_type"] = dependency_type
        if criticality_impact is not UNSET:
            field_dict["criticality_impact"] = criticality_impact

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        depends_on_asset_id = d.pop("depends_on_asset_id")

        dependency_type = d.pop("dependency_type", UNSET)

        criticality_impact = d.pop("criticality_impact", UNSET)

        dependency_create = cls(
            depends_on_asset_id=depends_on_asset_id,
            dependency_type=dependency_type,
            criticality_impact=criticality_impact,
        )

        dependency_create.additional_properties = d
        return dependency_create

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
