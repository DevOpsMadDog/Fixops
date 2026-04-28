from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.sbom_import_in_components_item import SBOMImportInComponentsItem


T = TypeVar("T", bound="SBOMImportIn")


@_attrs_define
class SBOMImportIn:
    """
    Attributes:
        components (list[SBOMImportInComponentsItem] | Unset):
    """

    components: list[SBOMImportInComponentsItem] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        components: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.components, Unset):
            components = []
            for components_item_data in self.components:
                components_item = components_item_data.to_dict()
                components.append(components_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if components is not UNSET:
            field_dict["components"] = components

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.sbom_import_in_components_item import SBOMImportInComponentsItem

        d = dict(src_dict)
        _components = d.pop("components", UNSET)
        components: list[SBOMImportInComponentsItem] | Unset = UNSET
        if _components is not UNSET:
            components = []
            for components_item_data in _components:
                components_item = SBOMImportInComponentsItem.from_dict(components_item_data)

                components.append(components_item)

        sbom_import_in = cls(
            components=components,
        )

        sbom_import_in.additional_properties = d
        return sbom_import_in

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
