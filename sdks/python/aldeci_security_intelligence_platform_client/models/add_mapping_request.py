from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AddMappingRequest")


@_attrs_define
class AddMappingRequest:
    """
    Attributes:
        source_control_id (str): Source control identifier
        target_control_id (str): Target control identifier
        source_framework (str): Source framework key
        target_framework (str): Target framework key
        mapping_strength (str): strong | moderate | weak
        notes (None | str | Unset):
    """

    source_control_id: str
    target_control_id: str
    source_framework: str
    target_framework: str
    mapping_strength: str
    notes: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        source_control_id = self.source_control_id

        target_control_id = self.target_control_id

        source_framework = self.source_framework

        target_framework = self.target_framework

        mapping_strength = self.mapping_strength

        notes: None | str | Unset
        if isinstance(self.notes, Unset):
            notes = UNSET
        else:
            notes = self.notes

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "source_control_id": source_control_id,
                "target_control_id": target_control_id,
                "source_framework": source_framework,
                "target_framework": target_framework,
                "mapping_strength": mapping_strength,
            }
        )
        if notes is not UNSET:
            field_dict["notes"] = notes

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        source_control_id = d.pop("source_control_id")

        target_control_id = d.pop("target_control_id")

        source_framework = d.pop("source_framework")

        target_framework = d.pop("target_framework")

        mapping_strength = d.pop("mapping_strength")

        def _parse_notes(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        notes = _parse_notes(d.pop("notes", UNSET))

        add_mapping_request = cls(
            source_control_id=source_control_id,
            target_control_id=target_control_id,
            source_framework=source_framework,
            target_framework=target_framework,
            mapping_strength=mapping_strength,
            notes=notes,
        )

        add_mapping_request.additional_properties = d
        return add_mapping_request

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
