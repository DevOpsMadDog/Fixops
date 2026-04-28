from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ReferenceCreate")


@_attrs_define
class ReferenceCreate:
    """
    Attributes:
        referenced_artifact_id (str): ID of the artifact being referenced
        reference_type (str | Unset): related | supersedes | implements | required_by Default: 'related'.
        notes (str | Unset):  Default: ''.
    """

    referenced_artifact_id: str
    reference_type: str | Unset = "related"
    notes: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        referenced_artifact_id = self.referenced_artifact_id

        reference_type = self.reference_type

        notes = self.notes

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "referenced_artifact_id": referenced_artifact_id,
            }
        )
        if reference_type is not UNSET:
            field_dict["reference_type"] = reference_type
        if notes is not UNSET:
            field_dict["notes"] = notes

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        referenced_artifact_id = d.pop("referenced_artifact_id")

        reference_type = d.pop("reference_type", UNSET)

        notes = d.pop("notes", UNSET)

        reference_create = cls(
            referenced_artifact_id=referenced_artifact_id,
            reference_type=reference_type,
            notes=notes,
        )

        reference_create.additional_properties = d
        return reference_create

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
