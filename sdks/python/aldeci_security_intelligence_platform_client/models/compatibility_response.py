from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.compatibility_result import CompatibilityResult

T = TypeVar("T", bound="CompatibilityResponse")


@_attrs_define
class CompatibilityResponse:
    """
    Attributes:
        result (CompatibilityResult): Outcome of a compatibility check between two licenses.
        project_license (str):
        dependency_license (str):
        notes (str):
    """

    result: CompatibilityResult
    project_license: str
    dependency_license: str
    notes: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        result = self.result.value

        project_license = self.project_license

        dependency_license = self.dependency_license

        notes = self.notes

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "result": result,
                "project_license": project_license,
                "dependency_license": dependency_license,
                "notes": notes,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        result = CompatibilityResult(d.pop("result"))

        project_license = d.pop("project_license")

        dependency_license = d.pop("dependency_license")

        notes = d.pop("notes")

        compatibility_response = cls(
            result=result,
            project_license=project_license,
            dependency_license=dependency_license,
            notes=notes,
        )

        compatibility_response.additional_properties = d
        return compatibility_response

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
