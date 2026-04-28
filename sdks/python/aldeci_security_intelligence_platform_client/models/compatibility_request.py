from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="CompatibilityRequest")


@_attrs_define
class CompatibilityRequest:
    """Request body for license compatibility check.

    Attributes:
        project_license (str): SPDX ID of the project license
        dependency_license (str): SPDX ID of the dependency license
    """

    project_license: str
    dependency_license: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        project_license = self.project_license

        dependency_license = self.dependency_license

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "project_license": project_license,
                "dependency_license": dependency_license,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        project_license = d.pop("project_license")

        dependency_license = d.pop("dependency_license")

        compatibility_request = cls(
            project_license=project_license,
            dependency_license=dependency_license,
        )

        compatibility_request.additional_properties = d
        return compatibility_request

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
