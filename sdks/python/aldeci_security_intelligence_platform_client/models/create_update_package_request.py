from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="CreateUpdatePackageRequest")


@_attrs_define
class CreateUpdatePackageRequest:
    """Request to create an offline update package.

    Attributes:
        package_type (str): Type: vuln_db | signatures | compliance_rules | llm_model | full_system
        content_paths (list[str]): List of absolute server-side paths to include in the package
        version (str): Package version string (e.g. 2024.11.1)
        output_path (str): Absolute output path for the generated ZIP package
    """

    package_type: str
    content_paths: list[str]
    version: str
    output_path: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        package_type = self.package_type

        content_paths = self.content_paths

        version = self.version

        output_path = self.output_path

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "package_type": package_type,
                "content_paths": content_paths,
                "version": version,
                "output_path": output_path,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        package_type = d.pop("package_type")

        content_paths = cast(list[str], d.pop("content_paths"))

        version = d.pop("version")

        output_path = d.pop("output_path")

        create_update_package_request = cls(
            package_type=package_type,
            content_paths=content_paths,
            version=version,
            output_path=output_path,
        )

        create_update_package_request.additional_properties = d
        return create_update_package_request

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
