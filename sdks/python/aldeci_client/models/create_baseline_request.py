from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CreateBaselineRequest")


@_attrs_define
class CreateBaselineRequest:
    """
    Attributes:
        baseline_name (str): Descriptive name for the baseline
        target_type (str): server | workstation | network_device | cloud_instance | container | database | application
        framework (str): CIS | NIST | STIG | ISO27001 | PCI-DSS | custom
        created_by (str): Username of creator
        version (str | Unset): Baseline version string Default: '1.0'.
    """

    baseline_name: str
    target_type: str
    framework: str
    created_by: str
    version: str | Unset = "1.0"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        baseline_name = self.baseline_name

        target_type = self.target_type

        framework = self.framework

        created_by = self.created_by

        version = self.version

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "baseline_name": baseline_name,
                "target_type": target_type,
                "framework": framework,
                "created_by": created_by,
            }
        )
        if version is not UNSET:
            field_dict["version"] = version

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        baseline_name = d.pop("baseline_name")

        target_type = d.pop("target_type")

        framework = d.pop("framework")

        created_by = d.pop("created_by")

        version = d.pop("version", UNSET)

        create_baseline_request = cls(
            baseline_name=baseline_name,
            target_type=target_type,
            framework=framework,
            created_by=created_by,
            version=version,
        )

        create_baseline_request.additional_properties = d
        return create_baseline_request

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
