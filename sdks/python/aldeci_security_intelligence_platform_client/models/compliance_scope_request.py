from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="ComplianceScopeRequest")


@_attrs_define
class ComplianceScopeRequest:
    """
    Attributes:
        frameworks (list[str]): Compliance framework values to apply: pci, hipaa, sox, itar, gdpr, nist, iso27001
    """

    frameworks: list[str]
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        frameworks = self.frameworks

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "frameworks": frameworks,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        frameworks = cast(list[str], d.pop("frameworks"))

        compliance_scope_request = cls(
            frameworks=frameworks,
        )

        compliance_scope_request.additional_properties = d
        return compliance_scope_request

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
