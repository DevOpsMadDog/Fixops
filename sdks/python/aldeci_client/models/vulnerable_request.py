from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="VulnerableRequest")


@_attrs_define
class VulnerableRequest:
    """
    Attributes:
        cve_id (str):
        dependency_fqn_pattern (str): SQL LIKE pattern, e.g. 'requests.Session.mount' or 'requests.%'
        org_id (str | Unset):  Default: 'default'.
    """

    cve_id: str
    dependency_fqn_pattern: str
    org_id: str | Unset = "default"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        cve_id = self.cve_id

        dependency_fqn_pattern = self.dependency_fqn_pattern

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "cve_id": cve_id,
                "dependency_fqn_pattern": dependency_fqn_pattern,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        cve_id = d.pop("cve_id")

        dependency_fqn_pattern = d.pop("dependency_fqn_pattern")

        org_id = d.pop("org_id", UNSET)

        vulnerable_request = cls(
            cve_id=cve_id,
            dependency_fqn_pattern=dependency_fqn_pattern,
            org_id=org_id,
        )

        vulnerable_request.additional_properties = d
        return vulnerable_request

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
