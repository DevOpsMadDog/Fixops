from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.license_result_item import LicenseResultItem


T = TypeVar("T", bound="ViolationsResponse")


@_attrs_define
class ViolationsResponse:
    """
    Attributes:
        org_id (str):
        total_violations (int):
        violations (list[LicenseResultItem]):
    """

    org_id: str
    total_violations: int
    violations: list[LicenseResultItem]
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        total_violations = self.total_violations

        violations = []
        for violations_item_data in self.violations:
            violations_item = violations_item_data.to_dict()
            violations.append(violations_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "total_violations": total_violations,
                "violations": violations,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.license_result_item import LicenseResultItem

        d = dict(src_dict)
        org_id = d.pop("org_id")

        total_violations = d.pop("total_violations")

        violations = []
        _violations = d.pop("violations")
        for violations_item_data in _violations:
            violations_item = LicenseResultItem.from_dict(violations_item_data)

            violations.append(violations_item)

        violations_response = cls(
            org_id=org_id,
            total_violations=total_violations,
            violations=violations,
        )

        violations_response.additional_properties = d
        return violations_response

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
